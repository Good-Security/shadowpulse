import json
from datetime import datetime
from urllib.parse import urlparse

from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact, EdgeArtifact
from recongraph.normalize import normalize_url, normalize_domain, guess_asset_type_from_host


class KatanaScanner(BaseScanner):
    """Web crawler that discovers endpoints, JavaScript files, API routes, and hidden parameters using katana."""

    name = "katana"
    binary = "katana"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        depth = config.get("depth", "3")
        result = ScanResult(
            scanner=self.name,
            target=target,
            started_at=datetime.utcnow(),
        )

        cmd = [
            "katana",
            "-u", target,
            "-d", str(depth),
            "-jc",           # JavaScript crawling
            "-jsonl",
            "-or",           # Omit raw request/response in jsonl output
            "-ob",           # Omit response body in jsonl output
            "-silent",
            "-kf", "all",    # Known file detection
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",  # Exclude static assets
        ]

        lines = []

        async def on_line(line: str):
            lines.append(line)
            if stream_callback:
                await stream_callback(line)

        try:
            stdout, stderr, returncode = await self.exec_in_container(
                cmd, timeout=300, stream_callback=on_line
            )

            output_text = stdout.strip() if stdout else ""
            if not output_text and stderr:
                output_text = stderr.strip()

            if not lines and output_text:
                lines = output_text.split("\n")

            result.raw_output = "\n".join(lines)[:50000]

            if returncode != 0:
                # Katana prints usage/flag errors to stderr; surface that as failure.
                result.status = "failed"
                result.error = (stderr.strip() or stdout.strip() or f"katana exited {returncode}")[:50000]
            else:
                findings, discovered_urls = self._parse_results(lines, target)
                result.findings = findings

                # Artifacts: discovered URLs + host -> url edges.
                seen_norm: set[str] = set()
                for u in discovered_urls:
                    u_norm = normalize_url(u)
                    if not u_norm or u_norm in seen_norm:
                        continue
                    seen_norm.add(u_norm)
                    result.assets.append(AssetArtifact(type="url", value=u, normalized=u_norm))

                    host_norm = normalize_domain(u_norm)
                    if host_norm:
                        host_type = guess_asset_type_from_host(host_norm)
                        result.assets.append(AssetArtifact(type=host_type, value=host_norm, normalized=host_norm))
                        result.edges.append(EdgeArtifact(
                            from_type=host_type,
                            from_value=host_norm,
                            from_normalized=host_norm,
                            to_type="url",
                            to_value=u,
                            to_normalized=u_norm,
                            rel_type="serves",
                        ))

                result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    def _parse_results(self, lines: list[str], target: str) -> tuple[list[FindingResult], list[str]]:
        findings: list[FindingResult] = []
        seen_urls = set()
        discovered_urls: list[str] = []
        js_files = []
        api_endpoints = []
        forms = []
        interesting = []

        for line in lines:
            if not line.strip():
                continue

            # Try to parse as JSON
            try:
                data = json.loads(line)
                url = data.get("request", {}).get("endpoint", "") or data.get("endpoint", line.strip())
            except json.JSONDecodeError:
                url = line.strip()
                data = {}

            if url in seen_urls:
                continue
            seen_urls.add(url)
            discovered_urls.append(url)

            source = data.get("source", "")
            tag = data.get("tag", "")

            # Categorize discovered URLs
            parsed = urlparse(url)
            path = parsed.path.lower()

            if path.endswith(".js") or path.endswith(".mjs"):
                js_files.append(url)
            elif any(seg in path for seg in ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"]):
                api_endpoints.append(url)
            elif tag == "form" or "action=" in str(data):
                forms.append(url)
            elif any(seg in path for seg in [".env", "config", "admin", "debug", "backup", ".git", "wp-", "phpmy"]):
                interesting.append(url)

        # Create findings for each category
        if js_files:
            js_list = "\n".join(f"  - {u}" for u in js_files[:20])
            findings.append(FindingResult(
                severity="info",
                title=f"JavaScript files discovered ({len(js_files)})",
                description=f"Crawling found {len(js_files)} JavaScript files that may contain API keys, endpoints, or sensitive logic.",
                impact="JavaScript files often contain hardcoded API keys, internal API endpoint URLs, authentication logic, and comments with sensitive information. Tools like LinkFinder and JSBeautifier can extract secrets from minified JS.",
                evidence=f"Discovered JS files:\n{js_list}",
                url=target,
                remediation="Audit JS files for hardcoded secrets. Use environment variables instead of embedding API keys in client-side code.",
                remediation_example="# Search for secrets in JS files\n# Install trufflehog or gitleaks\nfor f in *.js; do\n  grep -E '(api[_-]?key|secret|token|password|authorization)' \"$f\"\ndone\n\n# Use environment variables instead\nconst API_KEY = process.env.REACT_APP_API_KEY;  // Not hardcoded",
            ))

        if api_endpoints:
            api_list = "\n".join(f"  - {u}" for u in api_endpoints[:20])
            findings.append(FindingResult(
                severity="low",
                title=f"API endpoints discovered ({len(api_endpoints)})",
                description=f"Crawling found {len(api_endpoints)} API endpoints that should be tested for authentication and authorization.",
                impact="Discovered API endpoints expand the attack surface. Each endpoint should be tested for authentication bypass, IDOR (Insecure Direct Object Reference), injection vulnerabilities, and excessive data exposure.",
                evidence=f"Discovered API endpoints:\n{api_list}",
                url=target,
                remediation="Ensure all API endpoints require proper authentication and authorization. Test each endpoint with the API scanner.",
            ))

        if forms:
            form_list = "\n".join(f"  - {u}" for u in forms[:10])
            findings.append(FindingResult(
                severity="low",
                title=f"Forms discovered ({len(forms)})",
                description=f"Crawling found {len(forms)} HTML forms that accept user input — potential injection points.",
                impact="Forms are primary targets for XSS, SQL injection, and CSRF attacks. Each form should be tested for input validation, CSRF token presence, and proper encoding of output.",
                evidence=f"Discovered forms:\n{form_list}",
                url=target,
                remediation="Ensure all forms have CSRF tokens, validate/sanitize input server-side, and encode output properly.",
            ))

        if interesting:
            for url in interesting:
                findings.append(FindingResult(
                    severity="medium",
                    title=f"Interesting path crawled: {urlparse(url).path}",
                    description=f"The crawler discovered a potentially sensitive path: {url}",
                    impact="This path may contain sensitive configuration, admin functionality, or exposed internal tooling. It should be investigated further with targeted scanning.",
                    url=url,
                    remediation="Verify this path should be publicly accessible. If not, block it at the web server level.",
                ))

        # Summary finding
        findings.append(FindingResult(
            severity="info",
            title=f"Crawl complete: {len(seen_urls)} unique URLs discovered",
            description=f"Katana crawled {target} and discovered {len(seen_urls)} unique URLs: {len(js_files)} JS files, {len(api_endpoints)} API endpoints, {len(forms)} forms, {len(interesting)} interesting paths.",
            url=target,
        ))

        return findings, discovered_urls
