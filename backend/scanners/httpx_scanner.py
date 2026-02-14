import json
import shlex
from datetime import datetime
from urllib.parse import urlparse

from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact, EdgeArtifact
from recongraph.normalize import normalize_url, normalize_domain, guess_asset_type_from_host


class HttpxScanner(BaseScanner):
    """Probe discovered hosts/URLs for live services, tech stack, and status codes using httpx."""

    name = "httpx"
    binary = "httpx"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        result = ScanResult(
            scanner=self.name,
            target=target,
            started_at=datetime.utcnow(),
        )

        # httpx can take a single URL or a list via stdin
        # We'll pipe the target(s) in
        targets = config.get("targets", [target])
        if isinstance(targets, str):
            targets = [targets]

        cmd = [
            "httpx",
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-follow-redirects",
            "-content-length",
            "-web-server",
        ]

        # Feed targets via -u for a single target, or -l for list
        if len(targets) == 1:
            cmd += ["-u", targets[0]]
        else:
            cleaned = [str(t).strip() for t in targets if str(t).strip()]
            if not cleaned:
                cmd += ["-u", target]
            else:
                quoted = " ".join(shlex.quote(t) for t in cleaned)
                cmd = ["sh", "-c", "printf '%s\\n' " + quoted + " | httpx -json -silent -status-code -title -tech-detect -follow-redirects -content-length -web-server"]

        lines = []

        async def on_line(line: str):
            lines.append(line)
            if stream_callback:
                await stream_callback(line)

        try:
            stdout, stderr, returncode = await self.exec_in_container(
                cmd, timeout=120, stream_callback=on_line
            )

            if not lines and stdout:
                lines = stdout.strip().split("\n")

            result.raw_output = "\n".join(lines)
            findings, assets, edges = self._parse_results(lines)
            result.findings = findings
            result.assets = assets
            result.edges = edges
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    def _parse_results(self, lines: list[str]) -> tuple[list[FindingResult], list[AssetArtifact], list[EdgeArtifact]]:
        findings: list[FindingResult] = []
        assets: list[AssetArtifact] = []
        edges: list[EdgeArtifact] = []

        for line in lines:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = data.get("url", data.get("input", ""))
            status = data.get("status_code", 0)
            title = data.get("title", "")
            tech = data.get("tech", [])
            web_server = data.get("webserver", "")
            content_length = data.get("content_length", 0)

            url_norm = normalize_url(url)
            if url_norm:
                assets.append(AssetArtifact(type="url", value=url, normalized=url_norm))

                parsed = urlparse(url_norm)
                host = parsed.hostname or ""
                host_norm = normalize_domain(host)
                if host_norm:
                    host_type = guess_asset_type_from_host(host_norm)
                    assets.append(AssetArtifact(type=host_type, value=host, normalized=host_norm))
                    edges.append(EdgeArtifact(
                        from_type=host_type,
                        from_value=host,
                        from_normalized=host_norm,
                        to_type="url",
                        to_value=url,
                        to_normalized=url_norm,
                        rel_type="serves",
                    ))

            tech_str = ", ".join(tech) if tech else "none detected"
            desc = f"Live host: {url} [HTTP {status}]"
            if title:
                desc += f" Title: {title}"
            if web_server:
                desc += f" Server: {web_server}"
            desc += f" Technologies: {tech_str}"

            findings.append(FindingResult(
                severity="info",
                title=f"Live host: {url} [{status}]",
                description=desc,
                impact=f"This host is live and publicly accessible. Technologies detected: {tech_str}. Each technology expands the attack surface — attackers will look for known vulnerabilities in these specific versions.",
                evidence=f"Status: {status}, Title: {title}, Server: {web_server}, Tech: {tech_str}, Content-Length: {content_length}",
                url=url,
            ))

            # Flag interesting findings
            if web_server and any(v in web_server.lower() for v in ["apache/2.2", "nginx/1.0", "iis/6", "iis/7"]):
                findings.append(FindingResult(
                    severity="medium",
                    title=f"Outdated web server: {web_server}",
                    description=f"The web server at {url} is running {web_server}, which is outdated and likely has known vulnerabilities.",
                    impact=f"Outdated server software ({web_server}) has publicly known CVEs with available exploits. Attackers can use automated tools to identify and exploit these vulnerabilities for remote code execution or denial of service.",
                    url=url,
                    remediation="Upgrade to the latest stable version of your web server.",
                    remediation_example="# Check current version and upgrade\nnginx -v  # Then upgrade via package manager\napt-get update && apt-get upgrade nginx\n\n# Or for Apache\napachectl -v\napt-get update && apt-get upgrade apache2",
                ))

        return findings, assets, edges
