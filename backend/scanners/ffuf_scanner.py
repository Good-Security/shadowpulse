import json
import uuid
from datetime import datetime
from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact, EdgeArtifact
from recongraph.normalize import normalize_url, normalize_domain, guess_asset_type_from_host

# Common soft-404 body indicators (lowercase)
SOFT_404_KEYWORDS = [
    "page not found", "not found", "404", "does not exist",
    "doesn't exist", "no longer available", "page you requested",
    "could not be found", "cannot be found", "isn't available",
    "page is missing", "nothing here", "page has moved",
]


# Interesting paths that indicate specific risks
SENSITIVE_PATHS = {
    ".env": ("critical", "Environment file containing secrets"),
    ".git": ("critical", "Git repository exposed — source code and history leak"),
    ".git/config": ("critical", "Git config exposed — may contain credentials"),
    ".svn": ("high", "SVN metadata exposed"),
    "wp-admin": ("medium", "WordPress admin panel"),
    "wp-login.php": ("medium", "WordPress login page"),
    "phpmyadmin": ("high", "phpMyAdmin database admin exposed"),
    "adminer": ("high", "Adminer database admin exposed"),
    "admin": ("medium", "Admin panel accessible"),
    "backup": ("high", "Backup directory accessible"),
    "debug": ("high", "Debug endpoint accessible"),
    "console": ("high", "Debug console accessible (possible RCE)"),
    "server-status": ("medium", "Apache server-status exposed"),
    "server-info": ("medium", "Apache server-info exposed"),
    "elmah.axd": ("high", "ASP.NET error log exposed"),
    "trace.axd": ("high", "ASP.NET trace exposed"),
    "actuator": ("medium", "Spring Boot Actuator exposed"),
    "actuator/env": ("critical", "Spring Boot environment — secrets exposed"),
    "swagger": ("medium", "Swagger API docs exposed"),
    "graphql": ("medium", "GraphQL endpoint exposed"),
    "api-docs": ("medium", "API documentation exposed"),
}


class FfufScanner(BaseScanner):
    """Fast web fuzzer for directory and file brute-forcing using ffuf."""

    name = "ffuf"
    binary = "ffuf"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        wordlist = config.get("wordlist", "/usr/share/wordlists/common.txt")
        result = ScanResult(
            scanner=self.name,
            target=target,
            started_at=datetime.utcnow(),
        )

        base_url = target.rstrip("/")

        # Base URL artifact
        base_norm = normalize_url(base_url)
        if base_norm:
            result.assets.append(AssetArtifact(type="url", value=base_url, normalized=base_norm))
            host_norm = normalize_domain(base_url)
            if host_norm:
                host_type = guess_asset_type_from_host(host_norm)
                result.assets.append(AssetArtifact(type=host_type, value=host_norm, normalized=host_norm))
                result.edges.append(EdgeArtifact(
                    from_type=host_type,
                    from_value=host_norm,
                    from_normalized=host_norm,
                    to_type="url",
                    to_value=base_url,
                    to_normalized=base_norm,
                    rel_type="serves",
                ))

        # --- Soft-404 calibration ---
        # Fetch a random nonexistent path to measure the baseline "404 page" size.
        # If the site returns 200 with a custom error page, we filter by that size.
        calibration_path = f"shadowpulse_calibration_{uuid.uuid4().hex[:8]}"
        filter_size = None
        baseline_body = ""
        try:
            cal_stdout, _, _ = await self.exec_in_container(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{size_download}",
                 "-k", "--max-time", "10", f"{base_url}/{calibration_path}"],
                timeout=15,
            )
            parts = cal_stdout.strip().split()
            if len(parts) >= 2:
                cal_status = int(parts[0])
                cal_size = int(parts[1])
                if cal_status == 200 and cal_size > 0:
                    # Site returns 200 for nonexistent paths — filter by this size
                    filter_size = cal_size
                    if stream_callback:
                        await stream_callback(
                            f"[ffuf] Soft-404 detected: site returns 200 with {cal_size} bytes for unknown paths, filtering by size"
                        )
                    # Also grab the body for keyword matching during post-processing
                    body_stdout, _, _ = await self.exec_in_container(
                        ["curl", "-s", "-k", "--max-time", "10", f"{base_url}/{calibration_path}"],
                        timeout=15,
                    )
                    baseline_body = body_stdout.strip()
        except Exception:
            pass  # Calibration failure is non-fatal; proceed without filter

        cmd = [
            "ffuf",
            "-u", f"{base_url}/FUZZ",
            "-w", wordlist,
            "-o", "/tmp/ffuf_output.json",
            "-of", "json",
            "-mc", "200,201,204,301,302,307,401,403",  # Match these status codes
            "-fc", "404",
            "-t", "20",  # 20 threads — reasonable for scanning
            "-timeout", "10",
            "-s",  # Silent mode (no banner)
        ]

        # If we detected a soft-404 page, filter responses of that exact size
        # (and ±10% to account for minor dynamic content variations)
        if filter_size is not None:
            low = max(0, filter_size - max(50, filter_size // 10))
            high = filter_size + max(50, filter_size // 10)
            cmd.extend(["-fs", f"{low}-{high}"])

        try:
            stdout, stderr, returncode = await self.exec_in_container(
                cmd, timeout=300, stream_callback=stream_callback
            )
            result.raw_output = stdout

            # Read the JSON output
            json_stdout, _, _ = await self.exec_in_container(
                ["cat", "/tmp/ffuf_output.json"], timeout=10
            )
            result.findings = self._parse_results(json_stdout, base_url, baseline_body)

            # Artifacts for discovered endpoints (URLs).
            seen_url_norm: set[str] = set()
            for f in result.findings:
                if not f.url:
                    continue
                u_norm = normalize_url(f.url)
                if not u_norm or u_norm in seen_url_norm:
                    continue
                seen_url_norm.add(u_norm)
                result.assets.append(AssetArtifact(type="url", value=f.url, normalized=u_norm))

                host_norm = normalize_domain(u_norm)
                if host_norm:
                    host_type = guess_asset_type_from_host(host_norm)
                    result.assets.append(AssetArtifact(type=host_type, value=host_norm, normalized=host_norm))
                    result.edges.append(EdgeArtifact(
                        from_type=host_type,
                        from_value=host_norm,
                        from_normalized=host_norm,
                        to_type="url",
                        to_value=f.url,
                        to_normalized=u_norm,
                        rel_type="serves",
                    ))

            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    def _parse_results(self, json_str: str, base_url: str, baseline_body: str = "") -> list[FindingResult]:
        findings = []
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return findings

        results = data.get("results", [])
        for item in results:
            path = item.get("input", {}).get("FUZZ", "")
            status = item.get("status", 0)
            length = item.get("length", 0)
            url = f"{base_url}/{path}"

            # --- Soft-404 post-processing ---
            # If the response body looks like a generic error page, skip it
            if status == 200 and self._looks_like_soft_404(length, baseline_body):
                continue

            # Check if this is a known sensitive path
            sensitivity = None
            for sensitive_path, (sev, desc) in SENSITIVE_PATHS.items():
                if sensitive_path.lower() in path.lower():
                    sensitivity = (sev, desc)
                    break

            if sensitivity:
                sev, desc = sensitivity
                findings.append(FindingResult(
                    severity=sev,
                    title=f"Sensitive path found: /{path}",
                    description=f"{desc}. Returned HTTP {status} with {length} bytes.",
                    impact=self._sensitive_impact(path, sev),
                    evidence=f"GET {url} → HTTP {status} ({length} bytes)",
                    url=url,
                    remediation=f"Block access to /{path} in your web server configuration.",
                    remediation_example=self._sensitive_remediation(path),
                ))
            elif status in (200, 201, 204):
                findings.append(FindingResult(
                    severity="info",
                    title=f"Discovered path: /{path} [{status}]",
                    description=f"The path /{path} returned HTTP {status} ({length} bytes). This endpoint is accessible.",
                    impact="Each discovered path expands the known attack surface. Attackers use directory brute-forcing to find hidden admin panels, backup files, configuration endpoints, and unprotected API routes.",
                    evidence=f"GET {url} → HTTP {status} ({length} bytes)",
                    url=url,
                ))
            elif status == 401:
                findings.append(FindingResult(
                    severity="low",
                    title=f"Authenticated endpoint: /{path} [{status}]",
                    description=f"The path /{path} requires authentication (HTTP 401). This confirms the endpoint exists.",
                    impact="While properly protected by authentication, the existence of this endpoint is now confirmed. Attackers can attempt credential brute-forcing or look for authentication bypass vulnerabilities.",
                    evidence=f"GET {url} → HTTP {status} ({length} bytes)",
                    url=url,
                ))
            elif status == 403:
                findings.append(FindingResult(
                    severity="info",
                    title=f"Forbidden path: /{path} [{status}]",
                    description=f"The path /{path} exists but returns 403 Forbidden.",
                    impact="A 403 response confirms the path exists even though access is denied. Attackers may try to bypass the restriction through path traversal, alternate HTTP methods, or header manipulation.",
                    evidence=f"GET {url} → HTTP {status} ({length} bytes)",
                    url=url,
                ))

        return findings

    @staticmethod
    def _sensitive_impact(path: str, severity: str) -> str:
        path_lower = path.lower()
        if ".git" in path_lower:
            return "The .git directory is exposed, allowing attackers to download your complete source code, commit history, and potentially credentials stored in previous commits. Tools like git-dumper automate full repository reconstruction from exposed .git directories."
        if ".env" in path_lower:
            return "The .env file is publicly accessible. It typically contains database credentials, API keys, encryption secrets, and third-party service tokens. This is often a complete application compromise."
        if "backup" in path_lower:
            return "Backup files may contain full database dumps, source code, or configuration files with credentials. Attackers regularly scan for common backup file patterns."
        if "admin" in path_lower or "phpmyadmin" in path_lower or "adminer" in path_lower:
            return "Administrative interfaces provide elevated access to application or database management. If accessible without proper authentication, attackers can read/modify all data, create admin accounts, or execute arbitrary commands."
        if "actuator" in path_lower:
            return "Spring Boot Actuator endpoints can expose environment variables (including secrets), heap dumps, thread dumps, and application configuration. The /actuator/env endpoint is especially dangerous as it may reveal database passwords and API keys."
        if "debug" in path_lower or "console" in path_lower:
            return "Debug endpoints and consoles (like Werkzeug debugger, Django debug toolbar) often allow arbitrary code execution. An exposed debug console is effectively remote code execution (RCE)."
        return f"This sensitive path (/{path}) being accessible indicates a security misconfiguration that could lead to information disclosure or unauthorized access."

    @staticmethod
    def _sensitive_remediation(path: str) -> str:
        path_lower = path.lower()
        if ".git" in path_lower:
            return "# Nginx — block .git access\nlocation ~ /\\.git {\n    deny all;\n    return 404;\n}\n\n# Apache .htaccess\nRedirectMatch 404 /\\.git\n\n# Also consider: remove .git from production deployments entirely"
        if ".env" in path_lower:
            return "# Nginx — block dotfiles\nlocation ~ /\\. {\n    deny all;\n    return 404;\n}\n\n# IMPORTANT: Rotate ALL credentials in the .env file immediately"
        if "actuator" in path_lower:
            return "# Spring Boot — restrict actuator in application.properties\nmanagement.endpoints.web.exposure.include=health,info\nmanagement.server.port=8081  # Different port, not public\n\n# Or require authentication\nmanagement.endpoints.web.exposure.include=*\nspring.security.user.name=admin\nspring.security.user.password=<strong-password>"
        return f"# Nginx — block access\nlocation /{path} {{\n    deny all;\n    return 404;\n}}\n\n# Apache\n<Location /{path}>\n    Require all denied\n</Location>"

    @staticmethod
    def _looks_like_soft_404(response_length: int, baseline_body: str) -> bool:
        """Check if a response is likely a soft-404 based on the calibration baseline."""
        if not baseline_body:
            return False
        baseline_len = len(baseline_body)
        if baseline_len == 0:
            return False
        # If the response size is within 15% of the baseline 404 page, it's likely the same page
        tolerance = max(50, baseline_len * 0.15)
        return abs(response_length - baseline_len) < tolerance
