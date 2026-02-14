from datetime import datetime
from urllib.parse import urlparse

from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact, EdgeArtifact
from recongraph.normalize import normalize_url, normalize_domain, guess_asset_type_from_host


# Nikto finding IDs and their enrichment
NIKTO_ENRICHMENT = {
    "outdated": {
        "impact": "Outdated server software has publicly known vulnerabilities with available exploits. Attackers use version-specific CVE databases and automated tools to compromise unpatched systems.",
        "remediation_example": "# Update your web server\napt-get update && apt-get upgrade\n\n# Or for specific packages:\napt-get install --only-upgrade apache2\napt-get install --only-upgrade nginx",
    },
    "directory listing": {
        "impact": "Directory listing reveals all files in a directory, potentially exposing backup files, configuration files, source code, and other sensitive data that should not be publicly accessible.",
        "remediation_example": "# Nginx\nautoindex off;\n\n# Apache\nOptions -Indexes\n\n# Apache .htaccess\nOptions -Indexes",
    },
    "default": {
        "impact": "Default files, pages, or configurations left in production provide attackers with information about your server software and version, and may include known vulnerabilities or default credentials.",
        "remediation_example": "# Remove default files\nrm -rf /var/www/html/index.html  # Default welcome page\nrm -rf /usr/share/nginx/html/50x.html  # Default error pages\n\n# Or replace with custom pages",
    },
}


class NiktoScanner(BaseScanner):
    """Classic web server scanner using Nikto — finds outdated software, dangerous files, and misconfigurations."""

    name = "nikto"
    binary = "nikto.pl"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        result = ScanResult(
            scanner=self.name,
            target=target,
            started_at=datetime.utcnow(),
        )

        # Parse target into components Nikto understands.
        # Nikto's -h flag expects hostname or hostname:port — NOT a full URL.
        # We must also pass -ssl for HTTPS targets.
        use_ssl = False
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            use_ssl = parsed.scheme == "https"
            host = parsed.hostname or target
            port = parsed.port or (443 if use_ssl else 80)
            # Keep original target as the canonical URL for artifacts/findings
            target_url = target
        else:
            # Bare domain — assume HTTPS
            host = target.split(":")[0].split("/")[0]
            port = int(target.split(":")[1]) if ":" in target else 443
            use_ssl = True
            target_url = f"https://{host}:{port}" if port != 443 else f"https://{host}"

        nikto_host = f"{host}:{port}" if port not in (80, 443) else host

        # ReconGraph artifacts: base URL + host -> url.
        url_norm = normalize_url(target_url)
        if url_norm:
            result.assets.append(AssetArtifact(type="url", value=target_url, normalized=url_norm))
            host_norm = normalize_domain(url_norm)
            if host_norm:
                host_type = guess_asset_type_from_host(host_norm)
                result.assets.append(AssetArtifact(type=host_type, value=host_norm, normalized=host_norm))
                result.edges.append(EdgeArtifact(
                    from_type=host_type,
                    from_value=host_norm,
                    from_normalized=host_norm,
                    to_type="url",
                    to_value=target_url,
                    to_normalized=url_norm,
                    rel_type="serves",
                ))

        cmd = [
            "nikto.pl",
            "-h", nikto_host,
            "-port", str(port),
            "-Format", "csv",
            "-output", "/tmp/nikto_output.csv",
            "-Tuning", config.get("tuning", "123bde"),  # Common tests
            "-timeout", "10",
            "-nointeractive",
        ]
        if use_ssl:
            cmd.extend(["-ssl"])

        try:
            stdout, stderr, returncode = await self.exec_in_container(
                cmd, timeout=600, stream_callback=stream_callback
            )
            result.raw_output = stdout

            # Read CSV output
            csv_stdout, _, _ = await self.exec_in_container(
                ["cat", "/tmp/nikto_output.csv"], timeout=10
            )
            result.findings = self._parse_csv(csv_stdout, target_url)

            # Also parse stdout for findings (nikto outputs findings to stdout too)
            if not result.findings:
                result.findings = self._parse_stdout(stdout, target_url)

            # URL artifacts for any finding URLs.
            seen_norm: set[str] = set()
            for f in result.findings:
                if not f.url:
                    continue
                u_norm = normalize_url(f.url)
                if not u_norm or u_norm in seen_norm:
                    continue
                seen_norm.add(u_norm)
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

    def _parse_csv(self, csv_str: str, target: str) -> list[FindingResult]:
        findings = []
        for line in csv_str.strip().split("\n"):
            if not line.strip() or line.startswith('"') and "Hostname" in line:
                continue

            parts = line.strip().strip('"').split('","')
            if len(parts) < 7:
                continue

            try:
                # CSV format: "hostname","IP","port","reference","method","URL","message"
                hostname = parts[0].strip('"')
                ip = parts[1].strip('"')
                port = parts[2].strip('"')
                ref = parts[3].strip('"')
                method = parts[4].strip('"')
                url_path = parts[5].strip('"')
                message = parts[6].strip('"')
            except IndexError:
                continue

            severity = self._classify_severity(message, ref)
            enrichment = self._get_enrichment(message)

            full_url = f"{target.rstrip('/')}{url_path}" if url_path else target

            findings.append(FindingResult(
                severity=severity,
                title=f"[nikto] {message[:80]}",
                description=message,
                impact=enrichment.get("impact", f"This web server issue identified by Nikto could expose sensitive information, enable further attacks, or indicate outdated/misconfigured software."),
                evidence=f"Nikto ID: {ref}\nMethod: {method}\nPath: {url_path}",
                url=full_url,
                remediation=enrichment.get("remediation", "Review and address the finding based on Nikto's recommendation."),
                remediation_example=enrichment.get("remediation_example", ""),
            ))

        return findings

    def _parse_stdout(self, stdout: str, target: str) -> list[FindingResult]:
        """Parse nikto's stdout output as a fallback."""
        findings = []
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith("-") or line.startswith("+") and "Target" in line:
                continue

            # Nikto prefixes findings with "+ "
            if line.startswith("+ "):
                message = line[2:].strip()
                if any(skip in message.lower() for skip in ["target ip:", "target hostname:", "target port:", "start time:", "end time:", "host(s) tested"]):
                    continue

                severity = self._classify_severity(message, "")
                enrichment = self._get_enrichment(message)

                # Extract URL if present (Nikto often includes it)
                url = target
                if ": " in message and "/" in message.split(": ")[0]:
                    url_path = message.split(":")[0].strip()
                    if url_path.startswith("/"):
                        url = f"{target.rstrip('/')}{url_path}"

                findings.append(FindingResult(
                    severity=severity,
                    title=f"[nikto] {message[:80]}",
                    description=message,
                    impact=enrichment.get("impact", "This finding indicates a potential security issue in your web server configuration that should be investigated."),
                    evidence=f"Raw output: {message}",
                    url=url,
                    remediation=enrichment.get("remediation", "Address the finding based on the description."),
                    remediation_example=enrichment.get("remediation_example", ""),
                ))

        return findings

    @staticmethod
    def _classify_severity(message: str, ref: str) -> str:
        """Classify nikto finding severity based on message content."""
        msg_lower = message.lower()

        if any(kw in msg_lower for kw in ["remote code execution", "rce", "command injection", "backdoor", "shell"]):
            return "critical"
        if any(kw in msg_lower for kw in ["sql injection", "xss", "file inclusion", "traversal", "upload"]):
            return "high"
        if any(kw in msg_lower for kw in ["outdated", "vulnerable", "cve-", "exploit"]):
            return "high"
        if any(kw in msg_lower for kw in ["directory listing", "index of", "directory indexing"]):
            return "medium"
        if any(kw in msg_lower for kw in ["default", "backup", "config", "password"]):
            return "medium"
        if any(kw in msg_lower for kw in ["header", "cookie", "disclosure", "information"]):
            return "low"
        return "info"

    @staticmethod
    def _get_enrichment(message: str) -> dict:
        """Get enrichment data based on message content."""
        msg_lower = message.lower()
        for key, data in NIKTO_ENRICHMENT.items():
            if key in msg_lower:
                return data
        return {}
