import json
from datetime import datetime

from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact, ServiceArtifact
from recongraph.normalize import normalize_domain, guess_asset_type_from_host

# Map testssl severity to our severity levels
SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "OK": "info",
    "WARN": "medium",
}

# Enriched impact/remediation for common TLS findings
TLS_ENRICHMENT = {
    "BEAST": {
        "impact": "The BEAST attack allows a network attacker to decrypt portions of HTTPS traffic by exploiting a vulnerability in TLS 1.0's CBC cipher mode. While partially mitigated by modern browsers, it indicates outdated TLS configuration.",
        "remediation": "Disable TLS 1.0 and 1.1. Use TLS 1.2+ with AEAD cipher suites (GCM).",
        "remediation_example": "# Nginx\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\n\n# Apache\nSSLProtocol -all +TLSv1.2 +TLSv1.3",
    },
    "POODLE": {
        "impact": "POODLE allows attackers to downgrade connections to SSL 3.0 and decrypt traffic. Any system still supporting SSL 3.0 is at risk of session hijacking and credential theft.",
        "remediation": "Disable SSL 3.0 entirely.",
        "remediation_example": "# Nginx\nssl_protocols TLSv1.2 TLSv1.3;\n\n# Apache\nSSLProtocol -all -SSLv3 +TLSv1.2 +TLSv1.3",
    },
    "HEARTBLEED": {
        "impact": "Heartbleed (CVE-2014-0160) allows attackers to read server memory, potentially exposing private keys, session tokens, and user credentials. This is one of the most critical TLS vulnerabilities ever discovered.",
        "remediation": "Upgrade OpenSSL immediately, revoke and reissue all certificates, and rotate all credentials.",
        "remediation_example": "# Check OpenSSL version\nopenssl version\n# Must be >= 1.0.1g\napt-get update && apt-get upgrade openssl\n\n# Then reissue your TLS certificates",
    },
    "SWEET32": {
        "impact": "SWEET32 exploits 64-bit block ciphers (3DES, Blowfish) in long-lived HTTPS connections. An attacker monitoring traffic can eventually recover plaintext data.",
        "remediation": "Disable 3DES and other 64-bit block ciphers.",
        "remediation_example": "# Nginx — use only strong ciphers\nssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';\n\n# Verify no 3DES:\nnmap --script ssl-enum-ciphers -p 443 target.com",
    },
    "LUCKY13": {
        "impact": "LUCKY13 is a timing attack against TLS CBC cipher suites that can allow decryption of sensitive data. While difficult to exploit remotely, it indicates weak cipher configuration.",
        "remediation": "Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) over CBC modes.",
        "remediation_example": "# Nginx — prefer GCM ciphers\nssl_prefer_server_ciphers on;\nssl_ciphers 'ECDHE+AESGCM:ECDHE+CHACHA20';",
    },
    "ROBOT": {
        "impact": "The ROBOT attack can decrypt TLS traffic or forge signatures using RSA key exchange. It affects servers that still support RSA encryption (not RSA signing).",
        "remediation": "Disable RSA key exchange cipher suites. Use only ECDHE-based key exchange.",
        "remediation_example": "# Nginx\nssl_ciphers 'ECDHE+AESGCM:ECDHE+CHACHA20:!RSA';\n\n# Apache\nSSLCipherSuite ECDHE+AESGCM:ECDHE+CHACHA20:!RSA",
    },
}


class TestsslScanner(BaseScanner):
    """Deep TLS/SSL analysis using testssl.sh — checks cipher suites, protocols, vulnerabilities."""

    name = "testssl"
    binary = "testssl.sh"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        result = ScanResult(
            scanner=self.name,
            target=target,
            started_at=datetime.utcnow(),
        )

        # Strip protocol for testssl — it handles https automatically
        host = target.replace("https://", "").replace("http://", "").rstrip("/")
        host_only = host
        port = 443
        if host.startswith("[") and "]" in host:
            # IPv6 in brackets; testssl supports bracketed targets.
            host_only = host
        else:
            # host:port
            parts = host.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                host_only = parts[0]
                port = int(parts[1])

        host_norm = normalize_domain(host_only)
        if host_norm:
            host_type = guess_asset_type_from_host(host_norm)
            result.assets.append(AssetArtifact(type=host_type, value=host_only, normalized=host_norm))
            result.services.append(ServiceArtifact(
                host_type=host_type,
                host_value=host_only,
                host_normalized=host_norm,
                port=port,
                proto="tcp",
                name="tls",
                product="",
                version="",
            ))

        cmd = [
            "testssl.sh",
            "--jsonfile", "/tmp/testssl_output.json",
            "--severity", "LOW",
            "--quiet",
            "--color", "0",
            host,
        ]

        try:
            stdout, stderr, returncode = await self.exec_in_container(
                cmd, timeout=300, stream_callback=stream_callback
            )
            result.raw_output = stdout

            # Read the JSON output file from the container
            json_stdout, _, _ = await self.exec_in_container(
                ["cat", "/tmp/testssl_output.json"], timeout=10
            )
            result.findings = self._parse_json(json_stdout, target)
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    def _parse_json(self, json_str: str, target: str) -> list[FindingResult]:
        findings = []
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            # Try line-by-line (testssl sometimes outputs JSON lines)
            data = []
            for line in json_str.strip().split("\n"):
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if isinstance(data, dict):
            data = data.get("scanResult", [data])

        for entry in data:
            if isinstance(entry, dict):
                entries = entry.get("serverDefaults", []) + entry.get("vulnerabilities", []) + entry.get("protocols", []) + entry.get("ciphers", [])
                if not entries:
                    entries = [entry]
                for item in entries:
                    self._process_item(item, target, findings)

        return findings

    def _process_item(self, item: dict, target: str, findings: list[FindingResult]):
        item_id = item.get("id", "")
        severity_str = item.get("severity", "INFO").upper()
        finding_text = item.get("finding", "")

        if not finding_text or severity_str in ("OK", "INFO"):
            # Still capture interesting info items
            if severity_str == "INFO" and item_id and any(k in item_id.lower() for k in ["cert", "chain", "trust"]):
                findings.append(FindingResult(
                    severity="info",
                    title=f"[TLS] {item_id}",
                    description=finding_text,
                    url=target,
                ))
            return

        severity = SEVERITY_MAP.get(severity_str, "info")

        # Look up enrichment
        enrichment = {}
        for key, data in TLS_ENRICHMENT.items():
            if key.lower() in item_id.lower() or key.lower() in finding_text.lower():
                enrichment = data
                break

        findings.append(FindingResult(
            severity=severity,
            title=f"[TLS] {item_id}: {finding_text[:80]}",
            description=finding_text,
            impact=enrichment.get("impact", f"This TLS/SSL issue ({item_id}) weakens the encryption protecting data in transit. Depending on severity, attackers may be able to decrypt traffic, downgrade connections, or perform man-in-the-middle attacks."),
            evidence=f"testssl.sh finding: {item_id}\n{finding_text}",
            url=target,
            remediation=enrichment.get("remediation", "Review and update your TLS configuration to use modern protocols (TLS 1.2+) and strong cipher suites."),
            remediation_example=enrichment.get("remediation_example", "# Nginx — modern TLS config\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\nssl_prefer_server_ciphers off;\n\n# Mozilla SSL Configuration Generator:\n# https://ssl-config.mozilla.org/"),
        ))
