import json
import shlex
from datetime import datetime

from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact
from recongraph.normalize import normalize_domain


WEAK_TLS = {"tls10", "tls11", "ssl30"}


class TlsxScanner(BaseScanner):
    """Grab TLS certificate metadata (SANs, issuer, version) via tlsx."""

    name = "tlsx"
    binary = "tlsx"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        result = ScanResult(scanner=self.name, target=target, started_at=datetime.utcnow())

        targets = config.get("targets", [target])
        if isinstance(targets, str):
            targets = [targets]
        cleaned = [str(t).strip() for t in targets if str(t).strip()]
        if not cleaned:
            cleaned = [target]

        quoted = " ".join(shlex.quote(t) for t in cleaned)
        # -json full cert metadata, -san subject alt names, -tls-version negotiated version
        cmd = ["sh", "-c",
               "printf '%s\\n' " + quoted +
               " | tlsx -json -san -tls-version -silent"]

        lines: list[str] = []

        async def on_line(line: str):
            lines.append(line)
            if stream_callback:
                await stream_callback(line)

        try:
            stdout, stderr, returncode = await self.exec_in_container(
                cmd, timeout=180, stream_callback=on_line
            )
            if not lines and stdout:
                lines = stdout.strip().split("\n")
            result.raw_output = "\n".join(lines)
            findings, assets = self._parse_lines(lines)
            result.findings = findings
            result.assets = assets
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    def _parse_lines(self, lines: list[str]) -> tuple[list[FindingResult], list[AssetArtifact]]:
        findings: list[FindingResult] = []
        assets: list[AssetArtifact] = []

        for line in lines:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = data.get("host", "")
            issuer = data.get("issuer_cn", "")
            tls_version = (data.get("tls_version") or "").lower()
            not_after = data.get("not_after", "")

            # SAN hostnames -> subdomain assets
            for san in data.get("subject_an", []) or []:
                san_norm = normalize_domain(san)
                if san_norm and not san_norm.startswith("*"):
                    assets.append(AssetArtifact(type="subdomain", value=san, normalized=san_norm))

            # Info finding: cert summary
            findings.append(FindingResult(
                severity="info",
                title=f"TLS certificate: {host}",
                description=f"Host {host} — issuer: {issuer or 'unknown'}, TLS: {tls_version or 'unknown'}, expires: {not_after or 'unknown'}",
                evidence=f"issuer={issuer} tls_version={tls_version} not_after={not_after}",
                url=host,
            ))

            # Low finding: weak TLS version
            if tls_version in WEAK_TLS:
                findings.append(FindingResult(
                    severity="low",
                    title=f"Weak TLS version {tls_version} on {host}",
                    description=f"Host {host} negotiates {tls_version}, which is deprecated and vulnerable to downgrade/known attacks.",
                    impact="Deprecated TLS versions (1.0/1.1, SSL 3.0) have known cryptographic weaknesses. Attackers on-path can exploit these for downgrade attacks or decryption.",
                    remediation="Disable TLS 1.0/1.1 and SSL 3.0; require TLS 1.2+ (ideally 1.3).",
                    url=host,
                ))

        return findings, assets
