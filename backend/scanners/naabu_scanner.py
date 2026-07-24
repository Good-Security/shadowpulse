import json
import shlex
from datetime import datetime

from scanners.base import BaseScanner, ScanResult, FindingResult, ServiceArtifact, AssetArtifact
from recongraph.normalize import normalize_domain, guess_asset_type_from_host


def ports_by_host(services: list[ServiceArtifact]) -> dict[str, str]:
    """Group open ports per host into an nmap -p string: {host: '80,443'}."""
    grouped: dict[str, set[int]] = {}
    for s in services:
        if not s.host_normalized or not s.port:
            continue
        grouped.setdefault(s.host_normalized, set()).add(s.port)
    return {
        host: ",".join(str(p) for p in sorted(ports))
        for host, ports in grouped.items()
    }


class NaabuScanner(BaseScanner):
    """Fast SYN/CONNECT port discovery. Feeds open ports to nmap for deep scans."""

    name = "naabu"
    binary = "naabu"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        result = ScanResult(scanner=self.name, target=target, started_at=datetime.utcnow())

        targets = config.get("targets", [target])
        if isinstance(targets, str):
            targets = [targets]
        cleaned = [str(t).strip() for t in targets if str(t).strip()]
        if not cleaned:
            cleaned = [target]

        # naabu reads hosts from stdin with -list -, emits JSON per open port.
        # -top-ports 1000 keeps it fast; -silent suppresses banner.
        quoted = " ".join(shlex.quote(t) for t in cleaned)
        cmd = ["sh", "-c",
               "printf '%s\\n' " + quoted +
               " | naabu -json -silent -top-ports 1000 -list -"]

        lines: list[str] = []

        async def on_line(line: str):
            lines.append(line)
            if stream_callback:
                await stream_callback(line)

        try:
            stdout, stderr, returncode = await self.exec_in_container(
                cmd, timeout=300, stream_callback=on_line
            )
            if not lines and stdout:
                lines = stdout.strip().split("\n")
            result.raw_output = "\n".join(lines)
            findings, assets, services = self._parse_lines(lines)
            result.findings = findings
            result.assets = assets
            result.services = services
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    def _parse_lines(self, lines: list[str]) -> tuple[list[FindingResult], list[AssetArtifact], list[ServiceArtifact]]:
        findings: list[FindingResult] = []
        assets: list[AssetArtifact] = []
        services: list[ServiceArtifact] = []

        for line in lines:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip = data.get("ip") or data.get("host") or ""
            port = data.get("port")
            proto = (data.get("protocol") or "tcp").lower()
            if not ip or not port:
                continue

            host_norm = normalize_domain(ip)
            if not host_norm:
                continue
            host_type = guess_asset_type_from_host(host_norm)

            services.append(ServiceArtifact(
                host_type=host_type,
                host_value=ip,
                host_normalized=host_norm,
                port=int(port),
                proto=proto,
            ))
            findings.append(FindingResult(
                severity="info",
                title=f"Open port {port}/{proto} on {ip}",
                description=f"naabu found port {port}/{proto} open on {ip}",
                url=f"{ip}:{port}",
            ))

        return findings, assets, services
