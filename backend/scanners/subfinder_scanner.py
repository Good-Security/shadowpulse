from datetime import datetime

from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact
from recongraph.normalize import normalize_domain


class SubfinderScanner(BaseScanner):
    name = "subfinder"
    binary = "subfinder"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        result = ScanResult(
            scanner=self.name,
            target=target,
            started_at=datetime.utcnow(),
        )

        cmd = ["subfinder", "-d", target, "-silent"]

        try:
            stdout, stderr, returncode = await self.exec_in_container(cmd, timeout=120, stream_callback=stream_callback)
            result.raw_output = stdout

            subdomains = [
                line.strip() for line in stdout.strip().split("\n")
                if line.strip()
            ]

            for sub in subdomains:
                result.assets.append(AssetArtifact(
                    type="subdomain",
                    value=sub,
                    normalized=normalize_domain(sub),
                ))
                result.findings.append(FindingResult(
                    severity="info",
                    title=f"Subdomain discovered: {sub}",
                    description=f"Subdomain {sub} was found via passive enumeration",
                    url=sub,
                ))

            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result
