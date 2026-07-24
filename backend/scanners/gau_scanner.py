from datetime import datetime

from scanners.base import BaseScanner, ScanResult, AssetArtifact
from recongraph.normalize import normalize_url


class GauScanner(BaseScanner):
    """Fetch historical URLs (Wayback/CommonCrawl/OTX) for a domain via gau."""

    name = "gau"
    binary = "gau"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        max_urls = int(config.get("max_urls", 500))
        result = ScanResult(scanner=self.name, target=target, started_at=datetime.utcnow())

        # gau takes the domain as an argument; --subs includes subdomains.
        cmd = ["gau", "--subs", "--threads", "5", target]

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
            result.raw_output = "\n".join(lines[:2000])  # cap raw output size
            result.assets = self._parse_lines(lines, max_urls=max_urls)
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    def _parse_lines(self, lines: list[str], max_urls: int = 500) -> list[AssetArtifact]:
        assets: list[AssetArtifact] = []
        seen: set[str] = set()

        for line in lines:
            url = line.strip()
            if not url or "://" not in url:
                continue
            norm = normalize_url(url)
            if not norm or norm in seen:
                continue
            seen.add(norm)
            assets.append(AssetArtifact(type="url", value=url, normalized=norm))
            if len(assets) >= max_urls:
                break

        return assets
