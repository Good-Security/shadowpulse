import json
import shlex
from datetime import datetime

from scanners.base import BaseScanner, ScanResult, FindingResult


# Detectors whose secrets grant broad/high-privilege access -> critical when verified.
CRITICAL_DETECTORS = {
    "aws", "gcp", "azure", "privatekey", "ssh", "stripe", "github",
    "gitlab", "slackwebhook", "twilio",
}


def _redact_secret(secret: str) -> str:
    """Mask a secret for safe storage. Short/medium secrets (<= 16 chars) are
    fully masked; longer secrets reveal only a 4-char prefix + 4-char suffix,
    with the majority of characters masked."""
    if not secret:
        return ""
    if len(secret) <= 16:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"


class TrufflehogScanner(BaseScanner):
    """Fetch discovered URLs and scan their content for verified secrets."""

    name = "trufflehog"
    binary = "trufflehog"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        result = ScanResult(scanner=self.name, target=target, started_at=datetime.utcnow())

        targets = config.get("targets", [])
        if isinstance(targets, str):
            targets = [targets]
        urls = [str(t).strip() for t in targets if str(t).strip()]

        if not urls:
            result.status = "completed"
            result.completed_at = datetime.utcnow()
            return result

        # Fetch each URL into a per-run temp dir, then trufflehog filesystem over it.
        # curl writes numbered files so trufflehog scans the fetched content.
        # We build a single sh -c that: makes a temp dir, curls each URL to a file,
        # runs trufflehog, then cleans up.
        quoted_urls = " ".join(shlex.quote(u) for u in urls)
        script = (
            "d=$(mktemp -d) && "
            # Ensure the temp dir (with fetched, possibly secret-bearing files) is
            # removed even if this script is killed on the outer exec timeout.
            "trap 'rm -rf \"$d\"' EXIT && i=0 && "
            "for u in " + quoted_urls + "; do "
            "  i=$((i+1)); "
            "  curl -sL --max-time 20 --max-filesize 5000000 \"$u\" -o \"$d/f$i\" 2>/dev/null || true; "
            "done; "
            # verification ON (no --only-verified) so we get both verified + unverified
            "trufflehog filesystem \"$d\" --json --no-update 2>/dev/null"
        )
        cmd = ["sh", "-c", script]

        lines: list[str] = []

        async def on_line(line: str):
            lines.append(line)
            if stream_callback:
                await stream_callback(line)

        try:
            # trufflehog + fetching many URLs can be slow; generous timeout.
            stdout, stderr, returncode = await self.exec_in_container(
                cmd, timeout=600, stream_callback=on_line
            )
            if not lines and stdout:
                lines = stdout.strip().split("\n")
            # Store redacted raw output only (never the full secrets).
            result.raw_output = f"trufflehog scanned {len(urls)} URLs; {len([l for l in lines if l.strip()])} output lines"
            result.findings = self._parse_lines(lines)
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    def _parse_lines(self, lines: list[str]) -> list[FindingResult]:
        findings: list[FindingResult] = []

        for line in lines:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # A finding has a DetectorName + Raw; log lines don't.
            detector = data.get("DetectorName")
            raw = data.get("Raw", "")
            if not detector or not raw:
                continue

            verified = bool(data.get("Verified", False))
            source_file = (
                data.get("SourceMetadata", {})
                .get("Data", {})
                .get("Filesystem", {})
                .get("file", "")
            )

            if verified:
                severity = "critical" if detector.lower() in CRITICAL_DETECTORS else "high"
                verdict = "VERIFIED (live credential)"
            else:
                severity = "low"
                verdict = "unverified (potential secret)"

            redacted = _redact_secret(raw)

            findings.append(FindingResult(
                severity=severity,
                title=f"{verdict}: {detector} secret",
                description=f"trufflehog detected a {detector} secret in fetched content. Status: {verdict}.",
                impact=(
                    "A verified secret is a live, working credential exposed in client-accessible content — "
                    "an attacker can use it directly to access the associated service/data."
                    if verified else
                    "A potential secret was found but could not be automatically verified. It may be a real "
                    "credential (e.g. an internal key with no public endpoint to test) or a false positive; review manually."
                ),
                evidence=f"detector={detector} verified={verified} value={redacted} source={source_file}",
                remediation=(
                    "Rotate the exposed credential immediately, remove it from client-served assets, and load "
                    "secrets server-side only (never in client JS or public files)."
                ),
            ))

        return findings
