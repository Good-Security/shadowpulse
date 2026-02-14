import json
import shlex
from datetime import datetime

from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact
from recongraph.normalize import normalize_url


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


class NucleiScanner(BaseScanner):
    name = "nuclei"
    binary = "nuclei"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        templates = config.get("templates", "")
        severity = config.get("severity", "")  # critical,high,medium,low
        tags = config.get("tags", "")
        targets = config.get("targets")  # optional list[str]
        stats_interval = int(config.get("stats_interval", 5))

        result = ScanResult(
            scanner=self.name,
            target=target,
            started_at=datetime.utcnow(),
        )

        # In jsonl+silent mode, nuclei can legitimately produce no output for a long time
        # when there are no findings. Emit periodic stats lines while streaming so the UI
        # doesn't look hung.
        extra_flags: list[str] = []
        if stream_callback:
            extra_flags += ["-sj", "-si", str(stats_interval)]

        cmd: list[str]
        if targets and isinstance(targets, list) and len(targets) > 0:
            # Batch mode: feed targets via a file written in the tools container.
            # Use printf with shell-quoting to avoid heredoc injection issues.
            cleaned = [str(t).strip() for t in targets if str(t).strip()]
            if not cleaned:
                cmd = ["nuclei", "-u", target, "-jsonl", "-silent"] + extra_flags
            else:
                quoted = " ".join(shlex.quote(t) for t in cleaned)
                script = (
                    f"printf '%s\\n' {quoted} > /tmp/nuclei_targets.txt"
                    f" && nuclei -l /tmp/nuclei_targets.txt -jsonl -silent {' '.join(extra_flags)}"
                )
                cmd = ["sh", "-c", script]
        else:
            cmd = ["nuclei", "-u", target, "-jsonl", "-silent"] + extra_flags

        if templates:
            if cmd[:2] == ["sh", "-c"]:
                cmd[2] += f" -t {shlex.quote(str(templates))}"
            else:
                cmd += ["-t", templates]
        if severity:
            if cmd[:2] == ["sh", "-c"]:
                cmd[2] += f" -severity {shlex.quote(str(severity))}"
            else:
                cmd += ["-severity", severity]
        if tags:
            if cmd[:2] == ["sh", "-c"]:
                cmd[2] += f" -tags {shlex.quote(str(tags))}"
            else:
                cmd += ["-tags", tags]

        lines = []

        async def on_line(line: str):
            lines.append(line)
            if stream_callback:
                await stream_callback(self._format_stream_line(line))

        try:
            if stream_callback:
                await stream_callback(f"nuclei: started target={target} jsonl=true silent=true stats={bool(extra_flags)}")

            stdout, stderr, returncode = await self.exec_in_container(
                cmd, timeout=600, stream_callback=on_line
            )

            if not lines and stdout:
                lines = stdout.strip().split("\n")

            result.raw_output = "\n".join(lines)[:50000]

            if returncode != 0:
                result.status = "failed"
                result.error = (stderr.strip() or stdout.strip() or f"nuclei exited {returncode}")[:50000]
            else:
                result.findings = self._parse_jsonl(lines, target)
                # Artifacts: treat each matched-at URL/host as a URL asset when it normalizes.
                seen: set[str] = set()
                for f in result.findings:
                    if not f.url:
                        continue
                    u_norm = normalize_url(f.url)
                    if not u_norm or u_norm in seen:
                        continue
                    seen.add(u_norm)
                    result.assets.append(AssetArtifact(type="url", value=f.url, normalized=u_norm))
                result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    @staticmethod
    def _format_stream_line(line: str) -> str:
        """Make nuclei jsonl output readable in the UI without losing raw_output fidelity."""
        s = (line or "").strip()
        if not s:
            return s
        try:
            data = json.loads(s)
        except Exception:
            return s[:300]

        # Stats JSONL: no template-id, but includes percent/requests/etc.
        if "template-id" not in data and "percent" in data and "requests" in data:
            return (
                f"stats: {data.get('percent','?')}% "
                f"req={data.get('requests','?')} "
                f"matched={data.get('matched','?')} "
                f"errors={data.get('errors','?')} "
                f"rps={data.get('rps','?')} "
                f"dur={data.get('duration','?')}"
            )

        tid = data.get("template-id")
        info = data.get("info") or {}
        name = ""
        sev = ""
        if isinstance(info, dict):
            name = str(info.get("name") or "")
            sev = str(info.get("severity") or "")
        matched_at = data.get("matched-at") or data.get("host") or ""
        if tid:
            base = f"match: [{tid}]"
            if sev:
                base += f" sev={sev}"
            if name:
                base += f" name={name}"
            if matched_at:
                base += f" at={matched_at}"
            return base[:300]

        return s[:300]

    def _parse_jsonl(self, lines: list[str], target: str) -> list[FindingResult]:
        findings = []
        for line in lines:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Skip non-finding lines such as stats-json output.
            template_id = data.get("template-id")
            if not template_id:
                continue

            info = data.get("info", {})
            severity_raw = info.get("severity", "info").lower()
            severity = SEVERITY_MAP.get(severity_raw, "info")

            matched_at = data.get("matched-at", data.get("host", target))
            template_name = info.get("name", template_id)

            description_parts = []
            if info.get("description"):
                description_parts.append(info["description"])
            if data.get("matcher-name"):
                description_parts.append(f"Matcher: {data['matcher-name']}")

            evidence_parts = []
            if data.get("curl-command"):
                evidence_parts.append(f"curl: {data['curl-command']}")
            if data.get("extracted-results"):
                evidence_parts.append(f"extracted: {data['extracted-results']}")

            # Impact — use Nuclei's field if available, else generate from severity
            impact = info.get("impact", "") or self._severity_impact(severity, template_name)

            remediation = ""
            if info.get("remediation"):
                remediation = info["remediation"]
            elif info.get("reference"):
                refs = info["reference"]
                if isinstance(refs, list):
                    remediation = "References:\n" + "\n".join(f"- {r}" for r in refs)

            cve = ""
            classification = info.get("classification", {})
            cve_id = classification.get("cve-id")
            if cve_id:
                if isinstance(cve_id, list):
                    cve = cve_id[0] if cve_id else ""
                else:
                    cve = str(cve_id)

            cvss_score = 0.0
            cvss = classification.get("cvss-score")
            if cvss:
                try:
                    cvss_score = float(cvss)
                except (ValueError, TypeError):
                    pass

            findings.append(FindingResult(
                severity=severity,
                title=f"[{template_id}] {template_name}",
                description="\n".join(description_parts) or template_name,
                impact=impact,
                evidence="\n".join(evidence_parts),
                remediation=remediation,
                url=matched_at,
                cve=cve,
                cvss_score=cvss_score,
            ))

        return findings

    @staticmethod
    def _severity_impact(severity: str, name: str) -> str:
        """Generate a generic impact statement based on severity when Nuclei template lacks one."""
        base = {
            "critical": f"This is a critical-severity finding that could lead to full system compromise. '{name}' may allow remote code execution, authentication bypass, or direct access to sensitive data. Immediate remediation is strongly recommended.",
            "high": f"This high-severity finding represents a significant security risk. '{name}' could be exploited to gain unauthorized access, steal sensitive data, or disrupt services. Remediation should be prioritized.",
            "medium": f"This medium-severity finding indicates a security weakness that could be exploited in combination with other vulnerabilities. '{name}' may assist attackers in reconnaissance or provide a stepping stone for more serious attacks.",
            "low": f"This low-severity finding represents a minor security concern. While '{name}' alone may not be directly exploitable, it provides information that helps attackers map your attack surface.",
            "info": f"This informational finding documents a detected technology, configuration, or service. While not a vulnerability itself, '{name}' gives attackers useful reconnaissance data about your infrastructure.",
        }
        return base.get(severity, base["info"])
