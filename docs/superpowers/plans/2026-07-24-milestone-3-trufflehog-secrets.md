# Milestone 3: JS/Secrets Scanning (trufflehog) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a trufflehog-based secrets scanner that fetches the pipeline's discovered URLs (live + historical JS/pages), scans their content for credentials with live verification, and reports verified secrets as high/critical + unverified as low.

**Architecture:** A `TrufflehogScanner` (BaseScanner subclass) receives a list of URLs, fetches each into a temp directory inside the tools container (via `curl`, already installed), runs `trufflehog filesystem --json` over that directory, and parses results. Verified secrets → high (or critical for high-privilege detectors) findings; unverified → low. Secret values are redacted in stored evidence. The pipeline runs it after gau/httpx, scanning the same `httpx_urls` surface, before nuclei.

**Tech Stack:** Python 3.11, async subprocess via `docker exec`, trufflehog (Go binary), curl, pytest.

## Global Constraints

- The scanner MUST subclass `BaseScanner` (`backend/scanners/base.py`): set `name`/`binary`, implement `async run(self, target, config=None, stream_callback=None) -> ScanResult`, emit `FindingResult` artifacts, use `self.exec_in_container`.
- **Redact secrets in stored evidence.** Never store the full raw secret value in a `FindingResult`. Store the detector name, source URL, and a redacted/truncated fragment (e.g. first 4 + last 4 chars, middle masked). The task's redaction helper MUST be unit-tested.
- **Verification is ON** (authorized pentest, per design decision) — trufflehog runs WITHOUT `--only-verified` so both verified and unverified results are returned; the scanner tiers them by the `Verified` boolean in the JSON.
- Tiering: `Verified: true` → severity "high" (or "critical" if the detector is a high-privilege type — AWS, GCP, private keys); `Verified: false` → severity "low".
- Tests run from the backend container with **`python3 -m pytest`** (the repo has a pre-existing sys.path quirk where the bare `pytest` console-script fails). Run `docker compose` from repo root `/Users/bspindler/src/servicevelocity/security`.
- Dockerfile install follows the existing pattern. trufflehog is `trufflesecurity/trufflehog`, released as a `.tar.gz` (like gau). Use the `ARCH=$(case ${TARGETARCH} ...)` line verbatim. Verify `docker exec shadowpulse-tools which trufflehog` after rebuild.
- All URL fetching and scanning happens inside the tools container in a per-run temp dir; clean it up after the scan.
- Verify against the authorized target `servicevelocity.ai` (id `87d323c6-91b7-441e-80a6-dfc1bd69e091`) — user owns it. servicevelocity.ai is a Next.js app (JS-heavy), the ideal trufflehog target.

---

## File Structure

- `backend/scanners/trufflehog_scanner.py` — new: `TrufflehogScanner` + `_redact_secret` helper + `_parse_lines`.
- `backend/tests/test_trufflehog_scanner.py` — new: parse-path + redaction unit tests.
- `docker/tools.Dockerfile` — modify: add trufflehog install block.
- `backend/pipeline/run_pipeline.py` — modify: add a trufflehog stage scanning `httpx_urls`.

---

## Task 1: trufflehog scanner + Dockerfile install

**Files:**
- Create: `backend/scanners/trufflehog_scanner.py`
- Create: `backend/tests/test_trufflehog_scanner.py`
- Modify: `docker/tools.Dockerfile`

**Interfaces:**
- Consumes: `BaseScanner`, `ScanResult`, `FindingResult` from `scanners.base`.
- Produces: `TrufflehogScanner` (name="trufflehog", binary="trufflehog"). `run(target, config)` where `config["targets"]` is a list of URLs to fetch+scan. Returns `ScanResult` with findings. Module-level helpers: `_redact_secret(secret: str) -> str` and the scanner's `_parse_lines(lines: list[str]) -> list[FindingResult]`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_trufflehog_scanner.py`:

```python
"""Tests for TrufflehogScanner: JSON parse, tiering, redaction."""
import json
from scanners.trufflehog_scanner import TrufflehogScanner, _redact_secret


def test_redact_secret_masks_middle():
    r = _redact_secret("AKIAIOSFODNN7EXAMPLE")
    assert r != "AKIAIOSFODNN7EXAMPLE"          # not the raw value
    assert r.startswith("AKIA")                  # keeps a prefix
    assert r.endswith("MPLE")                    # keeps a suffix
    assert "*" in r or "…" in r                  # middle masked


def test_redact_short_secret_fully_masked():
    # short secrets can't safely show prefix+suffix; mask entirely
    r = _redact_secret("abc")
    assert "abc" not in r


def test_parse_verified_secret_is_high_or_critical():
    # trufflehog --json emits one JSON object per finding
    line = json.dumps({
        "DetectorName": "Github",
        "Verified": True,
        "Raw": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/app.js"}}},
    })
    scanner = TrufflehogScanner()
    findings = scanner._parse_lines([line])
    assert len(findings) == 1
    assert findings[0].severity in ("high", "critical")
    # secret is redacted in evidence
    assert "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in findings[0].evidence
    assert "Github" in findings[0].title


def test_parse_unverified_secret_is_low():
    line = json.dumps({
        "DetectorName": "Generic",
        "Verified": False,
        "Raw": "sk-somethingthatlookslikeakey12345",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/main.js"}}},
    })
    scanner = TrufflehogScanner()
    findings = scanner._parse_lines([line])
    assert len(findings) == 1
    assert findings[0].severity == "low"


def test_parse_aws_verified_is_critical():
    line = json.dumps({
        "DetectorName": "AWS",
        "Verified": True,
        "Raw": "AKIAIOSFODNN7EXAMPLE",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/config.js"}}},
    })
    scanner = TrufflehogScanner()
    findings = scanner._parse_lines([line])
    assert findings[0].severity == "critical"


def test_parse_skips_malformed_and_non_finding_lines():
    # trufflehog may emit log lines / blanks interleaved with JSON findings
    lines = ["", "not json", '{"level":"info","msg":"scanning"}',
             json.dumps({"DetectorName": "Github", "Verified": False, "Raw": "ghp_x",
                         "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/a.js"}}}})]
    scanner = TrufflehogScanner()
    findings = scanner._parse_lines(lines)
    # only the one real finding (a line with no DetectorName is not a finding)
    assert len(findings) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec -T -w /app backend python3 -m pytest tests/test_trufflehog_scanner.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scanners.trufflehog_scanner'`.

- [ ] **Step 3: Implement the scanner**

Create `backend/scanners/trufflehog_scanner.py`:

```python
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
    """Mask a secret for safe storage: keep a short prefix+suffix, mask the middle.

    Short secrets (<= 8 chars) are fully masked (can't safely reveal prefix+suffix).
    """
    if not secret:
        return ""
    if len(secret) <= 8:
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
            "d=$(mktemp -d) && i=0 && "
            "for u in " + quoted_urls + "; do "
            "  i=$((i+1)); "
            "  curl -sL --max-time 20 --max-filesize 5000000 \"$u\" -o \"$d/f$i\" 2>/dev/null || true; "
            "done; "
            # verification ON (no --only-verified) so we get both verified + unverified
            "trufflehog filesystem \"$d\" --json --no-update 2>/dev/null; "
            "rm -rf \"$d\""
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose exec -T -w /app backend python3 -m pytest tests/test_trufflehog_scanner.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Add the trufflehog install block to the Dockerfile**

trufflehog is `trufflesecurity/trufflehog`, released as `.tar.gz`. In `docker/tools.Dockerfile`, immediately after the gau install block (added in M2), add:

```dockerfile
# Install trufflehog (pre-built binary)
RUN TRUFFLEHOG_VERSION=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/^v//') && \
    ARCH=$(case ${TARGETARCH} in amd64) echo "amd64" ;; arm64) echo "arm64" ;; *) echo "amd64" ;; esac) && \
    curl -sL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${ARCH}.tar.gz" -o /tmp/trufflehog.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin/ trufflehog && \
    chmod +x /usr/local/bin/trufflehog && \
    rm /tmp/trufflehog.tar.gz
```

Note: verify the real release asset naming for trufflesecurity/trufflehog linux via `curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep browser_download_url | grep linux` and adjust the URL if it differs (keep the fetch → tar → chmod pattern).

- [ ] **Step 6: Rebuild the tools image and verify trufflehog**

Run:
```bash
docker compose build tools && docker compose up -d tools
docker exec shadowpulse-tools which trufflehog && docker exec shadowpulse-tools trufflehog --version 2>&1 | head -2
```
Expected: `/usr/local/bin/trufflehog` and a version line.

- [ ] **Step 7: Commit**

```bash
git add backend/scanners/trufflehog_scanner.py backend/tests/test_trufflehog_scanner.py docker/tools.Dockerfile
git commit -m "feat(scanner): add trufflehog secrets scanner

Fetches discovered URLs and scans content for secrets with live verification.
Verified secrets -> high/critical, unverified -> low; secret values redacted
in stored evidence. Adds _redact_secret helper (unit-tested)."
```

---

## Task 2: Wire trufflehog into the pipeline

**Files:**
- Modify: `backend/pipeline/run_pipeline.py`

**Interfaces:**
- Consumes: `TrufflehogScanner` from `scanners.trufflehog_scanner`; existing `_run_scanner_and_persist`, `_ensure_run_not_discarded`, `httpx_urls`.
- Produces: updated `run_pipeline` with a trufflehog stage. No signature change.

- [ ] **Step 1: Add the import**

In `backend/pipeline/run_pipeline.py`, after the M2 scanner imports (naabu/tlsx/gau, around lines 14-16), add:

```python
from scanners.trufflehog_scanner import TrufflehogScanner
```

- [ ] **Step 2: Add the trufflehog stage after nuclei**

Find the nuclei stage (`# 5) nuclei constrained to live URLs` and its `if httpx_urls:` block). Insert the trufflehog stage **immediately after the nuclei `if httpx_urls:` block closes** (after the nuclei `_run_scanner_and_persist(...)` call) and **before** the existing line `await _ensure_run_not_discarded(db, run.id)` that precedes the `# Phase 5: mark candidates not seen...` / `_enqueue_verification_jobs(...)` finalization. Insert:

```python
        # 6) trufflehog: fetch discovered URLs and scan content for secrets.
        await _ensure_run_not_discarded(db, run.id)
        if httpx_urls:
            trufflehog = TrufflehogScanner()
            await _run_scanner_and_persist(
                db,
                run=run,
                target=target.root_domain,
                scanner_name="trufflehog",
                scanner=trufflehog,
                config={"targets": httpx_urls},
            )
```

Note: `httpx_urls` at this point is the capped (`max_http_targets`) set of live + historical URLs — the client-accessible surface where secrets in JS/pages would live. trufflehog fetches and scans them. Findings persist via `_run_scanner_and_persist` like every other stage.

- [ ] **Step 3: Restart backend + worker**

Run:
```bash
docker compose restart backend worker
```

- [ ] **Step 4: Run the full test suite**

Run:
```bash
docker compose exec -T -w /app backend python3 -m pytest -q
```
Expected: all pass (M1 7 + naabu 4 + tlsx 4 + gau 3 + trufflehog 6 = 24).

- [ ] **Step 5: Live end-to-end verification against servicevelocity.ai**

Ensure the queue is clear (cancel stale non-servicevelocity jobs if needed), then trigger a run:
```bash
curl -fsS -X POST http://localhost:8000/api/targets/87d323c6-91b7-441e-80a6-dfc1bd69e091/pipeline -H "Content-Type: application/json" -d '{}'
```
Poll the events and confirm a `trufflehog` stage runs after nuclei:
```bash
curl -fsS http://localhost:8000/api/targets/87d323c6-91b7-441e-80a6-dfc1bd69e091/events | python3 -c "import sys,json; [print(e['event_type'], e.get('detail',{}).get('scanner','')) for e in json.load(sys.stdin)[:24]]"
```
Expected: after `nuclei` completes, a `scan_started`/`scan_completed` for `trufflehog`. The scan should complete (status completed). If any secrets are found on servicevelocity.ai, confirm they appear in the findings endpoint with the secret value REDACTED (not the raw value). A clean result (no secrets) is also a valid, expected outcome — the key check is that the stage runs, scans the URLs, and persists cleanly.

- [ ] **Step 6: Verify redaction end-to-end (if any findings)**

```bash
curl -fsS "http://localhost:8000/api/targets/87d323c6-91b7-441e-80a6-dfc1bd69e091/findings" | python3 -c "import sys,json; [print(f.get('severity'), f.get('title'), '::', f.get('evidence','')[:120]) for f in json.load(sys.stdin) if 'secret' in (f.get('title','').lower())]"
```
Expected: any trufflehog findings show `value=XXXX****XXXX` (redacted), never a full raw secret. (If no secrets found, this prints nothing — also fine.)

- [ ] **Step 7: Commit**

```bash
git add backend/pipeline/run_pipeline.py
git commit -m "feat(pipeline): add trufflehog secrets stage after nuclei

Scans the discovered URL surface (live + historical, capped) for exposed
secrets with live verification. Verified -> high/critical, unverified -> low."
```

---

## Self-Review notes

- **Spec coverage:** M3 spec §"trufflehog scanner" → Task 1; pipeline integration → Task 2. Verification-on + both-tiers + redaction (the design decisions) are all in Task 1.
- **Placeholder scan:** no TBD/TODO; every code step shows full code.
- **Type consistency:** `_redact_secret(secret) -> str` and `TrufflehogScanner`/`_parse_lines` consistent across scanner file, tests, and pipeline import.
- **Security:** secret values are redacted before storage (`_redact_secret`, unit-tested); raw_output stores only a summary, never secrets; URL fetching uses `shlex.quote` (no command injection) and `curl` bounds (`--max-time`, `--max-filesize`); temp dir cleaned up after scan.
- **Failure isolation:** trufflehog stage uses `_run_scanner_and_persist`; a failure yields `status="failed"` and the run still completes (consistent with existing stages).
- **Deferred:** M4 (subdomain takeover) — separate plan.
