# Milestone 4: Subdomain Takeover Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect subdomain takeover (dangling CNAME → unclaimed third-party service) by running nuclei's takeover templates against all discovered subdomains, as a dedicated pipeline stage.

**Architecture:** No new scanner or binary — reuse the existing `NucleiScanner`, which already accepts `config["tags"]` (→ `-tags`) and a `config["targets"]` list. Add a pipeline stage that runs `NucleiScanner` with `{"tags": "takeover", "targets": <all discovered subdomains, including unresolved>}`. Takeover templates are authored with high/critical severity, so findings map correctly through the existing `SEVERITY_MAP`. Runs against subdomain hostnames (not just live URLs) because takeover is a DNS/CNAME condition — unresolved subdomains (dangling records) are prime candidates.

**Tech Stack:** Python 3.11, existing nuclei binary (v10.4.6, 84 takeover templates available), async pipeline.

## Global Constraints

- No new scanner class, no Dockerfile change. Reuse `NucleiScanner` (`backend/scanners/nuclei_scanner.py`) via `config={"tags": "takeover", "targets": [...]}`.
- The stage scans **all discovered subdomains** — both resolved and unresolved. Unresolved subdomains (e.g. `www.app.servicevelocity.ai`, seen `unresolved` in prior runs) are exactly the dangling-record candidates takeover detection targets. Collect the subdomain hostname list (the `subdomains` variable already built at ~line 103, which is scope-filtered) plus any unresolved subdomain hostnames.
- Scope enforcement: the input is the already-scope-filtered `subdomains` list; no new external assets are introduced. (nuclei only checks the hostnames we give it.)
- Findings: nuclei's own severity mapping applies (takeover templates are high/critical). No custom severity override needed — trust the template severity via `SEVERITY_MAP`.
- Tests run from the backend container with **`python3 -m pytest`** (pre-existing sys.path quirk). Run `docker compose` from repo root `/Users/bspindler/src/servicevelocity/security`.
- Verify against the authorized target `servicevelocity.ai` (id `87d323c6-91b7-441e-80a6-dfc1bd69e091`) — user owns it. A clean result (no takeover) is the expected/good outcome; the check is that the stage runs against the subdomains.
- Postgres runs on host port 5433 (from M1). Branch is `feature/m2-recon-depth` (M2+M3+M4 stacked per user request).

---

## File Structure

- `backend/pipeline/run_pipeline.py` — modify: add a takeover-detection stage (reusing NucleiScanner with the takeover tag) and collect the full subdomain list (resolved + unresolved) to scan.
- `backend/tests/test_takeover_stage.py` — new: a unit test for the helper that assembles the takeover target list (resolved + unresolved subdomains, deduped, scope-safe).

---

## Task 1: Add subdomain-takeover detection stage

**Files:**
- Modify: `backend/pipeline/run_pipeline.py`
- Create: `backend/tests/test_takeover_stage.py`

**Interfaces:**
- Consumes: existing `NucleiScanner` (already imported), `_run_scanner_and_persist`, `_ensure_run_not_discarded`, the `subdomains` list, and the `unresolved` list of `(hostname, reason)` tuples built in the DNS stage.
- Produces: a module-level helper `_takeover_targets(subdomains: list[str], unresolved: list) -> list[str]` returning the deduped list of subdomain hostnames to scan for takeover (resolved subdomains + unresolved subdomain hostnames). Used by the new pipeline stage.

- [ ] **Step 1: Write the failing test for the target-assembly helper**

Create `backend/tests/test_takeover_stage.py`:

```python
"""Tests for the takeover-target assembly helper."""
from pipeline.run_pipeline import _takeover_targets


def test_includes_resolved_subdomains():
    targets = _takeover_targets(
        subdomains=["app.example.com", "api.example.com"],
        unresolved=[],
    )
    assert "app.example.com" in targets
    assert "api.example.com" in targets


def test_includes_unresolved_subdomains():
    # unresolved is a list of (hostname, reason) tuples from the DNS stage.
    targets = _takeover_targets(
        subdomains=["app.example.com"],
        unresolved=[("dangling.example.com", "NXDOMAIN"), ("www.app.example.com", "NO_ANSWER")],
    )
    # dangling / unresolved subdomains are prime takeover candidates -> must be scanned
    assert "dangling.example.com" in targets
    assert "www.app.example.com" in targets


def test_dedups_across_resolved_and_unresolved():
    targets = _takeover_targets(
        subdomains=["app.example.com"],
        unresolved=[("app.example.com", "NO_ANSWER")],  # same host in both
    )
    assert targets.count("app.example.com") == 1


def test_empty_inputs_return_empty():
    assert _takeover_targets(subdomains=[], unresolved=[]) == []


def test_skips_blank_entries():
    targets = _takeover_targets(
        subdomains=["", "  ", "real.example.com"],
        unresolved=[("", "x"), ("also.example.com", "y")],
    )
    assert "real.example.com" in targets
    assert "also.example.com" in targets
    assert "" not in targets
    assert "  " not in targets
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec -T -w /app backend python3 -m pytest tests/test_takeover_stage.py -v`
Expected: FAIL — `ImportError: cannot import name '_takeover_targets'`.

- [ ] **Step 3: Add the `_takeover_targets` helper**

In `backend/pipeline/run_pipeline.py`, add this module-level function (near the other helpers like `_build_http_targets`, e.g. right after it):

```python
def _takeover_targets(subdomains, unresolved) -> list[str]:
    """Assemble the subdomain hostname list to scan for takeover.

    Includes resolved subdomains AND unresolved ones (dangling records are the
    prime takeover candidates). `unresolved` is a list of (hostname, reason)
    tuples from the DNS stage. Deduped, blanks skipped.
    """
    targets: list[str] = []
    seen: set[str] = set()

    for host in subdomains:
        h = (host or "").strip()
        if h and h not in seen:
            seen.add(h)
            targets.append(h)

    for entry in unresolved:
        host = entry[0] if entry else ""
        h = (host or "").strip()
        if h and h not in seen:
            seen.add(h)
            targets.append(h)

    return targets
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose exec -T -w /app backend python3 -m pytest tests/test_takeover_stage.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Add the takeover stage to the pipeline**

The `unresolved` list is built in the DNS stage (search for `unresolved.append(` — it's a list of `(rr_name_norm, err)` tuples, in scope within `run_pipeline`). The takeover stage should run after the trufflehog stage (stage 6 from M3) and before the `_enqueue_verification_jobs` finalization — i.e. it's the last scanning stage.

Find the trufflehog stage (`# 6) trufflehog: ...` block). Immediately AFTER the trufflehog `if httpx_urls:` block closes, and BEFORE the `await _ensure_run_not_discarded(db, run.id)` that precedes `# Phase 5: mark candidates...` / `_enqueue_verification_jobs`, insert:

```python
        # 7) subdomain takeover: nuclei takeover templates against all subdomains
        #    (resolved + unresolved — dangling records are prime candidates).
        await _ensure_run_not_discarded(db, run.id)
        takeover_targets = _takeover_targets(subdomains, unresolved)
        if takeover_targets:
            takeover = NucleiScanner()
            await _run_scanner_and_persist(
                db,
                run=run,
                target=target.root_domain,
                scanner_name="takeover",
                scanner=takeover,
                config={"tags": "takeover", "targets": takeover_targets},
            )
```

Notes:
- `NucleiScanner` is already imported at the top of the file (used by the nuclei stage). No new import needed.
- `scanner_name="takeover"` labels this scan/stage distinctly from the main `nuclei` stage in the events/DB, even though it reuses the NucleiScanner class.
- Findings inherit the takeover templates' own severity (high/critical) via the scanner's `SEVERITY_MAP` — no override needed.
- `takeover_targets` is derived from `subdomains` (already scope-filtered) + `unresolved` subdomain hostnames (also from in-scope enumeration), so no new scope check is required — but these are all hostnames under the target's scope by construction.

- [ ] **Step 6: Restart backend + worker**

Run:
```bash
docker compose restart backend worker
```

- [ ] **Step 7: Run the full test suite**

Run:
```bash
docker compose exec -T -w /app backend python3 -m pytest -q
```
Expected: all pass (26 from M1-M3 + 5 takeover = 31).

- [ ] **Step 8: Live end-to-end verification against servicevelocity.ai**

Clear the queue if needed (cancel stale non-servicevelocity jobs), then trigger a run:
```bash
curl -fsS -X POST http://localhost:8000/api/targets/87d323c6-91b7-441e-80a6-dfc1bd69e091/pipeline -H "Content-Type: application/json" -d '{}'
```
The full pipeline is long (~12 min incl. nuclei + trufflehog); the takeover stage runs LAST. Poll the events endpoint with SPARSE polling (every 30-60s, single `sleep` between checks — do NOT tight-loop). Confirm a `takeover` scan_started/scan_completed event appears after trufflehog:
```bash
curl -fsS http://localhost:8000/api/targets/87d323c6-91b7-441e-80a6-dfc1bd69e091/events | python3 -c "import sys,json; [print(e['event_type'], (e.get('detail') or {}).get('scanner','')) for e in json.load(sys.stdin)[:30]]"
```
Expected: after `trufflehog` completes, a `scan_started`/`scan_completed` for `takeover`. The scan should complete cleanly. A clean result (no takeover found) is the expected/good outcome for a well-maintained domain — the key check is that the stage runs against the subdomains (including the unresolved `www.app.servicevelocity.ai`).

If the pipeline hits transient subfinder flakiness (subfinder returns 0 subdomains → DNS-dependent stages skip), re-run — that's an external-source issue, not a code bug (seen in M3). The takeover stage needs subdomains to have been found.

- [ ] **Step 9: Commit**

```bash
git add backend/pipeline/run_pipeline.py backend/tests/test_takeover_stage.py
git commit -m "feat(pipeline): add subdomain-takeover detection stage

Reuse NucleiScanner with the takeover template tag against all discovered
subdomains (resolved + unresolved — dangling records are prime candidates).
Findings inherit the takeover templates' high/critical severity."
```

---

## Self-Review notes

- **Spec coverage:** M4 spec §"subdomain takeover: reuse existing nuclei binary with takeover templates" → Task 1. Runs against discovered subdomains incl. unresolved, findings → template severity (high). Covered.
- **Placeholder scan:** no TBD/TODO; every code step shows full code.
- **Type consistency:** `_takeover_targets(subdomains, unresolved) -> list[str]` used identically in the test, the helper, and the pipeline stage.
- **No new tool/scope surface:** reuses NucleiScanner; targets are the already-in-scope subdomain hostnames — no new external assets, no scope-check gap.
- **Failure isolation:** the takeover stage uses `_run_scanner_and_persist`; a failure yields `status="failed"` and the run still completes (consistent with existing stages).
- **This is the final planned milestone (M4).**
