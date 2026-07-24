# SHADOWPULSE: Recon Depth + New-Capability Scanners

**Date:** 2026-07-24
**Status:** Approved design, pending spec review

## Motivation

Two real defects surfaced while running the recon pipeline against `servicevelocity.ai`:

1. **`_build_http_targets` targets CDN edge IPs, not hostnames.** For any CDN/load-balancer-fronted app (Azure Front Door, Cloudflare, etc.), httpx probes `https://<edge-ip>` which returns 404, so httpx finds no live URLs and the nuclei vulnerability stage is skipped entirely. The pipeline silently performs *no application vulnerability scanning* on fronted targets. Verified twice against `servicevelocity.ai`: a manual `httpx` by hostname returns HTTP 200 for 4 hosts; by IP returns 404.
2. **Single serial worker.** One `worker` container processes jobs strictly serially. `MAX_CONCURRENT_JOBS_GLOBAL=5` implies parallelism that does not exist with one worker. Scheduled and stale jobs repeatedly starved authorized runs.

Beyond the bug fixes, the scanner set has depth and capability gaps: no fast port pre-scan, no TLS SAN harvesting, no historical-URL discovery, no JS/secrets analysis (where modern SPA/Next.js findings live), and no subdomain-takeover detection.

## Scope

Delivered as **4 sequenced milestones**, each implemented and verified against `servicevelocity.ai` before the next begins.

Out of scope: chat/agent LLM mode (blocked on a separate API-key issue), sqlmap/wpscan (deferred, noisier/situational), Amass (subfinder is sufficient for now).

---

## Architecture context (existing)

- **Scanners** live in `backend/scanners/`, each subclassing `BaseScanner` (`backend/scanners/base.py`):
  - class attrs `name: str`, `binary: str`
  - `async run(self, target, config=None, stream_callback=None) -> ScanResult`
  - `exec_in_container(cmd, timeout, stream_callback)` runs the tool via `docker exec <TOOLS_CONTAINER> <cmd>`
  - returns a `ScanResult` carrying `findings: list[FindingResult]`, `assets: list[AssetArtifact]`, `services: list[ServiceArtifact]`, `edges: list[EdgeArtifact]`
- **Pipeline** `backend/pipeline/run_pipeline.py` orchestrates stages sequentially, persisting artifacts via the ingestion layer and enforcing scope with `check_in_scope` (`backend/scope.py`).
- **Tools container** `docker/tools.Dockerfile` installs binaries. ProjectDiscovery tools follow an identical pattern: fetch latest GitHub release zip → unzip to `/usr/local/bin` → chmod.
- **Worker** `backend/worker/main.py` claims jobs with `SELECT … FOR UPDATE SKIP LOCKED` (already concurrency-safe) and processes them serially in one process.
- **Scope** default allowlist is `[root_domain, *.root_domain]`; every discovered asset is scope-checked before persistence.

New scanners MUST conform to the `BaseScanner` contract and emit structured artifacts so the existing ingestion + UI work unchanged.

---

## Milestone 1 — Fix the 2 core bugs

### Bug A: hostname targeting in `_build_http_targets`

**Current:** `_build_http_targets(services)` builds `https://{host}:{port}` from nmap `ServiceArtifact`s whose `host_normalized` is a resolved **IP** (e.g. `150.171.109.73`). Front Door returns 404 to IP-addressed requests → httpx empty → nuclei skipped.

**Fix:** Build httpx targets from the **discovered hostname assets** (subdomains/root domain from the subfinder + DNS stage), not from IP-based nmap services. Concretely:
- Collect in-scope `subdomain`/`domain` asset values discovered earlier in the run.
- For each, emit `https://<hostname>` (and `http://<hostname>` where appropriate), deduped and normalized via `normalize_url`.
- Keep IP-based service targets only when there is no hostname (bare-IP targets), so non-fronted hosts still work.
- Continue capping at `max_http_targets`.

**Result:** httpx probes `https://app.servicevelocity.ai` (200) → nuclei receives live URLs → application vuln scanning actually runs.

**Verification:** re-run pipeline for `servicevelocity.ai`; confirm httpx returns the 4 live hosts (`servicevelocity.ai`, `app.`, `dev.app.`, `stg.app.`) and nuclei executes against hostnames with findings persisted to the DB.

### Bug B: worker scaling

**Fix:** Scale the `worker` service to **3 replicas**. The `SKIP LOCKED` claim logic is already safe for concurrent workers, so no core-loop rewrite is needed. Requirements:
- `docker-compose.yml`: set the worker service to run 3 replicas (`--scale worker=3`, or a `deploy.replicas: 3` / duplicated service approach compatible with the compose version in use).
- Ensure each replica has a distinct `WORKER_ID` (the code already falls back to `worker-<pid>`, which differs per container; make this explicit if needed for clarity in `locked_by`).

**Result:** up to 3 jobs run in parallel; scheduled/stale jobs no longer head-of-line-block authorized runs as severely.

**Verification:** enqueue 3 pipeline runs; confirm all 3 move to `running` with distinct `locked_by` values simultaneously.

**Non-goal for M1:** stale-job reclaim (zombie `running` jobs from killed workers) — noted as a known reliability gap, deferred; user chose replica scaling only.

---

## Milestone 2 — Recon depth: naabu + tlsx + gau

Three new scanners, each a `BaseScanner` subclass, each with a `docker/tools.Dockerfile` install block.

### naabu (`backend/scanners/naabu_scanner.py`, binary `naabu`)
- Fast SYN/CONNECT port discovery. Install via PD release pattern.
- Runs **before** nmap in the pipeline: naabu discovers open ports per host; nmap then runs deep `-sV -sC` against **only the open ports** naabu found (not a full range), cutting the slow nmap stage.
- Emits `ServiceArtifact`s (port/proto per host) for downstream nmap refinement.
- JSON output (`-json`) parsed into services.

### tlsx (`backend/scanners/tlsx_scanner.py`, binary `tlsx`)
- TLS metadata grab: certificate SANs, issuer, expiry, negotiated TLS version. Install via PD release pattern.
- **Cert SANs feed back as new `subdomain` assets** (scope-checked) — surfaces subdomains subfinder misses.
- Emits: asset artifacts (SAN hostnames), info findings (cert issuer/expiry, negotiated version), low findings (TLS 1.0/1.1 support, cert expiring soon / expired).
- JSON output (`-json`) parsed.

### gau (`backend/scanners/gau_scanner.py`, binary `gau`)
- Historical URLs from Wayback Machine / CommonCrawl / OTX. Install as a single Go binary (its own repo release).
- Emits `url` assets (scope-filtered via `url_in_scope`), giving nuclei and trufflehog more endpoints to test.
- Deduped; capped to a sane per-run limit to avoid flooding.

### Pipeline order after M2
```
subfinder → dnsx → naabu → nmap(open ports only) → tlsx → httpx → gau → nuclei
```
All newly discovered assets are scope-checked via `check_in_scope` before persistence; each stage logs `run_events` audit entries consistent with existing stages.

**Verification:** run pipeline for `servicevelocity.ai`; confirm naabu feeds nmap, tlsx adds SAN-derived subdomains (if any), gau adds historical URLs, all scope-filtered, all persisted.

---

## Milestone 3 — JS/secrets scanning: trufflehog

### trufflehog (`backend/scanners/trufflehog_scanner.py`, binary `trufflehog`)
- Single Go binary, JSON output. Install via GitHub release.
- Runs in URL/filesystem mode against discovered JS/endpoint URLs (sourced from httpx + gau + katana output).
- **Live-verifies** detected secrets (its `--only-verified` / verification mode) to minimize false positives.
- Findings:
  - Verified secret → **high** (or **critical** for high-privilege key types) `FindingResult` with the detector name, redacted match, and source URL as evidence.
  - Unverified candidate → **low** finding (reported but flagged as unverified).
- Redact secret values in stored evidence (store detector + location + partial match, never the full live credential).

**Verification:** run against `servicevelocity.ai` JS endpoints; confirm trufflehog executes, parses cleanly, and any verified/unverified results persist with redaction.

---

## Milestone 4 — Subdomain takeover detection

### Approach: reuse existing nuclei binary with takeover templates
- No new binary. Run `nuclei -tags takeover` (takeover template category) against discovered subdomains.
- Detects dangling CNAMEs pointing at unclaimed third-party services (GitHub Pages, S3, Azure, Heroku, etc.).
- Implemented as either a focused pipeline stage or a `TakeoverScanner` wrapping the nuclei invocation with the takeover tag; findings mapped to **high** severity `FindingResult` (takeover is directly exploitable).
- Directly relevant: `dev.app`, `stg.app`, `www.app.servicevelocity.ai` subdomains exist; `www.app` was already observed `unresolved`, a classic dangling-record candidate.

**Verification:** run against `servicevelocity.ai` subdomains; confirm the takeover stage runs and reports cleanly (no takeover expected on a well-maintained domain, but the stage must execute and persist correctly).

---

## Cross-cutting requirements

- Each new scanner conforms to `BaseScanner` (`name`, `binary`, `async run() -> ScanResult`) and emits structured artifacts so ingestion + UI need no changes.
- Each new pipeline stage: scope-enforced via `check_in_scope`, audit-logged via `run_events`, wrapped so a single scanner failure does not abort the whole pipeline (consistent with existing stage error handling).
- Dockerfile additions follow the existing PD release-fetch pattern; pin or dynamically fetch latest consistent with the current file's approach.
- Each milestone verified end-to-end against `servicevelocity.ai` before starting the next.

## Testing strategy

- Per-scanner: a parsing unit test feeding representative JSON tool output into the scanner's parser, asserting correct `FindingResult` / `AssetArtifact` / `ServiceArtifact` extraction (no live network needed for the parse path).
- Per-milestone: a live pipeline run against `servicevelocity.ai` (authorized target) confirming the stage executes, scope-filters, and persists.
- Bug A regression: assert `_build_http_targets` (or its replacement) produces hostname URLs given hostname assets, and does not emit CDN-edge-IP URLs when hostnames exist.
- Bug B: operational check that 3 workers claim concurrently.

## Known deferred items (not in this spec)

- Stale/zombie `running`-job reclaim (killed-worker recovery).
- Retention purge FK-violation bug (`retention.py` deletes `scans` still referenced by `findings`) — separate fix.
- LLM chat mode (blocked on API-key/credential issue).
- sqlmap, wpscan, Amass, LinkFinder/SecretFinder — evaluated and deferred.
