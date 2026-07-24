# Milestone 1: Pipeline Bug Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix two pipeline defects so CDN-fronted apps are actually vulnerability-scanned (hostname targeting) and so multiple jobs run concurrently (worker scaling).

**Architecture:** Bug A changes HTTP-target selection in `run_pipeline.py` to build httpx targets from resolved in-scope **hostnames** (falling back to bare IPs only when a host has no hostname), replacing the current IP-only logic that CDNs 404. Bug B scales the `worker` service to 3 concurrent containers, relying on the existing `SELECT … FOR UPDATE SKIP LOCKED` claim logic which is already concurrency-safe.

**Tech Stack:** Python 3.11, FastAPI, SQLAlchemy async, pytest + pytest-asyncio, Docker Compose.

## Global Constraints

- New scanners/pipeline code MUST conform to the existing `BaseScanner` contract and emit structured artifacts (`FindingResult`/`AssetArtifact`/`ServiceArtifact`/`EdgeArtifact`). (Not directly exercised in M1 but the pipeline edits must preserve it.)
- All discovered/derived targets MUST be scope-checked via `check_in_scope` (`backend/scope.py`) before use.
- Docker Compose file is `version: "3.8"`; `deploy.replicas` is ignored outside Swarm, so replica scaling uses `docker compose up --scale worker=N`.
- Verify end-to-end against the authorized target `servicevelocity.ai` (target id `87d323c6-91b7-441e-80a6-dfc1bd69e091`) before declaring M1 done.
- Tests run from the `backend/` directory. The backend imports are flat (e.g. `from pipeline.run_pipeline import ...`), so pytest must run with `backend/` on `sys.path` (run pytest with `cwd=backend`).

---

## File Structure

- `backend/requirements.txt` — add `pytest` and `pytest-asyncio` (test deps).
- `backend/pytest.ini` — new: configure asyncio mode and test paths.
- `backend/tests/__init__.py` — new: make tests a package (empty).
- `backend/tests/test_build_http_targets.py` — new: unit tests for the hostname-targeting fix.
- `backend/pipeline/run_pipeline.py` — modify: replace `_build_http_targets` and its call site to use hostnames.
- `docker-compose.yml` — modify: give each worker a distinct `WORKER_ID` (via hostname) so `locked_by` is legible across replicas.
- `Makefile` — modify: add a `docker-up-scaled` target that starts the stack with 3 workers.

---

## Task 1: Set up the test framework

**Files:**
- Modify: `backend/requirements.txt`
- Create: `backend/pytest.ini`
- Create: `backend/tests/__init__.py`

**Interfaces:**
- Consumes: nothing.
- Produces: a runnable pytest environment inside the `backend` container (and locally if deps installed). Later tasks run `pytest tests/... -v` from `backend/`.

- [ ] **Step 1: Add test dependencies to requirements**

Append these two lines to `backend/requirements.txt` (keep existing content):

```
pytest==8.3.4
pytest-asyncio==0.24.0
```

- [ ] **Step 2: Create pytest config**

Create `backend/pytest.ini`:

```ini
[pytest]
asyncio_mode = auto
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
```

- [ ] **Step 3: Create the tests package marker**

Create `backend/tests/__init__.py` with a single comment line:

```python
# test package for shadowpulse backend
```

- [ ] **Step 4: Install deps in the running backend container**

Run:
```bash
docker compose exec -T backend pip install pytest==8.3.4 pytest-asyncio==0.24.0
```
Expected: `Successfully installed pytest-8.3.4 pytest-asyncio-0.24.0` (or "already satisfied").

- [ ] **Step 5: Verify pytest runs (collects zero tests, exits cleanly)**

Run:
```bash
docker compose exec -T -w /app backend pytest -q
```
Expected: `no tests ran` (exit code 5 is acceptable here — it means "no tests collected", not a failure). The point is pytest imports and runs.

- [ ] **Step 6: Commit**

```bash
git add backend/requirements.txt backend/pytest.ini backend/tests/__init__.py
git commit -m "test: add pytest + pytest-asyncio framework"
```

---

## Task 2: Fix Bug A — build httpx targets from hostnames

**Files:**
- Create: `backend/tests/test_build_http_targets.py`
- Modify: `backend/pipeline/run_pipeline.py` (replace `_build_http_targets` at lines ~264-291; update call site at lines ~207-208)

**Interfaces:**
- Consumes: `WEB_PORTS_HTTP`, `WEB_PORTS_HTTPS` module constants (already defined at top of `run_pipeline.py`); `normalize_url` from `recongraph.normalize`.
- Produces: a new function
  `_build_http_targets(hostnames: list[str], ip_services: list, seen_hostnames: set[str] | None = None) -> list[str]`
  returning a deduped list of normalized `http(s)://host` URL strings. Hostnames yield both `https://host` and `http://host`; IP services yield a URL only when the IP is NOT already represented by a hostname. Called from the httpx stage in `run_pipeline`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_build_http_targets.py`:

```python
"""Tests for _build_http_targets: hostname-first HTTP target selection."""
from pipeline.run_pipeline import _build_http_targets


def test_hostnames_produce_https_and_http_urls():
    targets = _build_http_targets(hostnames=["app.example.com"], ip_services=[])
    assert "https://app.example.com" in targets
    assert "http://app.example.com" in targets


def test_multiple_hostnames_all_included():
    targets = _build_http_targets(
        hostnames=["a.example.com", "b.example.com"], ip_services=[]
    )
    for h in ("a.example.com", "b.example.com"):
        assert f"https://{h}" in targets


def test_hostnames_deduped():
    targets = _build_http_targets(
        hostnames=["app.example.com", "app.example.com"], ip_services=[]
    )
    assert targets.count("https://app.example.com") == 1


def test_bare_ip_service_included_when_no_hostname():
    # A ServiceArtifact-like object: has .port, .proto, .host_normalized
    class Svc:
        port = 443
        proto = "tcp"
        host_normalized = "203.0.113.9"

    targets = _build_http_targets(hostnames=[], ip_services=[Svc()])
    assert "https://203.0.113.9" in targets


def test_no_cdn_edge_ip_url_when_hostname_present():
    # Regression for Bug A: when we have a hostname, we must NOT emit the
    # CDN edge IP as an http target (Front Door 404s IP-addressed requests).
    class Svc:
        port = 443
        proto = "tcp"
        host_normalized = "150.171.109.73"  # Azure Front Door edge IP

    targets = _build_http_targets(
        hostnames=["app.servicevelocity.ai"], ip_services=[Svc()]
    )
    assert "https://app.servicevelocity.ai" in targets
    assert "https://150.171.109.73" not in targets


def test_empty_inputs_return_empty():
    assert _build_http_targets(hostnames=[], ip_services=[]) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
docker compose exec -T -w /app backend pytest tests/test_build_http_targets.py -v
```
Expected: FAIL — `_build_http_targets()` currently takes `(services)` with a different signature, so calls with `hostnames=`/`ip_services=` raise `TypeError`.

- [ ] **Step 3: Replace `_build_http_targets` with the hostname-first implementation**

In `backend/pipeline/run_pipeline.py`, replace the entire existing `_build_http_targets` function (currently around lines 264-291) with:

```python
def _build_http_targets(hostnames, ip_services, seen_hostnames=None) -> list[str]:
    """Build httpx probe URLs, hostname-first.

    Hostnames (discovered, in-scope subdomains/root) yield both https and http
    URLs so CDN-fronted apps (which route by Host header) are actually probed.
    IP-based services are included ONLY when the IP is not already covered by a
    hostname — bare IPs (non-fronted hosts) still get probed, but CDN edge IPs
    behind a hostname do not (they 404 on IP-addressed requests).
    """
    targets: list[str] = []
    seen: set[str] = set()

    # 1) Hostnames first — both schemes.
    for host in hostnames:
        host = (host or "").strip().rstrip(".")
        if not host:
            continue
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            norm = normalize_url(url)
            if not norm or norm in seen:
                continue
            seen.add(norm)
            targets.append(norm)

    # Hosts we already covered by name — used to skip their edge IPs below.
    covered = set(seen_hostnames or [])

    # 2) IP-based services only when no hostname covers them.
    for s in ip_services:
        host = getattr(s, "host_normalized", None)
        proto = (getattr(s, "proto", "tcp") or "tcp").lower()
        port = getattr(s, "port", None)
        if not host or proto != "tcp" or port is None:
            continue
        if host in covered:
            continue  # covered by a hostname — don't probe the edge IP
        if port in WEB_PORTS_HTTPS:
            url = f"https://{host}:{port}"
        elif port in WEB_PORTS_HTTP:
            url = f"http://{host}" if port == 80 else f"http://{host}:{port}"
        else:
            continue
        norm = normalize_url(url)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        targets.append(norm)

    return targets
```

- [ ] **Step 4: Update the call site to pass hostnames**

In `backend/pipeline/run_pipeline.py`, the httpx stage currently reads (around lines 205-208):

```python
        await _ensure_run_not_discarded(db, run.id)
        # 4) httpx probe on likely-web services -> URLs
        http_targets = _build_http_targets(nmap_services)
        http_targets = http_targets[:max_http_targets]
```

Replace those lines with:

```python
        await _ensure_run_not_discarded(db, run.id)
        # 4) httpx probe — hostname-first so CDN-fronted apps are actually probed.
        # `subdomains` (line ~103) holds the in-scope discovered hostnames.
        http_targets = _build_http_targets(
            hostnames=subdomains,
            ip_services=nmap_services,
            seen_hostnames=set(),
        )
        http_targets = http_targets[:max_http_targets]
```

Note: `subdomains` is the in-scope hostname list built at Step ~103 of the same function (`subdomains = [a.normalized for a in sub_res.assets if a.type == "subdomain" and ... check_in_scope(...)]`). It is in scope at this point in the function body. If the root domain itself should also be probed, it is included among discovered subdomains by subfinder; no separate addition needed.

- [ ] **Step 5: Run tests to verify they pass**

Run:
```bash
docker compose exec -T -w /app backend pytest tests/test_build_http_targets.py -v
```
Expected: PASS (6 passed).

- [ ] **Step 6: Restart backend + worker to load the changed pipeline module**

Run:
```bash
docker compose restart backend worker
```
Expected: both containers restart cleanly.

- [ ] **Step 7: Live verification — run the pipeline and confirm hostnames are probed**

Trigger a run:
```bash
curl -fsS -X POST http://localhost:8000/api/targets/87d323c6-91b7-441e-80a6-dfc1bd69e091/pipeline -H "Content-Type: application/json" -d '{}'
```
Then poll the run events until httpx completes and confirm httpx probed hostnames (findings > 0) and nuclei started:
```bash
curl -fsS http://localhost:8000/api/targets/87d323c6-91b7-441e-80a6-dfc1bd69e091/events | python3 -c "import sys,json; [print(e['event_type'],'::',json.dumps(e.get('detail',{}))[:100]) for e in json.load(sys.stdin)[:12]]"
```
Expected: an `scan_completed` event for `httpx` with `findings` >= the number of live hosts, followed by a `scan_started` for `nuclei`. (Contrast with the buggy behavior: httpx findings 0, no nuclei.)

- [ ] **Step 8: Commit**

```bash
git add backend/tests/test_build_http_targets.py backend/pipeline/run_pipeline.py
git commit -m "fix(pipeline): probe discovered hostnames, not CDN edge IPs

_build_http_targets now builds httpx targets from resolved in-scope
hostnames (both http/https), including bare IPs only when no hostname
covers them. Fixes CDN-fronted apps being silently skipped by nuclei."
```

---

## Task 3: Fix Bug B — distinct WORKER_ID per replica + scaled launch

**Files:**
- Modify: `docker-compose.yml` (worker service `environment`)
- Modify: `Makefile` (add scaled-up target)

**Interfaces:**
- Consumes: existing `claim_next_job` `SKIP LOCKED` logic (no code change) and `_worker_id()` in `jobqueue/ops.py` which reads `WORKER_ID` env or falls back to `worker-<pid>`.
- Produces: a `make docker-up-scaled` command that runs 3 worker replicas, each with a distinct `locked_by` value.

- [ ] **Step 1: Give each worker replica a distinct WORKER_ID from its hostname**

In `docker-compose.yml`, the `worker` service currently has:

```yaml
  worker:
    build:
      context: .
      dockerfile: docker/Dockerfile.backend
    env_file:
      - .env
    environment:
      DATABASE_URL: postgresql+asyncpg://shadowpulse:shadowpulse@postgres:5432/shadowpulse
    command: ["sh", "-lc", "python -m worker.main"]
```

Change the `command` so `WORKER_ID` is derived from the container hostname (unique per replica). Replace the `command:` line with:

```yaml
    command: ["sh", "-lc", "export WORKER_ID=\"worker-$(hostname)\"; python -m worker.main"]
```

(Leave `environment`, `env_file`, `volumes`, `depends_on` unchanged.)

- [ ] **Step 2: Add a scaled-launch Makefile target**

In `Makefile`, add this target (and add `docker-up-scaled` to the `.PHONY` line at the top):

```makefile
docker-up-scaled:
	docker compose up --build -d --scale worker=3
	@echo ""
	@echo "SHADOWPULSE running with 3 workers:"
	@echo "  Frontend: http://localhost:3000"
	@echo "  Backend:  http://localhost:8000"
```

- [ ] **Step 3: Launch the stack scaled to 3 workers**

Run:
```bash
docker compose up -d --scale worker=3
```
Expected: `security-worker-1`, `security-worker-2`, `security-worker-3` all `Started`.

- [ ] **Step 4: Confirm 3 worker containers are running**

Run:
```bash
docker compose ps worker
```
Expected: 3 rows, all `Up`.

- [ ] **Step 5: Live verification — 3 jobs claim concurrently**

Enqueue 3 pipeline runs for the authorized target (they will run in parallel across the 3 workers):
```bash
for i in 1 2 3; do curl -fsS -X POST http://localhost:8000/api/targets/87d323c6-91b7-441e-80a6-dfc1bd69e091/pipeline -H "Content-Type: application/json" -d '{}'; echo; done
```
Then immediately check that up to 3 are `running` with distinct `locked_by`:
```bash
docker compose exec -T postgres psql -U shadowpulse -d shadowpulse -c "SELECT status, locked_by FROM jobs WHERE status='running';"
```
Expected: up to 3 rows in `running`, each with a **different** `locked_by` (e.g. `worker-<hostname1>`, `worker-<hostname2>`, `worker-<hostname3>`). This proves concurrency; the single-serial bottleneck is gone.

Note: these are real scans against `servicevelocity.ai` (authorized). Let them complete or cancel extras via the DB if you only wanted the concurrency proof.

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yml Makefile
git commit -m "fix(worker): run 3 concurrent worker replicas

Derive a distinct WORKER_ID per replica from the container hostname so
locked_by is legible, and add a make docker-up-scaled target. The
existing SKIP LOCKED claim logic already supports concurrent workers;
this removes the single-serial-worker bottleneck."
```

---

## Self-Review notes

- **Spec coverage:** M1 Bug A → Task 2; M1 Bug B → Task 3; test-framework prerequisite (spec's testing strategy requires a parse-path unit test) → Task 1. All M1 spec items covered.
- **Placeholder scan:** no TBD/TODO; every code step shows full code.
- **Type consistency:** `_build_http_targets(hostnames, ip_services, seen_hostnames=None)` signature is used identically in the test (Task 2 Step 1), the implementation (Step 3), and the call site (Step 4).
- **Deferred (not in M1):** stale-job reclaim, retention FK bug, new scanners (M2-M4) — each has its own future plan.
