## Implementation Plan (Postgres-in-Docker, Confirmed Closed/Unresolved)

### 0) Reframe the Product Model (target-first)
1. Introduce `targets` as the primary object (what you monitor continuously).
2. Keep `sessions` as an optional “chat UI wrapper”, but link it to a `target_id`.

**Done when**
- Every scan/run belongs to a `target_id` (even if started from a session).

---

## Phase 1: Move Persistence to Postgres + Migrations
1. Update `docker-compose.yml`
   - Add `postgres` service + volume
   - Backend depends on Postgres health
2. Update backend config
   - `DATABASE_URL` -> `postgresql+asyncpg://...`
3. Add deps
   - `asyncpg`
   - `alembic`
4. Replace `init_db()` auto-create with Alembic migrations
   - Startup runs migrations (or provide `make db-migrate` / `make db-upgrade`)

**Done when**
- `docker compose up` brings up Postgres + backend + frontend
- DB schema is created by migrations, not `create_all`

---

## Phase 2: ReconGraph-lite Schema (Artifacts + Provenance)
Add tables (Postgres, via Alembic):

1. `targets`
   - `id`, `name`, `root_domain`, `scope_json`, `created_at`, `updated_at`
2. `runs`
   - `id`, `target_id`, `trigger` (manual/scheduled), `status`, `started_at`, `completed_at`
3. `scans`
   - add `target_id`, `run_id` (keep raw output if you want)
4. `assets`
   - `id`, `target_id`, `type` (subdomain/host/ip/url), `value`, `normalized`
   - `first_seen_run_id`, `last_seen_run_id`, `first_seen_at`, `last_seen_at`
   - `status` (active/stale/closed/unresolved), `status_reason`, `verified_at`
5. `services`
   - `id`, `target_id`, `asset_id` (host/ip), `port`, `proto`, `name`, `product`, `version`
   - same seen/verified fields as `assets`
6. `edges`
   - `from_asset_id`, `to_asset_id`, `rel_type` (resolves_to/serves/redirects_to/etc)
   - same seen fields
7. `findings`
   - add `target_id`, `run_id`, and optional `asset_id` / `service_id` foreign keys

Key indexing/dedupe
- Unique constraints on `(target_id, type, normalized)` for `assets`
- Unique constraints on `(target_id, asset_id, port, proto)` for `services`

**Done when**
- You can upsert assets/services/edges per run with proper dedupe + timestamps

---

## Phase 3: Ingestion Layer (Upserts + State)
1. Create a small “artifact ingestion” module
   - `upsert_asset_seen(target_id, run_id, type, value, metadata)`
   - `upsert_service_seen(target_id, run_id, host_asset_id, port, proto, fingerprint)`
   - `upsert_edge_seen(target_id, run_id, from_id, to_id, rel_type)`
2. Update scanners to emit:
   - findings (as today)
   - artifacts (assets/services/edges)

**Done when**
- Running subfinder/nmap/httpx updates inventory tables, not just `findings`

---

## Phase 4: Deterministic Baseline Pipeline (Continuous Recon)
Implement a non-LLM pipeline for each `run`:

1. `subfinder` -> subdomain assets
2. DNS resolve step (add either `dnsx` in tools container or Python `dnspython`)
   - edges: subdomain -> ip
   - mark unresolved explicitly
3. `nmap` (or later `naabu` + `nmap` refine) -> services on discovered hosts
4. `httpx` probe on likely-web services -> URL assets + tech fingerprints (optional)
5. `nuclei` constrained to live URLs -> findings linked to URL assets

**Done when**
- `run_pipeline(target_id)` produces a complete “inventory snapshot” for that run

---

## Phase 5: “Confirmed Closed/Unresolved” Change Semantics
You want “gone” to mean confirmed, so implement a two-step model per run:

1. After pipeline completes, compute candidates:
   - assets/services seen in previous run but not in current run => `candidate_stale`
2. Verification jobs (targeted checks):
   - For subdomain: DNS resolve again (multiple resolvers if you want)
   - For URL: `httpx` single URL probe
   - For service: `nmap -p PORT HOST` or a lightweight TCP connect (tools container)
3. Only after verification fails, mark:
   - `status=unresolved` (DNS/host disappeared)
   - `status=closed` (service no longer reachable / port closed)
   - store `verified_at`, `status_reason`, and the verification scan record

**Done when**
- UI/API can show “new”, “still present”, and “confirmed closed/unresolved” with evidence

---

## Phase 6: Scheduler + Worker (No Redis, DB-Backed Queue)
Keep it local and simple using Postgres as the queue:

1. Add `schedules` table
   - cron/interval, enabled, next_run_at, pipeline_config_json
2. Add `jobs` table for run execution + verification tasks
3. Implement worker claiming with `SELECT ... FOR UPDATE SKIP LOCKED`
4. Add `scheduler` service (container) that enqueues due runs
5. Add `worker` service (container) that executes jobs

**Done when**
- A target can be scheduled (daily/weekly), runs execute unattended, verification jobs run, statuses update

---

## Phase 7: API + UI (Attack Surface Intelligence)
Backend endpoints (target-first):
- Targets CRUD
- Target inventory (`assets`, `services`, `edges`)
- Runs list + run detail
- Changes:
  - `new_assets/services` (first seen in last run)
  - `confirmed_closed/unresolved` (verified in last run)
- Findings filtered by target/run, linked to assets/services

Frontend:
- Targets list
- Target detail tabs: Inventory, Changes, Runs, Findings
- Keep chat as an “operator console” that can trigger manual runs and answer questions over inventory

**Done when**
- You can open a target and see: inventory, what changed since last run, confirmed closures, and findings

---

## Phase 8: Hardening (must-have for continuous scanning)
- Scope enforcement per target (domain allowlist, CIDR allowlist, URL prefixes)
- Concurrency limits (global + per target)
- Retention policy (raw outputs, old runs)
- Audit trail (`run_events`)

---

### Suggested PR-sized slices (fastest path to MVP)
1. Postgres + Alembic wired up
2. `targets` + `runs` + link existing `sessions`
3. `assets/services/edges` + ingestion upserts
4. Pipeline: subfinder + dns resolve + nmap + httpx + nuclei -> artifacts
5. Change detection + verification jobs -> confirmed closed/unresolved
6. Scheduler/worker services (DB queue)
7. UI: Targets + Inventory + Changes

If you want, I can start implementing Phase 1 (Postgres + Alembic + schema skeleton) in this repo next.