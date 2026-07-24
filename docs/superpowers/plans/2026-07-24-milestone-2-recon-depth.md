# Milestone 2: Recon Depth (naabu + tlsx + gau) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three recon scanners — naabu (fast port pre-scan feeding nmap), tlsx (TLS/cert SAN harvesting), gau (historical URL discovery) — and wire them into the pipeline with scope enforcement.

**Architecture:** Each scanner is a `BaseScanner` subclass in `backend/scanners/` with a matching install block in `docker/tools.Dockerfile`. naabu runs before nmap and passes discovered open ports to nmap via nmap's existing `config["ports"]` param (so nmap does deep `-sV -sC` only on open ports). tlsx runs after nmap on discovered hostnames, emitting cert-SAN subdomains + TLS findings. gau runs after httpx, emitting scope-filtered historical URL assets. New pipeline order: subfinder → dnsx → **naabu → nmap(open ports)** → **tlsx** → httpx → **gau** → nuclei.

**Tech Stack:** Python 3.11, async subprocess via `docker exec`, pytest + pytest-asyncio, Docker (Alpine tools image).

## Global Constraints

- Each scanner MUST subclass `BaseScanner` (`backend/scanners/base.py`): set `name`/`binary`, implement `async run(self, target, config=None, stream_callback=None) -> ScanResult`, and emit structured `FindingResult` / `AssetArtifact` / `ServiceArtifact` artifacts. Use `self.exec_in_container(cmd, timeout, stream_callback)` to run tools.
- All discovered/derived assets (tlsx SAN subdomains, gau URLs) MUST be scope-checked via `check_in_scope(scope, value, type)` from `backend/scope.py` before use in the pipeline. The scanner itself emits everything; the pipeline filters (mirrors how subfinder subdomains are filtered at `run_pipeline.py:103-107`).
- Dockerfile installs follow the existing ProjectDiscovery pattern (the `dnsx` block is the template): fetch latest release → unzip → chmod. naabu and tlsx are PD tools (`projectdiscovery/naabu`, `projectdiscovery/tlsx`). gau is `lc/gau` (tar.gz release, like ffuf).
- The tools image build arg is `TARGETARCH` (default amd64); the `ARCH=$(case ${TARGETARCH} ...)` line is copied verbatim into each install block.
- Tests run from the backend container: `docker compose exec -T -w /app backend pytest tests/<file> -v` (run `docker compose` from repo root `/Users/bspindler/src/servicevelocity/security`).
- After Dockerfile changes, the tools image must be rebuilt: `docker compose build tools` then `docker compose up -d tools`.
- Verify against the authorized target `servicevelocity.ai` (id `87d323c6-91b7-441e-80a6-dfc1bd69e091`) — user owns it.
- Postgres runs on host port 5433 (from M1); do not change it.

---

## File Structure

- `backend/scanners/naabu_scanner.py` — new: `NaabuScanner`, fast port scan → `ServiceArtifact`s + a `ports_by_host` helper output.
- `backend/scanners/tlsx_scanner.py` — new: `TlsxScanner`, TLS grab → SAN subdomain assets + TLS findings.
- `backend/scanners/gau_scanner.py` — new: `GauScanner`, historical URLs → url assets.
- `backend/tests/test_naabu_scanner.py` — new: parse-path unit test.
- `backend/tests/test_tlsx_scanner.py` — new: parse-path unit test.
- `backend/tests/test_gau_scanner.py` — new: parse-path unit test.
- `docker/tools.Dockerfile` — modify: add naabu, tlsx, gau install blocks.
- `backend/pipeline/run_pipeline.py` — modify: insert naabu (before nmap, feed ports), tlsx (after nmap), gau (after httpx) stages with scope enforcement.

---

## Task 1: naabu scanner + Dockerfile install

**Files:**
- Create: `backend/scanners/naabu_scanner.py`
- Create: `backend/tests/test_naabu_scanner.py`
- Modify: `docker/tools.Dockerfile`

**Interfaces:**
- Consumes: `BaseScanner`, `ScanResult`, `ServiceArtifact`, `FindingResult` from `scanners.base`; `guess_asset_type_from_host`, `normalize_domain` from `recongraph.normalize`.
- Produces: `NaabuScanner` (name="naabu", binary="naabu"). `run(target, config)` where `config["targets"]` is a list of IPs/hosts to scan. Returns `ScanResult` with `services` (one `ServiceArtifact` per open port) and info findings. Also exposes a module-level helper `ports_by_host(services: list[ServiceArtifact]) -> dict[str, str]` returning `{host_normalized: "80,443,..."}` for feeding nmap.

- [ ] **Step 1: Write the failing parse test**

Create `backend/tests/test_naabu_scanner.py`:

```python
"""Tests for NaabuScanner JSON parsing and ports_by_host helper."""
from scanners.naabu_scanner import NaabuScanner, ports_by_host
from scanners.base import ServiceArtifact


def test_parse_naabu_jsonl_emits_services():
    # naabu -json emits one JSON object per open port
    lines = [
        '{"ip":"203.0.113.5","port":443,"protocol":"tcp","host":"203.0.113.5"}',
        '{"ip":"203.0.113.5","port":80,"protocol":"tcp","host":"203.0.113.5"}',
    ]
    scanner = NaabuScanner()
    findings, assets, services = scanner._parse_lines(lines)
    ports = sorted(s.port for s in services)
    assert ports == [80, 443]
    assert all(s.proto == "tcp" for s in services)
    assert all(s.host_normalized == "203.0.113.5" for s in services)


def test_parse_naabu_skips_malformed_lines():
    lines = ["not json", "", '{"ip":"203.0.113.5","port":22,"protocol":"tcp"}']
    scanner = NaabuScanner()
    _, _, services = scanner._parse_lines(lines)
    assert [s.port for s in services] == [22]


def test_ports_by_host_groups_and_joins():
    services = [
        ServiceArtifact(host_type="ip", host_value="10.0.0.1", host_normalized="10.0.0.1", port=443, proto="tcp"),
        ServiceArtifact(host_type="ip", host_value="10.0.0.1", host_normalized="10.0.0.1", port=80, proto="tcp"),
        ServiceArtifact(host_type="ip", host_value="10.0.0.2", host_normalized="10.0.0.2", port=8443, proto="tcp"),
    ]
    mapping = ports_by_host(services)
    # ports sorted ascending, comma-joined, no duplicates
    assert mapping["10.0.0.1"] == "80,443"
    assert mapping["10.0.0.2"] == "8443"


def test_ports_by_host_dedups():
    services = [
        ServiceArtifact(host_type="ip", host_value="10.0.0.1", host_normalized="10.0.0.1", port=443, proto="tcp"),
        ServiceArtifact(host_type="ip", host_value="10.0.0.1", host_normalized="10.0.0.1", port=443, proto="tcp"),
    ]
    assert ports_by_host(services)["10.0.0.1"] == "443"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec -T -w /app backend pytest tests/test_naabu_scanner.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scanners.naabu_scanner'`.

- [ ] **Step 3: Implement the scanner**

Create `backend/scanners/naabu_scanner.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose exec -T -w /app backend pytest tests/test_naabu_scanner.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Add the naabu install block to the Dockerfile**

In `docker/tools.Dockerfile`, immediately after the existing `dnsx` install block (the `RUN DNSX_VERSION=... rm /tmp/dnsx.zip` block), add:

```dockerfile
# Install naabu (pre-built binary)
RUN NAABU_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/naabu/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/^v//') && \
    ARCH=$(case ${TARGETARCH} in amd64) echo "amd64" ;; arm64) echo "arm64" ;; *) echo "amd64" ;; esac) && \
    curl -sL "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${ARCH}.zip" -o /tmp/naabu.zip && \
    unzip -o /tmp/naabu.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/naabu && \
    rm /tmp/naabu.zip
```

- [ ] **Step 6: Rebuild the tools image and verify naabu is installed**

Run:
```bash
docker compose build tools && docker compose up -d tools
docker exec shadowpulse-tools which naabu && docker exec shadowpulse-tools naabu -version 2>&1 | head -2
```
Expected: a path (`/usr/local/bin/naabu`) and a version line. (naabu needs `libpcap` for SYN mode; Alpine has it via nmap deps, but naabu falls back to CONNECT scan if unavailable — either is fine for our use.)

- [ ] **Step 7: Commit**

```bash
git add backend/scanners/naabu_scanner.py backend/tests/test_naabu_scanner.py docker/tools.Dockerfile
git commit -m "feat(scanner): add naabu fast port scanner

naabu discovers open ports (JSON output, top-1000) and emits ServiceArtifacts;
ports_by_host() groups them into an nmap -p string for deep service scans."
```

---

## Task 2: tlsx scanner + Dockerfile install

**Files:**
- Create: `backend/scanners/tlsx_scanner.py`
- Create: `backend/tests/test_tlsx_scanner.py`
- Modify: `docker/tools.Dockerfile`

**Interfaces:**
- Consumes: `BaseScanner`, `ScanResult`, `FindingResult`, `AssetArtifact` from `scanners.base`; `normalize_domain` from `recongraph.normalize`.
- Produces: `TlsxScanner` (name="tlsx", binary="tlsx"). `run(target, config)` where `config["targets"]` is a list of hostnames. Returns `ScanResult` with `assets` (subdomain assets from cert SANs) and findings (info: cert issuer/expiry/TLS version; low: TLS 1.0/1.1 or expired cert).

- [ ] **Step 1: Write the failing parse test**

Create `backend/tests/test_tlsx_scanner.py`:

```python
"""Tests for TlsxScanner JSON parsing."""
from scanners.tlsx_scanner import TlsxScanner


def test_parse_emits_san_subdomain_assets():
    # tlsx -json -san emits cert metadata incl. subject_an (SAN list)
    lines = [
        '{"host":"app.example.com","port":"443","subject_an":["app.example.com","api.example.com"],'
        '"issuer_cn":"R3","tls_version":"tls13","not_after":"2030-01-01T00:00:00Z"}'
    ]
    scanner = TlsxScanner()
    findings, assets = scanner._parse_lines(lines)
    values = {a.normalized for a in assets if a.type == "subdomain"}
    assert "app.example.com" in values
    assert "api.example.com" in values


def test_parse_flags_weak_tls_version():
    lines = [
        '{"host":"old.example.com","port":"443","subject_an":["old.example.com"],'
        '"issuer_cn":"CA","tls_version":"tls10","not_after":"2030-01-01T00:00:00Z"}'
    ]
    scanner = TlsxScanner()
    findings, assets = scanner._parse_lines(lines)
    weak = [f for f in findings if "tls" in f.title.lower() and f.severity == "low"]
    assert weak, "expected a low-severity weak-TLS finding for tls10"


def test_parse_skips_malformed():
    lines = ["garbage", "", '{"host":"h.example.com","port":"443","subject_an":["h.example.com"],"tls_version":"tls13","not_after":"2030-01-01T00:00:00Z"}']
    scanner = TlsxScanner()
    findings, assets = scanner._parse_lines(lines)
    assert any(a.normalized == "h.example.com" for a in assets)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec -T -w /app backend pytest tests/test_tlsx_scanner.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scanners.tlsx_scanner'`.

- [ ] **Step 3: Implement the scanner**

Create `backend/scanners/tlsx_scanner.py`:

```python
import json
import shlex
from datetime import datetime

from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact
from recongraph.normalize import normalize_domain


WEAK_TLS = {"tls10", "tls11", "ssl30"}


class TlsxScanner(BaseScanner):
    """Grab TLS certificate metadata (SANs, issuer, version) via tlsx."""

    name = "tlsx"
    binary = "tlsx"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        result = ScanResult(scanner=self.name, target=target, started_at=datetime.utcnow())

        targets = config.get("targets", [target])
        if isinstance(targets, str):
            targets = [targets]
        cleaned = [str(t).strip() for t in targets if str(t).strip()]
        if not cleaned:
            cleaned = [target]

        quoted = " ".join(shlex.quote(t) for t in cleaned)
        # -json full cert metadata, -san subject alt names, -tls-version negotiated version
        cmd = ["sh", "-c",
               "printf '%s\\n' " + quoted +
               " | tlsx -json -san -tls-version -silent"]

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
            result.raw_output = "\n".join(lines)
            findings, assets = self._parse_lines(lines)
            result.findings = findings
            result.assets = assets
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    def _parse_lines(self, lines: list[str]) -> tuple[list[FindingResult], list[AssetArtifact]]:
        findings: list[FindingResult] = []
        assets: list[AssetArtifact] = []

        for line in lines:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = data.get("host", "")
            issuer = data.get("issuer_cn", "")
            tls_version = (data.get("tls_version") or "").lower()
            not_after = data.get("not_after", "")

            # SAN hostnames -> subdomain assets
            for san in data.get("subject_an", []) or []:
                san_norm = normalize_domain(san)
                if san_norm and not san_norm.startswith("*"):
                    assets.append(AssetArtifact(type="subdomain", value=san, normalized=san_norm))

            # Info finding: cert summary
            findings.append(FindingResult(
                severity="info",
                title=f"TLS certificate: {host}",
                description=f"Host {host} — issuer: {issuer or 'unknown'}, TLS: {tls_version or 'unknown'}, expires: {not_after or 'unknown'}",
                evidence=f"issuer={issuer} tls_version={tls_version} not_after={not_after}",
                url=host,
            ))

            # Low finding: weak TLS version
            if tls_version in WEAK_TLS:
                findings.append(FindingResult(
                    severity="low",
                    title=f"Weak TLS version {tls_version} on {host}",
                    description=f"Host {host} negotiates {tls_version}, which is deprecated and vulnerable to downgrade/known attacks.",
                    impact="Deprecated TLS versions (1.0/1.1, SSL 3.0) have known cryptographic weaknesses. Attackers on-path can exploit these for downgrade attacks or decryption.",
                    remediation="Disable TLS 1.0/1.1 and SSL 3.0; require TLS 1.2+ (ideally 1.3).",
                    url=host,
                ))

        return findings, assets
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose exec -T -w /app backend pytest tests/test_tlsx_scanner.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Add the tlsx install block to the Dockerfile**

In `docker/tools.Dockerfile`, immediately after the naabu block added in Task 1, add:

```dockerfile
# Install tlsx (pre-built binary)
RUN TLSX_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/tlsx/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/^v//') && \
    ARCH=$(case ${TARGETARCH} in amd64) echo "amd64" ;; arm64) echo "arm64" ;; *) echo "amd64" ;; esac) && \
    curl -sL "https://github.com/projectdiscovery/tlsx/releases/download/v${TLSX_VERSION}/tlsx_${TLSX_VERSION}_linux_${ARCH}.zip" -o /tmp/tlsx.zip && \
    unzip -o /tmp/tlsx.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/tlsx && \
    rm /tmp/tlsx.zip
```

- [ ] **Step 6: Rebuild tools image and verify tlsx**

Run:
```bash
docker compose build tools && docker compose up -d tools
docker exec shadowpulse-tools which tlsx && docker exec shadowpulse-tools tlsx -version 2>&1 | head -2
```
Expected: path + version line.

- [ ] **Step 7: Commit**

```bash
git add backend/scanners/tlsx_scanner.py backend/tests/test_tlsx_scanner.py docker/tools.Dockerfile
git commit -m "feat(scanner): add tlsx TLS/cert-SAN scanner

tlsx grabs cert metadata; SAN hostnames become subdomain assets (finds
subdomains subfinder misses), plus info cert findings and low weak-TLS findings."
```

---

## Task 3: gau scanner + Dockerfile install

**Files:**
- Create: `backend/scanners/gau_scanner.py`
- Create: `backend/tests/test_gau_scanner.py`
- Modify: `docker/tools.Dockerfile`

**Interfaces:**
- Consumes: `BaseScanner`, `ScanResult`, `AssetArtifact` from `scanners.base`; `normalize_url` from `recongraph.normalize`.
- Produces: `GauScanner` (name="gau", binary="gau"). `run(target, config)` where `target` is the root domain. Returns `ScanResult` with `assets` (url assets), deduped and capped at `config["max_urls"]` (default 500).

- [ ] **Step 1: Write the failing parse test**

Create `backend/tests/test_gau_scanner.py`:

```python
"""Tests for GauScanner URL parsing."""
from scanners.gau_scanner import GauScanner


def test_parse_emits_url_assets():
    lines = [
        "https://example.com/old/page?a=1",
        "https://example.com/api/v1/users",
        "http://example.com/legacy",
    ]
    scanner = GauScanner()
    assets = scanner._parse_lines(lines, max_urls=500)
    norms = {a.normalized for a in assets}
    assert any("example.com/old/page" in n for n in norms)
    assert all(a.type == "url" for a in assets)


def test_parse_dedups_and_caps():
    lines = ["https://example.com/x"] * 10 + [f"https://example.com/p{i}" for i in range(10)]
    scanner = GauScanner()
    assets = scanner._parse_lines(lines, max_urls=5)
    assert len(assets) <= 5
    # dedup: the repeated /x collapses to one
    norms = [a.normalized for a in assets]
    assert len(norms) == len(set(norms))


def test_parse_skips_blank_and_garbage():
    lines = ["", "   ", "not a url", "https://example.com/ok"]
    scanner = GauScanner()
    assets = scanner._parse_lines(lines, max_urls=500)
    assert any("example.com/ok" in a.normalized for a in assets)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec -T -w /app backend pytest tests/test_gau_scanner.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scanners.gau_scanner'`.

- [ ] **Step 3: Implement the scanner**

Create `backend/scanners/gau_scanner.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose exec -T -w /app backend pytest tests/test_gau_scanner.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Add the gau install block to the Dockerfile**

gau is `lc/gau`, released as a `.tar.gz` (like ffuf). In `docker/tools.Dockerfile`, immediately after the tlsx block, add:

```dockerfile
# Install gau (pre-built binary)
RUN GAU_VERSION=$(curl -s https://api.github.com/repos/lc/gau/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/^v//') && \
    ARCH=$(case ${TARGETARCH} in amd64) echo "amd64" ;; arm64) echo "arm64" ;; *) echo "amd64" ;; esac) && \
    curl -sL "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_${ARCH}.tar.gz" -o /tmp/gau.tar.gz && \
    tar -xzf /tmp/gau.tar.gz -C /usr/local/bin/ gau && \
    chmod +x /usr/local/bin/gau && \
    rm /tmp/gau.tar.gz
```

- [ ] **Step 6: Rebuild tools image and verify gau**

Run:
```bash
docker compose build tools && docker compose up -d tools
docker exec shadowpulse-tools which gau && docker exec shadowpulse-tools gau --version 2>&1 | head -2
```
Expected: path + version (gau may print version to stderr; the `which` success is the key check).

- [ ] **Step 7: Commit**

```bash
git add backend/scanners/gau_scanner.py backend/tests/test_gau_scanner.py docker/tools.Dockerfile
git commit -m "feat(scanner): add gau historical-URL scanner

gau pulls URLs from Wayback/CommonCrawl/OTX; emits deduped, capped url assets
to expand the endpoint surface for nuclei/later stages."
```

---

## Task 4: Wire naabu, tlsx, gau into the pipeline

**Files:**
- Modify: `backend/pipeline/run_pipeline.py`

**Interfaces:**
- Consumes: `NaabuScanner` + `ports_by_host` from `scanners.naabu_scanner`; `TlsxScanner` from `scanners.tlsx_scanner`; `GauScanner` from `scanners.gau_scanner`; existing `check_in_scope`, `_run_scanner_and_persist`, `_ensure_run_not_discarded`.
- Produces: updated `run_pipeline` with the new stage order. No signature change.

- [ ] **Step 1: Add imports**

In `backend/pipeline/run_pipeline.py`, after the existing scanner imports (near line 11-13), add:

```python
from scanners.naabu_scanner import NaabuScanner, ports_by_host
from scanners.tlsx_scanner import TlsxScanner
from scanners.gau_scanner import GauScanner
```

- [ ] **Step 2: Insert naabu before nmap and feed its ports to nmap**

The current nmap stage (around lines 190-203) reads:

```python
        # 3) Nmap: services on discovered hosts
        nmap = NmapScanner()
        nmap_services = []
        for ip in uniq_ips:
            await _ensure_run_not_discarded(db, run.id)
            n_res = await _run_scanner_and_persist(
                db,
                run=run,
                target=ip,
                scanner_name="nmap",
                scanner=nmap,
                config={"scan_type": "service"},
            )
            nmap_services.extend(n_res.services)
```

Replace that block with (naabu first, then nmap constrained to naabu's open ports):

```python
        # 2.5) naabu: fast port discovery across all resolved hosts.
        naabu_ports: dict[str, str] = {}
        if uniq_ips:
            await _ensure_run_not_discarded(db, run.id)
            naabu = NaabuScanner()
            naabu_res = await _run_scanner_and_persist(
                db,
                run=run,
                target=target.root_domain,
                scanner_name="naabu",
                scanner=naabu,
                config={"targets": uniq_ips},
            )
            naabu_ports = ports_by_host(naabu_res.services)

        # 3) Nmap: deep service scan, constrained to naabu's open ports per host.
        nmap = NmapScanner()
        nmap_services = []
        for ip in uniq_ips:
            await _ensure_run_not_discarded(db, run.id)
            nmap_config = {"scan_type": "service"}
            if ip in naabu_ports:
                nmap_config["ports"] = naabu_ports[ip]
            n_res = await _run_scanner_and_persist(
                db,
                run=run,
                target=ip,
                scanner_name="nmap",
                scanner=nmap,
                config=nmap_config,
            )
            nmap_services.extend(n_res.services)
```

Note: if naabu found no ports for a host (or naabu failed), `nmap_config` has no `"ports"` key and nmap does its normal default scan for that host — a safe fallback.

- [ ] **Step 3: Insert tlsx after nmap, scope-filtering SAN subdomains**

Immediately AFTER the nmap loop (after `nmap_services.extend(...)` completes) and BEFORE the httpx stage (`# 4) httpx probe`), insert:

```python
        # 3.5) tlsx: TLS/cert metadata on discovered hostnames; SAN -> new subdomains.
        await _ensure_run_not_discarded(db, run.id)
        if subdomains:
            tlsx = TlsxScanner()
            tlsx_res = await _run_scanner_and_persist(
                db,
                run=run,
                target=target.root_domain,
                scanner_name="tlsx",
                scanner=tlsx,
                config={"targets": subdomains},
            )
            # Fold in-scope SAN subdomains into the hostname set for httpx.
            for a in tlsx_res.assets:
                if a.type == "subdomain" and a.normalized and check_in_scope(scope, a.normalized, "subdomain"):
                    if a.normalized not in subdomains:
                        subdomains.append(a.normalized)
```

Note: `subdomains` is the in-scope hostname list built at line ~103. `check_in_scope` and `scope` are already in scope in this function. Appending in-scope SAN subdomains means the httpx stage (which uses `hostnames=subdomains`) probes them too.

- [ ] **Step 4: Insert gau after httpx, scope-filtering URLs**

The httpx stage populates `httpx_urls`. Immediately AFTER the httpx stage block (after the `for a in h_res.assets:` loop that fills `httpx_urls`) and BEFORE the `# 5) nuclei` stage, insert:

```python
        # 4.5) gau: historical URLs for the root domain, scope-filtered, feed nuclei.
        await _ensure_run_not_discarded(db, run.id)
        gau = GauScanner()
        gau_res = await _run_scanner_and_persist(
            db,
            run=run,
            target=target.root_domain,
            scanner_name="gau",
            scanner=gau,
            config={"max_urls": 500},
        )
        for a in gau_res.assets:
            if a.type == "url" and a.normalized and check_in_scope(scope, a.normalized, "url"):
                if a.normalized not in httpx_urls:
                    httpx_urls.append(a.normalized)
```

Note: this appends in-scope historical URLs to `httpx_urls`, which the nuclei stage consumes (nuclei runs `if httpx_urls:`). So gau's URLs get vuln-scanned too.

- [ ] **Step 5: Restart backend + worker to load the new pipeline**

Run:
```bash
docker compose restart backend worker
```

- [ ] **Step 6: Run the full test suite (all scanners + pipeline)**

Run:
```bash
docker compose exec -T -w /app backend pytest -v
```
Expected: all tests pass (the M1 `test_build_http_targets.py` 7 + naabu 4 + tlsx 3 + gau 3 = 17).

- [ ] **Step 7: Live end-to-end verification against servicevelocity.ai**

Trigger a run:
```bash
curl -fsS -X POST http://localhost:8000/api/targets/87d323c6-91b7-441e-80a6-dfc1bd69e091/pipeline -H "Content-Type: application/json" -d '{}'
```
Poll the events endpoint and confirm the new stage order appears:
```bash
curl -fsS http://localhost:8000/api/targets/87d323c6-91b7-441e-80a6-dfc1bd69e091/events | python3 -c "import sys,json; [print(e['event_type'], e.get('detail',{}).get('scanner','')) for e in json.load(sys.stdin)[:20]]"
```
Expected: `scan_started`/`scan_completed` events for `naabu`, then `nmap`, then `tlsx`, then `httpx`, then `gau`, then `nuclei` — in that order. Each should complete (status completed). Confirm no scope violations (all discovered assets under servicevelocity.ai).

- [ ] **Step 8: Commit**

```bash
git add backend/pipeline/run_pipeline.py
git commit -m "feat(pipeline): wire naabu -> nmap(open ports) -> tlsx -> httpx -> gau -> nuclei

naabu pre-scans ports and constrains nmap to open ports; tlsx folds in-scope
cert-SAN subdomains into the httpx hostname set; gau folds in-scope historical
URLs into the nuclei target set. All new assets scope-checked."
```

---

## Self-Review notes

- **Spec coverage:** M2 spec §"naabu" → Task 1; §"tlsx" → Task 2; §"gau" → Task 3; §"pipeline order after M2" → Task 4. All covered.
- **Placeholder scan:** no TBD/TODO; every code step shows full code.
- **Type consistency:** `ports_by_host(services) -> dict[str,str]` defined in Task 1, consumed in Task 4 Step 2. `TlsxScanner`/`GauScanner`/`NaabuScanner` class names consistent across scanner files, tests, and pipeline imports.
- **Scope enforcement:** tlsx SAN subdomains (Task 4 Step 3) and gau URLs (Step 4) both filtered via `check_in_scope` before use — satisfies the global constraint.
- **Fallback safety:** naabu failure or zero-ports → nmap falls back to default scan (Task 4 Step 2 note). Every new stage uses `_run_scanner_and_persist` which isolates per-scanner failures (consistent with existing stages).
- **Deferred:** M3 (trufflehog), M4 (takeover) — separate plans.
