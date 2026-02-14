from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import Target, Run, Scan, Finding, Asset, Service, gen_id
from scanners.subfinder_scanner import SubfinderScanner
from scanners.nmap_scanner import NmapScanner
from scanners.httpx_scanner import HttpxScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.base import ScanResult as ScannerScanResult, AssetArtifact, EdgeArtifact
from recongraph.ingest import ingest_scan_result, set_asset_status, upsert_asset_seen
from recongraph.normalize import normalize_domain, normalize_url, is_ip
from pipeline.dns_resolve import resolve_many
from jobqueue.ops import enqueue_job
from scope import parse_scope, check_in_scope
from audit import log_event


WEB_PORTS_HTTP = {80, 8080, 8000, 3000, 5000, 8888, 8081, 9000, 10000}
WEB_PORTS_HTTPS = {443, 8443, 9443}


class CancelledError(Exception):
    pass


async def _ensure_run_not_discarded(db: AsyncSession, run_id: str) -> None:
    """Best-effort cancellation check (used between long-running steps)."""
    result = await db.execute(select(Run.status).where(Run.id == run_id))
    status = result.scalar_one_or_none()
    if status in {"discarded", "cancelled"}:
        raise CancelledError(f"run {run_id} is {status}")


async def run_pipeline(
    db: AsyncSession,
    *,
    target_id: str,
    trigger: str = "manual",
    run_id: str | None = None,
    max_hosts: int = 50,
    max_http_targets: int = 200,
) -> str:
    """Run a deterministic recon pipeline and persist inventory + findings.

    Returns the created run_id.
    """
    target = await db.get(Target, target_id)
    if not target:
        raise ValueError("Target not found")

    scope = parse_scope(target.scope_json, target.root_domain)

    now = datetime.utcnow()
    if run_id:
        run = await db.get(Run, run_id)
        if not run:
            raise ValueError("Run not found")
        if run.target_id != target_id:
            raise ValueError("Run target_id mismatch")
        # If someone discarded/cancelled the run before we start, honor that.
        if run.status in {"discarded", "cancelled"}:
            raise CancelledError(f"run {run.id} is {run.status}")
        run.trigger = trigger
        run.status = "running"
        run.started_at = run.started_at or now
        await db.commit()
    else:
        run = Run(
            id=gen_id(),
            target_id=target_id,
            trigger=trigger,
            status="running",
            started_at=now,
        )
        db.add(run)
        await db.commit()

    try:
        await log_event(
            db, target_id=target_id, run_id=run.id,
            event_type="pipeline_started",
            detail={"trigger": trigger, "max_hosts": max_hosts, "max_http_targets": max_http_targets},
            actor="worker",
        )

        await _ensure_run_not_discarded(db, run.id)
        # 1) Subdomain enumeration
        subfinder = SubfinderScanner()
        sub_res = await _run_scanner_and_persist(
            db,
            run=run,
            target=target.root_domain,
            scanner_name="subfinder",
            scanner=subfinder,
            config={},
        )

        subdomains = [
            a.normalized
            for a in sub_res.assets
            if a.type == "subdomain" and a.normalized and check_in_scope(scope, a.normalized, "subdomain")
        ]

        await _ensure_run_not_discarded(db, run.id)
        # 2) DNS resolve: subdomain -> ip edges; mark unresolved explicitly.
        dns_results = await resolve_many(subdomains, concurrency=50)
        resolved_ips: list[str] = []

        dns_scan = Scan(
            id=gen_id(),
            session_id=None,
            target_id=run.target_id,
            run_id=run.id,
            scanner="dns_resolve",
            target=target.root_domain,
            status="running",
            config=json.dumps({"count": len(subdomains)}),
            started_at=datetime.utcnow(),
        )
        db.add(dns_scan)
        await db.commit()

        dns_sr = ScannerScanResult(scanner="dns_resolve", target=target.root_domain)
        raw_lines: list[str] = []
        unresolved: list[tuple[str, str]] = []

        for rr in dns_results:
            rr_name_norm = normalize_domain(rr.name)
            if not rr_name_norm:
                continue

            dns_sr.assets.append(AssetArtifact(type="subdomain", value=rr.name, normalized=rr_name_norm))

            if rr.ips:
                for ip in rr.ips:
                    if not is_ip(ip):
                        continue
                    resolved_ips.append(ip)
                    dns_sr.assets.append(AssetArtifact(type="ip", value=ip, normalized=ip))
                    dns_sr.edges.append(EdgeArtifact(
                        from_type="subdomain",
                        from_value=rr.name,
                        from_normalized=rr_name_norm,
                        to_type="ip",
                        to_value=ip,
                        to_normalized=ip,
                        rel_type="resolves_to",
                    ))
                raw_lines.append(f"{rr_name_norm} -> {', '.join(rr.ips)}")
            else:
                unresolved.append((rr_name_norm, rr.error or "NO_ANSWER"))
                raw_lines.append(f"{rr_name_norm} -> unresolved ({rr.error or 'NO_ANSWER'})")

        dns_scan.status = "completed"
        dns_scan.raw_output = "\n".join(raw_lines)[:50000]
        dns_scan.completed_at = datetime.utcnow()
        await db.commit()

        await ingest_scan_result(db, target_id=target_id, run_id=run.id, scan_result=dns_sr)

        for rr_name_norm, err in unresolved:
            await set_asset_status(
                db,
                target_id=target_id,
                type="subdomain",
                normalized=rr_name_norm,
                status="unresolved",
                reason=err,
                verified_at=datetime.utcnow(),
                commit=False,
            )
        if unresolved:
            await db.commit()

        await _ensure_run_not_discarded(db, run.id)
        # De-dupe IPs, keep stable order
        seen_ip: set[str] = set()
        uniq_ips: list[str] = []
        for ip in resolved_ips:
            if ip not in seen_ip:
                seen_ip.add(ip)
                uniq_ips.append(ip)
        uniq_ips = uniq_ips[:max_hosts]

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

        await _ensure_run_not_discarded(db, run.id)
        # 4) httpx probe on likely-web services -> URLs
        http_targets = _build_http_targets(nmap_services)
        http_targets = http_targets[:max_http_targets]

        httpx_urls: list[str] = []
        if http_targets:
            httpx = HttpxScanner()
            h_res = await _run_scanner_and_persist(
                db,
                run=run,
                target=target.root_domain,
                scanner_name="httpx",
                scanner=httpx,
                config={"targets": http_targets},
            )
            for a in h_res.assets:
                if a.type == "url" and a.normalized:
                    httpx_urls.append(a.normalized)

        await _ensure_run_not_discarded(db, run.id)
        # 5) nuclei constrained to live URLs
        if httpx_urls:
            nuclei = NucleiScanner()
            # Run as one batch; the scanner supports config["targets"].
            nuclei_res = await _run_scanner_and_persist(
                db,
                run=run,
                target=target.root_domain,
                scanner_name="nuclei",
                scanner=nuclei,
                config={"targets": httpx_urls},
                link_findings_to_url_assets=True,
            )

        await _ensure_run_not_discarded(db, run.id)
        # Phase 5: mark candidates not seen in this run as stale and enqueue verification jobs.
        await _enqueue_verification_jobs(db, target_id=target_id, run_id=run.id)

        run.status = "completed"
        run.completed_at = datetime.utcnow()
        await db.commit()
        await log_event(
            db, target_id=target_id, run_id=run.id,
            event_type="pipeline_completed", actor="worker",
        )
        return run.id
    except CancelledError:
        # Preserve status set by the discard/cancel request.
        run.completed_at = datetime.utcnow()
        await db.commit()
        raise
    except Exception as e:
        run.status = "failed"
        run.completed_at = datetime.utcnow()
        await db.commit()
        raise


def _build_http_targets(services) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()

    for s in services:
        port = s.port
        proto = (s.proto or "tcp").lower()
        host = s.host_normalized
        if not host:
            continue

        if proto != "tcp":
            continue

        if port in WEB_PORTS_HTTPS:
            url = f"https://{host}:{port}"
        elif port in WEB_PORTS_HTTP:
            url = f"http://{host}:{port}" if port != 80 else f"http://{host}"
        else:
            continue

        norm = normalize_url(url)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        targets.append(norm)

    return targets


async def _run_scanner_and_persist(
    db: AsyncSession,
    *,
    run: Run,
    target: str,
    scanner_name: str,
    scanner,
    config: dict,
    link_findings_to_url_assets: bool = False,
):
    """Run a scanner, persist scan row, ingest artifacts, persist findings."""
    scan = Scan(
        id=gen_id(),
        session_id=None,
        target_id=run.target_id,
        run_id=run.id,
        scanner=scanner_name,
        target=target,
        status="running",
        config=json.dumps(config),
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    await db.commit()

    await log_event(
        db, target_id=run.target_id, run_id=run.id,
        event_type="scan_started",
        detail={"scanner": scanner_name, "target": target},
        actor="worker",
    )

    scan_result = await scanner.run(target, config)

    scan.status = scan_result.status
    scan.raw_output = scan_result.raw_output[:50000]
    scan.completed_at = datetime.utcnow()
    await db.commit()

    await log_event(
        db, target_id=run.target_id, run_id=run.id,
        event_type="scan_completed",
        detail={"scanner": scanner_name, "target": target, "status": scan_result.status, "findings": len(scan_result.findings)},
        actor="worker",
    )

    # Inventory ingestion
    await ingest_scan_result(db, target_id=run.target_id, run_id=run.id, scan_result=scan_result)

    # Persist findings
    for fr in scan_result.findings:
        asset_id = None
        if link_findings_to_url_assets and fr.url:
            url_norm = normalize_url(fr.url)
            if url_norm:
                asset_id = await _url_asset_id(db, run.target_id, url_norm)
                if not asset_id:
                    res = await upsert_asset_seen(
                        db,
                        target_id=run.target_id,
                        run_id=run.id,
                        type="url",
                        value=fr.url,
                        normalized=url_norm,
                    )
                    asset_id = res.id

        finding = Finding(
            id=gen_id(),
            session_id=None,
            scan_id=scan.id,
            target_id=run.target_id,
            run_id=run.id,
            asset_id=asset_id,
            severity=fr.severity,
            title=fr.title,
            description=fr.description,
            impact=fr.impact,
            evidence=fr.evidence,
            remediation=fr.remediation,
            remediation_example=fr.remediation_example,
            url=fr.url,
            cve=fr.cve,
            cvss_score=fr.cvss_score,
        )
        db.add(finding)

    await db.commit()
    return scan_result


async def _url_asset_id(db: AsyncSession, target_id: str, url_norm: str) -> str | None:
    result = await db.execute(
        select(Asset.id).where(
            Asset.target_id == target_id,
            Asset.type == "url",
            Asset.normalized == url_norm,
        )
    )
    return result.scalar_one_or_none()


async def _enqueue_verification_jobs(db: AsyncSession, *, target_id: str, run_id: str) -> None:
    now = datetime.utcnow()

    # Assets: verify only subdomain + url artifacts.
    assets_result = await db.execute(
        select(Asset).where(
            Asset.target_id == target_id,
            Asset.status == "active",
            Asset.last_seen_run_id.is_not(None),
            Asset.last_seen_run_id != run_id,
            Asset.type.in_(["subdomain", "url"]),
        )
    )
    assets = assets_result.scalars().all()
    for a in assets:
        a.status = "stale"
        a.status_reason = f"not_seen_in_run:{run_id}"
        await enqueue_job(
            db,
            type="verify_asset",
            target_id=target_id,
            run_id=run_id,
            payload={"asset_id": a.id},
            available_at=now,
            commit=False,
        )

    # Services: verify services not seen this run.
    svc_result = await db.execute(
        select(Service).where(
            Service.target_id == target_id,
            Service.status == "active",
            Service.last_seen_run_id.is_not(None),
            Service.last_seen_run_id != run_id,
        )
    )
    services = svc_result.scalars().all()
    for s in services:
        s.status = "stale"
        s.status_reason = f"not_seen_in_run:{run_id}"
        await enqueue_job(
            db,
            type="verify_service",
            target_id=target_id,
            run_id=run_id,
            payload={"service_id": s.id},
            available_at=now,
            commit=False,
        )

    await db.commit()
