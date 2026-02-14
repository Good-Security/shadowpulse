from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime

import httpx

from sqlalchemy.ext.asyncio import AsyncSession

from database import Asset, Scan, Service, gen_id
from pipeline.dns_resolve import resolve_many
from recongraph.ingest import (
    ingest_scan_result,
    set_asset_status,
    set_service_status,
    upsert_asset_seen,
)
from recongraph.normalize import is_ip, normalize_domain, normalize_url
from scanners.base import ScanResult as ScannerScanResult, AssetArtifact, EdgeArtifact


@dataclass(frozen=True)
class VerifyOutcome:
    ok: bool
    status: str  # active/closed/unresolved
    reason: str


async def verify_asset(db: AsyncSession, *, asset_id: str, target_id: str, run_id: str) -> None:
    asset = await db.get(Asset, asset_id)
    if not asset or asset.target_id != target_id:
        return

    scan = Scan(
        id=gen_id(),
        session_id=None,
        target_id=target_id,
        run_id=run_id,
        scanner="verify_asset",
        target=asset.value,
        status="running",
        config=None,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    await db.commit()

    try:
        if asset.type == "subdomain":
            outcome = await _verify_subdomain(db, asset=asset, target_id=target_id, run_id=run_id)
        elif asset.type == "url":
            outcome = await _verify_url(db, asset=asset, target_id=target_id, run_id=run_id)
        else:
            # Other asset types are not verified in Phase 5.
            outcome = VerifyOutcome(ok=True, status="active", reason="skipped")

        # Verification can legitimately conclude "closed" or "unresolved".
        # Only unexpected exceptions should mark the scan as failed.
        scan.status = "completed"
        scan.raw_output = f"{asset.type} {asset.normalized} -> {outcome.status} ({outcome.reason})"
        scan.completed_at = datetime.utcnow()
        await db.commit()
    except Exception as e:
        scan.status = "failed"
        scan.raw_output = f"error: {str(e)}"
        scan.completed_at = datetime.utcnow()
        await db.commit()
        raise


async def verify_service(db: AsyncSession, *, service_id: str, target_id: str, run_id: str) -> None:
    svc = await db.get(Service, service_id)
    if not svc or svc.target_id != target_id:
        return

    host_asset = await db.get(Asset, svc.asset_id)
    host = host_asset.normalized if host_asset else ""

    scan = Scan(
        id=gen_id(),
        session_id=None,
        target_id=target_id,
        run_id=run_id,
        scanner="verify_service",
        target=f"{host}:{svc.port}/{svc.proto}",
        status="running",
        config=None,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    await db.commit()

    try:
        outcome = await _verify_tcp(host, svc.port, timeout=3.0)

        if outcome.ok:
            # Mark active + seen in this run.
            svc.status = "active"
            svc.status_reason = None
            svc.last_seen_run_id = run_id
            svc.last_seen_at = datetime.utcnow()
            svc.verified_at = datetime.utcnow()
            svc.verified_run_id = run_id
            await db.commit()
        else:
            await set_service_status(
                db,
                service_id=svc.id,
                status=outcome.status,
                reason=outcome.reason,
                verified_at=datetime.utcnow(),
                verified_run_id=run_id,
            )

        scan.status = "completed"
        scan.raw_output = f"{host}:{svc.port}/{svc.proto} -> {outcome.status} ({outcome.reason})"
        scan.completed_at = datetime.utcnow()
        await db.commit()
    except Exception as e:
        scan.status = "failed"
        scan.raw_output = f"error: {str(e)}"
        scan.completed_at = datetime.utcnow()
        await db.commit()
        raise


async def _verify_subdomain(db: AsyncSession, *, asset: Asset, target_id: str, run_id: str) -> VerifyOutcome:
    name = asset.normalized
    res = await resolve_many([name], concurrency=1)
    rr = res[0] if res else None

    if rr and rr.ips:
        # Update the subdomain asset as active/seen.
        await upsert_asset_seen(
            db,
            target_id=target_id,
            run_id=run_id,
            type="subdomain",
            value=asset.value,
            normalized=name,
        )

        # Add resolved IPs and edges.
        sr = ScannerScanResult(scanner="verify_dns", target=name)
        sr.assets.append(AssetArtifact(type="subdomain", value=asset.value, normalized=name))
        for ip in rr.ips:
            if not is_ip(ip):
                continue
            sr.assets.append(AssetArtifact(type="ip", value=ip, normalized=ip))
            sr.edges.append(EdgeArtifact(
                from_type="subdomain",
                from_value=asset.value,
                from_normalized=name,
                to_type="ip",
                to_value=ip,
                to_normalized=ip,
                rel_type="resolves_to",
            ))
        await ingest_scan_result(db, target_id=target_id, run_id=run_id, scan_result=sr)

        # Mark verified
        await set_asset_status(
            db,
            target_id=target_id,
            type="subdomain",
            normalized=name,
            status="active",
            reason=None,
            verified_at=datetime.utcnow(),
            verified_run_id=run_id,
        )
        return VerifyOutcome(ok=True, status="active", reason="dns_resolved")

    # No resolution: unresolved
    await set_asset_status(
        db,
        target_id=target_id,
        type="subdomain",
        normalized=name,
        status="unresolved",
        reason=(rr.error if rr else "NO_ANSWER"),
        verified_at=datetime.utcnow(),
        verified_run_id=run_id,
    )
    return VerifyOutcome(ok=False, status="unresolved", reason=(rr.error if rr else "NO_ANSWER"))


async def _verify_url(db: AsyncSession, *, asset: Asset, target_id: str, run_id: str) -> VerifyOutcome:
    url_norm = asset.normalized or normalize_url(asset.value)
    if not url_norm:
        return VerifyOutcome(ok=False, status="unresolved", reason="invalid_url")

    try:
        async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=True) as client:
            resp = await client.get(url_norm)
            # Any response is enough to consider it active.
            await upsert_asset_seen(
                db,
                target_id=target_id,
                run_id=run_id,
                type="url",
                value=asset.value,
                normalized=url_norm,
            )
            await set_asset_status(
                db,
                target_id=target_id,
                type="url",
                normalized=url_norm,
                status="active",
                reason=f"http:{resp.status_code}",
                verified_at=datetime.utcnow(),
                verified_run_id=run_id,
            )
            return VerifyOutcome(ok=True, status="active", reason=f"http:{resp.status_code}")
    except Exception as e:
        msg = str(e).lower()
        if any(s in msg for s in ["name or service not known", "temporary failure in name resolution", "nodename nor servname"]):
            await set_asset_status(
                db,
                target_id=target_id,
                type="url",
                normalized=url_norm,
                status="unresolved",
                reason=str(e)[:300],
                verified_at=datetime.utcnow(),
                verified_run_id=run_id,
            )
            return VerifyOutcome(ok=False, status="unresolved", reason=str(e)[:200])

        await set_asset_status(
            db,
            target_id=target_id,
            type="url",
            normalized=url_norm,
            status="closed",
            reason=str(e)[:300],
            verified_at=datetime.utcnow(),
            verified_run_id=run_id,
        )
        return VerifyOutcome(ok=False, status="closed", reason=str(e)[:200])


async def _verify_tcp(host: str, port: int, *, timeout: float) -> VerifyOutcome:
    if not host:
        return VerifyOutcome(ok=False, status="unresolved", reason="missing_host")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return VerifyOutcome(ok=True, status="active", reason="tcp_connect_ok")
    except Exception as e:
        msg = str(e).lower()
        if any(s in msg for s in ["name or service not known", "temporary failure in name resolution", "nodename nor servname", "gaierror"]):
            return VerifyOutcome(ok=False, status="unresolved", reason=str(e)[:200])
        return VerifyOutcome(ok=False, status="closed", reason=str(e)[:200])
