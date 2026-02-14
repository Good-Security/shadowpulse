from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import Asset, Edge, Service, Target, gen_id
from scanners.base import ScanResult


@dataclass(frozen=True)
class UpsertResult:
    id: str
    created: bool


async def get_or_create_target(
    db: AsyncSession,
    *,
    root_domain: str,
    name: str | None = None,
    scope_json: dict | None = None,
) -> Target:
    result = await db.execute(select(Target).where(Target.root_domain == root_domain))
    target = result.scalar_one_or_none()
    if target:
        return target

    target = Target(
        id=gen_id(),
        name=name or root_domain,
        root_domain=root_domain,
        scope_json=scope_json or {"root_domain": root_domain},
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


async def upsert_asset_seen(
    db: AsyncSession,
    *,
    target_id: str,
    run_id: str | None,
    type: str,
    value: str,
    normalized: str,
    seen_at: datetime | None = None,
    commit: bool = True,
) -> UpsertResult:
    """Idempotently record that an asset exists (deduped by target_id/type/normalized)."""
    now = seen_at or datetime.utcnow()

    result = await db.execute(
        select(Asset).where(
            Asset.target_id == target_id,
            Asset.type == type,
            Asset.normalized == normalized,
        )
    )
    asset = result.scalar_one_or_none()
    if asset:
        asset.value = value
        asset.last_seen_run_id = run_id
        asset.last_seen_at = now
        if asset.status != "active":
            asset.status = "active"
            asset.status_reason = None
        if commit:
            await db.commit()
        else:
            await db.flush()
        return UpsertResult(id=asset.id, created=False)

    asset = Asset(
        id=gen_id(),
        target_id=target_id,
        type=type,
        value=value,
        normalized=normalized,
        first_seen_run_id=run_id,
        last_seen_run_id=run_id,
        first_seen_at=now,
        last_seen_at=now,
        status="active",
    )
    db.add(asset)
    if commit:
        await db.commit()
    else:
        await db.flush()
    return UpsertResult(id=asset.id, created=True)


async def upsert_service_seen(
    db: AsyncSession,
    *,
    target_id: str,
    run_id: str | None,
    asset_id: str,
    port: int,
    proto: str,
    name: str | None = None,
    product: str | None = None,
    version: str | None = None,
    seen_at: datetime | None = None,
    commit: bool = True,
) -> UpsertResult:
    """Idempotently record that a service exists (deduped by target_id/asset_id/port/proto)."""
    now = seen_at or datetime.utcnow()

    result = await db.execute(
        select(Service).where(
            Service.target_id == target_id,
            Service.asset_id == asset_id,
            Service.port == port,
            Service.proto == proto,
        )
    )
    svc = result.scalar_one_or_none()
    if svc:
        svc.name = name
        svc.product = product
        svc.version = version
        svc.last_seen_run_id = run_id
        svc.last_seen_at = now
        if svc.status != "active":
            svc.status = "active"
            svc.status_reason = None
        if commit:
            await db.commit()
        else:
            await db.flush()
        return UpsertResult(id=svc.id, created=False)

    svc = Service(
        id=gen_id(),
        target_id=target_id,
        asset_id=asset_id,
        port=port,
        proto=proto,
        name=name,
        product=product,
        version=version,
        first_seen_run_id=run_id,
        last_seen_run_id=run_id,
        first_seen_at=now,
        last_seen_at=now,
        status="active",
    )
    db.add(svc)
    if commit:
        await db.commit()
    else:
        await db.flush()
    return UpsertResult(id=svc.id, created=True)


async def upsert_edge_seen(
    db: AsyncSession,
    *,
    target_id: str,
    run_id: str | None,
    from_asset_id: str,
    to_asset_id: str,
    rel_type: str,
    seen_at: datetime | None = None,
    commit: bool = True,
) -> UpsertResult:
    """Idempotently record a relationship edge for a target."""
    now = seen_at or datetime.utcnow()

    result = await db.execute(
        select(Edge).where(
            Edge.target_id == target_id,
            Edge.from_asset_id == from_asset_id,
            Edge.to_asset_id == to_asset_id,
            Edge.rel_type == rel_type,
        )
    )
    edge = result.scalar_one_or_none()
    if edge:
        edge.last_seen_run_id = run_id
        edge.last_seen_at = now
        if commit:
            await db.commit()
        else:
            await db.flush()
        return UpsertResult(id=edge.id, created=False)

    edge = Edge(
        id=gen_id(),
        target_id=target_id,
        from_asset_id=from_asset_id,
        to_asset_id=to_asset_id,
        rel_type=rel_type,
        first_seen_run_id=run_id,
        last_seen_run_id=run_id,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(edge)
    if commit:
        await db.commit()
    else:
        await db.flush()
    return UpsertResult(id=edge.id, created=True)


async def ingest_scan_result(
    db: AsyncSession,
    *,
    target_id: str,
    run_id: str | None,
    scan_result: ScanResult,
    seen_at: datetime | None = None,
) -> None:
    """Upsert assets/services/edges from a scanner run into ReconGraph-lite tables."""
    now = seen_at or datetime.utcnow()

    # De-dupe within the scan_result itself to reduce DB round-trips.
    asset_keys: set[tuple[str, str]] = set()
    service_keys: set[tuple[str, str, int, str]] = set()
    edge_keys: set[tuple[str, str, str, str, str]] = set()

    asset_id_by_key: dict[tuple[str, str], str] = {}

    for a in scan_result.assets:
        key = (a.type, a.normalized)
        if key in asset_keys:
            continue
        asset_keys.add(key)
        res = await upsert_asset_seen(
            db,
            target_id=target_id,
            run_id=run_id,
            type=a.type,
            value=a.value,
            normalized=a.normalized,
            seen_at=now,
            commit=False,
        )
        asset_id_by_key[key] = res.id

    for s in scan_result.services:
        skey = (s.host_type, s.host_normalized, s.port, s.proto)
        if skey in service_keys:
            continue
        service_keys.add(skey)

        host_key = (s.host_type, s.host_normalized)
        host_id = asset_id_by_key.get(host_key)
        if not host_id:
            res = await upsert_asset_seen(
                db,
                target_id=target_id,
                run_id=run_id,
                type=s.host_type,
                value=s.host_value,
                normalized=s.host_normalized,
                seen_at=now,
                commit=False,
            )
            host_id = res.id
            asset_id_by_key[host_key] = host_id

        await upsert_service_seen(
            db,
            target_id=target_id,
            run_id=run_id,
            asset_id=host_id,
            port=s.port,
            proto=s.proto,
            name=s.name or None,
            product=s.product or None,
            version=s.version or None,
            seen_at=now,
            commit=False,
        )

    for e in scan_result.edges:
        ekey = (e.from_type, e.from_normalized, e.to_type, e.to_normalized, e.rel_type)
        if ekey in edge_keys:
            continue
        edge_keys.add(ekey)

        from_key = (e.from_type, e.from_normalized)
        to_key = (e.to_type, e.to_normalized)

        from_id = asset_id_by_key.get(from_key)
        if not from_id:
            res = await upsert_asset_seen(
                db,
                target_id=target_id,
                run_id=run_id,
                type=e.from_type,
                value=e.from_value,
                normalized=e.from_normalized,
                seen_at=now,
                commit=False,
            )
            from_id = res.id
            asset_id_by_key[from_key] = from_id

        to_id = asset_id_by_key.get(to_key)
        if not to_id:
            res = await upsert_asset_seen(
                db,
                target_id=target_id,
                run_id=run_id,
                type=e.to_type,
                value=e.to_value,
                normalized=e.to_normalized,
                seen_at=now,
                commit=False,
            )
            to_id = res.id
            asset_id_by_key[to_key] = to_id

        await upsert_edge_seen(
            db,
            target_id=target_id,
            run_id=run_id,
            from_asset_id=from_id,
            to_asset_id=to_id,
            rel_type=e.rel_type,
            seen_at=now,
            commit=False,
        )

    await db.commit()


async def set_asset_status(
    db: AsyncSession,
    *,
    target_id: str,
    type: str,
    normalized: str,
    status: str,
    reason: str | None = None,
    verified_at: datetime | None = None,
    verified_run_id: str | None = None,
    commit: bool = True,
) -> None:
    """Set an asset status (e.g. unresolved) by its unique key."""
    result = await db.execute(
        select(Asset).where(
            Asset.target_id == target_id,
            Asset.type == type,
            Asset.normalized == normalized,
        )
    )
    asset = result.scalar_one_or_none()
    if not asset:
        return

    asset.status = status
    asset.status_reason = reason
    asset.verified_at = verified_at or datetime.utcnow()
    asset.verified_run_id = verified_run_id
    if commit:
        await db.commit()
    else:
        await db.flush()


async def set_service_status(
    db: AsyncSession,
    *,
    service_id: str,
    status: str,
    reason: str | None = None,
    verified_at: datetime | None = None,
    verified_run_id: str | None = None,
    commit: bool = True,
) -> None:
    svc = await db.get(Service, service_id)
    if not svc:
        return
    svc.status = status
    svc.status_reason = reason
    svc.verified_at = verified_at or datetime.utcnow()
    svc.verified_run_id = verified_run_id
    if commit:
        await db.commit()
    else:
        await db.flush()
