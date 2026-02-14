from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, Target, Run, Asset, Service


router = APIRouter()


@router.get("/targets/{target_id}/changes")
async def get_changes(
    target_id: str,
    run_id: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    rid = run_id
    if not rid:
        res = await db.execute(
            select(Run)
            .where(Run.target_id == target_id, Run.status == "completed")
            .order_by(Run.created_at.desc())
            .limit(1)
        )
        latest = res.scalar_one_or_none()
        if not latest:
            raise HTTPException(status_code=404, detail="No completed runs for target")
        rid = latest.id

    run = await db.get(Run, rid)
    if not run or run.target_id != target_id:
        raise HTTPException(status_code=404, detail="Run not found for target")

    stale_reason = f"not_seen_in_run:{rid}"

    new_assets = (await db.execute(
        select(Asset).where(Asset.target_id == target_id, Asset.first_seen_run_id == rid)
    )).scalars().all()
    new_services = (await db.execute(
        select(Service).where(Service.target_id == target_id, Service.first_seen_run_id == rid)
    )).scalars().all()

    pending_assets = (await db.execute(
        select(Asset).where(
            Asset.target_id == target_id,
            Asset.status == "stale",
            Asset.status_reason == stale_reason,
        )
    )).scalars().all()
    pending_services = (await db.execute(
        select(Service).where(
            Service.target_id == target_id,
            Service.status == "stale",
            Service.status_reason == stale_reason,
        )
    )).scalars().all()

    closed_assets = (await db.execute(
        select(Asset).where(
            Asset.target_id == target_id,
            Asset.status == "closed",
            Asset.verified_run_id == rid,
        )
    )).scalars().all()
    unresolved_assets = (await db.execute(
        select(Asset).where(
            Asset.target_id == target_id,
            Asset.status == "unresolved",
            Asset.verified_run_id == rid,
        )
    )).scalars().all()

    closed_services = (await db.execute(
        select(Service).where(
            Service.target_id == target_id,
            Service.status == "closed",
            Service.verified_run_id == rid,
        )
    )).scalars().all()
    unresolved_services = (await db.execute(
        select(Service).where(
            Service.target_id == target_id,
            Service.status == "unresolved",
            Service.verified_run_id == rid,
        )
    )).scalars().all()

    def _asset(a: Asset) -> dict:
        return {
            "id": a.id,
            "type": a.type,
            "value": a.value,
            "normalized": a.normalized,
            "status": a.status,
            "status_reason": a.status_reason,
            "first_seen_run_id": a.first_seen_run_id,
            "last_seen_run_id": a.last_seen_run_id,
            "verified_run_id": a.verified_run_id,
            "first_seen_at": a.first_seen_at.isoformat() if a.first_seen_at else None,
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
            "verified_at": a.verified_at.isoformat() if a.verified_at else None,
        }

    def _service(s: Service) -> dict:
        return {
            "id": s.id,
            "asset_id": s.asset_id,
            "port": s.port,
            "proto": s.proto,
            "name": s.name,
            "product": s.product,
            "version": s.version,
            "status": s.status,
            "status_reason": s.status_reason,
            "first_seen_run_id": s.first_seen_run_id,
            "last_seen_run_id": s.last_seen_run_id,
            "verified_run_id": s.verified_run_id,
            "first_seen_at": s.first_seen_at.isoformat() if s.first_seen_at else None,
            "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
            "verified_at": s.verified_at.isoformat() if s.verified_at else None,
        }

    return {
        "target_id": target_id,
        "run_id": rid,
        "new": {
            "assets": [_asset(a) for a in new_assets],
            "services": [_service(s) for s in new_services],
        },
        "pending_verification": {
            "assets": [_asset(a) for a in pending_assets],
            "services": [_service(s) for s in pending_services],
        },
        "confirmed": {
            "closed": {
                "assets": [_asset(a) for a in closed_assets],
                "services": [_service(s) for s in closed_services],
            },
            "unresolved": {
                "assets": [_asset(a) for a in unresolved_assets],
                "services": [_service(s) for s in unresolved_services],
            },
        },
        "counts": {
            "new_assets": len(new_assets),
            "new_services": len(new_services),
            "pending_assets": len(pending_assets),
            "pending_services": len(pending_services),
            "confirmed_closed_assets": len(closed_assets),
            "confirmed_closed_services": len(closed_services),
            "confirmed_unresolved_assets": len(unresolved_assets),
            "confirmed_unresolved_services": len(unresolved_services),
        },
    }

