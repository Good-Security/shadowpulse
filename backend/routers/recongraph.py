from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, Target, Asset, Service, Edge

router = APIRouter()


@router.get("/targets/{target_id}/assets")
async def list_assets(target_id: str, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    result = await db.execute(
        select(Asset)
        .where(Asset.target_id == target_id)
        .order_by(Asset.last_seen_at.desc().nullslast(), Asset.created_at.desc())
    )
    assets = result.scalars().all()
    return [
        {
            "id": a.id,
            "type": a.type,
            "value": a.value,
            "normalized": a.normalized,
            "status": a.status,
            "first_seen_at": a.first_seen_at.isoformat() if a.first_seen_at else None,
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
            "verified_at": a.verified_at.isoformat() if a.verified_at else None,
        }
        for a in assets
    ]


@router.get("/targets/{target_id}/services")
async def list_services(target_id: str, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    result = await db.execute(
        select(Service)
        .where(Service.target_id == target_id)
        .order_by(Service.last_seen_at.desc().nullslast(), Service.created_at.desc())
    )
    services = result.scalars().all()
    return [
        {
            "id": s.id,
            "asset_id": s.asset_id,
            "port": s.port,
            "proto": s.proto,
            "name": s.name,
            "product": s.product,
            "version": s.version,
            "status": s.status,
            "first_seen_at": s.first_seen_at.isoformat() if s.first_seen_at else None,
            "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
        }
        for s in services
    ]


@router.get("/targets/{target_id}/edges")
async def list_edges(target_id: str, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    result = await db.execute(
        select(Edge)
        .where(Edge.target_id == target_id)
        .order_by(Edge.last_seen_at.desc().nullslast(), Edge.created_at.desc())
    )
    edges = result.scalars().all()
    return [
        {
            "id": e.id,
            "from_asset_id": e.from_asset_id,
            "to_asset_id": e.to_asset_id,
            "rel_type": e.rel_type,
            "first_seen_at": e.first_seen_at.isoformat() if e.first_seen_at else None,
            "last_seen_at": e.last_seen_at.isoformat() if e.last_seen_at else None,
        }
        for e in edges
    ]

