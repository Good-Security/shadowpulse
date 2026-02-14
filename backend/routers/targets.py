from pydantic import BaseModel, ValidationError
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, Target, Run, RunEvent, gen_id
from scope import ScopeConfig

router = APIRouter()


class CreateTargetRequest(BaseModel):
    name: str
    root_domain: str
    scope_json: dict | None = None


@router.post("/targets")
async def create_target(req: CreateTargetRequest, db: AsyncSession = Depends(get_db)):
    root = req.root_domain.strip().lower()
    existing = await db.execute(select(Target).where(Target.root_domain == root))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Target with this root_domain already exists")

    # Validate scope_json structure if provided
    scope_data = req.scope_json or {"root_domain": root}
    scope_data.setdefault("root_domain", root)
    try:
        ScopeConfig(**scope_data)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=f"Invalid scope_json: {e}")

    target = Target(
        id=gen_id(),
        name=req.name,
        root_domain=root,
        scope_json=scope_data,
    )
    db.add(target)
    await db.commit()

    return {
        "id": target.id,
        "name": target.name,
        "root_domain": target.root_domain,
        "scope_json": target.scope_json,
        "created_at": target.created_at.isoformat() if target.created_at else None,
    }


@router.get("/targets")
async def list_targets(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    targets = result.scalars().all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "root_domain": t.root_domain,
            "scope_json": t.scope_json,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "updated_at": t.updated_at.isoformat() if t.updated_at else None,
        }
        for t in targets
    ]


@router.get("/targets/{target_id}")
async def get_target(target_id: str, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return {
        "id": target.id,
        "name": target.name,
        "root_domain": target.root_domain,
        "scope_json": target.scope_json,
        "created_at": target.created_at.isoformat() if target.created_at else None,
        "updated_at": target.updated_at.isoformat() if target.updated_at else None,
    }


@router.get("/targets/{target_id}/runs")
async def list_runs(target_id: str, db: AsyncSession = Depends(get_db)):
    # Verify target exists
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    result = await db.execute(
        select(Run).where(Run.target_id == target_id).order_by(Run.created_at.desc())
    )
    runs = result.scalars().all()
    return [
        {
            "id": r.id,
            "target_id": r.target_id,
            "trigger": r.trigger,
            "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in runs
    ]


@router.get("/targets/{target_id}/events")
async def list_events(target_id: str, limit: int = 100, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    result = await db.execute(
        select(RunEvent)
        .where(RunEvent.target_id == target_id)
        .order_by(RunEvent.created_at.desc())
        .limit(limit)
    )
    events = result.scalars().all()
    return [
        {
            "id": e.id,
            "target_id": e.target_id,
            "run_id": e.run_id,
            "event_type": e.event_type,
            "detail": e.detail,
            "actor": e.actor,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in events
    ]

