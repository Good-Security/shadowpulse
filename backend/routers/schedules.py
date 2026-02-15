from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, Target, Schedule, gen_id


router = APIRouter()


class CreateScheduleRequest(BaseModel):
    enabled: bool = True
    interval_seconds: int = 86400
    pipeline_config: dict | None = None
    start_immediately: bool = True


class UpdateScheduleRequest(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = None
    pipeline_config: dict | None = None
    next_run_at: datetime | None = None


@router.get("/targets/{target_id}/schedules")
async def list_schedules(target_id: str, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    res = await db.execute(select(Schedule).where(Schedule.target_id == target_id).order_by(Schedule.created_at.desc()))
    schedules = res.scalars().all()
    return [
        {
            "id": s.id,
            "target_id": s.target_id,
            "enabled": s.enabled,
            "interval_seconds": s.interval_seconds,
            "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
            "pipeline_config": s.pipeline_config,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        }
        for s in schedules
    ]


@router.post("/targets/{target_id}/schedules")
async def create_schedule(target_id: str, req: CreateScheduleRequest, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if req.interval_seconds < 60:
        raise HTTPException(status_code=400, detail="interval_seconds must be >= 60")

    now = datetime.utcnow()
    next_run_at = now if req.start_immediately else (now + timedelta(seconds=req.interval_seconds))

    schedule = Schedule(
        id=gen_id(),
        target_id=target_id,
        enabled=req.enabled,
        interval_seconds=req.interval_seconds,
        next_run_at=next_run_at,
        pipeline_config=req.pipeline_config or {},
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)

    return {
        "id": schedule.id,
        "target_id": schedule.target_id,
        "enabled": schedule.enabled,
        "interval_seconds": schedule.interval_seconds,
        "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        "pipeline_config": schedule.pipeline_config,
        "created_at": schedule.created_at.isoformat() if schedule.created_at else None,
        "updated_at": schedule.updated_at.isoformat() if schedule.updated_at else None,
    }


@router.patch("/schedules/{schedule_id}")
async def update_schedule(schedule_id: str, req: UpdateScheduleRequest, db: AsyncSession = Depends(get_db)):
    schedule = await db.get(Schedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if req.enabled is not None:
        schedule.enabled = req.enabled
    if req.interval_seconds is not None:
        if req.interval_seconds < 60:
            raise HTTPException(status_code=400, detail="interval_seconds must be >= 60")
        schedule.interval_seconds = req.interval_seconds
    if req.pipeline_config is not None:
        schedule.pipeline_config = req.pipeline_config
    if req.next_run_at is not None:
        schedule.next_run_at = req.next_run_at

    await db.commit()
    await db.refresh(schedule)
    return {
        "id": schedule.id,
        "target_id": schedule.target_id,
        "enabled": schedule.enabled,
        "interval_seconds": schedule.interval_seconds,
        "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        "pipeline_config": schedule.pipeline_config,
        "created_at": schedule.created_at.isoformat() if schedule.created_at else None,
        "updated_at": schedule.updated_at.isoformat() if schedule.updated_at else None,
    }


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str, db: AsyncSession = Depends(get_db)):
    schedule = await db.get(Schedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    await db.delete(schedule)
    await db.commit()
    return {"status": "deleted", "id": schedule_id}

