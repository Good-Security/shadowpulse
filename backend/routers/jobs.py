from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, Run, Job


router = APIRouter()


@router.get("/runs/{run_id}/jobs")
async def list_jobs_for_run(
    run_id: str,
    status: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    run = await db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    q = select(Job).where(Job.run_id == run_id)
    if status:
        q = q.where(Job.status == status)
    q = q.order_by(Job.created_at.desc())

    res = await db.execute(q)
    jobs = res.scalars().all()
    return [
        {
            "id": j.id,
            "type": j.type,
            "status": j.status,
            "target_id": j.target_id,
            "run_id": j.run_id,
            "payload": j.payload,
            "available_at": j.available_at.isoformat() if j.available_at else None,
            "locked_at": j.locked_at.isoformat() if j.locked_at else None,
            "locked_by": j.locked_by,
            "attempts": j.attempts,
            "last_error": j.last_error,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "updated_at": j.updated_at.isoformat() if j.updated_at else None,
        }
        for j in jobs
    ]

