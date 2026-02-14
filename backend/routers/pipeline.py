from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, Target, Run, Job, Asset, Service, gen_id
from jobqueue.ops import enqueue_job
from audit import log_event


router = APIRouter()


class StartPipelineRequest(BaseModel):
    max_hosts: int = 50
    max_http_targets: int = 200


class DiscardRunRequest(BaseModel):
    reason: str | None = None


@router.post("/targets/{target_id}/pipeline")
async def start_pipeline(
    target_id: str,
    req: StartPipelineRequest,
    db: AsyncSession = Depends(get_db),
):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    run = Run(
        id=gen_id(),
        target_id=target_id,
        trigger="manual",
        status="queued",
        started_at=None,
    )
    db.add(run)
    await db.commit()

    job = await enqueue_job(
        db,
        type="run_pipeline",
        target_id=target_id,
        run_id=run.id,
        payload={
            "max_hosts": req.max_hosts,
            "max_http_targets": req.max_http_targets,
            "scheduled": False,
        },
    )
    await log_event(
        db, target_id=target_id, run_id=run.id,
        event_type="pipeline_triggered",
        detail={"max_hosts": req.max_hosts, "max_http_targets": req.max_http_targets},
        actor="user",
    )
    return {"status": "queued", "run_id": run.id, "job_id": job.id}


@router.get("/runs/{run_id}")
async def get_run(run_id: str, db: AsyncSession = Depends(get_db)):
    run = await db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {
        "id": run.id,
        "target_id": run.target_id,
        "trigger": run.trigger,
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }

@router.get("/jobs/{job_id}")
async def get_job(job_id: str, db: AsyncSession = Depends(get_db)):
    job = await db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "id": job.id,
        "type": job.type,
        "status": job.status,
        "target_id": job.target_id,
        "run_id": job.run_id,
        "payload": job.payload,
        "available_at": job.available_at.isoformat() if job.available_at else None,
        "locked_at": job.locked_at.isoformat() if job.locked_at else None,
        "locked_by": job.locked_by,
        "attempts": job.attempts,
        "last_error": job.last_error,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "updated_at": job.updated_at.isoformat() if job.updated_at else None,
    }


@router.post("/runs/{run_id}/discard")
async def discard_run(run_id: str, req: DiscardRunRequest | None = None, db: AsyncSession = Depends(get_db)):
    run = await db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    reason = (req.reason if req else None) or "discarded_by_user"
    now = datetime.utcnow()

    # Mark run as discarded.
    run.status = "discarded"
    run.completed_at = now
    await db.commit()

    # Cancel any queued/running jobs for the run. Worker completion/failure won't overwrite
    # because jobqueue ops only transition from "running".
    await db.execute(
        update(Job)
        .where(Job.run_id == run_id, Job.status.in_(["queued", "running"]))
        .values(status="cancelled", last_error=reason[:2000], locked_at=None, locked_by=None, updated_at=now)
    )
    await db.commit()

    return {"status": "discarded", "run_id": run_id}


@router.post("/targets/{target_id}/runs/{run_id}/verify")
async def verify_run(target_id: str, run_id: str, db: AsyncSession = Depends(get_db)):
    run = await db.get(Run, run_id)
    if not run or run.target_id != target_id:
        raise HTTPException(status_code=404, detail="Run not found for target")

    stale_reason = f"not_seen_in_run:{run_id}"

    assets = (
        await db.execute(
            select(Asset).where(
                Asset.target_id == target_id,
                Asset.status == "stale",
                Asset.status_reason == stale_reason,
                Asset.type.in_(["subdomain", "url"]),
            )
        )
    ).scalars().all()

    services = (
        await db.execute(
            select(Service).where(
                Service.target_id == target_id,
                Service.status == "stale",
                Service.status_reason == stale_reason,
            )
        )
    ).scalars().all()

    jobs = []
    now = datetime.utcnow()
    for a in assets:
        jobs.append(
            await enqueue_job(
                db,
                type="verify_asset",
                target_id=target_id,
                run_id=run_id,
                payload={"asset_id": a.id},
                available_at=now,
                commit=False,
            )
        )
    for s in services:
        jobs.append(
            await enqueue_job(
                db,
                type="verify_service",
                target_id=target_id,
                run_id=run_id,
                payload={"service_id": s.id},
                available_at=now,
                commit=False,
            )
        )
    await db.commit()

    return {
        "status": "queued",
        "target_id": target_id,
        "run_id": run_id,
        "verify_jobs_enqueued": len(jobs),
        "job_ids": [j.id for j in jobs],
    }
