from __future__ import annotations

import os
from datetime import datetime, timedelta

from sqlalchemy import select, update, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from database import Job, Target, gen_id
from config import settings


def _worker_id() -> str:
    return os.getenv("WORKER_ID") or f"worker-{os.getpid()}"


async def enqueue_job(
    db: AsyncSession,
    *,
    type: str,
    target_id: str,
    run_id: str | None = None,
    payload: dict | None = None,
    available_at: datetime | None = None,
    commit: bool = True,
) -> Job:
    job = Job(
        id=gen_id(),
        type=type,
        status="queued",
        target_id=target_id,
        run_id=run_id,
        payload=payload or {},
        available_at=available_at or datetime.utcnow(),
    )
    db.add(job)
    if commit:
        await db.commit()
    else:
        await db.flush()
    return job


async def _count_running_jobs(db: AsyncSession, target_id: str | None = None) -> int:
    """Count currently running jobs, optionally filtered by target."""
    q = select(func.count()).select_from(Job).where(Job.status == "running")
    if target_id:
        q = q.where(Job.target_id == target_id)
    result = await db.execute(q)
    return result.scalar() or 0


async def _per_target_limit(db: AsyncSession, target_id: str) -> int:
    """Get the per-target concurrency limit (scope override or global default)."""
    target = await db.get(Target, target_id)
    if target and target.scope_json and "max_concurrent_jobs" in target.scope_json:
        return int(target.scope_json["max_concurrent_jobs"])
    return settings.MAX_CONCURRENT_JOBS_PER_TARGET


async def claim_next_job(db: AsyncSession) -> Job | None:
    """Claim one queued job using SELECT .. FOR UPDATE SKIP LOCKED.

    Enforces global and per-target concurrency limits before claiming.
    Must be called within a transaction.
    """
    # Global concurrency check
    running_global = await _count_running_jobs(db)
    if running_global >= settings.MAX_CONCURRENT_JOBS_GLOBAL:
        return None

    now = datetime.utcnow()
    result = await db.execute(
        select(Job)
        .where(
            Job.status == "queued",
            or_(Job.available_at.is_(None), Job.available_at <= now),
        )
        .order_by(Job.available_at.asc(), Job.created_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    job = result.scalar_one_or_none()
    if not job:
        return None

    # Per-target concurrency check
    per_target_limit = await _per_target_limit(db, job.target_id)
    running_for_target = await _count_running_jobs(db, target_id=job.target_id)
    if running_for_target >= per_target_limit:
        return None

    job.status = "running"
    job.locked_at = now
    job.locked_by = _worker_id()
    job.attempts = (job.attempts or 0) + 1
    await db.flush()
    return job


async def complete_job(db: AsyncSession, job_id: str) -> None:
    await db.execute(
        update(Job)
        # Don't overwrite terminal states like "cancelled".
        .where(Job.id == job_id, Job.status == "running")
        .values(status="completed", updated_at=datetime.utcnow())
    )
    await db.commit()


async def fail_job(db: AsyncSession, job_id: str, error: str, *, retry_in_seconds: int | None = None) -> None:
    vals = {
        "status": "failed" if retry_in_seconds is None else "queued",
        "last_error": error[:2000],
        "updated_at": datetime.utcnow(),
    }
    if retry_in_seconds is not None:
        vals["available_at"] = datetime.utcnow() + timedelta(seconds=retry_in_seconds)
        vals["locked_at"] = None
        vals["locked_by"] = None

    # Don't overwrite terminal states like "cancelled".
    await db.execute(update(Job).where(Job.id == job_id, Job.status == "running").values(**vals))
    await db.commit()


async def cancel_job(db: AsyncSession, job_id: str, reason: str | None = None) -> None:
    vals = {
        "status": "cancelled",
        "updated_at": datetime.utcnow(),
        "locked_at": None,
        "locked_by": None,
    }
    if reason:
        vals["last_error"] = reason[:2000]

    await db.execute(update(Job).where(Job.id == job_id).values(**vals))
    await db.commit()
