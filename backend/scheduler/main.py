from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta

from sqlalchemy import select, or_

from database import Schedule, Run, async_session, gen_id
from jobqueue.ops import enqueue_job


POLL_SECONDS = float(os.getenv("SCHEDULER_POLL_SECONDS", "5"))


async def _tick_once() -> dict | None:
    """Find one due schedule, create a run, enqueue a run_pipeline job, advance next_run_at."""
    now = datetime.utcnow()

    async with async_session() as db:
        async with db.begin():
            res = await db.execute(
                select(Schedule)
                .where(
                    Schedule.enabled.is_(True),
                    or_(Schedule.next_run_at.is_(None), Schedule.next_run_at <= now),
                )
                .order_by(Schedule.next_run_at.asc().nullsfirst(), Schedule.created_at.asc())
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            sched = res.scalar_one_or_none()
            if not sched:
                return None

            run = Run(
                id=gen_id(),
                target_id=sched.target_id,
                trigger="scheduled",
                status="queued",
                started_at=None,
            )
            db.add(run)
            await db.flush()

            payload = dict(sched.pipeline_config or {})
            payload["scheduled"] = True

            job = await enqueue_job(
                db,
                type="run_pipeline",
                target_id=sched.target_id,
                run_id=run.id,
                payload=payload,
                available_at=now,
                commit=False,
            )

            interval = int(sched.interval_seconds or 86400)
            sched.next_run_at = now + timedelta(seconds=interval)

            return {"schedule_id": sched.id, "run_id": run.id, "job_id": job.id}


async def main() -> None:
    while True:
        try:
            got = await _tick_once()
            if not got:
                await asyncio.sleep(POLL_SECONDS)
            else:
                await asyncio.sleep(0)
        except Exception:
            # Don't crash the scheduler loop on transient errors.
            await asyncio.sleep(POLL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
