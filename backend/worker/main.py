from __future__ import annotations

import asyncio
import logging
import os
import time

from sqlalchemy.ext.asyncio import AsyncSession

from database import async_session
from pipeline.run_pipeline import run_pipeline, CancelledError
from jobqueue.ops import claim_next_job, complete_job, fail_job, cancel_job
from worker.verify import verify_asset, verify_service
from retention import purge_old_data
from audit import log_event

logger = logging.getLogger(__name__)

POLL_SECONDS = float(os.getenv("WORKER_POLL_SECONDS", "2"))
RETENTION_INTERVAL_SECONDS = 3600  # run retention purge once per hour


async def _process_job(db: AsyncSession, job) -> None:
    if job.type == "run_pipeline":
        max_hosts = int((job.payload or {}).get("max_hosts", 50))
        max_http_targets = int((job.payload or {}).get("max_http_targets", 200))
        await run_pipeline(
            db,
            target_id=job.target_id,
            trigger="scheduled" if (job.payload or {}).get("scheduled") else "manual",
            run_id=job.run_id,
            max_hosts=max_hosts,
            max_http_targets=max_http_targets,
        )
        return

    if job.type == "verify_asset":
        asset_id = (job.payload or {}).get("asset_id")
        if not job.run_id:
            raise ValueError("verify_asset job missing run_id")
        if asset_id:
            await verify_asset(db, asset_id=asset_id, target_id=job.target_id, run_id=job.run_id)
        return

    if job.type == "verify_service":
        service_id = (job.payload or {}).get("service_id")
        if not job.run_id:
            raise ValueError("verify_service job missing run_id")
        if service_id:
            await verify_service(db, service_id=service_id, target_id=job.target_id, run_id=job.run_id)
        return

    raise ValueError(f"Unknown job type: {job.type}")


async def main() -> None:
    last_retention_run = 0.0
    while True:
        # Periodic retention purge
        now_ts = time.monotonic()
        if now_ts - last_retention_run >= RETENTION_INTERVAL_SECONDS:
            try:
                async with async_session() as db:
                    await purge_old_data(db)
            except Exception as e:
                logger.warning("Retention purge failed: %s", e)
            last_retention_run = now_ts

        async with async_session() as db:
            job = None
            # Claim a job in a short transaction so we don't hold locks while executing.
            async with db.begin():
                job = await claim_next_job(db)
            if not job:
                await asyncio.sleep(POLL_SECONDS)
                continue

            worker_actor = f"worker:{os.getenv('WORKER_ID', os.getpid())}"
            await log_event(
                db, target_id=job.target_id, run_id=job.run_id,
                event_type="job_claimed",
                detail={"job_id": job.id, "job_type": job.type, "attempt": job.attempts},
                actor=worker_actor,
            )
            try:
                await _process_job(db, job)
                await complete_job(db, job.id)
                await log_event(
                    db, target_id=job.target_id, run_id=job.run_id,
                    event_type="job_completed",
                    detail={"job_id": job.id, "job_type": job.type},
                    actor=worker_actor,
                )
            except CancelledError as e:
                await cancel_job(db, job.id, reason=str(e))
            except Exception as e:
                # Retry a couple times with backoff; after that mark failed.
                retry_in = 10 if (job.attempts or 0) < 3 else None
                await fail_job(db, job.id, str(e), retry_in_seconds=retry_in)
                await log_event(
                    db, target_id=job.target_id, run_id=job.run_id,
                    event_type="job_failed",
                    detail={"job_id": job.id, "job_type": job.type, "error": str(e)[:500]},
                    actor=worker_actor,
                )
        await asyncio.sleep(0)


if __name__ == "__main__":
    asyncio.run(main())
