"""Retention policy — purge old raw scan outputs and completed runs."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy import update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from database import Scan, Run, RunEvent, gen_id
from config import settings

logger = logging.getLogger(__name__)


async def purge_old_data(db: AsyncSession) -> dict:
    """Remove stale data according to retention settings.

    - Null out raw_output on scans older than RETENTION_RAW_OUTPUT_DAYS.
    - Delete completed runs (and their scans) older than RETENTION_COMPLETED_RUNS_DAYS.
      Findings are preserved (they reference target_id independently).

    Returns a summary dict of what was purged.
    """
    now = datetime.utcnow()
    summary = {"raw_output_cleared": 0, "runs_deleted": 0, "scans_deleted": 0}

    # 1. Clear raw_output on old scans
    raw_cutoff = now - timedelta(days=settings.RETENTION_RAW_OUTPUT_DAYS)
    result = await db.execute(
        update(Scan)
        .where(
            Scan.completed_at.is_not(None),
            Scan.completed_at < raw_cutoff,
            Scan.raw_output.is_not(None),
        )
        .values(raw_output=None)
    )
    summary["raw_output_cleared"] = result.rowcount or 0

    # 2. Delete old completed runs and their scans
    run_cutoff = now - timedelta(days=settings.RETENTION_COMPLETED_RUNS_DAYS)
    # First delete scans belonging to old completed runs
    old_runs_result = await db.execute(
        delete(Scan)
        .where(
            Scan.run_id.is_not(None),
            Scan.completed_at.is_not(None),
            Scan.completed_at < run_cutoff,
        )
        .returning(Scan.id)
    )
    deleted_scan_ids = old_runs_result.fetchall()
    summary["scans_deleted"] = len(deleted_scan_ids)

    # Delete the runs themselves
    run_del_result = await db.execute(
        delete(Run)
        .where(
            Run.status.in_(["completed", "failed", "discarded"]),
            Run.completed_at.is_not(None),
            Run.completed_at < run_cutoff,
        )
        .returning(Run.id)
    )
    deleted_run_ids = run_del_result.fetchall()
    summary["runs_deleted"] = len(deleted_run_ids)

    await db.commit()

    if any(v > 0 for v in summary.values()):
        logger.info("Retention purge completed: %s", summary)

    return summary
