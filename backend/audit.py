"""Audit trail helper — log events to the run_events table."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from database import RunEvent, gen_id


async def log_event(
    db: AsyncSession,
    *,
    target_id: str,
    run_id: str | None = None,
    event_type: str,
    detail: dict | None = None,
    actor: str | None = None,
    commit: bool = True,
) -> RunEvent:
    event = RunEvent(
        id=gen_id(),
        target_id=target_id,
        run_id=run_id,
        event_type=event_type,
        detail=detail,
        actor=actor,
        created_at=datetime.utcnow(),
    )
    db.add(event)
    if commit:
        await db.commit()
    else:
        await db.flush()
    return event
