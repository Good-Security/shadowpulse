from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, Scan

router = APIRouter()


@router.get("/sessions/{session_id}/scans")
async def list_scans(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan)
        .where(Scan.session_id == session_id)
        .order_by(Scan.created_at.desc())
    )
    scans = result.scalars().all()
    return [
        {
            "id": s.id,
            "scanner": s.scanner,
            "target": s.target,
            "status": s.status,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "created_at": s.created_at.isoformat(),
        }
        for s in scans
    ]


@router.get("/targets/{target_id}/scans")
async def list_scans_for_target(target_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan)
        .where(Scan.target_id == target_id)
        .order_by(Scan.created_at.desc())
    )
    scans = result.scalars().all()
    return [
        {
            "id": s.id,
            "scanner": s.scanner,
            "target": s.target,
            "status": s.status,
            "run_id": s.run_id,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "created_at": s.created_at.isoformat(),
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": scan.id,
        "scanner": scan.scanner,
        "target": scan.target,
        "status": scan.status,
        "config": scan.config,
        "raw_output": scan.raw_output,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }
