from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, Finding

router = APIRouter()


class UpdateFindingRequest(BaseModel):
    status: str  # open, confirmed, false_positive, fixed


@router.get("/sessions/{session_id}/findings")
async def list_findings(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding)
        .where(Finding.session_id == session_id)
        .order_by(Finding.created_at.desc())
    )
    findings = result.scalars().all()
    return [
        {
            "id": f.id,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "impact": f.impact or "",
            "url": f.url,
            "cve": f.cve,
            "cvss_score": f.cvss_score,
            "status": f.status,
            "remediation": f.remediation,
            "remediation_example": f.remediation_example or "",
            "evidence": f.evidence,
            "scan_id": f.scan_id,
            "created_at": f.created_at.isoformat(),
        }
        for f in findings
    ]


@router.get("/targets/{target_id}/findings")
async def list_findings_for_target(target_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding)
        .where(Finding.target_id == target_id)
        .order_by(Finding.created_at.desc())
    )
    findings = result.scalars().all()
    return [
        {
            "id": f.id,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "impact": f.impact or "",
            "url": f.url,
            "cve": f.cve,
            "cvss_score": f.cvss_score,
            "status": f.status,
            "remediation": f.remediation,
            "remediation_example": f.remediation_example or "",
            "evidence": f.evidence,
            "scan_id": f.scan_id,
            "run_id": f.run_id,
            "asset_id": f.asset_id,
            "service_id": f.service_id,
            "created_at": f.created_at.isoformat(),
        }
        for f in findings
    ]


@router.patch("/findings/{finding_id}")
async def update_finding(
    finding_id: str,
    req: UpdateFindingRequest,
    db: AsyncSession = Depends(get_db),
):
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if req.status not in ("open", "confirmed", "false_positive", "fixed"):
        raise HTTPException(status_code=400, detail="Invalid status")

    finding.status = req.status
    await db.commit()

    return {"id": finding.id, "status": finding.status}
