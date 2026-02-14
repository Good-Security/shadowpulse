import asyncio
from urllib.parse import urlparse
from pydantic import BaseModel
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, Session, Message, Target, Finding, gen_id
from agent.orchestrator import run_agent

router = APIRouter()


class CreateSessionRequest(BaseModel):
    name: str
    target: str


class ChatRequest(BaseModel):
    message: str


def _root_domain_from_target(target: str) -> str:
    t = (target or "").strip()
    if "://" in t:
        parsed = urlparse(t)
        host = parsed.hostname or t
    else:
        # Accept bare hostnames/domains (optionally with a path/port).
        host = t.split("/")[0]
        host = host.split(":")[0]
    return host.lower()


@router.post("/sessions")
async def create_session(req: CreateSessionRequest, db: AsyncSession = Depends(get_db)):
    root_domain = _root_domain_from_target(req.target)

    # Phase 0: create (or reuse) a target record.
    result = await db.execute(select(Target).where(Target.root_domain == root_domain))
    target = result.scalar_one_or_none()
    if not target:
        target = Target(
            id=gen_id(),
            name=req.name,
            root_domain=root_domain,
            scope_json={"root_domain": root_domain},
        )
        db.add(target)
        await db.commit()
        await db.refresh(target)

    session = Session(
        id=gen_id(),
        name=req.name,
        target_id=target.id,
        target=req.target,
    )
    db.add(session)

    # Add system welcome message
    welcome = Message(
        id=gen_id(),
        session_id=session.id,
        role="assistant",
        content=(
            f"SHADOWPULSE initialized. Target locked: **{req.target}**\n\n"
            f"I'm ready to begin the security assessment. Before we start, "
            f"please confirm:\n"
            f"1. You have **authorization** to test this target\n"
            f"2. The scope is limited to **{req.target}** and its subdomains\n\n"
            f"Once confirmed, I'll begin with reconnaissance — mapping the attack surface "
            f"with subdomain enumeration and port scanning.\n\n"
            f"Type **\"confirmed\"** to proceed, or tell me about any specific areas you'd like to focus on."
        ),
    )
    db.add(welcome)
    await db.commit()

    return {
        "id": session.id,
        "target_id": session.target_id,
        "name": session.name,
        "target": session.target,
        "status": session.status,
        "created_at": session.created_at.isoformat(),
    }


@router.get("/sessions")
async def list_sessions(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Session).order_by(Session.created_at.desc()))
    sessions = result.scalars().all()
    return [
        {
            "id": s.id,
            "target_id": s.target_id,
            "name": s.name,
            "target": s.target,
            "status": s.status,
            "created_at": s.created_at.isoformat(),
        }
        for s in sessions
    ]


@router.get("/sessions/{session_id}")
async def get_session(session_id: str, db: AsyncSession = Depends(get_db)):
    session = await db.get(Session, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "id": session.id,
        "target_id": session.target_id,
        "name": session.name,
        "target": session.target,
        "status": session.status,
        "created_at": session.created_at.isoformat(),
    }


@router.get("/sessions/{session_id}/messages")
async def get_messages(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Message)
        .where(Message.session_id == session_id)
        .order_by(Message.created_at)
    )
    messages = result.scalars().all()

    # Collect finding_ids to hydrate in one query
    finding_ids = [m.finding_id for m in messages if m.finding_id]
    findings_map: dict[str, Finding] = {}
    if finding_ids:
        f_result = await db.execute(
            select(Finding).where(Finding.id.in_(finding_ids))
        )
        for f in f_result.scalars().all():
            findings_map[f.id] = f

    out = []
    for m in messages:
        msg = {
            "id": m.id,
            "role": m.role,
            "content": m.content,
            "tool_name": m.tool_name,
            "tool_args": m.tool_args,
            "tool_output": m.tool_output,
            "scan_id": m.scan_id,
            "finding_id": m.finding_id,
            "finding": None,
            "created_at": m.created_at.isoformat(),
        }
        if m.finding_id and m.finding_id in findings_map:
            f = findings_map[m.finding_id]
            msg["finding"] = {
                "id": f.id,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "impact": f.impact,
                "url": f.url,
                "cve": f.cve,
                "cvss_score": f.cvss_score,
                "status": f.status,
                "remediation": f.remediation,
                "remediation_example": f.remediation_example,
                "evidence": f.evidence,
                "scan_id": f.scan_id,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
        out.append(msg)
    return out


@router.post("/sessions/{session_id}/chat")
async def send_chat(
    session_id: str,
    req: ChatRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    session = await db.get(Session, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Run agent in background so the response returns immediately
    # The agent streams results via WebSocket
    background_tasks.add_task(_run_agent_task, session_id, req.message)

    return {"status": "processing", "message": "Agent is working..."}


async def _run_agent_task(session_id: str, message: str):
    """Run the agent in a background task with its own DB session."""
    from database import async_session

    async with async_session() as db:
        try:
            await run_agent(session_id, message, db)
        except Exception as e:
            from websocket.manager import ws_manager
            await ws_manager.send_activity(
                session_id,
                f"Agent error: {str(e)}",
                level="error",
            )
            await ws_manager.send_ai_chunk(
                session_id,
                f"An error occurred: {str(e)}",
                done=True,
            )
