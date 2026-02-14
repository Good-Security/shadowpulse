import logging
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import update

from config import settings
from database import async_session, Job, Run, Scan
from routers import chat, scans, findings
from routers import targets
from routers import recongraph
from routers import pipeline
from routers import schedules
from routers import changes
from routers import jobs
from websocket.manager import ws_manager

logger = logging.getLogger("shadowpulse")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Database schema is managed by Alembic migrations (run at container start).
    # Recover orphaned runs/jobs left in running state from a previous crash.
    async with async_session() as db:
        now = datetime.utcnow()
        result_jobs = await db.execute(
            update(Job)
            .where(Job.status == "running")
            .values(
                status="failed",
                last_error="Recovered: server restarted while job was running",
                updated_at=now,
            )
        )
        result_runs = await db.execute(
            update(Run)
            .where(Run.status == "running")
            .values(status="failed", completed_at=now)
        )
        result_scans = await db.execute(
            update(Scan)
            .where(Scan.status == "running")
            .values(status="failed", completed_at=now)
        )
        await db.commit()
        recovered = result_jobs.rowcount + result_runs.rowcount + result_scans.rowcount
        if recovered:
            logger.warning(
                "Startup recovery: marked %d jobs, %d runs, %d scans as failed",
                result_jobs.rowcount, result_runs.rowcount, result_scans.rowcount,
            )
    yield


app = FastAPI(
    title="SHADOWPULSE",
    description="AI-Native Security Pentesting Command Center",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REST routes
app.include_router(chat.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(findings.router, prefix="/api")
app.include_router(targets.router, prefix="/api")
app.include_router(recongraph.router, prefix="/api")
app.include_router(pipeline.router, prefix="/api")
app.include_router(schedules.router, prefix="/api")
app.include_router(changes.router, prefix="/api")
app.include_router(jobs.router, prefix="/api")


@app.get("/api/health")
async def health():
    return {"status": "ok", "app": "shadowpulse"}


@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    await ws_manager.connect(session_id, websocket)
    try:
        while True:
            # Keep connection alive, handle client pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(session_id, websocket)
