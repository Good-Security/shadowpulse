import uuid
from datetime import datetime

from sqlalchemy import Column, String, Text, Float, DateTime, ForeignKey, JSON, Index, UniqueConstraint, Integer, Boolean
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base, relationship

from config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()


def gen_id() -> str:
    return str(uuid.uuid4())


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String, nullable=False)
    # Phase 0: sessions are a chat wrapper around a target.
    target_id = Column(String, ForeignKey("targets.id"), nullable=True)
    target = Column(String, nullable=False)
    status = Column(String, default="active")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    target_rel = relationship("Target", back_populates="sessions")
    messages = relationship("Message", back_populates="session", order_by="Message.created_at")
    scans = relationship("Scan", back_populates="session")
    findings = relationship("Finding", back_populates="session")

    __table_args__ = (
        Index("ix_sessions_created_at", "created_at"),
        Index("ix_sessions_target_id_created_at", "target_id", "created_at"),
    )


class Target(Base):
    __tablename__ = "targets"

    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String, nullable=False)
    root_domain = Column(String, nullable=False)
    scope_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    sessions = relationship("Session", back_populates="target_rel")
    runs = relationship("Run", back_populates="target_rel")
    scans = relationship("Scan", back_populates="target_rel")
    findings = relationship("Finding", back_populates="target_rel")
    assets = relationship("Asset", back_populates="target_rel")
    services = relationship("Service", back_populates="target_rel")
    edges = relationship("Edge", back_populates="target_rel")

    __table_args__ = (
        UniqueConstraint("root_domain", name="uq_targets_root_domain"),
        Index("ix_targets_created_at", "created_at"),
    )


class Run(Base):
    __tablename__ = "runs"

    id = Column(String, primary_key=True, default=gen_id)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    trigger = Column(String, nullable=False)  # manual, scheduled
    status = Column(String, nullable=False, default="running")  # running, completed, failed
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    target_rel = relationship("Target", back_populates="runs")
    scans = relationship("Scan", back_populates="run_rel")
    findings = relationship("Finding", back_populates="run_rel")

    __table_args__ = (
        Index("ix_runs_target_id_created_at", "target_id", "created_at"),
    )


class Schedule(Base):
    __tablename__ = "schedules"

    id = Column(String, primary_key=True, default=gen_id)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    interval_seconds = Column(Integer, nullable=False, default=86400)  # default daily
    next_run_at = Column(DateTime, nullable=True)
    pipeline_config = Column(JSON, nullable=True)  # max_hosts, max_http_targets, etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    target_rel = relationship("Target")

    __table_args__ = (
        Index("ix_schedules_target_id_enabled", "target_id", "enabled"),
        Index("ix_schedules_next_run_at", "next_run_at"),
    )


class Job(Base):
    __tablename__ = "jobs"

    id = Column(String, primary_key=True, default=gen_id)
    type = Column(String, nullable=False)  # run_pipeline, verify_asset, verify_service
    status = Column(String, nullable=False, default="queued")  # queued, running, completed, failed
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    payload = Column(JSON, nullable=True)
    available_at = Column(DateTime, nullable=True)
    locked_at = Column(DateTime, nullable=True)
    locked_by = Column(String, nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    target_rel = relationship("Target")
    run_rel = relationship("Run")

    __table_args__ = (
        Index("ix_jobs_status_available_at", "status", "available_at"),
        Index("ix_jobs_target_id_status", "target_id", "status"),
        Index("ix_jobs_run_id", "run_id"),
    )

class Message(Base):
    __tablename__ = "messages"

    id = Column(String, primary_key=True, default=gen_id)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=False)
    role = Column(String, nullable=False)  # user, assistant, system, tool, finding
    content = Column(Text, nullable=False)
    tool_name = Column(String, nullable=True)
    tool_result = Column(Text, nullable=True)
    tool_args = Column(JSON, nullable=True)
    tool_output = Column(Text, nullable=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("Session", back_populates="messages")
    __table_args__ = (
        Index("ix_messages_session_id_created_at", "session_id", "created_at"),
    )


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=gen_id)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=True)
    target_id = Column(String, ForeignKey("targets.id"), nullable=True)
    run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    scanner = Column(String, nullable=False)
    target = Column(String, nullable=False)
    status = Column(String, default="pending")
    config = Column(Text, nullable=True)
    raw_output = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("Session", back_populates="scans")
    target_rel = relationship("Target", back_populates="scans")
    run_rel = relationship("Run", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")
    __table_args__ = (
        Index("ix_scans_session_id_created_at", "session_id", "created_at"),
        Index("ix_scans_target_id_created_at", "target_id", "created_at"),
        Index("ix_scans_run_id_created_at", "run_id", "created_at"),
    )


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String, primary_key=True, default=gen_id)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    type = Column(String, nullable=False)  # subdomain, host, ip, url
    value = Column(Text, nullable=False)
    normalized = Column(Text, nullable=False)

    first_seen_run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    last_seen_run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    first_seen_at = Column(DateTime, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)

    status = Column(String, nullable=False, default="active")  # active, stale, closed, unresolved
    status_reason = Column(Text, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    verified_run_id = Column(String, ForeignKey("runs.id"), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    target_rel = relationship("Target", back_populates="assets")
    services = relationship("Service", back_populates="asset_rel")

    __table_args__ = (
        UniqueConstraint("target_id", "type", "normalized", name="uq_assets_target_type_normalized"),
        Index("ix_assets_target_id_type_normalized", "target_id", "type", "normalized"),
        Index("ix_assets_target_id_last_seen_at", "target_id", "last_seen_at"),
        Index("ix_assets_target_id_verified_run_id", "target_id", "verified_run_id"),
    )


class Service(Base):
    __tablename__ = "services"

    id = Column(String, primary_key=True, default=gen_id)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    asset_id = Column(String, ForeignKey("assets.id"), nullable=False)  # host/ip asset
    port = Column(Integer, nullable=False)
    proto = Column(String, nullable=False)  # tcp/udp
    name = Column(String, nullable=True)
    product = Column(String, nullable=True)
    version = Column(String, nullable=True)

    first_seen_run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    last_seen_run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    first_seen_at = Column(DateTime, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)

    status = Column(String, nullable=False, default="active")  # active, stale, closed, unresolved
    status_reason = Column(Text, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    verified_run_id = Column(String, ForeignKey("runs.id"), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    target_rel = relationship("Target", back_populates="services")
    asset_rel = relationship("Asset", back_populates="services")

    __table_args__ = (
        UniqueConstraint("target_id", "asset_id", "port", "proto", name="uq_services_target_asset_port_proto"),
        Index("ix_services_target_asset_port_proto", "target_id", "asset_id", "port", "proto"),
        Index("ix_services_target_id_last_seen_at", "target_id", "last_seen_at"),
        Index("ix_services_target_id_verified_run_id", "target_id", "verified_run_id"),
    )


class Edge(Base):
    __tablename__ = "edges"

    id = Column(String, primary_key=True, default=gen_id)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    from_asset_id = Column(String, ForeignKey("assets.id"), nullable=False)
    to_asset_id = Column(String, ForeignKey("assets.id"), nullable=False)
    rel_type = Column(String, nullable=False)  # resolves_to, serves, redirects_to, etc

    first_seen_run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    last_seen_run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    first_seen_at = Column(DateTime, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    target_rel = relationship("Target", back_populates="edges")

    __table_args__ = (
        Index("ix_edges_target_rel", "target_id", "rel_type"),
        Index("ix_edges_target_from_to", "target_id", "from_asset_id", "to_asset_id"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=gen_id)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    target_id = Column(String, ForeignKey("targets.id"), nullable=True)
    run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    asset_id = Column(String, ForeignKey("assets.id"), nullable=True)
    service_id = Column(String, ForeignKey("services.id"), nullable=True)
    severity = Column(String, nullable=False)  # critical, high, medium, low, info
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    remediation_example = Column(Text, nullable=True)
    url = Column(String, nullable=True)
    cve = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    status = Column(String, default="open")
    created_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("Session", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
    target_rel = relationship("Target", back_populates="findings")
    run_rel = relationship("Run", back_populates="findings")
    __table_args__ = (
        Index("ix_findings_session_id_created_at", "session_id", "created_at"),
        Index("ix_findings_target_id_created_at", "target_id", "created_at"),
        Index("ix_findings_run_id_created_at", "run_id", "created_at"),
    )

class RunEvent(Base):
    __tablename__ = "run_events"

    id = Column(String, primary_key=True, default=gen_id)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    run_id = Column(String, ForeignKey("runs.id"), nullable=True)
    event_type = Column(String, nullable=False)
    detail = Column(JSON, nullable=True)
    actor = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_run_events_target_id_created_at", "target_id", "created_at"),
        Index("ix_run_events_run_id_created_at", "run_id", "created_at"),
        Index("ix_run_events_event_type", "event_type"),
    )


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session
