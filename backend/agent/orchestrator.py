"""AI Agent Orchestrator — the brain of SHADOWPULSE.

Implements a tool-use loop: message → LLM → tool calls → execute → LLM → response
"""

import json
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from agent.providers import chat_completion, stream_completion
from agent.tools import TOOL_DEFINITIONS
from agent.prompts import SYSTEM_PROMPT, REPORT_PROMPT
from database import Session, Message, Scan, Finding, Target, Run, gen_id
from scanners.nmap_scanner import NmapScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.subfinder_scanner import SubfinderScanner
from scanners.api_scanner import ApiScanner
from scanners.owasp_scanner import OwaspScanner
from scanners.httpx_scanner import HttpxScanner
from scanners.testssl_scanner import TestsslScanner
from scanners.ffuf_scanner import FfufScanner
from scanners.katana_scanner import KatanaScanner
from scanners.dnsx_scanner import DnsxScanner
from scanners.nikto_scanner import NiktoScanner
from websocket.manager import ws_manager
from recongraph.ingest import ingest_scan_result
from scope import parse_scope, check_in_scope


# Scanner registry
SCANNERS = {
    "subfinder": SubfinderScanner(),
    "nmap": NmapScanner(),
    "nuclei": NucleiScanner(),
    "api": ApiScanner(),
    "owasp": OwaspScanner(),
    "httpx": HttpxScanner(),
    "testssl": TestsslScanner(),
    "ffuf": FfufScanner(),
    "katana": KatanaScanner(),
    "dnsx": DnsxScanner(),
    "nikto": NiktoScanner(),
}

# Map tool names to scanner names
TOOL_SCANNER_MAP = {
    "run_subdomain_scan": "subfinder",
    "run_port_scan": "nmap",
    "run_nuclei_scan": "nuclei",
    "run_api_scan": "api",
    "run_owasp_check": "owasp",
    "run_httpx_probe": "httpx",
    "run_tls_scan": "testssl",
    "run_directory_fuzz": "ffuf",
    "run_crawl": "katana",
    "run_dns_scan": "dnsx",
    "run_nikto_scan": "nikto",
}

MAX_TOOL_ITERATIONS = 10


def _root_domain_from_target(target: str) -> str:
    t = (target or "").strip()
    if "://" in t:
        parsed = urlparse(t)
        host = parsed.hostname or t
    else:
        host = t.split("/")[0]
        host = host.split(":")[0]
    return host.lower()


async def run_agent(
    session_id: str,
    user_message: str,
    db: AsyncSession,
) -> str:
    """Run the AI agent loop for a user message. Returns the final assistant response."""

    # Load session
    session = await db.get(Session, session_id)
    if not session:
        return "Error: Session not found."

    # Phase 0: ensure a target exists and the session is linked to it.
    if not session.target_id:
        root_domain = _root_domain_from_target(session.target)
        result = await db.execute(select(Target).where(Target.root_domain == root_domain))
        target = result.scalar_one_or_none()
        if not target:
            target = Target(
                id=gen_id(),
                name=session.name,
                root_domain=root_domain,
                scope_json={"root_domain": root_domain},
            )
            db.add(target)
            await db.commit()
            await db.refresh(target)
        session.target_id = target.id
        await db.commit()

    # Save user message
    user_msg = Message(
        id=gen_id(),
        session_id=session_id,
        role="user",
        content=user_message,
    )
    db.add(user_msg)
    await db.commit()

    # Build message history
    messages = await _build_messages(session_id, db)

    # Create a run lazily (only when we execute scanner tools).
    run_id: str | None = None

    # Agent loop: LLM → tool calls → execute → repeat
    for iteration in range(MAX_TOOL_ITERATIONS):
        response = await chat_completion(
            messages=messages,
            tools=TOOL_DEFINITIONS,
        )

        assistant_content = response.get("content", "")
        tool_calls = response.get("tool_calls", [])

        # If there's text content, stream it to the frontend
        if assistant_content:
            await ws_manager.send_ai_chunk(session_id, assistant_content, done=not tool_calls)

        # If no tool calls, we're done
        if not tool_calls:
            # Save assistant message
            assistant_msg = Message(
                id=gen_id(),
                session_id=session_id,
                role="assistant",
                content=assistant_content,
            )
            db.add(assistant_msg)
            await db.commit()

            if run_id:
                run = await db.get(Run, run_id)
                if run:
                    run.status = "completed"
                    run.completed_at = datetime.utcnow()
                    await db.commit()
            return assistant_content

        # Add assistant message with tool calls to history
        messages.append({
            "role": "assistant",
            "content": assistant_content,
            "tool_calls": [
                {
                    "id": tc["id"],
                    "type": "function",
                    "function": tc["function"],
                }
                for tc in tool_calls
            ],
        })

        # Execute each tool call
        for tc in tool_calls:
            func_name = tc["function"]["name"]
            try:
                args = json.loads(tc["function"]["arguments"])
            except json.JSONDecodeError:
                args = {}

            if not run_id and func_name != "generate_report":
                run = Run(
                    id=gen_id(),
                    target_id=session.target_id,
                    trigger="manual",
                    status="running",
                    started_at=datetime.utcnow(),
                )
                db.add(run)
                await db.commit()
                run_id = run.id

            await ws_manager.send_tool_call(session_id, func_name, args)
            await ws_manager.send_activity(
                session_id,
                f"Executing: {func_name}({json.dumps(args, default=str)[:100]}...)",
                level="info",
            )

            # Execute the tool
            tool_result, scan_id_for_msg = await _execute_tool(
                func_name, args, session_id, session.target, session.target_id, run_id, db
            )

            # Persist the tool message with full args/output for replay
            tool_msg = Message(
                id=gen_id(),
                session_id=session_id,
                role="tool",
                content=tool_result[:4000] if tool_result else "",
                tool_name=func_name,
                tool_args=args,
                tool_output=tool_result,
                scan_id=scan_id_for_msg,
            )
            db.add(tool_msg)

            # Add tool result to messages (truncated to avoid context overflow)
            if len(tool_result) > MAX_TOOL_RESULT_CHARS:
                tool_result_trimmed = tool_result[:MAX_TOOL_RESULT_CHARS] + f"\n...[truncated, {len(tool_result)} total chars]"
            else:
                tool_result_trimmed = tool_result
            messages.append({
                "role": "tool",
                "tool_call_id": tc["id"],
                "content": tool_result_trimmed,
            })

        # Save the assistant message if there was text content
        if assistant_content:
            assistant_msg = Message(
                id=gen_id(),
                session_id=session_id,
                role="assistant",
                content=assistant_content,
            )
            db.add(assistant_msg)
        await db.commit()

    if run_id:
        run = await db.get(Run, run_id)
        if run:
            run.status = "completed"
            run.completed_at = datetime.utcnow()
            await db.commit()

    return "I've reached the maximum number of tool iterations. Please review the findings so far and let me know if you'd like to continue."


MAX_HISTORY_MESSAGES = 30  # Keep last N messages to avoid context overflow
MAX_TOOL_RESULT_CHARS = 4000  # Truncate individual tool results


async def _build_messages(session_id: str, db: AsyncSession) -> list[dict]:
    """Build the message history for the LLM, with size limits."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    result = await db.execute(
        select(Message)
        .where(Message.session_id == session_id)
        .order_by(Message.created_at)
    )
    db_messages = result.scalars().all()

    # Only keep the most recent messages to avoid blowing context
    recent = db_messages[-MAX_HISTORY_MESSAGES:] if len(db_messages) > MAX_HISTORY_MESSAGES else db_messages

    for msg in recent:
        if msg.role == "user":
            messages.append({"role": "user", "content": msg.content})
        elif msg.role == "assistant":
            # Skip assistant messages that were tool-call-only — we don't persist
            # tool_call IDs so we can't reconstruct the required tool_call/tool_result
            # pairs. Including them creates an invalid message sequence for the LLM.
            if msg.tool_name:
                continue
            content = msg.content
            # Truncate very long assistant messages (e.g. previous report output)
            if len(content) > 6000:
                content = content[:6000] + "\n...[truncated]"
            messages.append({"role": "assistant", "content": content})

    return messages


async def _execute_tool(
    tool_name: str,
    args: dict,
    session_id: str,
    default_target: str,
    target_id: str | None,
    run_id: str | None,
    db: AsyncSession,
) -> tuple[str, str | None]:
    """Execute a tool and return (result_text, scan_id) for the LLM and persistence."""

    if tool_name == "generate_report":
        result = await _generate_report(session_id, db, args.get("format", "markdown"))
        return result, None

    if not target_id:
        return "Error: Target not initialized for this session.", None

    scanner_name = TOOL_SCANNER_MAP.get(tool_name)
    if not scanner_name:
        return f"Error: Unknown tool '{tool_name}'", None

    scanner = SCANNERS.get(scanner_name)
    if not scanner:
        return f"Error: Scanner '{scanner_name}' not found", None

    # Extract target from args
    target = args.get("target") or args.get("domain") or default_target

    # Scope enforcement: validate scan target is in scope
    target_obj = await db.get(Target, target_id)
    if target_obj:
        scope = parse_scope(target_obj.scope_json, target_obj.root_domain)
        scan_target_str = target.lower().strip()
        if "://" in scan_target_str:
            target_type = "url"
        elif any(c.isalpha() for c in scan_target_str):
            target_type = "domain"
        else:
            target_type = "ip"
        if not check_in_scope(scope, scan_target_str, target_type):
            return f"Error: Target '{target}' is outside the allowed scope for this engagement.", None

    # Build scanner config from remaining args
    config = {k: v for k, v in args.items() if k not in ("target", "domain")}

    # Create scan record
    scan = Scan(
        id=gen_id(),
        session_id=session_id,
        target_id=target_id,
        run_id=run_id,
        scanner=scanner_name,
        target=target,
        status="running",
        config=json.dumps(config),
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    await db.commit()

    await ws_manager.send_scan_status(session_id, scan.id, "started", scanner=scanner_name)
    await ws_manager.send_activity(session_id, f"Started {scanner_name} scan on {target}")

    # Build a streaming callback that pushes raw output to the frontend
    async def on_output(line: str):
        await ws_manager.send_tool_output(session_id, line, scan_id=scan.id)

    # Run the scanner with live output streaming
    try:
        scan_result = await scanner.run(target, config, stream_callback=on_output)
    except Exception as e:
        scan.status = "failed"
        scan.completed_at = datetime.utcnow()
        await db.commit()
        await ws_manager.send_scan_status(session_id, scan.id, "failed", error=str(e))
        return f"Error running {scanner_name}: {str(e)}", scan.id

    # Update scan record
    scan.status = scan_result.status
    scan.raw_output = scan_result.raw_output[:50000]  # Truncate if huge
    scan.completed_at = datetime.utcnow()

    # Phase 3: ingest artifacts into ReconGraph-lite tables.
    if target_id and run_id:
        try:
            await ingest_scan_result(db, target_id=target_id, run_id=run_id, scan_result=scan_result)
        except Exception as e:
            await ws_manager.send_activity(
                session_id,
                f"ReconGraph ingest failed (non-fatal): {str(e)}",
                level="warning",
            )

    # Save findings
    finding_summaries = []
    for fr in scan_result.findings:
        finding = Finding(
            id=gen_id(),
            session_id=session_id,
            scan_id=scan.id,
            target_id=target_id,
            run_id=run_id,
            severity=fr.severity,
            title=fr.title,
            description=fr.description,
            impact=fr.impact,
            evidence=fr.evidence,
            remediation=fr.remediation,
            remediation_example=fr.remediation_example,
            url=fr.url,
            cve=fr.cve,
            cvss_score=fr.cvss_score,
        )
        db.add(finding)

        # Persist finding message for replay
        finding_msg = Message(
            id=gen_id(),
            session_id=session_id,
            role="finding",
            content="",
            finding_id=finding.id,
        )
        db.add(finding_msg)

        # Notify frontend
        await ws_manager.send_finding(session_id, {
            "id": finding.id,
            "severity": fr.severity,
            "title": fr.title,
            "url": fr.url,
            "description": fr.description,
            "impact": fr.impact,
            "remediation": fr.remediation,
            "remediation_example": fr.remediation_example,
            "evidence": fr.evidence,
            "cve": fr.cve,
            "cvss_score": fr.cvss_score,
        })

        finding_summaries.append(
            f"[{fr.severity.upper()}] {fr.title}" +
            (f" — {fr.url}" if fr.url else "") +
            (f" (CVE: {fr.cve})" if fr.cve else "")
        )

    await db.commit()

    await ws_manager.send_scan_status(
        session_id, scan.id, "completed",
        findings_count=len(scan_result.findings),
    )
    await ws_manager.send_activity(
        session_id,
        f"Completed {scanner_name} scan: {len(scan_result.findings)} findings",
        level="success" if scan_result.status == "completed" else "error",
    )

    # Return structured result for the LLM
    if scan_result.findings:
        findings_text = "\n".join(finding_summaries)
        return f"Scan completed ({scanner_name} on {target}). Found {len(scan_result.findings)} results:\n\n{findings_text}", scan.id
    else:
        return f"Scan completed ({scanner_name} on {target}). No findings discovered.", scan.id


async def _generate_report(session_id: str, db: AsyncSession, fmt: str) -> str:
    """Generate a pentest report from session findings."""
    result = await db.execute(
        select(Finding)
        .where(Finding.session_id == session_id)
        .order_by(Finding.severity)
    )
    findings = result.scalars().all()

    if not findings:
        return "No findings to report. Run some scans first."

    # Build findings summary for the LLM
    severity_counts = {}
    findings_detail = []

    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        findings_detail.append(
            f"- [{f.severity.upper()}] {f.title}\n"
            f"  URL: {f.url or 'N/A'}\n"
            f"  Description: {f.description or 'N/A'}\n"
            f"  Evidence: {f.evidence[:200] if f.evidence else 'N/A'}\n"
            f"  Remediation: {f.remediation or 'N/A'}\n"
            f"  CVE: {f.cve or 'N/A'}"
        )

    summary = ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))
    detail = "\n\n".join(findings_detail)

    return (
        f"Session findings summary: {summary}\n"
        f"Total: {len(findings)} findings\n\n"
        f"Detailed findings:\n{detail}\n\n"
        f"Please generate a comprehensive report in {fmt} format."
    )
