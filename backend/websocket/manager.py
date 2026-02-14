import json
from typing import Any
from fastapi import WebSocket


class ConnectionManager:
    """Manages WebSocket connections per session."""

    def __init__(self):
        self.connections: dict[str, list[WebSocket]] = {}

    async def connect(self, session_id: str, websocket: WebSocket):
        await websocket.accept()
        if session_id not in self.connections:
            self.connections[session_id] = []
        self.connections[session_id].append(websocket)

    def disconnect(self, session_id: str, websocket: WebSocket):
        if session_id in self.connections:
            self.connections[session_id].remove(websocket)
            if not self.connections[session_id]:
                del self.connections[session_id]

    async def send_to_session(self, session_id: str, event: dict[str, Any]):
        """Broadcast an event to all connections for a session."""
        if session_id not in self.connections:
            return
        message = json.dumps(event)
        dead = []
        for ws in self.connections[session_id]:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(session_id, ws)

    async def send_activity(self, session_id: str, message: str, level: str = "info"):
        await self.send_to_session(session_id, {
            "type": "activity",
            "message": message,
            "level": level,
        })

    async def send_finding(self, session_id: str, finding: dict):
        await self.send_to_session(session_id, {
            "type": "finding_discovered",
            "finding": finding,
        })

    async def send_scan_status(self, session_id: str, scan_id: str, status: str, **kwargs):
        await self.send_to_session(session_id, {
            "type": f"scan_{status}",
            "scan_id": scan_id,
            **kwargs,
        })

    async def send_ai_chunk(self, session_id: str, content: str, done: bool = False):
        await self.send_to_session(session_id, {
            "type": "ai_message",
            "content": content,
            "done": done,
        })

    async def send_tool_call(self, session_id: str, tool: str, args: dict, scan_id: str | None = None):
        event: dict[str, Any] = {
            "type": "ai_tool_call",
            "tool": tool,
            "args": args,
        }
        if scan_id:
            event["scan_id"] = scan_id
        await self.send_to_session(session_id, event)

    async def send_tool_output(self, session_id: str, line: str, scan_id: str | None = None):
        """Stream a raw output line from a running tool."""
        event: dict[str, Any] = {
            "type": "tool_output",
            "line": line,
        }
        if scan_id:
            event["scan_id"] = scan_id
        await self.send_to_session(session_id, event)


ws_manager = ConnectionManager()
