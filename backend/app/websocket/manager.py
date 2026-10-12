"""
WebSocket & Real-Time Telemetry Connection Manager
Tracks active WebSocket and SSE client connections and broadcasts typed real-time telemetry events.
"""

import json
import asyncio
from typing import List, Dict, Any, AsyncGenerator, Optional
from datetime import datetime, timezone
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_metadata: Dict[WebSocket, Dict[str, Any]] = {}
        self._sse_queues: List[asyncio.Queue] = []

    async def connect(
        self,
        websocket: WebSocket,
        organization_id: Optional[str] = None,
        user_info: Optional[Dict[str, Any]] = None
    ):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.connection_metadata[websocket] = {
            "organization_id": organization_id,
            "user_info": user_info or {},
            "connected_at": datetime.now(timezone.utc).isoformat()
        }
        # Send initial welcome and status
        await websocket.send_json({
            "type": "system.status",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "status": "CONNECTED",
                "organization_id": organization_id or "ALL",
                "active_connections": len(self.active_connections)
            }
        })

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        self.connection_metadata.pop(websocket, None)

    async def sse_subscribe(self, organization_id: Optional[str] = None) -> AsyncGenerator[str, None]:
        """Provides an asynchronous event stream for Server-Sent Events (SSE)."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._sse_queues.append(queue)
        initial_msg = json.dumps({
            "type": "system.status",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "status": "CONNECTED",
                "mode": "SSE",
                "organization_id": organization_id or "ALL",
                "active_connections": len(self.active_connections) + len(self._sse_queues)
            }
        })
        yield f"data: {initial_msg}\n\n"
        try:
            while True:
                msg = await queue.get()
                yield f"data: {msg}\n\n"
        finally:
            if queue in self._sse_queues:
                self._sse_queues.remove(queue)

    async def broadcast(
        self,
        event_type: str,
        data: Dict[str, Any],
        organization_id: Optional[str] = None
    ):
        """
        Broadcasts a structured JSON event to connected WebSocket and SSE clients.
        If organization_id is provided, delivers only to matching tenant sockets and global observers.
        """
        payload = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data
        }
        json_str = json.dumps(payload)

        # 1. WebSockets
        disconnected = []
        for connection in list(self.active_connections):
            meta = self.connection_metadata.get(connection, {})
            conn_org = meta.get("organization_id")
            # Tenant filter: deliver if no org specified, if socket is global (conn_org is None), or if match
            if organization_id and conn_org and conn_org != organization_id:
                continue

            try:
                await connection.send_json(payload)
            except Exception:
                disconnected.append(connection)

        # Cleanup dead sockets
        for dead in disconnected:
            self.disconnect(dead)

        # 2. SSE Queues
        for queue in list(self._sse_queues):
            try:
                queue.put_nowait(json_str)
            except asyncio.QueueFull:
                pass

    def connection_count(self) -> int:
        return len(self.active_connections) + len(self._sse_queues)

ws_manager = ConnectionManager()

