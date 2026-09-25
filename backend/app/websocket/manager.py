"""
WebSocket & Real-Time Telemetry Connection Manager
Tracks active WebSocket and SSE client connections and broadcasts typed real-time telemetry events.
"""

import json
import asyncio
from typing import List, Dict, Any, AsyncGenerator
from datetime import datetime, timezone
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._sse_queues: List[asyncio.Queue] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        # Send initial welcome and status
        await websocket.send_json({
            "type": "system.status",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "status": "CONNECTED",
                "active_connections": len(self.active_connections)
            }
        })

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def sse_subscribe(self) -> AsyncGenerator[str, None]:
        """Provides an asynchronous event stream for Server-Sent Events (SSE)."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._sse_queues.append(queue)
        initial_msg = json.dumps({
            "type": "system.status",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "status": "CONNECTED",
                "mode": "SSE",
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

    async def broadcast(self, event_type: str, data: Dict[str, Any]):
        """Broadcasts a structured JSON event to all connected WebSocket and SSE clients."""
        payload = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data
        }
        json_str = json.dumps(payload)

        # 1. WebSockets
        disconnected = []
        for connection in self.active_connections:
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

