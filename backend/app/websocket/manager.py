"""
WebSocket Connection Manager
Tracks active client WebSocket connections and broadcasts typed real-time telemetry events.
"""

import json
from typing import List, Dict, Any
from datetime import datetime, timezone
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

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

    async def broadcast(self, event_type: str, data: Dict[str, Any]):
        """Broadcasts a structured JSON event to all connected frontend clients."""
        payload = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data
        }
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(payload)
            except Exception:
                disconnected.append(connection)

        # Cleanup dead sockets
        for dead in disconnected:
            self.disconnect(dead)

    def connection_count(self) -> int:
        return len(self.active_connections)

ws_manager = ConnectionManager()
