"""
Versioned WebSocket Router (/api/v1/ws/dashboard)
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from datetime import datetime, timezone

from backend.app.websocket.manager import ws_manager

router = APIRouter(prefix="/ws", tags=["V1 Realtime WebSockets"])

@router.websocket("/dashboard")
async def dashboard_websocket(websocket: WebSocket):
    """
    Real-time bidirectional WebSocket connection for cybersecurity dashboard.
    Receives detection alerts, risk score changes, and agent status updates.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Listen for inbound heartbeat pings or query messages from dashboard
            text = await websocket.receive_text()
            if text == "ping":
                await websocket.send_text("pong")
            elif text == "status":
                await websocket.send_json({
                    "type": "system.status",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": {
                        "status": "HEALTHY",
                        "active_connections": ws_manager.connection_count()
                    }
                })
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
