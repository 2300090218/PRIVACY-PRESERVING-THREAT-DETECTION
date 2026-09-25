"""
Versioned WebSocket Router (/api/v1/ws/dashboard)
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from datetime import datetime, timezone

from backend.app.websocket.manager import ws_manager

router = APIRouter(prefix="/ws", tags=["V1 Realtime WebSockets"])

@router.get("/sse")
async def sse_dashboard_stream():
    """
    Real-time Server-Sent Events (SSE) telemetry stream for web dashboards.
    Alternative to WebSockets for environments where WebSockets are unsupported or blocked.
    """
    return StreamingResponse(
        ws_manager.sse_subscribe(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

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

