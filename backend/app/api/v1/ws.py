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
@router.websocket("/threats")
async def dashboard_websocket(
    websocket: WebSocket,
    token: str = None,
    tenant: str = None,
    organization_id: str = None
):
    """
    Real-time bidirectional WebSocket connection for cybersecurity dashboard.
    Receives detection alerts, risk score changes, and agent status updates with tenant isolation.
    """
    selected_org = tenant or organization_id
    user_info = None
    if token:
        try:
            from backend.app.security.authentication import decode_access_token
            payload = decode_access_token(token)
            if payload:
                user_info = {
                    "username": payload.get("sub"),
                    "role": payload.get("role"),
                    "organization_id": payload.get("organization_id")
                }
                selected_org = selected_org or payload.get("organization_id")
        except Exception:
            pass

    await ws_manager.connect(websocket, organization_id=selected_org, user_info=user_info)
    try:
        while True:
            text = await websocket.receive_text()
            if text == "ping":
                await websocket.send_text("pong")
            elif text == "status":
                await websocket.send_json({
                    "type": "system.status",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": {
                        "status": "HEALTHY",
                        "organization_id": selected_org or "ALL",
                        "active_connections": ws_manager.connection_count()
                    }
                })
    except (WebSocketDisconnect, Exception):
        ws_manager.disconnect(websocket)

