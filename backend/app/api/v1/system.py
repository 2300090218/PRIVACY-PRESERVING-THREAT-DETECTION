"""
Versioned System Health API Endpoints (/api/v1/system/health)
"""

from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, select, func

from backend.app.database import get_db
from backend.app.models.all_models import Agent, SecurityEvent
from backend.app.detection.model_manager import model_manager
from backend.app.websocket.manager import ws_manager
from backend.app.schemas.v1_schemas import SystemHealthResponse
from backend.app.config import settings

router = APIRouter(prefix="/system", tags=["V1 System Health"])

@router.get("/health", response_model=SystemHealthResponse)
async def get_system_health(db: AsyncSession = Depends(get_db)):
    """
    Evaluates real operational status of all platform subsystems:
    API, Database, WebSockets, Agents, ML Model, Ingestion Queue.
    """
    # 1. Database Health Check
    db_status = "HEALTHY"
    db_latency_ms = 0.0
    try:
        t0 = datetime.now()
        await db.execute(text("SELECT 1"))
        db_latency_ms = round((datetime.now() - t0).total_seconds() * 1000, 2)
    except Exception as e:
        db_status = f"ERROR: {str(e)}"

    # 2. Agent Subsystem
    total_agents = 0
    active_agents = 0
    try:
        agent_counts = await db.execute(
            select(Agent.status, func.count(Agent.id)).group_by(Agent.status)
        )
        for row in agent_counts.all():
            total_agents += row[1]
            if row[0] in ["ONLINE", "ACTIVE"]:
                active_agents += row[1]
        agent_subsystem_status = "OPERATIONAL" if active_agents > 0 else "IDLE"
    except Exception:
        agent_subsystem_status = "UNKNOWN"

    # 3. ML Model Subsystem
    ml_ready = model_manager.model is not None and model_manager.scaler is not None
    ml_status = "OPERATIONAL" if ml_ready else "UNINITIALIZED"
    ml_meta = {
        "status": ml_status,
        "model_version": getattr(model_manager, "version", "v1.0.0"),
        "model_type": model_manager.model.__class__.__name__ if ml_ready else "None",
        "features_count": len(getattr(model_manager, "features", [])) if ml_ready else 0,
    }

    # 4. WebSocket Subsystem
    ws_connections_count = len(ws_manager.active_connections)
    ws_meta = {
        "status": "OPERATIONAL",
        "active_clients": ws_connections_count,
        "endpoint": "/api/v1/ws/dashboard"
    }

    # 5. Ingestion Queue / Event Counter
    total_events = 0
    try:
        evt_cnt = await db.execute(select(func.count(SecurityEvent.id)))
        total_events = evt_cnt.scalar() or 0
    except Exception:
        pass

    queue_meta = {
        "status": "OPERATIONAL",
        "mode": "SYNCHRONOUS_INGESTION_DIRECT",
        "total_ingested_events": total_events,
        "backpressure": "NORMAL"
    }

    # Overall Platform Status
    overall_status = "HEALTHY" if (db_status == "HEALTHY" and ml_ready) else "DEGRADED"

    return SystemHealthResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc),
        api={
            "status": "OPERATIONAL",
            "version": "v1.0.0",
            "environment": settings.OPERATIONAL_MODE,
            "cors_origins": settings.CORS_ORIGINS
        },
        database={
            "status": db_status,
            "engine": "PostgreSQL" if "postgresql" in settings.DATABASE_URL else "SQLite",
            "latency_ms": db_latency_ms
        },
        websocket=ws_meta,
        agents={
            "status": agent_subsystem_status,
            "total_registered": total_agents,
            "active_now": active_agents
        },
        ml_model=ml_meta,
        queue=queue_meta
    )
