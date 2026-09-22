"""
Centralized Versioned API v1 Router Aggregator
Mounts all /api/v1/... endpoints in compliance with prompt specifications:
- POST /api/v1/auth/login
- POST /api/v1/organizations/register
- POST /api/v1/agents/register
- POST /api/v1/events
- GET /api/v1/events
- GET /api/v1/events/{event_id}
- GET /api/v1/detections
- GET /api/v1/alerts
- GET /api/v1/privacy/metrics
- GET /api/v1/privacy/policies
- PUT /api/v1/privacy/policies/{policy_id}
- GET /api/v1/audit-logs
- GET /api/v1/system/health
- GET /api/v1/agents
- GET /api/v1/agents/{agent_id}
- WS /api/v1/ws/dashboard
"""

from fastapi import APIRouter

from backend.app.api.v1.auth import router as auth_router
from backend.app.api.v1.organizations import router as organizations_router
from backend.app.api.v1.agents import router as agents_router
from backend.app.api.v1.events import router as events_router
from backend.app.api.v1.detections import router as detections_router
from backend.app.api.v1.alerts import router as alerts_router
from backend.app.api.v1.privacy import router as privacy_router
from backend.app.api.v1.audit import router as audit_router
from backend.app.api.v1.system import router as system_router
from backend.app.api.v1.ws import router as ws_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(auth_router)
api_v1_router.include_router(organizations_router)
api_v1_router.include_router(agents_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(detections_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(privacy_router)
api_v1_router.include_router(audit_router)
api_v1_router.include_router(system_router)
api_v1_router.include_router(ws_router)
