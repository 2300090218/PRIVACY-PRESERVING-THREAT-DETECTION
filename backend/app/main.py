"""
Privacy-Preserving Threat Detection Platform - Main FastAPI Application
"""

import uuid
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy.future import select

from backend.app.config import settings
from backend.app.database import init_db, AsyncSessionLocal
from backend.app.models.all_models import (
    User, Client, ModelVersion, Organization, Agent, ApiCredential, PrivacyPolicyRecord
)
from backend.app.security.authentication import get_password_hash
from backend.app.security.security_headers import SecurityHeadersMiddleware
from backend.app.detection.model_manager import model_manager
from backend.app.websocket.manager import ws_manager

# API Routers
from backend.app.api.auth import router as auth_router
from backend.app.api.events import router as events_router
from backend.app.api.detections import router as detections_router
from backend.app.api.alerts import router as alerts_router
from backend.app.api.incidents import router as incidents_router
from backend.app.api.clients import router as clients_router
from backend.app.api.federated import router as federated_router
from backend.app.api.models import router as models_router
from backend.app.api.privacy import router as privacy_router
from backend.app.api.audit import router as audit_router
from backend.app.api.metrics import router as metrics_router
from backend.app.api.health import router as health_router
from backend.app.api.test_routes import router as test_router
from backend.app.api.v1 import api_v1_router
from backend.app.api.v1.organizations import router as v1_org_router
from backend.app.api.v1.agents import router as v1_agents_router

async def initialize_platform():
    """Initializes Database schema and default seed data if not present."""
    print("[Startup] Initializing Database schema...")
    await init_db()

    # Seed default entities if empty
    async with AsyncSessionLocal() as session:
        # 1. Seed Organizations
        org_res = await session.execute(select(Organization))
        if not org_res.scalars().first():
            print("[Startup] Seeding multi-tenant organizations (Org A, Org B, Org C)...")
            initial_orgs = [
                Organization(org_id="org_enterprise_a", name="Enterprise Global A", status="ACTIVE", contact_email="security@org-a.internal"),
                Organization(org_id="org_finance_b", name="Financial Services B", status="ACTIVE", contact_email="soc@finance-b.internal"),
                Organization(org_id="org_cloud_c", name="Cloud Infrastructure C", status="ACTIVE", contact_email="cloud-sec@cloud-c.internal"),
            ]
            session.add_all(initial_orgs)

        # 2. Users (Admin & Security Analyst)
        admin_res = await session.execute(select(User).where(User.username == "admin"))
        if not admin_res.scalars().first():
            print("[Startup] Seeding initial administrator account...")
            admin_user = User(
                username="admin",
                email="security-admin@threat-detection.local",
                organization_id="org_enterprise_a",
                hashed_password=get_password_hash("AdminPass123!"),
                role="ADMIN"
            )
            session.add(admin_user)

        analyst_res = await session.execute(select(User).where(User.username == "analyst"))
        if not analyst_res.scalars().first():
            print("[Startup] Seeding initial security analyst account...")
            analyst_user = User(
                username="analyst",
                email="security-analyst@threat-detection.local",
                organization_id="org_enterprise_a",
                hashed_password=get_password_hash("AnalystPass123!"),
                role="SECURITY_ANALYST"
            )
            session.add(analyst_user)

        # 3. Agents & API Credentials
        agent_res = await session.execute(select(Agent))
        if not agent_res.scalars().first():
            print("[Startup] Registering default Organization edge agents...")
            import hashlib
            default_agents = [
                Agent(agent_id="agent-dmz-01", organization_id="org_enterprise_a", name="DMZ Gateway Edge Agent", status="ONLINE", version="1.0.0"),
                Agent(agent_id="agent-fin-01", organization_id="org_finance_b", name="Financial Subnet Edge Agent", status="ONLINE", version="1.0.0"),
                Agent(agent_id="agent-cld-01", organization_id="org_cloud_c", name="Cloud VPC Flow Edge Agent", status="ONLINE", version="1.0.0"),
            ]
            session.add_all(default_agents)

            # API Keys
            dmz_key = "agent_key_enterprise_a_dmz_prod_secret"
            session.add(ApiCredential(
                organization_id="org_enterprise_a",
                agent_id="agent-dmz-01",
                key_prefix="agent_key_ent...",
                hashed_secret=hashlib.sha256(dmz_key.encode("utf-8")).hexdigest(),
                name="DMZ Gateway Production Key"
            ))

        # 4. Default Privacy Policy Rules (Enterprise Data Minimization)
        policy_res = await session.execute(select(PrivacyPolicyRecord))
        if not policy_res.scalars().first():
            print("[Startup] Seeding default Privacy Policy Engine rules...")
            default_policies = [
                PrivacyPolicyRecord(policy_id="pol-usr-01", organization_id="org_enterprise_a", field_name="username", action="REMOVE", parameters={}, version="1.0.0"),
                PrivacyPolicyRecord(policy_id="pol-ip-01", organization_id="org_enterprise_a", field_name="source_ip", action="REMOVE", parameters={}, version="1.0.0"),
                PrivacyPolicyRecord(policy_id="pol-loc-01", organization_id="org_enterprise_a", field_name="exact_location", action="REMOVE", parameters={}, version="1.0.0"),
                PrivacyPolicyRecord(policy_id="pol-dev-01", organization_id="org_enterprise_a", field_name="device_id", action="PSEUDONYMIZE", parameters={"algorithm": "HMAC-SHA256"}, version="1.0.0"),
                PrivacyPolicyRecord(policy_id="pol-type-01", organization_id="org_enterprise_a", field_name="event_type", action="ALLOW", parameters={}, version="1.0.0"),
                PrivacyPolicyRecord(policy_id="pol-att-01", organization_id="org_enterprise_a", field_name="attack_indicators", action="ALLOW", parameters={}, version="1.0.0"),
                PrivacyPolicyRecord(policy_id="pol-time-01", organization_id="org_enterprise_a", field_name="timestamp", action="ALLOW", parameters={}, version="1.0.0"),
                PrivacyPolicyRecord(policy_id="pol-risk-01", organization_id="org_enterprise_a", field_name="risk_score", action="ALLOW", parameters={}, version="1.0.0"),
            ]
            session.add_all(default_policies)

        # 5. Federated Clients (Legacy/Federated ML)
        client_res = await session.execute(select(Client))
        existing_clients = client_res.scalars().all()
        if not existing_clients:
            print("[Startup] Registering default federated sensor clients...")
            initial_clients = [
                Client(
                    client_id="client-dmz-01",
                    name="DMZ Gateway Sensor",
                    status="ONLINE",
                    ip_address="10.0.0.1",
                    model_version="global-v1"
                ),
                Client(
                    client_id="client-finance-02",
                    name="Financial Subnet Agent",
                    status="ONLINE",
                    ip_address="10.0.1.1",
                    model_version="global-v1"
                ),
                Client(
                    client_id="client-cloud-03",
                    name="Cloud VPC Flow Monitor",
                    status="ONLINE",
                    ip_address="10.0.2.1",
                    model_version="global-v1"
                ),
            ]
            session.add_all(initial_clients)

        # 6. Baseline Model Version record
        mv_res = await session.execute(select(ModelVersion).where(ModelVersion.version == "global-v1"))
        if not mv_res.scalars().first() and model_manager.metrics:
            baseline_mv = ModelVersion(
                model_id="MOD-001",
                version="global-v1",
                dataset="CIC-IDS-Benchmark",
                features=model_manager.metrics.get("features", []),
                metrics=model_manager.metrics,
                status="ACTIVE"
            )
            session.add(baseline_mv)

        await session.commit()
    print("[Startup] Platform initialization complete.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup & shutdown lifecycle hooks."""
    await initialize_platform()
    yield
    print("[Shutdown] Cleaning up platform resources...")

app = FastAPI(
    title=settings.APP_NAME,
    description="Privacy-Preserving Collaborative Threat Detection Platform API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security Hardening Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# Centralized Error Handlers
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTP_ERROR",
            "message": exc.detail,
            "request_id": req_id
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    return JSONResponse(
        status_code=422,
        content={
            "error": "VALIDATION_ERROR",
            "message": "Invalid request payload schema",
            "details": exc.errors(),
            "request_id": req_id
        }
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    return JSONResponse(
        status_code=500,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": str(exc) if settings.DEBUG else "An unexpected error occurred",
            "request_id": req_id
        }
    )

# WebSocket Endpoint (backward-compatible /ws)
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# Include Version 1 Standard Central API Routers (/api/v1/...)
app.include_router(api_v1_router)

# Mount Organizations and Agents under /api as well for compatibility
app.include_router(v1_org_router, prefix="/api")
app.include_router(v1_agents_router, prefix="/api")

# Include Legacy Routers for Backward Compatibility
app.include_router(auth_router)
app.include_router(events_router)
app.include_router(detections_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(clients_router)
app.include_router(federated_router)
app.include_router(models_router)
app.include_router(privacy_router)
app.include_router(audit_router)
app.include_router(metrics_router)
app.include_router(health_router)
app.include_router(test_router)

@app.get("/")
async def root():
    return {
        "platform": settings.APP_NAME,
        "status": "OPERATIONAL",
        "mode": settings.OPERATIONAL_MODE,
        "documentation": "/docs"
    }
