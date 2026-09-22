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
from backend.app.models.all_models import User, Client, ModelVersion
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

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup & shutdown lifecycle hooks."""
    print("[Startup] Initializing Database schema...")
    await init_db()

    # Seed default admin user and federated clients if empty
    async with AsyncSessionLocal() as session:
        # 1. Admin User
        admin_res = await session.execute(select(User).where(User.username == "admin"))
        if not admin_res.scalars().first():
            print("[Startup] Seeding initial administrator account...")
            admin_user = User(
                username="admin",
                email="security-admin@threat-detection.local",
                hashed_password=get_password_hash("AdminPass123!"),
                role="ADMIN"
            )
            session.add(admin_user)

        # 2. Federated Clients
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

        # 3. Baseline Model Version record
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

# WebSocket Endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Handle inbound client ping or query messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# Include Routers
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
