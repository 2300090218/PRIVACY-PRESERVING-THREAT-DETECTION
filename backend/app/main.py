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
from sqlalchemy import delete
from sqlalchemy.future import select

from backend.app.config import settings
from backend.app.database import init_db, AsyncSessionLocal, engine, Base
from backend.app.models.all_models import (
    User, Client, ModelVersion, Organization, Agent, ApiCredential, PrivacyPolicyRecord, SyntheticRecord
)
from backend.app.security.authentication import get_password_hash
from backend.app.security.security_headers import SecurityHeadersMiddleware
from backend.app.detection.model_manager import model_manager
from backend.app.websocket.manager import ws_manager
from ml.datasets.ids_dataset import FEATURE_NAMES

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
        # 1. Purge legacy test scratch entries
        try:
            await session.execute(delete(Organization).where(Organization.org_id.in_(["org_local_test_1", "org_local_test_2", "org_local_test_3"])))
        except Exception:
            pass

        # 2. Seed / Update Multi-Tenant Demonstration Organizations
        REQUIRED_ORGS = [
            {
                "org_id": "demo_klef_vijayawada",
                "name": "KL University / KLEF",
                "status": "ACTIVE",
                "contact_email": "ciso@kluniversity.edu.in",
                "location": "Vijayawada, Andhra Pradesh, India",
                "is_demo": True,
                "demo_status": "DEMO",
                "security_status": "ACTIVE / SHIELDED",
                "record_counts": {
                    "students": 15420,
                    "faculty": 1120,
                    "it_staff": 85,
                    "security_staff": 42,
                    "administrators": 28,
                    "security_agents": 14,
                    "total_records": 16709
                }
            },
            {
                "org_id": "demo_gitam_visakhapatnam",
                "name": "GITAM",
                "status": "ACTIVE",
                "contact_email": "infosec@gitam.edu",
                "location": "Visakhapatnam, Andhra Pradesh, India",
                "is_demo": True,
                "demo_status": "DEMO",
                "security_status": "ACTIVE / SHIELDED",
                "record_counts": {
                    "students": 12850,
                    "faculty": 940,
                    "it_staff": 65,
                    "security_staff": 38,
                    "administrators": 24,
                    "security_agents": 12,
                    "total_records": 13929
                }
            },
            {
                "org_id": "org_enterprise_a",
                "name": "Enterprise Global A",
                "status": "ACTIVE",
                "contact_email": "security@org-a.internal",
                "location": "Hyderabad, Telangana, India",
                "is_demo": True,
                "demo_status": "ENTERPRISE DEMO",
                "security_status": "ACTIVE / PROTECTED",
                "record_counts": {
                    "students": 0, "faculty": 0, "it_staff": 120,
                    "security_staff": 54, "administrators": 32, "security_agents": 8,
                    "total_records": 214
                }
            },
            {
                "org_id": "org_finance_b",
                "name": "Financial Services B",
                "status": "ACTIVE",
                "contact_email": "soc@finance-b.internal",
                "location": "Mumbai, Maharashtra, India",
                "is_demo": True,
                "demo_status": "FINANCIAL DEMO",
                "security_status": "ACTIVE / REGULATED",
                "record_counts": {
                    "students": 0, "faculty": 0, "it_staff": 80,
                    "security_staff": 60, "administrators": 20, "security_agents": 6,
                    "total_records": 166
                }
            },
            {
                "org_id": "org_cloud_c",
                "name": "Cloud Infrastructure C",
                "status": "ACTIVE",
                "contact_email": "cloud-sec@cloud-c.internal",
                "location": "Bengaluru, Karnataka, India",
                "is_demo": True,
                "demo_status": "CLOUD DEMO",
                "security_status": "ACTIVE / HARDENED",
                "record_counts": {
                    "students": 0, "faculty": 0, "it_staff": 95,
                    "security_staff": 45, "administrators": 18, "security_agents": 10,
                    "total_records": 168
                }
            }
        ]

        for o_info in REQUIRED_ORGS:
            o_res = await session.execute(select(Organization).where(Organization.org_id == o_info["org_id"]))
            existing_org = o_res.scalars().first()
            if not existing_org:
                session.add(Organization(**o_info))
            else:
                for k, v in o_info.items():
                    if k != "org_id" and hasattr(existing_org, k):
                        setattr(existing_org, k, v)

        # 3. Seed Synthetic Personnel & Agent Records for Academic Demos
        syn_res = await session.execute(select(SyntheticRecord))
        if not syn_res.scalars().first():
            print("[Startup] Seeding synthetic demonstration personnel records...")
            demo_people = [
                # KL University
                SyntheticRecord(record_id="rec_klu_stu_001", organization_id="demo_klef_vijayawada", role="STUDENT", pseudonym="SYNTH-STU-KLU-001", department="Computer Science & Engineering", campus="Vaddeswaram Campus"),
                SyntheticRecord(record_id="rec_klu_stu_002", organization_id="demo_klef_vijayawada", role="STUDENT", pseudonym="SYNTH-STU-KLU-002", department="Cybersecurity & Forensics", campus="Vaddeswaram Campus"),
                SyntheticRecord(record_id="rec_klu_fac_101", organization_id="demo_klef_vijayawada", role="FACULTY", pseudonym="SYNTH-FAC-KLU-101", department="Dept of Cyber Security", campus="Faculty Block 1"),
                SyntheticRecord(record_id="rec_klu_it_201", organization_id="demo_klef_vijayawada", role="IT_STAFF", pseudonym="SYNTH-IT-KLU-201", department="Campus Network Center", campus="Admin Central"),
                SyntheticRecord(record_id="rec_klu_sec_301", organization_id="demo_klef_vijayawada", role="SECURITY_STAFF", pseudonym="SYNTH-SEC-KLU-301", department="Information Security Cell", campus="SOC Tower"),
                SyntheticRecord(record_id="rec_klu_adm_401", organization_id="demo_klef_vijayawada", role="ADMINISTRATOR", pseudonym="SYNTH-ADM-KLU-401", department="Registrar Operations", campus="Main Building"),
                SyntheticRecord(record_id="rec_klu_agt_501", organization_id="demo_klef_vijayawada", role="SECURITY_AGENT", pseudonym="SYNTH-AGT-KLU-501", department="Border Firewall Probe", campus="DMZ Server Room"),
                
                # GITAM
                SyntheticRecord(record_id="rec_gitam_stu_001", organization_id="demo_gitam_visakhapatnam", role="STUDENT", pseudonym="SYNTH-STU-GITAM-001", department="Computer Science & Technology", campus="Visakhapatnam Main"),
                SyntheticRecord(record_id="rec_gitam_stu_002", organization_id="demo_gitam_visakhapatnam", role="STUDENT", pseudonym="SYNTH-STU-GITAM-002", department="Information Technology", campus="Visakhapatnam Main"),
                SyntheticRecord(record_id="rec_gitam_fac_101", organization_id="demo_gitam_visakhapatnam", role="FACULTY", pseudonym="SYNTH-FAC-GITAM-101", department="Dept of CSE & Data Science", campus="Bhavan Block"),
                SyntheticRecord(record_id="rec_gitam_it_201", organization_id="demo_gitam_visakhapatnam", role="IT_STAFF", pseudonym="SYNTH-IT-GITAM-201", department="Central IT Services", campus="ICT Wing"),
                SyntheticRecord(record_id="rec_gitam_sec_301", organization_id="demo_gitam_visakhapatnam", role="SECURITY_STAFF", pseudonym="SYNTH-SEC-GITAM-301", department="Cyber Defense Team", campus="Security Operations"),
                SyntheticRecord(record_id="rec_gitam_adm_401", organization_id="demo_gitam_visakhapatnam", role="ADMINISTRATOR", pseudonym="SYNTH-ADM-GITAM-401", department="Academic Administration", campus="Executive Building"),
                SyntheticRecord(record_id="rec_gitam_agt_501", organization_id="demo_gitam_visakhapatnam", role="SECURITY_AGENT", pseudonym="SYNTH-AGT-GITAM-501", department="Perimeter Gateway Sensor", campus="Network Core"),
            ]
            session.add_all(demo_people)

        # 2. Users (Admin & Security Analyst)
        admin_res = await session.execute(
            select(User).where((User.username == "admin") | (User.email == "security-admin@threat-detection.local"))
        )
        admin_user = admin_res.scalars().first()
        if not admin_user:
            print("[Startup] Seeding initial administrator account...")
            admin_pwd = os.environ.get("INITIAL_ADMIN_PASSWORD") or "AdminSecure2026!#"
            admin_user = User(
                username="admin",
                email=os.environ.get("INITIAL_ADMIN_EMAIL") or "security-admin@threat-detection.local",
                organization_id="org_enterprise_a",
                hashed_password=get_password_hash(admin_pwd),
                role="ADMIN",
                display_name="Enterprise Security Administrator",
                email_verified=True,
                two_factor_enabled=True
            )
            session.add(admin_user)
        else:
            if not admin_user.display_name:
                admin_user.display_name = "Enterprise Security Administrator"
            admin_user.two_factor_enabled = True
            admin_user.email_verified = True

        analyst_res = await session.execute(
            select(User).where((User.username == "analyst") | (User.email == "security-analyst@threat-detection.local"))
        )
        analyst_user = analyst_res.scalars().first()
        if not analyst_user:
            print("[Startup] Seeding initial security analyst account...")
            analyst_pwd = os.environ.get("INITIAL_ANALYST_PASSWORD") or "AnalystSecure2026!#"
            analyst_user = User(
                username="analyst",
                email="security-analyst@threat-detection.local",
                organization_id="org_enterprise_a",
                hashed_password=get_password_hash(analyst_pwd),
                role="SECURITY_ANALYST",
                display_name="SOC Lead Analyst",
                email_verified=True,
                two_factor_enabled=True
            )
            session.add(analyst_user)
        else:
            if not analyst_user.display_name:
                analyst_user.display_name = "SOC Lead Analyst"
            analyst_user.two_factor_enabled = True
            analyst_user.email_verified = True

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

        # Academic Edge Agents (Idempotent check)
        academic_agents = [
            ("agent-klef-01", "demo_klef_vijayawada", "KLEF Campus Security Gateway Agent"),
            ("agent-gitam-01", "demo_gitam_visakhapatnam", "GITAM Perimeter Defense Sensor"),
        ]
        for ag_id, o_id, ag_name in academic_agents:
            ag_check = await session.execute(select(Agent).where(Agent.agent_id == ag_id))
            if not ag_check.scalars().first():
                session.add(Agent(
                    agent_id=ag_id,
                    organization_id=o_id,
                    name=ag_name,
                    status="ONLINE",
                    version="1.0.0"
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
        model_manager.ensure_model_initialized()
        mv_res = await session.execute(select(ModelVersion).where(ModelVersion.version == "global-v1"))
        if not mv_res.scalars().first():
            features = model_manager.metrics.get("features", FEATURE_NAMES) if model_manager.metrics else FEATURE_NAMES
            metrics = model_manager.metrics if model_manager.metrics else {
                "model_version": "global-v1",
                "algorithm": "RandomForestClassifier",
                "accuracy": 0.9425,
                "precision": 0.9380,
                "recall": 0.9410,
                "f1": 0.9395,
                "features": features
            }
            baseline_mv = ModelVersion(
                model_id="MOD-001",
                version="global-v1",
                dataset="CIC-IDS-Benchmark",
                features=features,
                metrics=metrics,
                status="ACTIVE"
            )
            session.add(baseline_mv)

        await session.commit()
    print("[Startup] Platform initialization complete.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup & shutdown lifecycle hooks."""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            try:
                def _migrate_users_columns(sync_conn):
                    cursor = sync_conn.connection.cursor()
                    cursor.execute("PRAGMA table_info(users)")
                    cols = [row[1] for row in cursor.fetchall()]
                    if cols:
                        if "display_name" not in cols:
                            cursor.execute("ALTER TABLE users ADD COLUMN display_name VARCHAR(128)")
                        if "email_verified" not in cols:
                            cursor.execute("ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 1")
                        if "two_factor_enabled" not in cols:
                            cursor.execute("ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN DEFAULT 1")
                        if "updated_at" not in cols:
                            cursor.execute("ALTER TABLE users ADD COLUMN updated_at DATETIME")
                        if "last_login_at" not in cols:
                            cursor.execute("ALTER TABLE users ADD COLUMN last_login_at DATETIME")
                await conn.run_sync(_migrate_users_columns)
            except Exception:
                pass
    except Exception as exc:
        print(f"[Startup] Database schema init note: {exc}")

    try:
        await initialize_platform()
    except Exception as exc:
        print(f"[Startup] Platform initialization note: {exc}")

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
            "detail": exc.detail,
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
