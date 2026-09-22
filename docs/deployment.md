# Deployment & Infrastructure Guide

## 1. Overview

The **Privacy-Preserving Threat Detection Platform** is designed as a distributed multi-tier system with distinct operational boundaries:
- **Local Organization Nodes**: Local Agents and Privacy Gateways running on enterprise edge networks (Organization A, B, C).
- **Central Platform**: FastAPI Central API, PostgreSQL Database, Dual Threat Detection Engine, Risk Engine, and WebSocket Broadcaster.
- **SOC Dashboard**: Next.js 14 Web Application communicating with the Central API and WebSocket streaming endpoint.

---

## 2. Docker & Containerized Deployment

The entire system is orchestrated via `docker-compose.yml` with four isolated microservices on an internal bridge network (`threat_net`):

| Container Name | Service | Port Mapping | Health Check |
|---|---|---|---|
| `threat_postgres` | PostgreSQL 16 Alpine | `5432:5432` | `pg_isready -U threat_user` |
| `threat_central_api` | FastAPI Central Server | `8000:8000` | `curl -f http://localhost:8000/api/v1/system/health` |
| `threat_dashboard` | Next.js 14 SOC UI | `3000:3000` | `wget -qO- http://localhost:3000/api/health` |
| `threat_local_agent` | Python Edge Sensor & Gateway | *Internal* | Native process supervisor |

### 2.1 Starting the Complete Platform
To build and launch all containers in detached mode:

```bash
# Build images and start all containers
docker compose up --build -d

# Check live container status
docker compose ps

# Follow logs across all services
docker compose logs -f

# Follow logs for the central API specifically
docker compose logs -f central-api
```

### 2.2 Verifying Deployment Health
Once the containers are up, query the centralized health check endpoint:

```bash
curl -s http://localhost:8000/api/v1/system/health | jq .
```
Expected output:
```json
{
  "status": "HEALTHY",
  "version": "1.0.0",
  "environment": "production",
  "uptime_seconds": 45,
  "subsystems": {
    "database": {
      "status": "HEALTHY",
      "latency_ms": 2.4,
      "details": "PostgreSQL connection active"
    },
    "api": {
      "status": "HEALTHY",
      "latency_ms": 0.5,
      "details": "FastAPI v1 engine running"
    },
    "websocket": {
      "status": "HEALTHY",
      "connected_clients": 1
    },
    "agents": {
      "status": "HEALTHY",
      "active_count": 1
    },
    "ml_model": {
      "status": "HEALTHY",
      "version": "v1.0.0-random-forest",
      "details": "Inference engine loaded"
    },
    "queue": {
      "status": "HEALTHY",
      "pending_events": 0,
      "details": "In-memory resilient queue operational"
    }
  }
}
```

### 2.3 Shutting Down the Platform
```bash
# Stop all services gracefully
docker compose down

# Stop all services and remove persistent storage volumes (CAUTION)
docker compose down -v
```

---

## 3. Native / Bare-Metal Local Development

For developers working without Docker, the services can be launched directly:

### 3.1 Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- PostgreSQL 14+ (or development fallback SQLite)

### 3.2 Backend & Central API Setup
```bash
# 1. Create and activate Python virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 2. Install backend dependencies
pip install -r backend/requirements.txt

# 3. Configure environment variables
cp .env.example .env
# Edit .env to configure DATABASE_URL, JWT_SECRET, etc.

# 4. Train baseline ML models
python ml/training/train_baseline.py

# 5. Start Central API server
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3.3 Frontend Dashboard Setup
```bash
cd frontend

# Install npm dependencies
npm install

# Build production bundle to verify types
npm run build

# Start Next.js development server
npm run dev
# The dashboard is accessible at http://localhost:3000
```

### 3.4 Running Organization A's Local Agent
```bash
# In a separate terminal with venv activated
python -m agent.local_agent --org-id org_enterprise_a --central-url http://127.0.0.1:8000
```

---

## 4. Environment Variables Reference

All runtime options are managed via environment variables. See `.env.example`:

| Variable Name | Default Value | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://threat_user:threat_pass@localhost:5432/threat_detection` | Async SQLAlchemy connection string |
| `SECRET_KEY` | *(Random 32-byte string)* | Secret for signing JWT access tokens |
| `ALGORITHM` | `HS256` | JWT signature algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` (24 hours) | Token expiration window |
| `ENVIRONMENT` | `production` | Runtime mode (`development`, `production`, `testing`) |
| `CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | Allowed web origins |
| `CENTRAL_API_URL` | `http://localhost:8000` | Target central API for local agents |
| `AGENT_API_KEY` | *(Set per agent)* | HMAC authentication credential for edge agent |
| `ML_MODEL_PATH` | `ml/models/random_forest_v1.pkl` | Path to persistent scikit-learn model artifact |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

---

## 5. Database Schema & Migrations

The platform uses SQLAlchemy 2.0 with asynchronous engine drivers (`asyncpg` for PostgreSQL, `aiosqlite` for local test fallbacks).

### 5.1 Automated Startup Seeding
Upon initial startup, `backend/app/main.py` checks for database schema readiness and idempotently creates:
1. Default multi-tenant organizations:
   - `org_enterprise_a` (Enterprise Alpha - Corporate DMZ)
   - `org_finance_b` (Financial Services Group B)
   - `org_cloud_c` (Cloud Infrastructure VPC C)
2. Seed administrative and analyst accounts:
   - `admin` (Role: `ADMIN`, Password: `AdminPass123!`)
   - `analyst` (Role: `SECURITY_ANALYST`, Password: `AnalystPass123!`)
3. Pre-registered edge agents with dedicated HMAC API keys.
4. Default enterprise privacy policies (`username` -> REMOVE, `source_ip` -> REMOVE, `exact_location` -> REMOVE, `device_id` -> PSEUDONYMIZE).

### 5.2 Alembic Migration Workflow
For schema evolution in staging and production:
```bash
# Generate a new migration revision
alembic revision --autogenerate -m "add_column_name"

# Apply pending migrations to database
alembic upgrade head

# Roll back the most recent migration
alembic downgrade -1
```

---

## 6. Production Security Best Practices

1. **Mandatory TLS/HTTPS Termination**:
   - In production, reverse-proxy (Nginx, Traefik, AWS ALB, Cloudflare) must terminate TLS 1.3 with valid certificates before routing traffic to `threat_central_api`.
   - Local agents must be configured with `CENTRAL_API_URL=https://central-api.yourcompany.com`.
2. **Secret Management**:
   - Never commit `.env` files to source control (enforced by `.gitignore`).
   - In production Kubernetes or AWS/GCP deployments, inject secrets via HashiCorp Vault, AWS Secrets Manager, or GCP Secret Manager.
3. **Database Security**:
   - Central PostgreSQL must not expose port 5432 to the public internet; restrict access to the internal Docker network or private VPC subnet.
4. **Zero Raw Retention Audit**:
   - Periodically verify that no unminimized fields have bypassed edge gateways by querying the central database schema.
