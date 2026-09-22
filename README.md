# Privacy-Preserving Threat Detection Platform

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![Next.js 14](https://img.shields.io/badge/Next.js-14.2-black.svg)](https://nextjs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A production-quality collaborative cybersecurity platform that collects authorized security telemetry, executes automated data minimization and PII pseudonymization, detects attacks via dual layers (rule-based heuristics + real machine learning), computes deterministic risk scores, generates real-time alerts over WebSockets, maintains an immutable audit trail, and supports privacy-preserving federated learning across distributed clients without raw training records ever leaving participating nodes.

---

## Key Features

1. **No-Fabrication Policy**: Authentic metrics throughout. If zero detections exist, displays *"No detections yet"*; if external threat feeds are not integrated, displays *"NOT CONFIGURED"*; unmapped IP ranges display *"LOCATION UNAVAILABLE"*.
2. **Dual-Layer Threat Detection**:
   - **Rule Engine**: Sliding-window brute force detection, request volume burst anomalies, known C2 ports (4444, 1337, 31337), multi-port scanning sweeps, and payload signature pattern matching.
   - **ML Engine**: Real scikit-learn Random Forest model trained on standard network flow characteristics (modeled after CIC-IDS2017 / UNSW-NB15) returning classification (`BENIGN`, `Brute Force`, `DDoS`, `Port Scan`, `Botnet`), confidence, severity, and processing latency.
3. **Privacy Engine**:
   - Automated regex & token scanner for emails, phone numbers, IP addresses, credentials, passwords, and API keys.
   - Salted HMAC-SHA256 pseudonymization generating reproducible tokens (`USER-7F31A`, `NET-SRC-94A1B`).
   - Strict credential masking (`[REDACTED]`).
   - Append-only `PrivacyEvent` audit log.
4. **Deterministic Risk Engine**:
   - Transparent scoring formula:
     $$\text{Risk Score} = 0.40 \times S_{\text{ML}} + 0.30 \times S_{\text{Rule}} + 0.15 \times S_{\text{Freq}} + 0.15 \times S_{\text{Asset}}$$
   - Categorical tiers: `LOW` (0–39), `MEDIUM` (40–69), `HIGH` (70–89), `CRITICAL` (90–100).
5. **Real Federated Learning**:
   - Flower-compatible FedAvg aggregation across 3 client data partitions (Client 1: DMZ Gateway, Client 2: Financial Branch, Client 3: Cloud VPC).
   - Raw training telemetry strictly remains local on each client. Only model weight updates are transmitted.
   - Differential privacy gradient & weight clipping.
   - Held-out central test evaluation yielding genuine accuracy, precision, recall, and F1 per version (`global-v1`, `global-v2`).
6. **Real-Time WebSockets (`/ws`)**:
   - Live streaming of `event.received`, `detection.created`, `alert.created`, `incident.updated`, `training.started`, `training.progress`, `training.completed`, `model.updated`.
   - The Next.js dashboard updates in real time without page reload.
7. **Safe Local Test Mode**:
   - Dedicated **"RUN SECURITY TEST"** button in the dashboard runs realistic synthetic attack vectors through the identical end-to-end pipeline, visibly tagged with `TEST MODE`.

---

## Architecture Overview

```
                        USER BROWSER
                             │
                             ▼
                     NEXT.JS FRONTEND (Port 3000)
                             │
                     REST API / WebSocket (/ws)
                             │
                             ▼
                     FASTAPI BACKEND (Port 8000)
                             │
       ┌─────────────────────┼─────────────────────┐
       ▼                     ▼                     ▼
Event Engine           Privacy Engine         Authentication & RBAC
 (Ingestion)       (PII / HMAC-SHA256)           (JWT / bcrypt)
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             │
                             ▼
                  Dual Threat Detection
                   ┌─────────┴─────────┐
                   ▼                   ▼
               ML Engine          Rule Engine
            (Random Forest)     (Heuristics)
                   └─────────┬─────────┘
                             │
                             ▼
                        Risk Engine
                (Deterministic Composite)
                             │
                   ┌─────────┴─────────┐
                   ▼                   ▼
             Alert Engine      PostgreSQL / SQLite
                   │
                   ▼
               WebSocket (/ws)
                   │
                   ▼
             LIVE DASHBOARD
```

---

## Quick Start (Local Development)

### Prerequisites
- Python 3.12+
- Node.js 18+ and npm

### 1. Backend Setup

```bash
# From repository root
# Install backend dependencies
pip install -r backend/requirements.txt

# Train baseline ML model and generate benchmark IDS dataset
python ml/training/train_baseline.py

# Start the FastAPI server (SQLite fallback will initialize automatically)
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Documentation available at: `http://127.0.0.1:8000/docs`
- Health check available at: `http://127.0.0.1:8000/api/health`

### 2. Frontend Setup

```bash
# In a separate terminal
cd frontend
npm install
npm run dev
```
- Dashboard available at: `http://localhost:3000`
- Pre-seeded Analyst Credentials: `admin` / `AdminPass123!`

---

## Running Automated Tests

### Backend Unit & Integration Tests (15 passing suites)
```bash
python -m pytest backend/tests -v
```

### Frontend Build Verification
```bash
cd frontend
npm run build
```

---

---

## Production Deployment Architecture & Operations Guide

The Privacy-Preserving Threat Detection Platform features a decoupled production architecture designed for security, scalability, and real-time operations:

```
┌────────────────────────────────────────┐       HTTPS REST       ┌────────────────────────────────────────┐
│            VERCEL PLATFORM             │ ─────────────────────> │       PERSISTENT BACKEND SERVICE       │
│                                        │                        │   (Railway / Render / Fly.io / ECS)    │
│  Next.js 14 Frontend                   │       WSS Telemetry    │  FastAPI (Uvicorn)                     │
│  * Serverless SSR & Edge Static Pages  │ <====================> │  * Persistent WebSocket (/ws)          │
│  * Root Directory: "frontend"          │                        │  * Dual Threat Engine (Rules + ML)     │
│  * Pure Browser/Client Execution       │                        │  * ModelManager Hot-Swapping           │
└────────────────────────────────────────┘                        │  * Federated Learning Coordinator      │
                                                                  └──────────────────┬─────────────────────┘
                                                                                     │
                                                                                     │ asyncpg pool
                                                                                     ▼
                                                                  ┌────────────────────────────────────────┐
                                                                  │          POSTGRESQL DATABASE           │
                                                                  │     (Managed AWS RDS / Supabase)       │
                                                                  │  * Audit Logs & Model History          │
                                                                  │  * Security Events, Alerts, Incidents  │
                                                                  └────────────────────────────────────────┘
```

### 1. Frontend Deployment to Vercel

The frontend is built with Next.js 14 and is fully optimized for deployment on **Vercel**.

#### Vercel Project Configuration
When importing this repository into Vercel:
1. **Framework Preset**: Next.js (automatically detected)
2. **Root Directory**: `frontend` *(CRITICAL: You must configure `frontend` as the Root Directory so Vercel resolves `frontend/package.json`)*
3. **Build Command**: `npm run build`
4. **Output Directory**: `.next` (default)
5. **Install Command**: `npm install`

#### Required Vercel Environment Variables
Add these under **Project Settings → Environment Variables** in the Vercel Dashboard:

| Variable | Environment | Example / Format | Purpose |
| :--- | :--- | :--- | :--- |
| `NEXT_PUBLIC_API_URL` | Production | `https://api.yourdomain.com` | Base URL of the deployed FastAPI backend |
| `NEXT_PUBLIC_WS_URL` | Production | `wss://api.yourdomain.com/ws` | Secure WebSocket endpoint for live threat streams |

> [!TIP]
> If `NEXT_PUBLIC_WS_URL` is omitted, the frontend automatically derives the WebSocket URL from `NEXT_PUBLIC_API_URL` by converting `https://` to `wss://` and appending `/ws`.

---

### 2. Backend Service Deployment (Persistent Runtime Required)

> [!IMPORTANT]
> **Why the Backend Requires a Persistent Runtime (Not Serverless)**:
> The FastAPI backend **cannot** be hosted on an ephemeral serverless runtime (like AWS Lambda or Vercel Functions) because:
> 1. **Persistent WebSocket Server**: Maintains active client connections (`/ws`) via `ws_manager` for real-time telemetry streaming and heartbeat pings.
> 2. **Model Persistence & Hot-Swapping**: `ModelManager` writes updated serialized weights (`.joblib`) and metrics to the filesystem upon completing federated aggregation rounds.
> 3. **Federated Learning & Background Tasks**: The server coordinates multi-round FedAvg training across client partitions and continuous automated test monitoring in background loops.
>
> **Recommended Platforms**: [Railway](https://railway.app), [Render](https://render.com), [Fly.io](https://fly.io), [AWS ECS / EC2](https://aws.amazon.com/ecs/), [GCP Cloud Run](https://cloud.google.com/run) *(with WebSockets & minimum 1 idle instance enabled)*, or Docker on a dedicated Linux VPS.

#### Deploying with Docker
The repository includes a production multi-stage `docker/Dockerfile.backend`:
```bash
# Build the backend container
docker build -f docker/Dockerfile.backend -t threat-detection-backend .

# Run the container with your production environment variables
docker run -d -p 8000:8000 \
  -e APP_ENV=production \
  -e DEBUG=false \
  -e DATABASE_URL="postgresql+asyncpg://user:password@db-host:5432/threat_detection" \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e JWT_SECRET="$(openssl rand -hex 32)" \
  -e PRIVACY_SALT="$(openssl rand -hex 32)" \
  -e CORS_ORIGINS="https://your-frontend-project.vercel.app" \
  --name threat_backend threat-detection-backend
```

#### Deploying with Docker Compose (Full Stack)
```bash
docker compose up --build -d
```
This provisions:
- `threat_detection_postgres`: PostgreSQL 16 database on port 5432
- `threat_detection_backend`: FastAPI server on port 8000
- `threat_detection_frontend`: Next.js web console on port 3000

---

### 3. Production Database Requirement

- **Local Development**: Uses local SQLite (`sqlite+aiosqlite:///./threat_detection.db`) with WAL mode enabled for zero-friction local execution.
- **Production**: A managed **PostgreSQL** instance is **mandatory** (e.g., Supabase, Neon, AWS RDS, GCP Cloud SQL).
- **Driver**: Set `DATABASE_URL` using `postgresql+asyncpg://...` (or standard `postgresql://...` which is automatically normalized by `backend/app/database.py`).
- **Persistence**: Ephemeral filesystems must never be relied on for production data.

---

### 4. WebSocket & Networking Requirement

- **Protocol**: Production deployments must use Secure WebSockets (`wss://`) over TLS to prevent mixed-content blocks when communicating with HTTPS-hosted Vercel frontends.
- **Reverse Proxies (NGINX / Caddy / Cloudflare)**: Ensure WebSocket upgrade headers are passed:
  ```nginx
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
  ```

---

### 5. ML & Federated Learning Deployment Requirements

- **Model Storage**: Pre-trained baseline models and encoders (`baseline_rf.joblib`, `scaler.joblib`, `label_encoder.joblib`) reside in `ml/models/` and are loaded at backend startup into memory.
- **Persistent Volumes**: Mount a persistent volume to `./ml/models` on the backend host if you wish newly trained global model iterations (`global-v2`, `global-v3`) from federated training rounds to persist across container restarts.
- **Dataset Partitions**: Client training partitions reside in `ml/datasets/` for simulated edge federation.

---

### 6. CORS & Security Hardening

- **CORS Configuration**: Set `CORS_ORIGINS` to your exact Vercel frontend domain:
  ```env
  CORS_ORIGINS=https://your-app.vercel.app
  ```
  *(Multiple origins can be separated by commas or formatted as a JSON array).*
- **No Wildcards**: Never configure unrestricted `*` CORS in production with credentials enabled.
- **Cryptographic Secrets**: Never use default development secrets in production. Generate cryptographically strong random values:
  ```bash
  openssl rand -hex 32
  ```
- **Secret Isolation**: Never prefix server secrets (`SECRET_KEY`, `JWT_SECRET`, `PRIVACY_SALT`, database passwords) with `NEXT_PUBLIC_`.

---

## Documentation Links

- [System Verification & Evidence Matrix](SYSTEM_VERIFICATION.md)
- [Architecture Specifications](docs/ARCHITECTURE.md)
- [REST & WebSocket API Guide](docs/API.md)
- [Privacy Architecture & Guarantees](docs/PRIVACY.md)
- [Security Model & Defensive Controls](docs/SECURITY.md)
- [Federated Learning Design](docs/FEDERATED_LEARNING.md)
- [Testing & Quality Assurance](docs/TESTING.md)

