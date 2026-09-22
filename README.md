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

## Docker Deployment

```bash
docker compose up --build
```
This launches:
- `threat_detection_postgres`: PostgreSQL 16 database on port 5432
- `threat_detection_backend`: FastAPI server on port 8000
- `threat_detection_frontend`: Next.js web console on port 3000

---

## Documentation Links

- [System Verification & Evidence Matrix](SYSTEM_VERIFICATION.md)
- [Architecture Specifications](docs/ARCHITECTURE.md)
- [REST & WebSocket API Guide](docs/API.md)
- [Privacy Architecture & Guarantees](docs/PRIVACY.md)
- [Security Model & Defensive Controls](docs/SECURITY.md)
- [Federated Learning Design](docs/FEDERATED_LEARNING.md)
- [Testing & Quality Assurance](docs/TESTING.md)
