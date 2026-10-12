# Privacy-Preserving Threat Detection Platform

> **Collaborative, Zero-Trust Threat Intelligence & Intrusion Detection with Mathematical Privacy Guarantees**

An enterprise-grade, real-time threat intelligence and intrusion detection platform designed for consortiums, universities, banking alliances, and defense contractors. It enables participating organizations to collaboratively detect sophisticated cyberattacks and train shared machine learning models **without ever disclosing raw network logs, IP addresses, employee identities, or sensitive internal credentials**.

---

## 1. System Architecture

```mermaid
flowchart TD
    subgraph EdgeNodes["Edge Organizations (Universities, Banks, Consortiums)"]
        RawLogs["Raw Network Telemetry\n(IPs, User IDs, Ports, Bytes)"]
        EdgeAgent["Privacy Gateway Agent\n(Salted HMAC, Secret Redaction, Noise Injection)"]
        LocalModel["Local ML Model Training\n(L2 Weight Clipping + Gaussian DP)"]
        RawLogs --> EdgeAgent
        RawLogs --> LocalModel
    end

    subgraph CentralPlatform["Central Threat Detection Platform"]
        IngestAPI["FastAPI Ingest Gateway\n(/api/v1/events)"]
        BoundaryValidation["Second Safety Boundary\n(Strict Pydantic PII Rejection)"]
        
        subgraph DualEngine["Dual Threat Detection Engine (<20ms)"]
            RuleEngine["Deterministic Rule Engine\n(Brute-Force Bursts, Port Sweeps, C2 Backdoors)"]
            MLInference["Random Forest ML Classifier\n(High-Dimensional Network Feature Inference)"]
        end
        
        RiskEngine["Multi-Factor Risk Engine\n(Severity Tiers 0-100)"]
        DPAggregator["DP-FedAvg Server Aggregator\n(Privacy-Preserving Model Convergence)"]
        
        Storage[("Encrypted Persistence\nPostgreSQL / SQLite")]
        WSManager["WebSocket Connection Manager\n(Tenant-Isolated Channels)"]
    end

    subgraph SOCDashboard["Privacy-Compliant SOC Dashboard (Next.js 14)"]
        ThreatFeed["Real-Time Live Threat Feed"]
        RadarMap["Global Threat Vector Radar"]
        Metrics["Telemetry Counters & Latency Tracker"]
        FLPanel["Federated Learning Convergence Monitor"]
    end

    EdgeAgent -->|Sanitized Pseudonyms Only: IP-3F9A1B, DEV-7A21| IngestAPI
    LocalModel -->|Noised Model Gradients (DP)| DPAggregator
    IngestAPI --> BoundaryValidation
    BoundaryValidation --> DualEngine
    RuleEngine --> RiskEngine
    MLInference --> RiskEngine
    RiskEngine --> Storage
    RiskEngine --> WSManager
    DPAggregator --> WSManager
    WSManager -->|Persistent WSS Stream| SOCDashboard
```

---

## 2. Core Capabilities & Privacy Guarantees

### A. Zero-Trust Telemetry Sanitization & Irreversibility
- **Salted HMAC Pseudonymization**: Raw IPv4 addresses, device serials, and employee usernames are irreversibly converted into structured tokens (e.g. `IP-3F9A1B`, `USER-7F31A9`, `DEV-0A8F3C`) using `HMAC-SHA-256` salted with a high-entropy secret.
- **Pre-Image Resistance**: Without the secret salt, recovering original identifiers from output tokens is mathematically infeasible under standard cryptographic assumptions.
- **Strict Boundary Rejection**: If an edge node or attacker attempts to transmit raw IPs, usernames, or API keys, the central API **strictly rejects the request with HTTP 400 Bad Request** before database persistence.

### B. Dual-Engine Threat Detection (<20 ms Latency)
- **Deterministic Heuristic Rules**: Identifies high-speed brute-force authentication bursts, SYN reconnaissance port sweeps, and unauthorized backdoor/reverse shell ports (e.g. 4444, 1337, 31337).
- **Machine Learning Inference**: Pre-trained Random Forest model evaluating packet rates, byte distributions, duration anomalies, and connection densities.
- **Composite Risk Scoring**: Produces normalized risk scores (0–100) and severity ratings (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) with average pipeline latency under 18 ms.

### C. Differential Privacy Federated Learning (DP-FedAvg)
- **Decentralized Model Training**: Participating clients compute model parameter updates locally on private network traces.
- **L2 Gradient Clipping**: Limits the maximum sensitivity of any single client update.
- **Calibrated Gaussian Noise**: Adds differential privacy noise ($\epsilon, \delta$) to aggregated weights before publishing the new global model version. Raw datasets never leave client enclaves.

### D. Privacy-Compliant SOC Dashboard
- **Live Bidirectional WebSocket Stream** (`/ws/threats` and `/ws`): Live telemetry, threat alerts, and federated convergence updates streamed instantly with zero page reloads.
- **Automatic Fallback**: Graceful degradation to Server-Sent Events (SSE) or adaptive HTTP polling if WebSocket connectivity is interrupted, featuring visual connection badges (`LIVE`, `RECONNECTING`, `OFFLINE / POLLING`).
- **Zero-PII Display**: Dashboard strictly renders pseudonymized tokens, coarse geolocation, and sanitized attack vectors.

---

## 3. Environment Variables Reference

### Backend (`backend/.env` / Cloud Host)
| Variable | Description | Default / Example |
|---|---|---|
| `APP_ENV` | Application environment (`development` or `production`) | `development` |
| `DEBUG` | Enable verbose error reporting | `true` |
| `PORT` | Listening HTTP/WS port | `8000` |
| `DATABASE_URL` | Asynchronous database connection string | `sqlite+aiosqlite:///./threat_detection.db` |
| `SECRET_KEY` | 32-byte secret for session signing | Required in production |
| `JWT_SECRET` | 32-byte secret for JWT token issuance | Required in production |
| `PRIVACY_SALT` | Cryptographic salt for HMAC pseudonymization | Required in production |
| `ALLOWED_ORIGINS` | Comma-separated or JSON list of permitted frontend origins | `http://localhost:3000,http://127.0.0.1:3000` |
| `ENABLE_SIMULATOR` | Auto-generate synthetic benign & attack traffic for demos | `true` |
| `SIMULATOR_INTERVAL_SECONDS` | Interval between generated telemetry events | `3.0` |
| `OPERATIONAL_MODE` | Runtime mode (`TEST` or `LIVE`) | `TEST` |

### Frontend (`frontend/.env.local` / Vercel)
| Variable | Description | Default / Example |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | Base HTTP endpoint for backend REST services | `http://127.0.0.1:8000` |
| `NEXT_PUBLIC_WS_URL` | WebSocket endpoint (`ws://` in dev, `wss://` in prod) | `ws://127.0.0.1:8000/ws/threats` |
| `NEXT_PUBLIC_DEMO_MODE` | Allow unauthenticated viewers to observe live demo feeds | `true` |

---

## 4. Local Quickstart

### Method 1: Docker Compose (One-Command Run)
```bash
docker compose up --build
```
- **Frontend Dashboard**: Open [http://localhost:3000](http://localhost:3000)
- **Backend API & Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Live Health Endpoint**: [http://localhost:8000/health](http://localhost:8000/health)

### Method 2: Non-Docker Local Run (Python + Node.js)

#### 1. Start Backend
```bash
# Install dependencies
pip install -r backend/requirements.txt

# Run FastAPI server with WebSocket and Simulator active
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### 2. Start Frontend
```bash
cd frontend
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 5. Verification & Testing

### Backend Test Suite (Pytest)
```bash
# Run 140+ unit, integration, and security tests
python -m pytest backend/tests/ -v
```
Verifies:
- Privacy Gateway & Pre-send edge sanitization
- Irreversibility and avalanche effect of HMAC pseudonyms
- Zero-PII verification across WebSocket broadcast payloads
- Deterministic rules, Random Forest ML inference, and risk scoring latency (<20 ms)
- Multi-tenant data isolation and role-based access control
- Federated learning DP-FedAvg weight aggregation and noise calibration

### Frontend Static & Build Checks
```bash
cd frontend
npm run type-check   # TypeScript compiler verification (0 errors)
npm run lint         # ESLint code health verification (0 warnings/errors)
npm run build        # Production Next.js bundle generation
```

---

## 6. Deployment Guide

### Architecture Split
- **Backend (FastAPI + WebSockets + ML)**: Deployed to a persistent container runtime (**Render**, **Railway**, or **Fly.io**) using `docker/Dockerfile.backend` and `render.yaml`.
- **Frontend (Next.js 14 App Router)**: Deployed to **Vercel** serverless CDN with static optimization.

### Step 1: Deploy Backend to Render / Persistent Host
1. Connect repository on [Render Dashboard](https://dashboard.render.com).
2. Select **Web Service** -> **Docker** (using `docker/Dockerfile.backend`).
3. Set Environment Variables:
   - `APP_ENV=production`
   - `PORT=8000`
   - `SECRET_KEY=<generate-32-byte-secret>`
   - `JWT_SECRET=<generate-32-byte-secret>`
   - `PRIVACY_SALT=<generate-32-byte-secret>`
   - `ALLOWED_ORIGINS=https://privacy-preserving-threat-detection.vercel.app`
   - `ENABLE_SIMULATOR=true`
4. Confirm healthcheck at `https://<backend-domain>/health` returns `{"status": "healthy"}`.

### Step 2: Deploy Frontend to Vercel
1. Link project via Vercel CLI or Vercel Web Dashboard:
   ```bash
   cd frontend
   vercel
   ```
2. Configure Environment Variables on Vercel:
   - `NEXT_PUBLIC_API_URL=https://<your-backend-domain>`
   - `NEXT_PUBLIC_WS_URL=wss://<your-backend-domain>/ws/threats`
   - `NEXT_PUBLIC_DEMO_MODE=true`
3. Trigger production deployment:
   ```bash
   vercel --prod
   ```

---

## 7. 5-Minute Live Presentation Script

1. **Introduction (1 min)**:
   - *"Welcome. This platform solves the core dilemma of modern cybersecurity: organizations want to collaborate against advanced threat actors, but data privacy regulations like GDPR and HIPAA prohibit sharing raw network logs."*
2. **Telemetry Ingestion & Privacy Gateway (1 min)**:
   - Navigate to `/dashboard` and `/privacy/viewer`.
   - Point to the live feed: show how raw IPv4s and user IDs are transformed into irreversibly salted tokens (`IP-3F9A1B`).
   - Mention the two-layer safety boundary that guarantees zero PII leaks.
3. **Dual-Engine Threat Detection & Risk Scoring (1 min)**:
   - Trigger a simulated security scan or watch the built-in simulator stream.
   - Show how the rule engine correlates burst heuristics while the Random Forest classifier calculates confidence scores in under 18 ms.
4. **Interactive Threat Vector Radar (1 min)**:
   - Direct attention to the animated Threat Radar: show pulsing beacons, severity color coding, and vector analysis.
5. **Differential Privacy Federated Learning (1 min)**:
   - Navigate to `/federated-learning`.
   - Show live training rounds: simulated edge nodes (DMZ, Finance, Cloud) training locally, clipping L2 gradients, injecting DP noise, and converging to >97% global accuracy.
