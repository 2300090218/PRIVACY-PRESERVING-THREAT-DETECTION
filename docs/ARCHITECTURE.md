# Distributed Platform Architecture

## Core Architectural Principle
The fundamental principle of the **Privacy-Preserving Threat Detection Platform** is:

> **Raw sensitive telemetry must remain inside the local organization boundary unless a privacy policy explicitly permits a transformed representation.**

Minimization, field redaction, and pseudonymization take place **BEFORE** transmission across network boundaries. The Central Server **NEVER** receives, stores, or processes raw usernames, exact source IP addresses, exact physical locations, or raw hardware IDs.

---

## High-Level Architecture Flow

```mermaid
graph TD
    subgraph Organization_A ["Organization A (Local Boundary)"]
        LocalCollector["Local Telemetry Collector\n(Network & Auth Logs)"] --> LocalGateway["Privacy Gateway\n(Data Minimization Engine)"]
        LocalGateway --> LocalQueue["Resilient Local Queue\n(Idempotency & Exponential Backoff)"]
        LocalLog["Local Audit & Health Logs\n(Raw Telemetry Stored ONLY Here)"] --- LocalCollector
    end

    subgraph Wire ["Encrypted Transport"]
        LocalQueue -->|HTTPS Authenticated API\n(HMAC API Key + Salted Pseudonyms)| CentralAPI
    end

    subgraph Central_Platform ["Central Security Server (Zero Raw Retention)"]
        CentralAPI["Central FastAPI Server\n(Server-Side Second Safety Boundary)"]
        CentralAPI --> RejectionGate{"Check for Prohibited\nRaw PII Fields"}
        RejectionGate -->|Leaked PII Detected| Reject400["HTTP 400 Bad Request\nLog Audit Violation"]
        RejectionGate -->|Only Minimized Telemetry| DualEngine["Dual Threat Detection Engine"]
        
        subgraph Detection ["Threat Detection"]
            DualEngine --> RuleEngine["Rule-Based Engine\n(Heuristics & Signatures)"]
            DualEngine --> MLEngine["Scikit-Learn ML Model\n(Flow Classification & Outliers)"]
        end
        
        DualEngine --> RiskEngine["Deterministic Risk Engine\n(Composite Scoring 0-100)"]
        RiskEngine --> DB[("PostgreSQL Database\n(Protected Events, Detections, Alerts)")]
        DB --> WSManager["WebSocket Broadcaster"]
    end

    subgraph Dashboard ["SOC Management Console"]
        WSManager -->|Real-Time WebSockets| NextJSDashboard["Next.js Cybersecurity Dashboard\n(Threats, Alerts, Privacy Center, Health)"]
    end
```

---

## Component Breakdown

### 1. Local Organization Agent (`agent/`)
- Deployed inside Organization A (or B, C) on the local DMZ / network edge.
- Collects and normalizes local telemetry from auth logs and network flows.
- Enforces strict classification of telemetry:
  - `REAL`: Live enterprise telemetry.
  - `TEST`: Controlled verification events generated for validation.
  - `DEMO`: Synthetic scenario events.
- Maintains an in-memory resilient event queue (`LocalEventQueue`) with delivery states (`PENDING`, `SENT`, `ACKNOWLEDGED`, `FAILED`, `RETRYING`).

### 2. Privacy Gateway (`privacy_gateway/`)
- Sits between local collectors and the outbound network.
- Applies granular per-field privacy policies (`ALLOW`, `REMOVE`, `MASK`, `PSEUDONYMIZE`, `AGGREGATE`).
- Uses salted HMAC-SHA256 pseudonymization with per-organization salts so that different enterprises cannot cross-correlate employee devices.
- Performs pre-flight privacy leakage validation before emitting any packet.

### 3. Server-Side Second Safety Boundary (`backend/app/api/v1/events.py`)
- The Central API acts as a second, independent safety boundary.
- Even if a misconfigured edge agent transmits raw sensitive fields (`username`, `source_ip`, `exact_location`), the central server rejects the payload with HTTP 400 Bad Request.
- The incident is permanently recorded in the central audit trail.

### 4. Dual Threat Detection Engine (`backend/app/detection/`)
- **Rule-Based Layer**: Deterministic heuristics for authentication brute forcing (sliding window >= 4 failures in 30s), rapid multi-port sweeps (>= 8 unique ports in 10s), Trojan/C2 backdoor ports (4444, 1337, 31337), and signature heuristics.
- **Machine Learning Layer**: Trained scikit-learn Random Forest model trained on network flow features (duration, forward/backward packets, inter-arrival time variance, packet sizes). Generates attack probability distributions and explainability feature attributions.

### 5. Deterministic Risk Engine (`backend/app/services/risk_service.py`)
- Calculates quantifiable composite risk scores (0–100):
  - **40%**: Machine Learning Confidence & Severity Weight
  - **30%**: Rule Engine Heuristic Matches
  - **15%**: Event Burst Repetition Frequency Multiplier
  - **15%**: Target Asset Criticality
- Produces deterministic categorical severities: `LOW` (0–39), `MEDIUM` (40–69), `HIGH` (70–89), `CRITICAL` (90–100).

### 6. Relational Database (`backend/app/models/all_models.py`)
- Powered by PostgreSQL with SQLAlchemy async ORM.
- Multi-organization isolation schema (`organizations`, `users`, `agents`, `api_credentials`, `privacy_policies`, `events`, `detections`, `alerts`, `risk_assessments`, `audit_logs`).
- **NO central raw_logs table exists.** Only minimized representations are persisted.

### 7. Real-Time WebSockets (`backend/app/websocket/`)
- Bidirectional async broadcaster pushes live security detections and alerts to connected SOC consoles within milliseconds of ingestion without page reloads.

### 8. SOC Frontend Dashboard (`frontend/`)
- Built with Next.js 14, TypeScript, modern React, and Tailwind CSS.
- Features a professional white/light cybersecurity interface.
- 20 fully pre-rendered static pages covering Live Threats, Alerts, Organizations, Privacy Center, Transformation Viewer, Policies, System Health, and Audit Logs.
