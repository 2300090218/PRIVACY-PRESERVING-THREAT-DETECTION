# Architecture Documentation

## 1. System Overview

**Privacy-Preserving Threat Detection** is an enterprise-grade collaborative cybersecurity platform designed to ingest security telemetry, detect cyber threats through dual-layer inspection (deterministic rules + scikit-learn ML), sanitize and pseudonymize sensitive identifiers (PII/credentials), generate contextual risk scores, broadcast real-time alerts over WebSockets, and conduct decentralized federated model training across edge clients without centralizing raw client records.

```mermaid
flowchart TD
    subgraph ClientLayer [Client Layer]
        C1[Client 1: DMZ Gateway]
        C2[Client 2: Internal Finance]
        C3[Client 3: Cloud VPC]
    end

    subgraph IngestionPrivacy [Ingestion & Privacy Pipeline]
        TP[Telemetry Ingestion POST /api/events]
        PII[PII Detection & Sanitization Engine]
        SALT[HMAC-SHA256 Pseudonymization]
    end

    subgraph DetectionRisk [Detection & Risk Engine]
        FE[Feature Extractor: 18 Flow Metrics]
        RD[Rule Engine: Auth, Port Sweeps, Backdoors]
        ML[ML Detector: Random Forest Classifier]
        RS[Risk Scoring Engine: Deterministic Composite]
    end

    subgraph PersistenceBroadcasting [Persistence & Real-Time Broadcasting]
        DB[(SQLAlchemy Async: SQLite / PostgreSQL)]
        WS[WebSocket Manager /ws]
        AUDIT[Immutable Audit Logger]
    end

    subgraph Presentation [Frontend Presentation]
        UI[Next.js 14 Web Dashboard]
    end

    C1 & C2 & C3 -->|Authorized Telemetry| TP
    TP --> PII
    PII --> SALT
    SALT --> FE
    FE --> RD & ML
    RD & ML --> RS
    RS --> DB
    RS --> WS
    RS --> AUDIT
    WS --> UI
```

---

## 2. Core Architectural Components

### 2.1 Telemetry Ingestion Pipeline
- **Endpoint**: `POST /api/events`
- **Authentication**: API Key (`X-Client-Key`) or JWT Bearer token with `CLIENT` role.
- **Normalizer**: Validates timestamps (RFC 3339 / ISO 8601), schemas, protocol strings (`TCP`, `UDP`, `ICMP`, etc.), source/destination ports, and packet/byte counters.
- **Latency Measurement**: Captures entry timestamp `t_in` and computes end-to-end processing latency before database commit.

### 2.2 Privacy & Pseudonymization Engine
Before any telemetry is evaluated by detection algorithms or committed to disk, it passes through the privacy transformation pipeline:
1. **PII Detection**:
   - High-entropy credential scanning: Detects authorization headers, bearer tokens, API keys, password fields, private keys (`-----BEGIN PRIVATE KEY-----`).
   - Personal Identifiable Information: RFC 5322 email patterns, E.164 international phone formats, IPv4 / IPv6 addresses.
2. **Redaction**:
   - Credentials, secrets, and auth tokens are replaced with `[REDACTED]`.
3. **Deterministic Pseudonymization**:
   - High-privilege identity fields (usernames, internal private IPs) are hashed using `HMAC-SHA256(field, salt)`.
   - Output formatted with human-readable prefixes (e.g., `USER-A7F9B1`, `IP-9C21A4`).
   - Allows threat frequency correlation without disclosing raw identity metadata.
4. **Data Minimization**:
   - Redundant client environment keys and unnecessary telemetry payloads are discarded before persistence.

### 2.3 Dual-Layer Threat Detection

```mermaid
flowchart LR
    E[Normalized Event] --> RD[Rule Detector]
    E --> ML[ML Inference Detector]
    RD -->|Rule Matches, Severities, Heuristics| C[Combiner / Arbiter]
    ML -->|Prediction, Attack Type, Confidence| C
    C --> RE[Deterministic Risk Engine]
    RE --> Score[Composite Risk Score 0.0 - 1.0]
```

#### Layer 1: Rule-Based Detection Engine
- **Auth Failure Burst Detector**: Maintains a sliding memory window tracking login failures per source. Flags `Brute Force` when 5+ failures occur within 60 seconds.
- **Backdoor Port Detector**: Flags unauthorized connections to known trojan/reverse shell ports (4444, 1337, 31337, 8888, 9999).
- **Port Sweep Detector**: Tracks distinct destination ports accessed by a single host within a 120-second rolling window. Flags `Port Scan` upon traversing >= 15 ports.
- **High-Volume Flood Detector**: Detects abnormal packet rates (> 50,000 packets/sec or > 10 MB/sec). Flags `DDoS / DoS Attack`.

#### Layer 2: Machine Learning Detection Engine
- **Model**: Scikit-Learn Random Forest Classifier trained on network flow benchmarks (CIC-IDS2017 / UNSW-NB15 schema).
- **Features (18 extracted flow metrics)**:
  1. `duration_sec`
  2. `src_bytes`
  3. `dst_bytes`
  4. `src_packets`
  5. `dst_packets`
  6. `byte_rate`
  7. `packet_rate`
  8. `failed_logins`
  9. `destination_port`
  10. `protocol_num`
  11. `flag_urg_count`
  12. `flag_syn_count`
  13. `flag_rst_count`
  14. `flag_ack_count`
  15. `flag_fin_count`
  16. `is_sensitive_port`
  17. `payload_entropy`
  18. `connection_count_1m`
- **Output Classes**: `BENIGN`, `Brute Force`, `Port Scan`, `DoS / DDoS`, `Malware / Botnet`, `Web Attack`.
- **Output Payload**: Prediction classification, attack subtype, confidence probability score (0.0 to 1.0), inference execution latency.

### 2.4 Deterministic Risk Scoring Formula
The risk engine synthesizes model confidence, attack severity, event frequency, asset tier, and rule corroboration into a mathematical score:

$$\text{Base Score} = (\text{Severity Weight} \times 0.35) + (\text{ML Confidence} \times 0.25) + (\text{Rule Corroboration} \times 0.20) + (\text{Asset Tier} \times 0.10) + (\text{Historical Frequency} \times 0.10)$$

Where:
- **Severity Weight**: `LOW` = 0.2, `MEDIUM` = 0.5, `HIGH` = 0.8, `CRITICAL` = 1.0.
- **Rule Corroboration**: Scaled by rule match count (max 1.0).
- **Asset Tier**: `DEVELOPMENT` = 0.2, `INTERNAL` = 0.5, `DMZ` = 0.8, `MISSION_CRITICAL` = 1.0.
- **Historical Frequency**: Logarithmic scaling of repeated offenses from same source.

**Output Categories**:
- `0.00 - 0.39`: **LOW**
- `0.40 - 0.69`: **MEDIUM**
- `0.70 - 0.84`: **HIGH**
- `0.85 - 1.00`: **CRITICAL**

### 2.5 Real-Time WebSocket Bus (`/ws`)
- **Protocol**: Native RFC 6455 WebSockets over ASGI.
- **Heartbeat & Keepalive**: Periodic ping/pong verification with client auto-reconnection.
- **Event Types**:
  - `event.received`: Raw telemetry ingested and sanitized.
  - `detection.created`: Threat evaluated by rule or ML engine.
  - `alert.created`: High/Critical risk detection escalated to security analyst alert.
  - `incident.updated`: Correlated alert cluster assigned or updated.
  - `client.updated`: Client heartbeat or status change (`ONLINE`, `OFFLINE`, `TRAINING`).
  - `training.started`: Federated round dispatched to participating edge nodes.
  - `training.progress`: Intermediate client epoch updates.
  - `training.completed`: Global model aggregation and evaluation complete.
  - `model.updated`: New global model version promoted (`global-v2`, `global-v3`, ...).
  - `system.status`: Overall platform health heartbeat.

---

## 3. Federated Learning Architecture

```mermaid
sequenceDiagram
    participant S as Federated Server
    participant C1 as Client 1 (DMZ)
    participant C2 as Client 2 (Finance)
    participant C3 as Client 3 (Cloud)

    Note over S: Round N Dispatch
    S->>C1: Transmit Current Global Parameters (W_G)
    S->>C2: Transmit Current Global Parameters (W_G)
    S->>C3: Transmit Current Global Parameters (W_G)

    Note over C1,C3: Local Training on Private Data (Raw data NEVER leaves client)
    C1->>C1: Train on Local Partition (N1 samples)
    C2->>C2: Train on Local Partition (N2 samples)
    C3->>C3: Train on Local Partition (N3 samples)

    Note over C1,C3: Parameter Clipping (Differential Privacy)
    C1-->>S: Send Model Update ΔW1, Sample Count N1
    C2-->>S: Send Model Update ΔW2, Sample Count N2
    C3-->>S: Send Model Update ΔW3, Sample Count N3

    Note over S: FedAvg Aggregation & Global Evaluation
    S->>S: W_new = Σ (Ni / N_total) * ΔWi
    S->>S: Evaluate on Held-Out Global Benchmark
    S->>S: Persist New Global Version (global-v{N+1})
    S->>UI: Broadcast model.updated via WebSocket
```

### 3.1 Local Data Isolation
- Raw telemetry records, packet captures, and network flow logs reside solely inside the client's local execution boundary.
- Only model parameter tensors (trees/weights) and sample counts are transmitted upstream.

### 3.2 Secure Aggregation & Differential Privacy (FedAvg)
- **Aggregation**: Federated Averaging weighted by local sample size $N_k$:
  $$W_{t+1} = \sum_{k=1}^K \frac{N_k}{N} W_{t+1}^k$$
- **Gradient/Weight Clipping**: Updates bounding threshold $L_2 \le C$ to prevent malicious poisoning and excessive single-client bias.
- **Differential Privacy (Optional/Configurable)**: Gaussian noise calibrated to sensitivity $S$ added to aggregate weights:
  $$\tilde{W} = W + \mathcal{N}\left(0, \sigma^2 C^2 I\right)$$

---

## 4. Storage & Persistence Schema

The database persistence layer is fully asynchronous, supporting SQLite for local zero-dependency testing and PostgreSQL for production deployments:

| Table Name | Description | Key Indexes |
| :--- | :--- | :--- |
| `users` | User accounts and credential hashes | `username`, `email` |
| `clients` | Registered telemetry clients | `client_id`, `status` |
| `events` | Normalized security telemetry | `event_id`, `timestamp`, `client_id` |
| `detections` | ML and rule classification records | `detection_id`, `timestamp`, `severity`, `threat_type` |
| `alerts` | Actionable security alerts | `alert_id`, `timestamp`, `status`, `severity` |
| `incidents` | Incident correlation dossiers | `incident_id`, `status`, `severity` |
| `threat_indicators` | Known indicators of compromise (IoCs) | `indicator_value`, `indicator_type` |
| `training_rounds` | Federated learning rounds | `round_number`, `status` |
| `model_versions` | Versioned global models and metrics | `version`, `model_id` |
| `client_model_updates`| Local model updates received from clients | `round_id`, `client_id` |
| `privacy_events` | Logs of PII redactions and pseudonymization | `timestamp`, `event_id`, `action_type` |
| `audit_logs` | Immutable security audit trail | `timestamp`, `actor`, `action`, `resource` |
| `system_metrics` | Real subsystem health telemetry | `timestamp`, `metric_name` |
