# REST & WebSocket API Specification

## 1. Authentication & Security Headers

All protected endpoints require an `Authorization` header containing a valid JSON Web Token (JWT):
```http
Authorization: Bearer <JWT_ACCESS_TOKEN>
```

Authorized telemetry client agents may authenticate using their unique Client Secret header:
```http
X-Client-ID: client-dmz-01
X-Client-Key: <PROVISIONED_CLIENT_SECRET>
```

### Roles & Permissions Matrix
| Role | Allowed Endpoints | Description |
| :--- | :--- | :--- |
| `ADMIN` | All endpoints | Complete system administration, model promotion, user provisioning |
| `SECURITY_ANALYST` | Events, Detections, Alerts, Incidents, Privacy, Audit, Metrics | Triage, alert resolution, incident investigation |
| `CLIENT` | `POST /api/events`, `POST /api/federated/update`, `POST /api/clients/heartbeat` | Edge telemetry sensor & federated trainer |
| `VIEWER` | Read-only access to `/api/status`, `/api/metrics`, `/api/health` | Read-only dashboards and monitoring |

---

## 2. API Endpoints

### 2.1 Authentication (`/api/auth`)

#### `POST /api/auth/login`
Authenticates a user and issues an access token.
- **Request Body**:
  ```json
  {
    "username": "admin",
    "password": "AdminPass123!"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
    "token_type": "bearer",
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@threatguard.internal",
      "role": "ADMIN"
    }
  }
  ```

#### `GET /api/auth/me`
Retrieves currently authenticated user metadata.
- **Response `200 OK`**:
  ```json
  {
    "id": 1,
    "username": "admin",
    "email": "admin@threatguard.internal",
    "role": "ADMIN",
    "is_active": true
  }
  ```

---

### 2.2 Security Events (`/api/events`)

#### `POST /api/events`
Ingests an authorized telemetry event. Triggers the privacy, rule, ML, risk, and alert pipelines.
- **Request Body**:
  ```json
  {
    "event_id": "evt-7729-ab4",
    "client_id": "client-dmz-01",
    "event_type": "NETWORK_FLOW",
    "source": "192.168.1.105",
    "destination": "10.0.0.15",
    "protocol": "TCP",
    "features": {
      "duration_sec": 12.5,
      "src_bytes": 1024,
      "dst_bytes": 4096,
      "src_packets": 15,
      "dst_packets": 20,
      "byte_rate": 409.6,
      "packet_rate": 2.8,
      "failed_logins": 0,
      "destination_port": 443,
      "protocol_num": 6,
      "flag_urg_count": 0,
      "flag_syn_count": 1,
      "flag_rst_count": 0,
      "flag_ack_count": 1,
      "flag_fin_count": 0,
      "is_sensitive_port": 0,
      "payload_entropy": 4.12,
      "connection_count_1m": 4
    },
    "metadata": {
      "environment": "DMZ",
      "auth_user": "operator@threatguard.internal"
    }
  }
  ```
- **Response `201 Created`**:
  ```json
  {
    "event_id": "evt-7729-ab4",
    "status": "PROCESSED",
    "privacy_applied": true,
    "sanitized_source": "IP-3F9A1B",
    "detection": {
      "detection_id": "det-9912-dfa",
      "prediction": "MALICIOUS",
      "threat_type": "Brute Force",
      "severity": "HIGH",
      "confidence": 0.942,
      "risk_score": 0.82
    },
    "alert_created": true,
    "processing_latency_ms": 14.8
  }
  ```

#### `GET /api/events`
Lists paginated security events.
- **Query Params**: `page` (default 1), `limit` (default 50), `severity`, `threat_type`, `client_id`

#### `GET /api/events/recent`
Retrieves the 20 most recent ingested events for quick display.

---

### 2.3 Threat Detections (`/api/detections`)

#### `GET /api/detections`
Lists all detected threats.
- **Query Params**: `threat_type`, `severity`, `limit`, `offset`
- **Response `200 OK`**:
  ```json
  [
    {
      "detection_id": "det-9912-dfa",
      "event_id": "evt-7729-ab4",
      "timestamp": "2026-09-12T10:30:15Z",
      "threat_type": "Brute Force",
      "prediction": "MALICIOUS",
      "severity": "HIGH",
      "confidence": 0.942,
      "risk_score": 0.82,
      "model_version": "global-v1",
      "detection_source": "HYBRID_ML_RULE"
    }
  ]
  ```

---

### 2.4 Alerts (`/api/alerts`)

#### `GET /api/alerts`
Retrieves active and historic security alerts.
- **Query Params**: `status` (`NEW`, `ACKNOWLEDGED`, `RESOLVED`), `severity`, `limit`

#### `POST /api/alerts/{id}/acknowledge`
Marks an alert as acknowledged by a security analyst.
- **Response `200 OK`**:
  ```json
  {
    "alert_id": "alt-5512-99",
    "status": "ACKNOWLEDGED",
    "acknowledged_by": "admin",
    "acknowledged_at": "2026-09-12T10:35:00Z"
  }
  ```

#### `POST /api/alerts/{id}/resolve`
Resolves an alert with closure notes.

---

### 2.5 Incidents (`/api/incidents`)

#### `GET /api/incidents`
Lists correlated incident dossiers.

#### `POST /api/incidents`
Creates an incident dossier clustering multiple related alerts.

#### `PATCH /api/incidents/{id}`
Updates incident severity or status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`).

---

### 2.6 Clients (`/api/clients`)

#### `POST /api/clients/register`
Registers a new edge telemetry sensor / federated client.
- **Request Body**:
  ```json
  {
    "client_id": "client-k8s-04",
    "name": "Production EKS Cluster Ingress",
    "ip_address": "10.200.4.12",
    "environment": "CLOUD_VPC"
  }
  ```

#### `GET /api/clients`
Lists all registered clients and their live statuses (`ONLINE`, `OFFLINE`, `TRAINING`, `ERROR`).

---

### 2.7 Federated Learning (`/api/federated`)

#### `GET /api/federated/status`
Returns real-time federated orchestrator state.
- **Response `200 OK`**:
  ```json
  {
    "status": "IDLE",
    "current_round": 1,
    "total_rounds": 5,
    "active_clients": 3,
    "global_model_version": "global-v1",
    "last_accuracy": 0.9729,
    "last_f1": 0.9726,
    "aggregation_method": "FedAvg"
  }
  ```

#### `POST /api/federated/start`
Dispatches a new federated training round across all connected edge nodes.
- **Response `200 OK`**:
  ```json
  {
    "message": "Federated round initiated",
    "round_number": 2,
    "clients_dispatched": ["client-dmz-01", "client-finance-02", "client-cloud-03"]
  }
  ```

---

### 2.8 Privacy Engine (`/api/privacy`)

#### `GET /api/privacy/status`
Returns technical privacy control guarantees.
- **Response `200 OK`**:
  ```json
  {
    "pii_detection": "ACTIVE",
    "pseudonymization": "ACTIVE",
    "data_minimization": "ACTIVE",
    "raw_training_data_shared": "NO",
    "audit_logging": "ACTIVE",
    "redaction_method": "HMAC-SHA256 + Regex Masking"
  }
  ```

#### `GET /api/privacy/events`
Lists all redaction and pseudonymization actions recorded by the privacy engine.

---

### 2.9 Test Mode (`/api/test/run`)

#### `POST /api/test/run`
Executes safe local synthetic attack vectors through the identical ingestion, privacy, detection, risk, alert, and WebSocket pipelines.
- **Request Body**:
  ```json
  {
    "attack_type": "Brute Force",
    "count": 5
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "status": "COMPLETED",
    "events_generated": 5,
    "detections_created": 5,
    "alerts_triggered": 5,
    "mode": "TEST MODE"
  }
  ```

---

### 2.10 Health & Status (`/api/health`, `/api/status`)

#### `GET /api/health`
Returns dynamic health evaluated from active subsystem probes:
```json
{
  "api": "ACTIVE",
  "database": "ACTIVE",
  "ml_model": "ACTIVE",
  "websocket": "ACTIVE",
  "federated_learning": "ACTIVE"
}
```

---

## 3. Real-Time WebSocket Protocol (`/ws`)

### 3.1 Connection
Clients connect to `/ws`. The connection is managed by the ASGI WebSocket Manager.

### 3.2 Message Envelope
All outgoing WebSocket messages follow a strict JSON structure:
```json
{
  "type": "<EVENT_NAME>",
  "timestamp": "2026-09-12T10:30:15.123Z",
  "data": { ... }
}
```

### 3.3 Broadcast Events Catalog
| Event Type | Trigger | Example Payload Summary |
| :--- | :--- | :--- |
| `event.received` | Ingested telemetry event | Event ID, client ID, sanitized source, timestamp |
| `detection.created` | Threat flagged by rule or ML | Detection ID, prediction, attack type, confidence, risk score |
| `alert.created` | High/Critical risk detection | Alert ID, severity, attack type, client ID |
| `incident.updated` | Incident dossier updated | Incident ID, title, status, severity |
| `client.updated` | Client heartbeat/status change | Client ID, status (`ONLINE`/`OFFLINE`/`TRAINING`) |
| `training.started` | FL round initiated | Round number, participants |
| `training.completed`| FL round finished | Round number, new accuracy, f1, global model version |
| `model.updated` | Global model version bumped | New model ID, version, benchmark metrics |
| `system.status` | System health heartbeat | Active subsystem statuses, connected client counts |
