# Privacy-Preserving Threat Detection Platform - API Documentation

## Base URLs
- **Central API Service**: `http://127.0.0.1:8000` or `https://central-server.example`
- **Version 1 Base Path**: `/api/v1`
- **Interactive OpenAPI Documentation**: `http://127.0.0.1:8000/docs`
- **ReDoc Documentation**: `http://127.0.0.1:8000/redoc`

---

## Authentication & Authorization

### 1. User Authentication (JWT)
Analysts and administrators authenticate using standard OAuth2 Bearer Tokens.

#### `POST /api/v1/auth/login`
- **Request Body**:
```json
{
  "email": "user@example.com",
  "password": "your_secure_password"
}
```
- **Response** (`200 OK`):
```json
{
  "session_nonce": "nonce_7f2a1b9c...",
  "requires_2fa": true,
  "masked_email": "u***@example.com",
  "expires_in_seconds": 300
}
```

#### `POST /api/v1/auth/verify-otp`
- **Request Body**:
```json
{
  "session_nonce": "nonce_7f2a1b9c...",
  "otp": "123456"
}
```
- **Response** (`200 OK`):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "security-admin@threat-detection.local",
    "role": "ADMIN"
  }
}
```

#### `GET /api/v1/auth/me`
- **Headers**: `Authorization: Bearer <token>`
- **Response** (`200 OK`):
```json
{
  "user_id": 1,
  "username": "admin",
  "email": "security-admin@threat-detection.local",
  "role": "ADMIN",
  "organization_id": "org_enterprise_a"
}
```

---

## Organizations & Multi-Tenancy

### `POST /api/v1/organizations/register`
Registers a new enterprise tenant with boundary isolation.
- **Request Body**:
```json
{
  "org_id": "org_finance_b",
  "name": "Financial Services Group B",
  "contact_email": "soc@finance-b.internal"
}
```
- **Response** (`201 Created`):
```json
{
  "id": 2,
  "org_id": "org_finance_b",
  "name": "Financial Services Group B",
  "status": "ACTIVE",
  "contact_email": "soc@finance-b.internal",
  "created_at": "2026-09-22T08:00:00Z",
  "active_agents": 1,
  "total_events": 0,
  "total_detections": 0
}
```

### `GET /api/v1/organizations`
Returns all registered organizations and their telemetry statistics.

---

## Edge Agents & Credentials

### `POST /api/v1/agents/register`
Registers a new local edge agent within an organization. Returns a unique HMAC API key for authenticated ingestion.
- **Request Body**:
```json
{
  "agent_id": "agent-dmz-01",
  "organization_id": "org_enterprise_a",
  "name": "DMZ Gateway Edge Sensor",
  "version": "1.0.0"
}
```
- **Response** (`201 Created`):
```json
{
  "agent_id": "agent-dmz-01",
  "organization_id": "org_enterprise_a",
  "name": "DMZ Gateway Edge Sensor",
  "status": "ONLINE",
  "api_key": "agent_key_4a91f...",
  "created_at": "2026-09-22T08:00:00Z"
}
```

### `GET /api/v1/agents`
Lists edge agents, optionally filtered by `organization_id`.

### `GET /api/v1/agents/{agent_id}`
Returns status and last-seen telemetry timestamp for a specific edge agent.

---

## Protected Event Ingestion & Second Safety Boundary

### `POST /api/v1/events`
Ingests a **minimized, protected event** from an edge organization agent.

> **CRITICAL SECURITY RULE**: The Central Server enforces a **Server-Side Second Safety Boundary**.
> If any prohibited raw sensitive field (`username`, `source_ip`, `exact_location`, `raw_device_id`, `password`) appears in the payload, the server **rejects the request immediately** with `400 Bad Request`, logs an audit violation, and refuses persistence.

- **Headers**:
  - `X-API-Key`: `<agent_api_key>`
  - `X-Organization-ID`: `org_enterprise_a`
  - `X-Agent-ID`: `agent-dmz-01`
- **Request Body (Protected Representation Only)**:
```json
{
  "event_id": "evt_9918a2bc",
  "organization_id": "org_enterprise_a",
  "agent_id": "agent-dmz-01",
  "timestamp": "2026-09-22T10:15:00Z",
  "event_type": "failed_login",
  "telemetry_source": "TEST",
  "source": "DEV-8F31",
  "device_id": "DEV-8F31",
  "destination_port": 22,
  "protocol": "SSH",
  "failed_attempts": 6,
  "attack_indicators": ["BRUTE_FORCE_PATTERN"],
  "privacy_metadata": {
    "policy_version": "1.0.0",
    "removed_fields": ["username", "source_ip", "location"],
    "pseudonymized_fields": ["device_id->DEV-8F31"]
  }
}
```
- **Response** (`201 Created`):
```json
{
  "status": "ACCEPTED",
  "event_id": "evt_9918a2bc",
  "organization_id": "org_enterprise_a",
  "detection_id": "det_7a1b09",
  "attack_type": "Brute Force",
  "severity": "HIGH",
  "risk_score": 78.5,
  "risk": {
    "score": 78.5,
    "severity": "HIGH",
    "factors": ["6 failed authentication attempts recorded", "Rule-based anomaly threshold triggered"],
    "explanation": "Threat classification: Brute Force. Severity: HIGH. Risk Score: 78.5."
  },
  "detection": {
    "id": "det_7a1b09",
    "attack_type": "Brute Force",
    "severity": "HIGH",
    "confidence": 0.88
  },
  "alert_created": true,
  "alert_id": "alt_1290ff",
  "processing_latency_ms": 1.45
}
```

### `GET /api/v1/events`
Query ingested protected events with pagination (`limit`, `offset`) and `organization_id` filter.

### `GET /api/v1/events/{event_id}`
Returns details of an ingested protected event.

---

## Threat Detections & Alerts

### `GET /api/v1/detections`
Returns detection results from dual-layer Rule Engine and Machine Learning model.
- **Parameters**: `limit`, `offset`, `organization_id`, `attack_type`, `severity`

### `GET /api/v1/alerts`
Returns active alerts generated by deterministic risk scoring.
- **Parameters**: `organization_id`, `status` (`NEW`, `ACKNOWLEDGED`, `RESOLVED`), `severity`

### `PUT /api/v1/alerts/{alert_id}/acknowledge`
Acknowledges an alert with analyst identity and audit log generation.

### `PUT /api/v1/alerts/{alert_id}/resolve`
Resolves an active alert.

---

## Privacy Policies & Live Metrics

### `GET /api/v1/privacy/metrics`
Returns real, calculated counts of data minimization operations:
```json
{
  "processed_events": 142,
  "protected_events": 142,
  "removed_fields": 426,
  "masked_fields": 0,
  "pseudonymized_fields": 142,
  "privacy_violations": 0,
  "transmission_failures": 0,
  "active_policies_count": 8,
  "status": "ENFORCED",
  "zero_raw_retention": true,
  "privacy_guarantee": "Zero raw sensitive telemetry retained or permitted"
}
```

### `GET /api/v1/privacy/policies`
Returns configured per-field transformation rules for an organization.

### `PUT /api/v1/privacy/policies/{policy_id}`
Updates a policy rule (`ALLOW`, `REMOVE`, `MASK`, `PSEUDONYMIZE`, `AGGREGATE`).

### `POST /api/v1/privacy/transform-demo`
Interactive demonstration endpoint for Privacy Transformation Viewer:
Runs candidate raw event through the local Privacy Gateway and returns a 3-stage comparison.

---

## Audit Logs & System Health

### `GET /api/v1/audit-logs`
Returns tamper-evident audit records (`LOGIN`, `INGEST_EVENT`, `POLICY_UPDATED`, `ALERT_ACKNOWLEDGED`, `PRIVACY_LEAKAGE_REJECTED`).

### `GET /api/v1/system/health`
Returns live subsystem status:
- API status
- Database status (live ping & query latency)
- Real-time WebSocket connection counts
- Edge Agent health & active count
- Scikit-learn ML model status
- Telemetry Ingestion Queue status

---

## Real-Time WebSockets

### `WS /api/v1/ws/dashboard`
Bidirectional WebSocket channel streaming live detections, alerts, and system health to cybersecurity dashboards.
- **Events Broadcast**:
  - `event.received`: Ingested event metadata
  - `detection.created`: Detection prediction, confidence, attack type
  - `alert.created`: New alert notification with risk score
  - `alert.updated`: Status changes (acknowledged / resolved)
  - `system.status`: Operational heartbeat
