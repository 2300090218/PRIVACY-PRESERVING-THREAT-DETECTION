# Privacy-Preserving Threat Detection Platform - Threat Model & Security Posture

## 1. Overview & Scope

This document provides a formal threat model for the distributed **Privacy-Preserving Threat Detection Platform**, evaluating security boundaries, adversarial models, asset exposure risks, and concrete architectural mitigations.

The core boundary principle:
> **Raw sensitive telemetry must never cross the local organization perimeter. Only minimized, policy-transformed representations are transmitted to the central server.**

---

## 2. System Architecture & Trust Boundaries

The system spans two primary trust domains separated by an untrusted network:

```
+-------------------------------------------------------------+
| TRUST DOMAIN 1: LOCAL ORGANIZATION (e.g. Org A, B, C)      |
|                                                             |
|  [Local Collector] -> [Raw Event]                           |
|                            |                                |
|                            v                                |
|  [PRIVACY GATEWAY]  (Policy Engine: REMOVE / MASK / PSEUDO) |
|                            |                                |
|                            v                                |
|  [Resilient Queue] -> [Protected Event Payload]             |
+-------------------------------------------------------------+
                              |
                     HTTPS (TLS 1.3 / API Key)
                              |
+-------------------------------------------------------------+
| TRUST DOMAIN 2: CENTRAL SECURITY PLATFORM                   |
|                                                             |
|  [Central API: /api/v1/events]                              |
|  [Second Safety Boundary Rejection Gate]                    |
|                            |                                |
|  [Dual Threat Engine: Rule + ML] -> [Deterministic Risk]    |
|                            |                                |
|  [PostgreSQL DB] (NO RAW LOGS) -> [WebSocket Manager]       |
|                            |                                |
|                            v                                |
|                 [SOC Central Dashboard]                     |
+-------------------------------------------------------------+
```

### Trust Boundary Analysis:
1. **Local Boundary (Internal DMZ)**: Trusted to access local raw logs (auth logs, IP flows, usernames, physical device IDs). Untrusted to transmit raw logs outside.
2. **Perimeter Boundary (Wire)**: Untrusted. Subject to eavesdropping, tampering, and replay if unencrypted.
3. **Central Boundary (Cloud / SaaS)**: Semi-honest / honest-but-curious or multi-tenant. The central server must detect threats across multiple organizations without learning private employee identities, exact internal IP subnets, or raw hardware identifiers.

---

## 3. Threat Analysis & Mitigations

### 3.1 Threat: Malicious or Compromised Local Agent
- **Description**: An adversary gains administrative control of a local sensor/agent node or deploys a malicious rogue agent attempting to poison central intelligence or exfiltrate enterprise secrets.
- **Risk Level**: High
- **Mitigations**:
  - **API Key Authentication**: Every agent requires a cryptographically strong, distinct API key issued per organization (`X-API-Key` or `Bearer` token).
  - **Organization Isolation**: Agent IDs and tokens are bound to a specific `organization_id`. An agent registered to `org_finance_b` cannot inject events for `org_enterprise_a`.
  - **Pre-Flight Schema Validation**: Payloads are strictly validated with Pydantic. Malformed attributes or extra unmapped parameters are rejected.
  - **Input Sanitization & Range Checks**: Numeric fields (packet counts, durations, ports) enforce valid bounds to prevent integer overflow or injection vectors.

---

### 3.2 Threat: Unauthorized Central API Access
- **Description**: Unauthenticated or unauthorized actors access sensitive API routes (`/api/v1/events`, `/api/v1/alerts`, `/api/v1/privacy/policies`, `/api/v1/audit-logs`).
- **Risk Level**: Critical
- **Mitigations**:
  - **Role-Based Access Control (RBAC)**: Central API separates permissions across roles (`ADMIN`, `SECURITY_ANALYST`, `AUDITOR`, `AGENT`).
  - **Stateless JWT with Expiration**: User authentication requires secure bcrypt-hashed passwords and returns signed HS256/RS256 JWTs with 24-hour expiration.
  - **Multi-Tenant Scoping**: All queries filter implicitly by `current_user.organization_id` unless the user holds global `ADMIN` status. Analysts in Org B cannot retrieve Org A's detections or alerts.

---

### 3.3 Threat: Privacy Leakage (Accidental or Malicious PII Transmission)
- **Description**: Sensitive fields (raw employee usernames, internal RFC1918 IP addresses, physical building locations, raw MAC addresses, or credentials) are transmitted to the central server.
- **Risk Level**: Critical
- **Mitigations**:
  - **Edge-Side Minimization**: The local Privacy Gateway executes *before* serialization. Prohibited fields are stripped (`REMOVE`), credentials redacted (`MASK`), and machine identifiers pseudonymized (`PSEUDONYMIZE`).
  - **Double Safety Boundary (Server-Side Rejection Gate)**: The central API checks incoming request bodies against `FORBIDDEN_RAW_FIELDS` (`username`, `user`, `password`, `source_ip`, `exact_location`, `location`, `raw_device_id`). If present, the request is immediately rejected with `HTTP 400 Bad Request`.
  - **Deep Regex Verification**: Edge validator scans for email addresses, AWS secret keys, private SSH keys, and raw IPv4 patterns before wire transmission.
  - **Zero-Raw-Data Central Storage**: The central PostgreSQL database contains zero tables or columns designed to store raw telemetry.
  - **Automated Regression Tests**: Continuous test suite (`test_privacy_leakage.py`) asserts that forbidden fields raise exceptions and are blocked at both edge and server boundaries.

---

### 3.4 Threat: Compromised Agent or User Credentials
- **Description**: An attacker obtains an agent API key or analyst JWT password.
- **Risk Level**: High
- **Mitigations**:
  - **Key Revocation & Lifecycle**: Central API provides endpoints to immediately revoke or rotate agent API keys (`PUT /api/v1/agents/{id}`).
  - **Salted Password Hashing**: Passwords stored using industry-standard `bcrypt` with salt rounds >= 12.
  - **Audit Trail Attribution**: Every authenticated request logs the `actor`, `action`, `client_ip`, and `timestamp` into an immutable audit log.

---

### 3.5 Threat: Replayed & Duplicate Telemetry
- **Description**: An eavesdropper on the network captures an authenticated event payload and retransmits it to artificially trigger false alerts or bias ML models.
- **Risk Level**: Medium
- **Mitigations**:
  - **Transport Security (HTTPS/TLS)**: Mandatory TLS 1.3 encryption prevents packet capture and plaintext inspection on the wire.
  - **Idempotency Keys (`event_id`)**: Every protected event includes a cryptographically unique `event_id` (UUIDv4). The central database enforces a unique constraint on `event_id`. Duplicate attempts are idempotently acknowledged without re-processing.
  - **Timestamp Freshness**: Payloads include UTC ISO-8601 timestamps. Events exceeding freshness tolerance (e.g. > 15 minutes skew) are flagged.

---

### 3.6 Threat: Malformed & Oversized Telemetry Payloads
- **Description**: Attackers transmit malformed JSON, recursive objects, or 100MB flood payloads to induce Denial of Service (DoS) or memory exhaustion.
- **Risk Level**: Medium
- **Mitigations**:
  - **Pydantic Validation**: Strict schema enforcement drops unexpected nested structures.
  - **Payload Size Limits**: Reverse proxy (Nginx/Envoy) and FastAPI enforce a 1MB maximum payload ceiling.
  - **Rate Limiting**: IP and Agent-level token bucket rate limiters prevent API flooding.

---

### 3.7 Threat: Cross-Organization Data Access (Tenant Confusion)
- **Description**: Organization A maliciously crafts queries or leverages authorization flaws to inspect Organization B's incident history or network behavioral patterns.
- **Risk Level**: Critical
- **Mitigations**:
  - **Strict Logical Partitioning**: Every database query (`ProtectedEvent`, `Detection`, `Alert`, `AuditLog`) is parameter-bound with `WHERE organization_id = :org_id`.
  - **Salt Unlinkability**: Even for pseudonymized identifiers (`device_id`), each organization maintains a distinct secret salt. Device `XYZ` in Org A hashes to `DEV-9B1A`, whereas the identical device name in Org B hashes to `DEV-4E8C`. Cross-organization correlation is mathematically intractable without knowing the private organization salt.

---

### 3.8 Threat: Central Database Compromise
- **Description**: An attacker extracts a full dump of the central PostgreSQL database.
- **Risk Level**: High
- **Mitigations**:
  - **Zero Raw Sensitive Telemetry Stored**: Even with a full database dump, the attacker gains zero employee usernames, zero exact physical locations, and zero raw IP addresses.
  - **Pseudonymized Identifiers Only**: Device IDs and network tokens remain non-reversible HMAC hashes.
  - **Encrypted at Rest**: Storage volumes utilize AES-256 transparent data encryption (CMEK/LUKS).

---

### 3.9 Threat: Machine Learning Model Poisoning & Abuse
- **Description**: Adversaries intentionally craft benign-appearing attacks or adversarial noise to evade ML detection or skew federated model updates.
- **Risk Level**: High
- **Mitigations**:
  - **Dual-Layer Detection (Defense in Depth)**: Even if an attack is engineered to evade the Random Forest ML classifier, deterministic heuristics in the Rule Engine (e.g., brute force sliding window, port scan sweeps) trigger independent detections.
  - **Differential Privacy & Gradient Clipping**: When federated learning is executed, local model updates are clipped using $L_2$ norm bounds ($C = 1.0$) and calibrated Gaussian noise is applied to prevent gradient inversion attacks.
  - **Held-Out Central Validation**: Model updates are evaluated on a central golden benchmark dataset before promotion to `global-model-v*`.

---

## 4. Threat Matrix Summary

| Threat Category | Likelihood | Impact | Severity | Primary Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **Malicious Local Agent** | Low | High | **Medium** | API Key per org, Pydantic schema validation, rate limits |
| **Unauthorized API Access** | Medium | Critical | **High** | JWT Bearer authentication, bcrypt hashing, RBAC |
| **Privacy Leakage (PII)** | High | Critical | **Critical** | Local Privacy Gateway + Server-Side Rejection Gate |
| **Compromised Credentials** | Medium | High | **High** | Key revocation, bcrypt, multi-tenant audit logs |
| **Replayed Telemetry** | Medium | Medium | **Medium** | Unique `event_id` idempotency, TLS 1.3, timestamp check |
| **Malformed Telemetry** | High | Medium | **Medium** | Strict Pydantic parsing, 1MB size limit, input ranges |
| **Cross-Org Data Access** | Medium | Critical | **Critical** | DB query tenant binding, per-org salts for pseudonymization |
| **Central DB Breach** | Low | Critical | **Medium** | Zero raw PII storage architecture, encrypted at rest |
| **ML Model Abuse / Evasion**| Medium | High | **High** | Dual-layer detection (ML + Rules), $L_2$ gradient clipping |

---

## 5. Security Incident Response
If a privacy leakage attempt or unauthorized access is detected:
1. The Central Rejection Gate raises `HTTP 400 Bad Request` or `HTTP 401/403`.
2. A high-priority entry is written to `audit_logs` with action `PRIVACY_LEAKAGE_REJECTED` or `UNAUTHORIZED_ACCESS`.
3. If an agent API key shows anomalous behavior, an administrator can instantly revoke it via `PUT /api/v1/agents/{id}` or delete the API credential.
