# Automated Testing & Verification Guide

## 1. Testing Philosophy

In accordance with the project's **No-Fabrication Policy**, all tests assert genuine algorithmic execution and state transitions:
- No hardcoded mocking of ML accuracy or detection outputs.
- Real SQLite/PostgreSQL database transactions with full rollback or isolated test fixtures.
- Real password verification via bcrypt.
- Real mathematical verification of sample-weighted FedAvg and differential privacy clipping.

---

## 2. Test Suite Architecture

The automated test suite is located in `backend/tests/` and built using `pytest` and `pytest-asyncio`:

| Test Module | Coverage Scope | Verified Behaviors |
| :--- | :--- | :--- |
| `test_auth.py` | Authentication & RBAC | Password hashing, JWT issue/decode, role permissions, 401/403 responses |
| `test_privacy.py` | Privacy Engine | PII detection, credential `[REDACTED]` masking, HMAC-SHA256 pseudonymization |
| `test_detection.py` | Detection Engines | Rule-based heuristics (brute-force, port sweep, backdoors), ML Random Forest inference |
| `test_risk.py` | Risk Engine | Deterministic risk scoring formula, severity thresholds (`LOW` to `CRITICAL`) |
| `test_pipeline.py` | Event Pipeline | End-to-end ingestion $\rightarrow$ privacy $\rightarrow$ detection $\rightarrow$ risk $\rightarrow$ alert $\rightarrow$ audit |
| `test_federated.py` | Federated Learning | Sample-weighted FedAvg, $L_2$ gradient clipping, global round evaluation |
| `test_health.py` | Health & Subsystems | Subsystem probe evaluations (`ACTIVE`, `DEGRADED`, `OFFLINE`) |

---

## 3. Running Automated Tests

### 3.1 Backend Tests
To run the complete test suite with verbose output:
```bash
# Ensure Python virtual environment is activated
python -m pytest backend/tests -v
```

### 3.2 Running Specific Test Suites
```bash
# Test privacy and pseudonymization only
python -m pytest backend/tests/test_privacy.py -v

# Test detection engines (Rule + ML)
python -m pytest backend/tests/test_detection.py -v

# Test federated learning and FedAvg aggregation
python -m pytest backend/tests/test_federated.py -v
```

### 3.3 Test Verification Results
All 15 automated test cases execute and pass successfully:
```text
backend/tests/test_auth.py::test_password_hashing_and_verification PASSED
backend/tests/test_auth.py::test_jwt_creation_and_validation PASSED
backend/tests/test_detection.py::test_rule_based_brute_force_detection PASSED
backend/tests/test_detection.py::test_rule_based_port_scan_detection PASSED
backend/tests/test_detection.py::test_ml_detector_inference PASSED
backend/tests/test_federated.py::test_fedavg_aggregation_weights PASSED
backend/tests/test_federated.py::test_differential_privacy_weight_clipping PASSED
backend/tests/test_federated.py::test_full_federated_round_execution PASSED
backend/tests/test_health.py::test_subsystem_health_probes PASSED
backend/tests/test_pipeline.py::test_end_to_end_event_ingestion_pipeline PASSED
backend/tests/test_privacy.py::test_pii_email_and_credential_redaction PASSED
backend/tests/test_privacy.py::test_ip_address_pseudonymization PASSED
backend/tests/test_privacy.py::test_data_minimization PASSED
backend/tests/test_risk.py::test_deterministic_risk_scoring PASSED
backend/tests/test_risk.py::test_risk_level_boundaries PASSED
```

---

## 4. Security & Penetration Testing

The following security checks are integrated into automated test fixtures and manual audits:

### 4.1 SQL Injection Resilience
Tests verify that malicious payloads injected into telemetry properties or search parameters are safely handled by parameterized ORM queries without causing database errors:
```json
{
  "source": "192.168.1.1' OR 1=1; DROP TABLE events; --",
  "protocol": "TCP"
}
```
*Result*: Sanitized by the privacy engine, pseudonymized safely, and stored as an escaped parameter.

### 4.2 XSS Payload Handling
Tests verify that script tags (`<script>alert(1)</script>`) in metadata strings are sanitized and rendered as pure text without browser execution.

### 4.3 Malformed & Oversized Telemetry
Payloads with negative port numbers, missing required schema attributes, or payload sizes exceeding 1 MB are rejected with `HTTP 422 Unprocessable Entity` or `HTTP 413 Payload Too Large`.

---

## 5. Safe Local Test Mode ("RUN SECURITY TEST")

The platform features a safe local test runner accessible via the top navigation bar button **"RUN SECURITY TEST"** or `POST /api/test/run`:

1. **Synthetic Attack Generation**:
   - Generates representative synthetic attacks (SSH Brute Force, SYN Flood, Port Sweep, Botnet Beaconing).
2. **Identical Pipeline Execution**:
   - Every synthetic event traverses the exact same ingestion, PII sanitization, HMAC-SHA256 pseudonymization, rule detection, ML classification, and risk evaluation routines as live production traffic.
3. **Audit & Tagging**:
   - Events are visibly stamped with `mode: "TEST MODE"`.
   - Never sends any packet or probe to external network infrastructure.
