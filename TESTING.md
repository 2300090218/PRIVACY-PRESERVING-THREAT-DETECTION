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
| `test_crypto_privacy.py` | Part 31 Cryptographic Suite | AES-256-GCM roundtrip, fresh nonce verification, tamper detection, HMAC-SHA256 correlation, secret leakage prevention, cross-org isolation |
| `test_aes_gcm_privacy.py` | Part 30 Privacy Engine | Nonce uniqueness, key rotation, coordinate coarsening (AP_REGION_01), 15 Pre-Send Security Validation checks |
| `test_demo_organizations_sharing.py` | Part 32 Cross-Org Sharing & Demo Orgs | KL & GITAM demo org seeding, synthetic people records, cross-org telemetry sharing, 15 privacy invariant validations |
| `test_pre_send_pipeline.py` | Pre-Send Pipeline | Raw IP/PII removal, device pseudonymization, API key/JWT blocking, telemetry optimization |
| `test_privacy_leakage.py` | Leakage Prevention | Central API rejection of unencrypted/raw IPs, locations, credentials, and usernames |
| `test_privacy.py` | Privacy Engine | PII detection, credential `[REDACTED]` masking, HMAC-SHA256 pseudonymization |
| `test_detection.py` | Detection Engines | Rule-based heuristics (brute-force, port sweep, backdoors), ML Random Forest inference |
| `test_risk.py` | Risk Engine | Deterministic risk scoring formula, severity thresholds (`LOW` to `CRITICAL`) |
| `test_pipeline.py` | Event Pipeline | End-to-end ingestion $\rightarrow$ privacy $\rightarrow$ detection $\rightarrow$ risk $\rightarrow$ alert $\rightarrow$ audit |
| `test_federated.py` | Federated Learning | Sample-weighted FedAvg, $L_2$ gradient clipping, global round evaluation |
| `test_health.py` | Health & Subsystems | Subsystem probe evaluations (`ACTIVE`, `DEGRADED`, `OFFLINE`) |
| `test_organization_isolation.py` | Multi-Tenant Isolation | Tenant event separation, agent scoping, zero cross-org data leakage |

---

## 3. Running Automated Tests

### 3.1 Backend Tests
To run the complete test suite (111 tests) with verbose output:
```bash
# Ensure Python virtual environment is activated
python -m pytest backend/tests -v
```

### 3.2 Running Specific Test Suites
```bash
# Run Part 32 Demo Organizations & Cross-Organization Sharing Suite (All 15 tests)
python -m pytest backend/tests/test_demo_organizations_sharing.py -v

# Run Part 31 Cryptographic Privacy Suite (All 15 tests)
python -m pytest backend/tests/test_crypto_privacy.py -v

# Run Part 30 AES-256-GCM & 15 Pre-Send Security Validation Checks
python -m pytest backend/tests/test_aes_gcm_privacy.py -v

# Run Pre-Send Pipeline & Leakage Detection tests
python -m pytest backend/tests/test_pre_send_pipeline.py backend/tests/test_privacy_leakage.py -v

# Run detection engines (Rule + ML)
python -m pytest backend/tests/test_detection.py -v

# Run federated learning and FedAvg aggregation
python -m pytest backend/tests/test_federated.py -v
```

### 3.3 Test Verification Results
All 111 automated test cases execute and pass successfully (100% pass rate):
```text
backend/tests/test_demo_organizations_sharing.py::test_01_both_demo_organizations_load PASSED
backend/tests/test_demo_organizations_sharing.py::test_02_synthetic_people_records_load PASSED
backend/tests/test_demo_organizations_sharing.py::test_03_duplicate_organization_seeding_prevented PASSED
backend/tests/test_demo_organizations_sharing.py::test_04_kl_to_gitam_sharing_works PASSED
backend/tests/test_demo_organizations_sharing.py::test_05_gitam_to_kl_sharing_works PASSED
backend/tests/test_demo_organizations_sharing.py::test_06_raw_ip_not_transmitted_when_prohibited PASSED
backend/tests/test_demo_organizations_sharing.py::test_07_precise_gps_not_transmitted_when_prohibited PASSED
backend/tests/test_demo_organizations_sharing.py::test_08_aes_gcm_encryption_decryption_works PASSED
backend/tests/test_demo_organizations_sharing.py::test_09_modified_ciphertext_fails_authentication PASSED
backend/tests/test_demo_organizations_sharing.py::test_10_wrong_key_fails_decryption PASSED
backend/tests/test_demo_organizations_sharing.py::test_11_aes_gcm_fresh_nonce PASSED
backend/tests/test_demo_organizations_sharing.py::test_12_hmac_pseudonyms_stable_for_same_input_key PASSED
backend/tests/test_demo_organizations_sharing.py::test_13_credentials_blocked_before_transmission PASSED
backend/tests/test_demo_organizations_sharing.py::test_14_receiver_cannot_access_original_sensitive_data PASSED
backend/tests/test_demo_organizations_sharing.py::test_15_public_demo_mode_cannot_access_private_org_data PASSED
...
======================= 111 passed in 77.59s (0:01:17) ========================
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
