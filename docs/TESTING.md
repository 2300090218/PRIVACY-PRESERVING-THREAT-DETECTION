# Automated Testing & Verification Guide

## 1. Testing Philosophy & Strict Standards

In accordance with the project's **No-Fabrication Policy**, all tests assert genuine algorithmic execution, cryptographic integrity, and state transitions:
- **No Mock Detections or Synthetic Statistics**: Tests execute real rules and real scikit-learn ML models.
- **Real Database Transactions**: Async sessions test schema constraints, foreign keys, unique idempotency keys, and tenant isolation.
- **Real Password Hashing**: Real bcrypt hashing with work factor salts.
- **Mathematical Privacy Verification**: Verifies HMAC-SHA256 pseudonymization, policy transformations (`REMOVE`, `MASK`, `PSEUDONYMIZE`, `AGGREGATE`), and server-side rejection gates.
- **Zero Leakage Invariants**: Rigorously proves that blocked raw PII fields cannot cross the privacy boundary or enter database storage.

---

## 2. Test Suite Architecture (52 Automated Tests)

The test suite is structured into 12 modular test files under `backend/tests/`:

| Test Suite File | Test Cases | Scope & Tested Invariants |
|---|:---:|---|
| `test_privacy_leakage.py` | 6 | **Zero Leakage Proofs**: Verifies raw username, exact IP, exact location, raw device ID, and AWS/email regexes are blocked at edge gateway and rejected at server gate with HTTP 400. |
| `test_privacy_gateway.py` | 6 | **Gateway Transformation**: Tests `transform_event()` for `REMOVE`, `MASK`, `PSEUDONYMIZE`, and `AGGREGATE`. Verifies deterministic per-org salted HMAC tokens. |
| `test_privacy.py` | 4 | **Core Privacy Logic**: Regex PII redaction, token masking, deterministic HMAC salting, data minimization filters. |
| `test_v1_api.py` | 6 | **Versioned V1 API**: Comprehensive tests for `/api/v1/events`, `/api/v1/detections`, `/api/v1/alerts`, `/api/v1/privacy/metrics`, `/api/v1/privacy/policies`, `/api/v1/system/health`. |
| `test_organization_isolation.py` | 3 | **Multi-Tenancy Isolation**: Asserts Org A cannot view Org B events, alerts, or audit logs. Tests salt unlinkability between tenants. |
| `test_agent_queue.py` | 5 | **Resilient Edge Queue**: Tests event queueing, delivery states (`PENDING`, `SENT`, `ACKNOWLEDGED`, `FAILED`, `RETRYING`), exponential backoff, and duplicate prevention. |
| `test_detection.py` | 4 | **Dual Detection Engine**: Sliding-window brute force (>=4 failed logins in 30s), port sweep heuristics (>=8 ports in 10s), backdoor ports (4444, 1337), scikit-learn Random Forest ML classifier. |
| `test_risk.py` | 4 | **Deterministic Risk Engine**: Composite risk scoring formula ($0.40 S_{\text{ML}} + 0.30 S_{\text{Rule}} + 0.15 S_{\text{Freq}} + 0.15 S_{\text{Asset}}$), categorical severity bounds (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `test_auth.py` | 2 | **Authentication & RBAC**: Password hashing verification, JWT creation/decoding, role permissions (`ADMIN` vs `SECURITY_ANALYST`). |
| `test_events_api.py` | 4 | **Event Ingestion Endpoints**: Validates payload schemas, idempotency on repeated `event_id`, and rejection of malformed events. |
| `test_health.py` | 3 | **Subsystem Health Probes**: Live checks for Database, API, WebSocket, Agents, ML Model, and Queue subsystems. |
| `test_federated.py` | 5 | **Federated Learning Module**: Sample-weighted FedAvg aggregation, differential privacy $L_2$ gradient clipping, global round evaluation on test sets. |

**Total Test Count**: **52 Passed, 0 Failed, 0 Skipped.**

---

## 3. Running the Test Suite

### 3.1 Full Test Suite Execution
To run all 52 tests with verbose reporting:

```bash
# Run from repository root
python -m pytest backend/tests -v
```

Expected output:
```text
============================= test session starts =============================
platform win32 -- Python 3.12.x, pytest-8.3.4, pluggy-1.5.0
plugins: anyio-4.8.0, asyncio-0.25.3
collected 52 items

backend/tests/test_agent_queue.py::test_queue_enqueue_and_peek PASSED    [  1%]
backend/tests/test_agent_queue.py::test_queue_state_transitions PASSED   [  3%]
backend/tests/test_agent_queue.py::test_exponential_backoff PASSED       [  5%]
backend/tests/test_agent_queue.py::test_idempotent_duplicate_prevention PASSED [  7%]
backend/tests/test_agent_queue.py::test_max_retry_limit PASSED           [  9%]
backend/tests/test_auth.py::test_password_hashing_and_verification PASSED [ 11%]
backend/tests/test_auth.py::test_jwt_creation_and_validation PASSED     [ 13%]
backend/tests/test_detection.py::test_rule_based_brute_force_detection PASSED [ 15%]
backend/tests/test_detection.py::test_rule_based_port_scan_detection PASSED [ 17%]
backend/tests/test_detection.py::test_ml_detector_inference PASSED       [ 19%]
backend/tests/test_detection.py::test_dual_detection_engine_aggregation PASSED [ 21%]
backend/tests/test_events_api.py::test_ingest_valid_protected_event PASSED [ 23%]
backend/tests/test_events_api.py::test_ingest_duplicate_event_idempotent PASSED [ 25%]
backend/tests/test_events_api.py::test_ingest_malformed_event_rejected PASSED [ 26%]
backend/tests/test_events_api.py::test_get_events_list_and_detail PASSED [ 28%]
backend/tests/test_federated.py::test_fedavg_aggregation_weights PASSED  [ 30%]
backend/tests/test_federated.py::test_differential_privacy_weight_clipping PASSED [ 32%]
backend/tests/test_federated.py::test_full_federated_round_execution PASSED [ 34%]
backend/tests/test_federated.py::test_federated_client_gradient_generation PASSED [ 36%]
backend/tests/test_federated.py::test_federated_aggregator_convergence PASSED [ 38%]
backend/tests/test_health.py::test_subsystem_health_probes PASSED        [ 40%]
backend/tests/test_health.py::test_health_endpoint_response_structure PASSED [ 42%]
backend/tests/test_health.py::test_health_degraded_state_handling PASSED [ 44%]
backend/tests/test_organization_isolation.py::test_organization_data_isolation PASSED [ 46%]
backend/tests/test_organization_isolation.py::test_cross_org_detection_access_forbidden PASSED [ 48%]
backend/tests/test_organization_isolation.py::test_salt_unlinkability_across_orgs PASSED [ 50%]
backend/tests/test_privacy.py::test_pii_email_and_credential_redaction PASSED [ 51%]
backend/tests/test_privacy.py::test_ip_address_pseudonymization PASSED   [ 53%]
backend/tests/test_privacy.py::test_data_minimization PASSED             [ 55%]
backend/tests/test_privacy.py::test_privacy_event_audit_logging PASSED   [ 57%]
backend/tests/test_privacy_gateway.py::test_gateway_remove_fields PASSED [ 59%]
backend/tests/test_privacy_gateway.py::test_gateway_mask_fields PASSED   [ 61%]
backend/tests/test_privacy_gateway.py::test_gateway_pseudonymize_device_id PASSED [ 63%]
backend/tests/test_privacy_gateway.py::test_gateway_aggregate_fields PASSED [ 65%]
backend/tests/test_privacy_gateway.py::test_gateway_rejection_of_untransformed_pii PASSED [ 67%]
backend/tests/test_privacy_gateway.py::test_gateway_end_to_end_transformation PASSED [ 69%]
backend/tests/test_privacy_leakage.py::test_blocked_username_never_transmitted PASSED [ 71%]
backend/tests/test_privacy_leakage.py::test_blocked_source_ip_never_transmitted PASSED [ 73%]
backend/tests/test_privacy_leakage.py::test_blocked_location_never_transmitted PASSED [ 75%]
backend/tests/test_privacy_leakage.py::test_raw_device_id_never_transmitted PASSED [ 76%]
backend/tests/test_privacy_leakage.py::test_central_rejection_gate_rejects_raw_pii PASSED [ 78%]
backend/tests/test_privacy_leakage.py::test_only_allowlisted_fields_reach_database PASSED [ 80%]
backend/tests/test_risk.py::test_deterministic_risk_scoring PASSED       [ 82%]
backend/tests/test_risk.py::test_risk_level_boundaries PASSED            [ 84%]
backend/tests/test_risk.py::test_frequency_burst_multiplier PASSED      [ 86%]
backend/tests/test_risk.py::test_risk_factors_explanation_structure PASSED [ 88%]
backend/tests/test_v1_api.py::test_v1_health_endpoint PASSED             [ 90%]
backend/tests/test_v1_api.py::test_v1_auth_login_and_me PASSED           [ 92%]
backend/tests/test_v1_api.py::test_v1_events_and_detections_pipeline PASSED [ 94%]
backend/tests/test_v1_api.py::test_v1_alerts_acknowledgement_lifecycle PASSED [ 96%]
backend/tests/test_v1_api.py::test_v1_privacy_metrics_and_policies PASSED [ 98%]
backend/tests/test_v1_api.py::test_v1_audit_logs_rbac PASSED             [100%]

============================= 52 passed in 37.78s =============================
```

---

## 4. Specific Test Suite Execution

### 4.1 Privacy Leakage & Boundary Enforcement Tests
Verifies that prohibited fields (`username`, `source_ip`, `exact_location`, `device_id`) cannot bypass the edge gateway, and that the central API server-side rejection gate raises `HTTP 400 Bad Request` if raw PII arrives:
```bash
python -m pytest backend/tests/test_privacy_leakage.py backend/tests/test_privacy_gateway.py -v
```

### 4.2 Multi-Organization Isolation Tests
Verifies logical partitioning between Organization A, B, and C:
```bash
python -m pytest backend/tests/test_organization_isolation.py -v
```

### 4.3 Dual Threat Detection & Risk Tests
Verifies deterministic rule heuristics, scikit-learn ML inference, and risk scoring:
```bash
python -m pytest backend/tests/test_detection.py backend/tests/test_risk.py -v
```

### 4.4 Central V1 API Tests
Verifies all REST API v1 endpoints with database transactions:
```bash
python -m pytest backend/tests/test_v1_api.py -v
```

---

## 5. Frontend Verification & Build Check

The Next.js 14 frontend includes end-to-end type validation and pre-rendering checks:

```bash
cd frontend
npm run build
```
Expected output:
```text
✓ Compiled successfully
✓ Generating static pages (20/20)
✓ Finalizing page optimization
```
All 20 routes (`/dashboard`, `/threats`, `/alerts`, `/events`, `/organizations`, `/privacy/viewer`, `/privacy/policies`, `/health`, `/audit`, `/federated-learning`, etc.) compile without any TypeScript errors or unresolved imports.
