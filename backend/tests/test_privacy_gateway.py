"""
Automated Tests for Privacy Gateway & Data Minimization
Validates that:
1. Blocked sensitive fields (username, exact IP, physical location, raw device ID) NEVER appear in transmitted payloads.
2. Configured policies (ALLOW, REMOVE, MASK, PSEUDONYMIZE, AGGREGATE) function accurately.
3. Pre-flight leakage validation prevents transmission if a violation is detected.
4. Privacy metrics accurately record transformations and counts.
"""

import pytest
from privacy_gateway.gateway import PrivacyGateway
from privacy_gateway.policy_engine import PrivacyPolicyConfig, PolicyAction
from privacy_gateway.leakage_prevention import validate_protected_payload, FORBIDDEN_RAW_FIELDS
from privacy_gateway.metrics import PrivacyMetricsTracker

@pytest.fixture
def gateway():
    return PrivacyGateway(organization_id="org_test_a")

def test_blocked_fields_never_appear_in_transmitted_payload(gateway):
    """
    CRITICAL PROOF: Raw sensitive telemetry MUST NOT cross the boundary.
    """
    raw_event = {
        "event_id": "evt_test_001",
        "username": "secret_corp_admin",
        "source_ip": "192.168.1.150",
        "device_id": "DEVICE-CONFIDENTIAL-44",
        "location": "HQ Executive Suite, Zurich",
        "event_type": "failed_login",
        "failed_attempts": 10,
        "timestamp": "2026-09-22T10:00:00Z"
    }

    protected_event = gateway.process_raw_event(raw_event)

    # 1. Assert raw sensitive keys are completely absent
    for forbidden in ["username", "source_ip", "location", "exact_location"]:
        assert forbidden not in protected_event, f"Privacy Leakage: '{forbidden}' found in transmitted payload!"

    # 2. Assert raw sensitive values do not exist anywhere in the payload string
    payload_str = str(protected_event)
    assert "secret_corp_admin" not in payload_str
    assert "192.168.1.150" not in payload_str
    assert "DEVICE-CONFIDENTIAL-44" not in payload_str
    assert "Zurich" not in payload_str

    # 3. Assert device_id was pseudonymized into a non-reversible token
    assert "device_id" in protected_event
    assert protected_event["device_id"].startswith("DEV-")
    assert protected_event["device_id"] != "DEVICE-CONFIDENTIAL-44"

    # 4. Assert allowable non-sensitive security telemetry is preserved
    assert protected_event["event_type"] == "failed_login"
    assert protected_event["failed_attempts"] == 10
    assert protected_event["organization_id"] == "org_test_a"

    # 5. Run independent leakage validation function
    is_valid, violations = validate_protected_payload(protected_event)
    assert is_valid, f"Validation failed with violations: {violations}"
    assert len(violations) == 0

def test_pseudonymization_is_deterministic_with_same_salt():
    """
    Verifies that the same edge agent produces consistent pseudonymized tokens
    for the same device without revealing the original identifier.
    """
    gw1 = PrivacyGateway(organization_id="org_a", pseudonym_salt="shared_test_salt")
    gw2 = PrivacyGateway(organization_id="org_a", pseudonym_salt="shared_test_salt")

    p1 = gw1.process_raw_event({"device_id": "HOST-ALPHA-01", "event_type": "flow"})
    p2 = gw2.process_raw_event({"device_id": "HOST-ALPHA-01", "event_type": "flow"})

    assert p1["device_id"] == p2["device_id"]
    assert p1["device_id"].startswith("DEV-")
    assert "HOST-ALPHA-01" not in p1["device_id"]

def test_different_salt_produces_unlinkable_tokens():
    """Different organizations cannot correlate device identifiers."""
    gw_a = PrivacyGateway(organization_id="org_a", pseudonym_salt="salt_org_a")
    gw_b = PrivacyGateway(organization_id="org_b", pseudonym_salt="salt_org_b")

    p_a = gw_a.process_raw_event({"device_id": "SHARED-LAPTOP-01", "event_type": "flow"})
    p_b = gw_b.process_raw_event({"device_id": "SHARED-LAPTOP-01", "event_type": "flow"})

    assert p_a["device_id"] != p_b["device_id"]

def test_mask_and_aggregate_policies():
    """Tests PolicyAction.MASK and PolicyAction.AGGREGATE behaviors."""
    config = PrivacyPolicyConfig()
    config.set_policy("destination_host", PolicyAction.MASK, {"mask_char": "*"})
    config.set_policy("duration_seconds", PolicyAction.AGGREGATE, {"tiers": [10, 60, 300]})

    gw = PrivacyGateway(policy_config=config)
    raw = {
        "destination_host": "db-server-01",
        "duration_seconds": 75,
        "event_type": "flow"
    }
    protected = gw.process_raw_event(raw)

    # Hostname masked
    assert protected.get("destination_host") == "db********01"
    # Duration aggregated to tier
    assert protected.get("duration_seconds") == "60-300s"

def test_pre_flight_leakage_detector_blocks_malformed_code():
    """
    If buggy code accidentally inserted a raw IP or raw email into 'source',
    the pre-flight leakage validation MUST detect and reject it.
    """
    leaky_payload = {
        "event_id": "evt_bad_01",
        "organization_id": "org_a",
        "source": "192.168.1.1", # Raw IP leaked
        "event_type": "network_flow"
    }

    is_valid, violations = validate_protected_payload(leaky_payload)
    assert not is_valid
    assert any("raw ip" in v.lower() for v in violations)

def test_privacy_metrics_tracker():
    """Ensures privacy metric counts reflect real operations, never hardcoded."""
    tracker = PrivacyMetricsTracker()
    assert tracker.processed_events == 0

    tracker.record_transformation(
        removed=3,
        masked=1,
        pseudonymized=2,
        violations=0,
        transmitted=True
    )

    summary = tracker.get_summary()
    assert summary["processed_events"] == 1
    assert summary["protected_events"] == 1
    assert summary["removed_fields"] == 3
    assert summary["masked_fields"] == 1
    assert summary["pseudonymized_fields"] == 2
    assert summary["privacy_violations"] == 0
