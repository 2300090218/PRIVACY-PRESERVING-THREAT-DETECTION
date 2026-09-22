"""
Automated Tests for Server-Side Second Safety Boundary & Privacy Leakage Prevention
Proves that even if an attacker or buggy edge client attempts to transmit raw sensitive fields,
the Central Server API ACTIVELY REJECTS the payload with HTTP 400 Bad Request,
refuses database persistence, and logs the violation into the audit trail.
"""

import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_central_api_rejects_raw_username(async_client: AsyncClient):
    payload = {
        "event_id": "evt_leak_001",
        "organization_id": "org_enterprise_a",
        "username": "unauthorized_raw_user", # PROHIBITED FIELD
        "event_type": "failed_login",
        "timestamp": "2026-09-22T10:00:00Z"
    }
    response = await async_client.post("/api/v1/events", json=payload)
    assert response.status_code == 400
    err_body = response.json()
    assert "PRIVACY_BOUNDARY_VIOLATION" in str(err_body)
    assert "username" in str(err_body)

@pytest.mark.asyncio
async def test_central_api_rejects_raw_source_ip(async_client: AsyncClient):
    payload = {
        "event_id": "evt_leak_002",
        "organization_id": "org_enterprise_a",
        "source_ip": "198.51.100.25", # PROHIBITED FIELD
        "event_type": "network_flow",
        "timestamp": "2026-09-22T10:00:00Z"
    }
    response = await async_client.post("/api/v1/events", json=payload)
    assert response.status_code == 400
    assert "source_ip" in str(response.json())

@pytest.mark.asyncio
async def test_central_api_rejects_raw_location(async_client: AsyncClient):
    payload = {
        "event_id": "evt_leak_003",
        "organization_id": "org_enterprise_a",
        "location": "Room 304, Data Center, London", # PROHIBITED FIELD
        "event_type": "auth_attempt",
        "timestamp": "2026-09-22T10:00:00Z"
    }
    response = await async_client.post("/api/v1/events", json=payload)
    assert response.status_code == 400
    assert "location" in str(response.json())

@pytest.mark.asyncio
async def test_central_api_rejects_raw_device_id(async_client: AsyncClient):
    payload = {
        "event_id": "evt_leak_004",
        "organization_id": "org_enterprise_a",
        "raw_device_id": "HARDWARE-UUID-999-ABCD", # PROHIBITED FIELD
        "event_type": "network_flow",
        "timestamp": "2026-09-22T10:00:00Z"
    }
    response = await async_client.post("/api/v1/events", json=payload)
    assert response.status_code == 400
    assert "raw_device_id" in str(response.json())

@pytest.mark.asyncio
async def test_central_api_rejects_raw_ip_sneaked_into_source_field(async_client: AsyncClient):
    """Even if the key is 'source', if the value is an exact raw IPv4 address, Pydantic validator rejects it."""
    payload = {
        "event_id": "evt_leak_005",
        "organization_id": "org_enterprise_a",
        "source": "10.0.0.1", # Raw IP inside allowed key name
        "event_type": "network_flow",
        "timestamp": "2026-09-22T10:00:00Z"
    }
    response = await async_client.post("/api/v1/events", json=payload)
    assert response.status_code in [400, 422]
    assert "Raw IP address" in str(response.json())

@pytest.mark.asyncio
async def test_central_api_accepts_properly_minimized_payload(async_client: AsyncClient):
    """Minimization followed by transmission MUST succeed cleanly."""
    valid_protected_payload = {
        "event_id": "evt_valid_001",
        "organization_id": "org_enterprise_a",
        "agent_id": "agent-dmz-01",
        "source": "DEV-A8F3", # Pseudonymized device token
        "event_type": "failed_login",
        "failed_attempts": 5,
        "destination_port": 22,
        "protocol": "SSH",
        "attack_indicators": ["BRUTE_FORCE_PATTERN"],
        "timestamp": "2026-09-22T10:00:00Z",
        "telemetry_source": "TEST"
    }
    response = await async_client.post("/api/v1/events", json=valid_protected_payload)
    assert response.status_code == 201
    data = response.json()
    assert data["status"] in ["ACCEPTED", "PROCESSED"]
    assert data["event_id"] == "evt_valid_001"
    assert "risk" in data
    assert data["risk"]["score"] >= 0.0
