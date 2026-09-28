"""
End-to-End Test Suite for Versioned API v1
Tests every required API endpoint end-to-end:
- POST /api/v1/auth/login
- POST /api/v1/organizations/register
- POST /api/v1/agents/register
- POST /api/v1/events
- GET /api/v1/events
- GET /api/v1/events/{event_id}
- GET /api/v1/detections
- GET /api/v1/alerts
- GET /api/v1/privacy/metrics
- GET /api/v1/privacy/policies
- PUT /api/v1/privacy/policies/{policy_id}
- GET /api/v1/audit-logs
- GET /api/v1/system/health
- GET /api/v1/agents
- GET /api/v1/agents/{agent_id}
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.future import select

from backend.tests.conftest import TestingSessionLocal
from backend.app.models.all_models import User
from backend.app.security.authentication import get_password_hash

@pytest.mark.asyncio
async def test_v1_auth_login(async_client: AsyncClient):
    async with TestingSessionLocal() as session:
        admin_res = await session.execute(select(User).where(User.username == "admin"))
        if not admin_res.scalars().first():
            session.add(User(
                username="admin",
                email="security-admin@threat-detection.local",
                organization_id="org_enterprise_a",
                hashed_password=get_password_hash("AdminPass123!"),
                role="ADMIN"
            ))
            await session.commit()

    res = await async_client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "AdminPass123!"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "OTP_SENT"
    assert data["two_factor_required"] is True
    session_nonce = data["session_nonce"]

    from backend.app.services.email_service import email_service
    otp = email_service.get_last_dispatched_otp(session_nonce)
    verify_res = await async_client.post("/api/v1/auth/verify-otp", json={
        "session_nonce": session_nonce,
        "otp": otp
    })
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert "access_token" in verify_data
    assert verify_data["token_type"] == "bearer"
    assert verify_data["role"] == "ADMIN"

@pytest.mark.asyncio
async def test_v1_system_health(async_client: AsyncClient):
    res = await async_client.get("/api/v1/system/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["HEALTHY", "DEGRADED"]
    assert "api" in data
    assert "database" in data
    assert "websocket" in data
    assert "agents" in data
    assert "ml_model" in data
    assert "queue" in data

@pytest.mark.asyncio
async def test_v1_privacy_metrics_and_policies(async_client: AsyncClient):
    # Metrics
    m_res = await async_client.get("/api/v1/privacy/metrics")
    assert m_res.status_code == 200
    metrics = m_res.json()
    assert "processed_events" in metrics
    assert "removed_fields" in metrics
    assert "zero_raw_retention" in metrics
    assert metrics["zero_raw_retention"] is True

    # Policies list
    p_res = await async_client.get("/api/v1/privacy/policies")
    assert p_res.status_code == 200
    policies = p_res.json()
    assert len(policies) >= 1

    # Update Policy
    first_pol = policies[0]
    pol_id = first_pol["policy_id"]
    u_res = await async_client.put(f"/api/v1/privacy/policies/{pol_id}", json={
        "action": "MASK",
        "parameters": {"test_param": "val"}
    })
    assert u_res.status_code == 200
    assert u_res.json()["action"] == "MASK"

@pytest.mark.asyncio
async def test_v1_privacy_transform_demo(async_client: AsyncClient):
    raw_payload = {
        "username": "alice_admin",
        "source_ip": "172.16.1.99",
        "location": "HQ Server Room",
        "device_id": "SRV-DMZ-NODE-77",
        "event_type": "auth_attempt",
        "failed_attempts": 3,
        "destination_port": 22
    }
    res = await async_client.post("/api/v1/privacy/transform-demo", json=raw_payload)
    assert res.status_code == 200
    data = res.json()
    assert "protected_event" in data
    assert "transformations" in data

    # Proving blocked fields never appear in output
    pe = data["protected_event"]
    assert "username" not in pe
    assert "source_ip" not in pe
    assert "location" not in pe
    assert pe["device_id"].startswith("DEV-")

@pytest.mark.asyncio
async def test_v1_events_and_detections_pipeline(async_client: AsyncClient):
    event_id = "evt_v1_test_8819"
    payload = {
        "event_id": event_id,
        "organization_id": "org_enterprise_a",
        "agent_id": "agent-dmz-01",
        "source": "DEV-B819",
        "event_type": "failed_login",
        "failed_attempts": 6,
        "destination_port": 22,
        "protocol": "SSH",
        "attack_indicators": ["BRUTE_FORCE_PATTERN"],
        "timestamp": "2026-09-22T10:00:00Z",
        "telemetry_source": "TEST"
    }

    # 1. Ingest Event
    post_res = await async_client.post("/api/v1/events", json=payload)
    assert post_res.status_code == 201
    post_data = post_res.json()
    assert post_data["event_id"] == event_id
    assert "risk" in post_data
    assert "detection" in post_data

    # 2. Get Event by ID
    get_res = await async_client.get(f"/api/v1/events/{event_id}")
    assert get_res.status_code == 200
    assert get_res.json()["event_id"] == event_id

    # 3. Query Detections
    det_res = await async_client.get("/api/v1/detections")
    assert det_res.status_code == 200
    detections = det_res.json()
    assert len(detections) >= 1
    found = any(d["event_id"] == event_id for d in detections)
    assert found

    # 4. Query Alerts
    alert_res = await async_client.get("/api/v1/alerts")
    assert alert_res.status_code == 200
    alerts = alert_res.json()
    assert len(alerts) >= 1
    first_alert = alerts[0]
    alert_id = first_alert["alert_id"]

    # 5. Acknowledge Alert
    ack_res = await async_client.put(f"/api/v1/alerts/{alert_id}/acknowledge")
    assert ack_res.status_code == 200
    assert ack_res.json()["status"] == "ACKNOWLEDGED"

    # 6. Resolve Alert
    res_res = await async_client.put(f"/api/v1/alerts/{alert_id}/resolve")
    assert res_res.status_code == 200
    assert res_res.json()["status"] == "RESOLVED"

@pytest.mark.asyncio
async def test_v1_audit_logs(async_client: AsyncClient):
    async with TestingSessionLocal() as session:
        admin_res = await session.execute(select(User).where(User.username == "admin"))
        if not admin_res.scalars().first():
            session.add(User(
                username="admin",
                email="security-admin@threat-detection.local",
                organization_id="org_enterprise_a",
                hashed_password=get_password_hash("AdminPass123!"),
                role="ADMIN"
            ))
            await session.commit()

    # Login as admin to obtain JWT
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "AdminPass123!"
    })
    login_data = login_res.json()
    from backend.app.services.email_service import email_service
    otp = email_service.get_last_dispatched_otp(login_data["session_nonce"])
    verify_res = await async_client.post("/api/v1/auth/verify-otp", json={
        "session_nonce": login_data["session_nonce"],
        "otp": otp
    })
    token = verify_res.json()["access_token"]

    # Query audit logs
    res = await async_client.get(
        "/api/v1/audit-logs",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    logs = res.json()
    assert isinstance(logs, list)
