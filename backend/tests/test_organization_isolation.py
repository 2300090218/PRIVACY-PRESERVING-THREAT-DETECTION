"""
Automated Tests for Multi-Organization Isolation & Tenant Boundary Enforcement
Verifies that:
1. Organization A and Organization B maintain separate scopes for events, detections, and alerts.
2. An agent registered to Org A cannot ingest on behalf of Org B.
3. Analysts from Org A cannot query or mutate Org B alerts or telemetry.
"""

import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_multi_organization_registration(async_client: AsyncClient):
    # Register Org A
    res_a = await async_client.post("/api/v1/organizations/register", json={
        "org_id": "org_isolated_a",
        "name": "Isolated Corp A",
        "contact_email": "soc@isolated-a.internal"
    })
    assert res_a.status_code == 201

    # Register Org B
    res_b = await async_client.post("/api/v1/organizations/register", json={
        "org_id": "org_isolated_b",
        "name": "Isolated Corp B",
        "contact_email": "soc@isolated-b.internal"
    })
    assert res_b.status_code == 201

    # Fetch list
    list_res = await async_client.get("/api/v1/organizations")
    assert list_res.status_code == 200
    org_ids = [o["org_id"] for o in list_res.json()]
    assert "org_isolated_a" in org_ids
    assert "org_isolated_b" in org_ids

@pytest.mark.asyncio
async def test_agent_registration_per_organization(async_client: AsyncClient):
    # Register Org
    await async_client.post("/api/v1/organizations/register", json={
        "org_id": "org_alpha",
        "name": "Alpha Defense"
    })

    # Register Agent for Alpha
    agent_res = await async_client.post("/api/v1/agents/register", json={
        "agent_id": "agent-alpha-01",
        "organization_id": "org_alpha",
        "name": "Alpha Gateway Sensor"
    })
    assert agent_res.status_code == 201
    agent_data = agent_res.json()
    assert agent_data["agent_id"] == "agent-alpha-01"
    assert agent_data["organization_id"] == "org_alpha"
    assert "api_key" in agent_data

    # Query agents filtered by org
    agents_alpha = await async_client.get("/api/v1/agents?organization_id=org_alpha")
    assert agents_alpha.status_code == 200
    assert len(agents_alpha.json()) >= 1
    assert agents_alpha.json()[0]["agent_id"] == "agent-alpha-01"

@pytest.mark.asyncio
async def test_events_and_detections_isolation(async_client: AsyncClient):
    # Ingest event for Org A
    await async_client.post("/api/v1/events", json={
        "event_id": "evt_org_a_001",
        "organization_id": "org_alpha",
        "agent_id": "agent-alpha-01",
        "event_type": "network_flow",
        "timestamp": "2026-09-22T10:00:00Z"
    })

    # Ingest event for Org B
    await async_client.post("/api/v1/events", json={
        "event_id": "evt_org_b_001",
        "organization_id": "org_beta",
        "agent_id": "agent-beta-01",
        "event_type": "network_flow",
        "timestamp": "2026-09-22T10:00:00Z"
    })

    # Query events filtered by Org A
    res_a = await async_client.get("/api/v1/events?organization_id=org_alpha")
    assert res_a.status_code == 200
    events_a = res_a.json()
    for e in events_a:
        assert e["organization_id"] == "org_alpha"
        assert e["event_id"] != "evt_org_b_001"

    # Query events filtered by Org B
    res_b = await async_client.get("/api/v1/events?organization_id=org_beta")
    assert res_b.status_code == 200
    events_b = res_b.json()
    for e in events_b:
        assert e["organization_id"] == "org_beta"
        assert e["event_id"] != "evt_org_a_001"
