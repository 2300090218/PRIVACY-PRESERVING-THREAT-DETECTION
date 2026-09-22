import pytest

@pytest.mark.asyncio
async def test_health_check_operational(async_client):
    """Verifies that /api/health queries live subsystems and returns READY states."""
    res = await async_client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["api"] is True
    assert data["database"] is True
    assert data["ml_model"] is True
    assert data["websocket"] is True
    assert data["federated_learning"] is True
    assert data["overall_status"] == "HEALTHY"

    subsystems = data["subsystems"]
    assert subsystems["api"] == "HEALTHY"
    assert subsystems["database"] == "READY"
    assert subsystems["threat_detection_ml"] == "READY"
    assert subsystems["websocket_broadcaster"] == "READY"
    assert "telemetry_source" in subsystems

@pytest.mark.asyncio
async def test_status_endpoint(async_client):
    """Verifies that /api/status provides operational status equivalent to /api/health."""
    res = await async_client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert "subsystems" in data
    assert "overall_status" in data
    assert "mode" in data

@pytest.mark.asyncio
async def test_incidents_lifecycle_api(async_client):
    """Verifies incident retrieval and resolution."""
    # List incidents
    res = await async_client.get("/api/incidents")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

    # Create an incident
    create_res = await async_client.post("/api/incidents", json={
        "title": "Suspected Brute Force Campaign",
        "severity": "HIGH",
        "summary": "Multiple automated login failures detected on DMZ."
    })
    assert create_res.status_code == 200
    inc_data = create_res.json()
    inc_id = inc_data["incident_id"]
    assert inc_data["status"] == "OPEN"

    # Fetch incident by ID
    get_res = await async_client.get(f"/api/incidents/{inc_id}")
    assert get_res.status_code == 200
    assert get_res.json()["incident_id"] == inc_id

    # Resolve incident
    resolve_res = await async_client.post(f"/api/incidents/{inc_id}/resolve")
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "RESOLVED"
