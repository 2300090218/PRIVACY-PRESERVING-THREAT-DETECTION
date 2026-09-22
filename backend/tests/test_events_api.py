import pytest

@pytest.mark.asyncio
async def test_event_ingestion_api(async_client):
    payload = {
        "client_id": "client-dmz-01",
        "event_type": "network_flow",
        "source": "192.168.1.105",
        "destination": "10.0.0.5",
        "protocol": "TCP",
        "features": {
            "dest_port": 22,
            "flow_duration": 3000.0,
            "total_fwd_packets": 5,
            "total_bwd_packets": 2,
            "fwd_packet_length_mean": 120.0
        },
        "metadata": {
            "user": "developer_test",
            "password": "PasswordToRedact!",
            "asset_type": "internal_server"
        },
        "is_test": True
    }

    res = await async_client.post("/api/events", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "PROCESSED"
    assert "event_id" in data
    assert "prediction" in data
    assert "risk_score" in data
    assert data["privacy_transformations"] >= 1

    # Verify event appears in list
    list_res = await async_client.get("/api/events")
    assert list_res.status_code == 200
    events = list_res.json()
    assert len(events) >= 1

@pytest.mark.asyncio
async def test_health_api(async_client):
    res = await async_client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["database"] is True
    assert data["api"] is True
    assert "subsystems" in data

@pytest.mark.asyncio
async def test_continuous_monitoring_api(async_client):
    # Check initial status
    status_res = await async_client.get("/api/test/continuous/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert "is_running" in status_data
    assert "total_scans" in status_data

    # Start continuous monitoring
    start_res = await async_client.post("/api/test/continuous/start?interval=2.0")
    assert start_res.status_code == 200
    assert start_res.json()["is_running"] is True

    # Stop continuous monitoring
    stop_res = await async_client.post("/api/test/continuous/stop")
    assert stop_res.status_code == 200
    assert stop_res.json()["is_running"] is False

@pytest.mark.asyncio
async def test_event_batch_ingestion_api(async_client):
    batch_payload = [
        {
            "client_id": "client-dmz-01",
            "event_type": "network_flow",
            "source": f"192.168.1.{10 + i}",
            "destination": "10.0.0.1",
            "protocol": "TCP",
            "features": {
                "dest_port": 80 if i % 2 == 0 else 4444,
                "flow_duration": 1500.0,
                "total_fwd_packets": 20 * (i + 1),
                "total_bwd_packets": 5
            },
            "metadata": {
                "asset_type": "web_server"
            },
            "is_test": True
        }
        for i in range(3)
    ]

    res = await async_client.post("/api/events/batch", json=batch_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "BATCH_PROCESSED"
    assert data["count"] == 3
    assert len(data["events"]) == 3
    for ev in data["events"]:
        assert "event_id" in ev
        assert "risk_score" in ev

