import pytest
import numpy as np
from httpx import AsyncClient

from backend.app.federated.aggregation import (
    federated_averaging,
    validate_and_clip_update,
    compute_dp_guarantees,
    add_gaussian_dp_noise
)
from backend.app.federated.server import fl_server
from backend.app.federated.client import FederatedClient
from backend.app.detection.model_manager import model_manager
from backend.tests.conftest import TestingSessionLocal
from ml.datasets.ids_dataset import FEATURE_NAMES

def test_fedavg_aggregation():
    w1 = np.array([1.0, 2.0, 3.0])
    w2 = np.array([3.0, 4.0, 5.0])
    # Weighted 50-50
    avg = federated_averaging([(w1, 100), (w2, 100)])
    np.testing.assert_allclose(avg, np.array([2.0, 3.0, 4.0]))

    # Weighted 75-25
    avg_weighted = federated_averaging([(w1, 300), (w2, 100)])
    np.testing.assert_allclose(avg_weighted, np.array([1.5, 2.5, 3.5]))

def test_weight_clipping():
    large_w = np.array([100.0, 100.0, 100.0])
    clipped = validate_and_clip_update(large_w, clip_threshold=5.0)
    assert np.linalg.norm(clipped) <= 5.0001

def test_differential_privacy_accounting():
    dp_res = compute_dp_guarantees(noise_multiplier=0.05, num_rounds=1, delta=1e-5)
    assert dp_res["is_private"] is True
    assert dp_res["epsilon"] > 0
    assert dp_res["delta"] == 1e-5
    assert "privacy_tier" in dp_res

def test_differential_privacy_noise():
    w = np.array([1.0, 2.0, 3.0])
    noisy_w = add_gaussian_dp_noise(w, clip_threshold=10.0, total_samples=1000, noise_multiplier=0.1, random_seed=42)
    assert not np.array_equal(w, noisy_w)
    assert np.all(np.isfinite(noisy_w))
    diff = np.abs(noisy_w - w)
    assert np.all(diff < 0.1)

@pytest.mark.asyncio
async def test_federated_round_execution():
    async with TestingSessionLocal() as session:
        initial_round = fl_server.current_round
        result = await fl_server.execute_federated_round(db=session, actor="TEST_ORCHESTRATOR")
        await session.commit()

        assert result["round"] == initial_round + 1
        assert f"global-v{initial_round + 1}" in result["model_version"]
        assert result["accuracy"] > 0.80
        assert result["f1"] > 0.80
        assert result["clients_completed"] == 3
        assert "differential_privacy" in result
        assert result["differential_privacy"]["is_private"] is True
        assert result["differential_privacy"]["epsilon"] > 0
        assert fl_server.current_round == initial_round + 1
        assert model_manager.active_version == f"global-v{initial_round + 1}"

def test_client_strict_contract_validation():
    client = fl_server.clients["client-dmz-01"]
    update = client.train_local(
        scaler=model_manager.scaler,
        label_encoder=model_manager.label_encoder,
        n_estimators=5
    )
    assert fl_server._is_valid_client_update(update) is True
    assert isinstance(update["client_id"], str)
    assert isinstance(update["sample_count"], int) and update["sample_count"] > 0
    assert isinstance(update["parameters"], np.ndarray)
    assert len(update["parameters"]) == len(FEATURE_NAMES)
    assert np.all(np.isfinite(update["parameters"]))
    assert isinstance(update["parameter_hash"], str) and len(update["parameter_hash"]) > 0
    assert isinstance(update["trained_estimators"], list) and len(update["trained_estimators"]) == 5
    assert isinstance(update["local_accuracy"], float) and 0.0 <= update["local_accuracy"] <= 1.0
    assert isinstance(update["local_loss"], float) and update["local_loss"] >= 0.0

def test_empty_client_result():
    with pytest.raises(ValueError, match="Cannot perform FedAvg with empty client updates list"):
        federated_averaging([])

def test_none_client_result():
    assert fl_server._is_valid_client_update(None) is False
    assert fl_server._is_valid_client_update({}) is False
    assert fl_server._is_valid_client_update({"client_id": "test", "sample_count": None}) is False

def test_model_shape_mismatch():
    invalid_update = {
        "client_id": "client-corrupt",
        "sample_count": 100,
        "parameters": np.array([1.0, 2.0]),  # Wrong length: expected len(FEATURE_NAMES)
        "parameter_hash": "abc123",
        "trained_estimators": [1],
        "local_loss": 0.2,
        "local_accuracy": 0.95
    }
    assert fl_server._is_valid_client_update(invalid_update) is False

@pytest.mark.asyncio
async def test_one_failed_client_handling():
    async with TestingSessionLocal() as session:
        # Temporarily make one client fail
        original_client = fl_server.clients["client-cloud-03"]
        class FailingClient:
            def train_local(self, **kwargs):
                raise RuntimeError("Simulated network dropout during local training")

        fl_server.clients["client-cloud-03"] = FailingClient()
        try:
            # 2 remaining clients is less than min_clients=3 -> should raise ValueError cleanly
            with pytest.raises(ValueError) as excinfo:
                await fl_server.execute_federated_round(db=session, actor="TEST_PARTIAL")
            assert "Insufficient participating clients" in str(excinfo.value)
            assert "Simulated network dropout" in str(excinfo.value)
        finally:
            fl_server.clients["client-cloud-03"] = original_client

@pytest.mark.asyncio
async def test_zero_valid_clients():
    async with TestingSessionLocal() as session:
        saved_clients = dict(fl_server.clients)
        class DeadClient:
            def train_local(self, **kwargs):
                return None  # Returns None instead of valid update

        fl_server.clients = {cid: DeadClient() for cid in saved_clients}
        try:
            with pytest.raises(ValueError) as excinfo:
                await fl_server.execute_federated_round(db=session, actor="TEST_ZERO")
            assert "Insufficient participating clients" in str(excinfo.value)
        finally:
            fl_server.clients = saved_clients

def test_invalid_participant_configuration():
    saved_clients = dict(fl_server.clients)
    class MissingTrainClient:
        pass
    fl_server.clients["client-broken"] = MissingTrainClient()
    try:
        assert fl_server._is_valid_client_update(None) is False
    finally:
        fl_server.clients = saved_clients

def test_no_raw_sensitive_information_leaks():
    client = fl_server.clients["client-finance-02"]
    update = client.train_local(
        scaler=model_manager.scaler,
        label_encoder=model_manager.label_encoder,
        n_estimators=5
    )
    # Check that update contains NO raw rows, payloads, IP strings, or credentials
    serialized_keys = list(update.keys())
    assert "raw_records" not in serialized_keys
    assert "data" not in serialized_keys
    assert "ip" not in serialized_keys
    assert "password" not in serialized_keys
    assert "token" not in serialized_keys
    assert "secret" not in serialized_keys

@pytest.mark.asyncio
async def test_api_response_schema(async_client: AsyncClient):
    response = await async_client.post("/api/federated/start")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "COMPLETED"
    assert "round" in data and isinstance(data["round"], int)
    assert "model_version" in data and data["model_version"].startswith("global-v")
    assert "metrics" in data
    assert "accuracy" in data["metrics"]
    assert "precision" in data["metrics"]
    assert "recall" in data["metrics"]
    assert "f1" in data["metrics"]
    assert "training_time" in data["metrics"]
    assert "clients_completed" in data["metrics"]

@pytest.mark.asyncio
async def test_regression_none_type_not_subscriptable():
    """
    REGRESSION TEST FOR: 'NoneType' object is not subscriptable.
    Reproduces the exact condition where local_df or eval_df or model_manager was None
    and verifies that the system self-heals, executes training, and never raises TypeError.
    """
    # 1. Test client with local_df = None
    client = FederatedClient("client-reg-test", "nonexistent_partition.csv", "/nonexistent/dir")
    client.local_df = None  # Force None
    # Training must self-heal and NOT throw 'NoneType' object is not subscriptable
    update = client.train_local(scaler=None, label_encoder=None, n_estimators=5)
    assert update is not None
    assert fl_server._is_valid_client_update(update) is True

    # 2. Test server with eval_df = None
    fl_server.eval_df = None  # Force None
    async with TestingSessionLocal() as session:
        result = await fl_server.execute_federated_round(db=session, actor="TEST_REGRESSION")
        assert result is not None
        assert result["accuracy"] > 0.80
        assert result["clients_completed"] == 3
