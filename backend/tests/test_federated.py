import pytest
import numpy as np
from backend.app.federated.aggregation import federated_averaging, validate_and_clip_update
from backend.app.federated.server import fl_server
from backend.tests.conftest import TestingSessionLocal

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
    from backend.app.federated.aggregation import compute_dp_guarantees
    dp_res = compute_dp_guarantees(noise_multiplier=0.05, num_rounds=1, delta=1e-5)
    assert dp_res["is_private"] is True
    assert dp_res["epsilon"] > 0
    assert dp_res["delta"] == 1e-5
    assert "privacy_tier" in dp_res

def test_differential_privacy_noise():
    from backend.app.federated.aggregation import add_gaussian_dp_noise
    w = np.array([1.0, 2.0, 3.0])
    noisy_w = add_gaussian_dp_noise(w, clip_threshold=10.0, total_samples=1000, noise_multiplier=0.1, random_seed=42)
    assert not np.array_equal(w, noisy_w)
    assert np.all(np.isfinite(noisy_w))
    # Noise should be bounded by sensitivity
    diff = np.abs(noisy_w - w)
    assert np.all(diff < 0.1)

@pytest.mark.asyncio
async def test_federated_round_execution():
    async with TestingSessionLocal() as session:
        result = await fl_server.execute_federated_round(db=session, actor="TEST_ORCHESTRATOR")
        await session.commit()

        assert result["round"] >= 2
        assert "global-v" in result["model_version"]
        assert result["accuracy"] > 0.80
        assert result["f1"] > 0.80
        assert result["clients_completed"] == 3
        assert "differential_privacy" in result
        assert result["differential_privacy"]["is_private"] is True
