"""
Federated Learning Aggregation Strategy
Implements FedAvg strategy configuration with Differential Privacy (DP) update clipping,
calibrated Gaussian noise injection, and participant validation.
"""

from typing import List, Tuple, Dict, Any, Optional
import numpy as np
from backend.app.federated.aggregation import (
    federated_averaging,
    validate_and_clip_update,
    compute_dp_guarantees,
    federated_averaging_dp
)

class FedAvgStrategy:
    """
    Coordinates weighted parameter averaging and privacy bounds across federated clients.
    """
    def __init__(
        self,
        min_clients: int = 3,
        clip_threshold: float = 10.0,
        fraction_fit: float = 1.0,
        enable_differential_privacy: bool = True,
        noise_multiplier: float = 0.05,
        target_delta: float = 1e-5
    ):
        self.min_clients = min_clients
        self.clip_threshold = clip_threshold
        self.fraction_fit = fraction_fit
        self.enable_differential_privacy = enable_differential_privacy
        self.noise_multiplier = noise_multiplier
        self.target_delta = target_delta

    def aggregate_fit(
        self,
        client_updates: List[Tuple[np.ndarray, int]],
        inject_noise: bool = False
    ) -> np.ndarray:
        """
        Validates client participation, clips update vectors for privacy preservation,
        and computes sample-weighted average parameters.
        """
        if client_updates is None:
            raise ValueError("No client updates provided for aggregation.")

        valid_updates = []
        for item in client_updates:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue
            w, s = item
            if w is not None and isinstance(w, np.ndarray) and s is not None and s > 0:
                if self.validate_client_update(w):
                    valid_updates.append((w, int(s)))

        if len(valid_updates) < self.min_clients:
            raise ValueError(
                f"Insufficient participating clients: received {len(valid_updates)}, "
                f"required minimum is {self.min_clients}."
            )

        threshold = self.clip_threshold if self.enable_differential_privacy else 1e6
        noise = self.noise_multiplier if (self.enable_differential_privacy and inject_noise) else 0.0
        return federated_averaging(valid_updates, clip_threshold=threshold, noise_multiplier=noise)

    def aggregate_fit_with_dp(
        self,
        client_updates: List[Tuple[np.ndarray, int]],
        num_rounds: int = 1,
        random_seed: Optional[int] = None
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Computes FedAvg with Differential Privacy noise and returns parameter vector
        together with formal analytical privacy certification metrics.
        """
        if client_updates is None:
            raise ValueError("No client updates provided for aggregation.")

        valid_updates = []
        for item in client_updates:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue
            w, s = item
            if w is not None and isinstance(w, np.ndarray) and s is not None and s > 0:
                if self.validate_client_update(w):
                    valid_updates.append((w, int(s)))

        if len(valid_updates) < self.min_clients:
            raise ValueError(
                f"Insufficient participating clients: received {len(valid_updates)}, "
                f"required minimum is {self.min_clients}."
            )

        return federated_averaging_dp(
            client_updates=valid_updates,
            clip_threshold=self.clip_threshold,
            noise_multiplier=self.noise_multiplier if self.enable_differential_privacy else 0.0,
            num_rounds=num_rounds,
            delta=self.target_delta,
            random_seed=random_seed
        )

    def validate_client_update(
        self,
        weights: np.ndarray,
        expected_dim: Optional[int] = None
    ) -> bool:
        """
        Validates numerical bounds and dimensionality of inbound client parameters.
        """
        if weights is None or len(weights) == 0:
            return False
        if expected_dim is not None and len(weights) != expected_dim:
            return False
        if np.isnan(weights).any() or np.isinf(weights).any():
            return False
        return True

default_strategy = FedAvgStrategy()
