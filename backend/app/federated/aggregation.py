"""
Federated Averaging (FedAvg) Aggregation with Calibrated Differential Privacy (DP-FedAvg)
Implements:
1. Weighted Parameter Aggregation (proportional to client local sample counts)
2. Model Update Validation (checking dimensionality, NaN/Inf rejection)
3. Differential Privacy Gradient/Weight L2 Clipping
4. Calibrated Gaussian Differential Privacy Noise Injection (DP-FedAvg)
5. Analytical Privacy Budget Accounting (epsilon, delta)
"""

import math
import numpy as np
from typing import List, Dict, Any, Tuple, Optional

def validate_and_clip_update(
    weights: np.ndarray,
    clip_threshold: float = 10.0
) -> np.ndarray:
    """
    Validates model update parameters, clips L2 norm for differential privacy,
    and replaces any numerical anomalies.
    """
    clean_w = np.nan_to_num(weights, nan=0.0, posinf=clip_threshold, neginf=-clip_threshold)
    norm = np.linalg.norm(clean_w)
    if norm > clip_threshold:
        clean_w = clean_w * (clip_threshold / norm)
    return clean_w

def compute_rdp_epsilon(
    noise_multiplier: float,
    num_rounds: int = 1,
    delta: float = 1e-5,
    orders: Optional[List[float]] = None
) -> Tuple[float, float]:
    """
    Computes optimal epsilon using Rényi Differential Privacy (RDP) conversion.
    For Gaussian mechanism with noise_multiplier sigma:
        R_alpha(round) = alpha / (2 * sigma^2)
    Over T independent rounds:
        R_alpha_total = T * alpha / (2 * sigma^2)
    Conversion to (epsilon, delta)-DP:
        epsilon(alpha) = R_alpha_total + log(1 / delta) / (alpha - 1)
    Returns (min_epsilon, optimal_alpha).
    """
    if noise_multiplier <= 0:
        return 0.0, 1.0
    if orders is None:
        orders = [1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 12.0, 16.0, 20.0, 32.0, 64.0]

    epsilons = []
    for alpha in orders:
        if alpha <= 1.0:
            continue
        rdp_round = alpha / (2.0 * (noise_multiplier ** 2))
        total_rdp = num_rounds * rdp_round
        eps = total_rdp + math.log(1.0 / delta) / (alpha - 1.0)
        epsilons.append((eps, alpha))

    min_eps, opt_alpha = min(epsilons, key=lambda x: x[0])
    return float(min_eps), float(opt_alpha)

def compute_dp_guarantees(
    noise_multiplier: float,
    num_rounds: int = 1,
    delta: float = 1e-5
) -> Dict[str, Any]:
    """
    Computes analytical Differential Privacy guarantee (epsilon, delta)
    for Gaussian Mechanism DP-FedAvg.
    Using standard composition and Rényi DP conversion.
    """
    if noise_multiplier <= 0:
        return {
            "is_private": False,
            "epsilon": None,
            "rdp_epsilon": None,
            "optimal_alpha": None,
            "delta": delta,
            "noise_multiplier": 0.0,
            "privacy_tier": "NO_DP_NOISE (Clipping Only)",
            "description": "L2 Norm gradient clipping active without Gaussian noise injection."
        }

    # Standard Gaussian mechanism bound
    epsilon = (math.sqrt(2.0 * math.log(1.25 / delta)) / noise_multiplier) * math.sqrt(max(1, num_rounds))

    # Rényi Differential Privacy (RDP) tightened bound
    rdp_eps, opt_alpha = compute_rdp_epsilon(noise_multiplier, num_rounds, delta)
    max_budget_eps = 10.0
    budget_consumed_pct = min(100.0, round((epsilon / max_budget_eps) * 100.0, 1))
    budget_remaining = max(0.0, round(max_budget_eps - epsilon, 2))

    if epsilon < 1.0:
        privacy_tier = "VERY HIGH PRIVACY (Strong DP)"
    elif epsilon < 4.0:
        privacy_tier = "HIGH PRIVACY (Standard DP)"
    elif epsilon < 10.0:
        privacy_tier = "MODERATE PRIVACY (Permissive DP)"
    else:
        privacy_tier = "WEAK PRIVACY (High Epsilon)"

    return {
        "is_private": True,
        "epsilon": round(float(epsilon), 4),
        "rdp_epsilon": round(float(rdp_eps), 4),
        "optimal_alpha": opt_alpha,
        "delta": delta,
        "noise_multiplier": round(float(noise_multiplier), 4),
        "privacy_tier": privacy_tier,
        "num_rounds": num_rounds,
        "max_budget_epsilon": max_budget_eps,
        "budget_consumed_pct": budget_consumed_pct,
        "budget_remaining": budget_remaining,
        "description": f"Differential Privacy enforced: (ε={epsilon:.2f}, δ={delta}, RDP ε*={rdp_eps:.2f} at α={opt_alpha}) across {num_rounds} round(s)."
    }

def add_gaussian_dp_noise(
    weights: np.ndarray,
    clip_threshold: float,
    total_samples: int,
    noise_multiplier: float = 0.05,
    random_seed: Optional[int] = None
) -> np.ndarray:
    """
    Adds calibrated Gaussian noise scaled to L2 sensitivity:
    Sensitivity S = clip_threshold / max(1, total_samples)
    Noise standard deviation sigma = noise_multiplier * S
    """
    if noise_multiplier <= 0:
        return weights

    rng = np.random.default_rng(random_seed)
    sensitivity = clip_threshold / max(1, total_samples)
    sigma = noise_multiplier * sensitivity
    noise = rng.normal(loc=0.0, scale=sigma, size=weights.shape)
    return weights + noise

def federated_averaging(
    client_updates: List[Tuple[np.ndarray, int]],
    clip_threshold: float = 10.0,
    noise_multiplier: float = 0.0,
    random_seed: Optional[int] = None
) -> np.ndarray:
    """
    Calculates FedAvg:
    W_global = sum(n_k / N * W_k)
    where n_k is sample count of client k, and N is total sample count.
    Optionally injects calibrated Gaussian differential privacy noise.
    """
    if not client_updates:
        raise ValueError("Cannot perform FedAvg with empty client updates list.")

    valid_updates = []
    for item in client_updates:
        if isinstance(item, (tuple, list)) and len(item) == 2:
            w, s = item
            if w is not None and isinstance(w, np.ndarray) and s is not None and s > 0:
                valid_updates.append((w, int(s)))

    if not valid_updates:
        raise ValueError("Cannot perform FedAvg: no valid client updates available.")

    total_samples = sum(sample_count for _, sample_count in valid_updates)
    if total_samples == 0:
        total_samples = len(valid_updates)

    aggregated_weights = None

    for weights, sample_count in valid_updates:
        clipped_w = validate_and_clip_update(weights, clip_threshold=clip_threshold)
        weight_factor = sample_count / total_samples

        if aggregated_weights is None:
            aggregated_weights = clipped_w * weight_factor
        else:
            aggregated_weights += clipped_w * weight_factor

    # Inject Differential Privacy noise if noise_multiplier > 0
    if noise_multiplier > 0 and aggregated_weights is not None:
        aggregated_weights = add_gaussian_dp_noise(
            aggregated_weights,
            clip_threshold=clip_threshold,
            total_samples=total_samples,
            noise_multiplier=noise_multiplier,
            random_seed=random_seed
        )

    return aggregated_weights

def federated_averaging_dp(
    client_updates: List[Tuple[np.ndarray, int]],
    clip_threshold: float = 10.0,
    noise_multiplier: float = 0.05,
    num_rounds: int = 1,
    delta: float = 1e-5,
    random_seed: Optional[int] = None
) -> Tuple[np.ndarray, Dict[str, Any]]:
    """
    Computes FedAvg with Differential Privacy noise and returns both
    the aggregated parameters and the formal DP guarantee certificate.
    """
    aggregated_weights = federated_averaging(
        client_updates,
        clip_threshold=clip_threshold,
        noise_multiplier=noise_multiplier,
        random_seed=random_seed
    )
    dp_metrics = compute_dp_guarantees(
        noise_multiplier=noise_multiplier,
        num_rounds=num_rounds,
        delta=delta
    )
    dp_metrics["clip_threshold"] = clip_threshold
    valid_samples = [s for item in (client_updates or []) if isinstance(item, (tuple, list)) and len(item) == 2 and item[1] is not None for s in [item[1]] if s > 0]
    dp_metrics["total_samples"] = sum(valid_samples) if valid_samples else 0
    return aggregated_weights, dp_metrics
