"""
IDS Benchmark Dataset Generator and Partitioner
Simulates structured network flow telemetry modeled after standard IDS benchmarks (CIC-IDS2017 / UNSW-NB15).
Provides:
- Realistic network flow distributions
- Distinct threat profiles (BENIGN, Brute Force, DDoS, Port Scan, Botnet)
- Non-IID / IID federated client partitioning
- Separate held-out global evaluation dataset
"""

import os
import json
import numpy as np
import pandas as pd
from typing import Dict, Tuple, List

FEATURE_NAMES = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "flow_iat_mean",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "dest_port",
    "packet_length_variance",
]

ATTACK_CLASSES = ["BENIGN", "Brute Force", "DDoS", "Port Scan", "Botnet"]

def generate_flow_samples(n_samples: int, attack_type: str, rng: np.random.RandomState) -> pd.DataFrame:
    """Generate realistic network flow rows for a specific traffic profile."""
    if attack_type == "BENIGN":
        dest_ports = rng.choice([80, 443, 8080, 53, 22], size=n_samples, p=[0.25, 0.50, 0.10, 0.10, 0.05])
        flow_duration = rng.exponential(scale=50000.0, size=n_samples) + 500
        total_fwd_packets = rng.poisson(lam=12, size=n_samples) + 1
        total_bwd_packets = rng.poisson(lam=15, size=n_samples) + 1
        fwd_packet_length_mean = rng.normal(loc=350, scale=100, size=n_samples).clip(40, 1500)
        bwd_packet_length_mean = rng.normal(loc=750, scale=200, size=n_samples).clip(40, 1500)
        syn_flags = rng.binomial(1, 0.15, size=n_samples)
        rst_flags = rng.binomial(1, 0.02, size=n_samples)
        psh_flags = rng.binomial(1, 0.40, size=n_samples)
        ack_flags = rng.binomial(1, 0.85, size=n_samples)
        flow_iat = flow_duration / (total_fwd_packets + total_bwd_packets + 1)
        pkt_len_var = rng.uniform(500, 25000, size=n_samples)

    elif attack_type == "Brute Force":
        dest_ports = rng.choice([22, 21, 3389, 80, 443], size=n_samples, p=[0.4, 0.25, 0.2, 0.1, 0.05])
        flow_duration = rng.uniform(1000, 15000, size=n_samples)
        total_fwd_packets = rng.randint(4, 10, size=n_samples)
        total_bwd_packets = rng.randint(2, 6, size=n_samples)
        fwd_packet_length_mean = rng.normal(loc=120, scale=25, size=n_samples).clip(40, 300)
        bwd_packet_length_mean = rng.normal(loc=80, scale=20, size=n_samples).clip(40, 250)
        syn_flags = np.ones(n_samples, dtype=int)
        rst_flags = rng.binomial(1, 0.30, size=n_samples)
        psh_flags = rng.binomial(1, 0.60, size=n_samples)
        ack_flags = np.ones(n_samples, dtype=int)
        flow_iat = rng.uniform(50, 400, size=n_samples)
        pkt_len_var = rng.uniform(100, 3000, size=n_samples)

    elif attack_type == "DDoS":
        dest_ports = rng.choice([80, 443, 53], size=n_samples, p=[0.45, 0.45, 0.10])
        flow_duration = rng.uniform(200, 3000, size=n_samples)
        total_fwd_packets = rng.poisson(lam=120, size=n_samples) + 20
        total_bwd_packets = rng.poisson(lam=2, size=n_samples)
        fwd_packet_length_mean = rng.normal(loc=64, scale=10, size=n_samples).clip(40, 120)
        bwd_packet_length_mean = rng.normal(loc=40, scale=10, size=n_samples).clip(0, 60)
        syn_flags = np.ones(n_samples, dtype=int)
        rst_flags = rng.binomial(1, 0.10, size=n_samples)
        psh_flags = rng.binomial(1, 0.05, size=n_samples)
        ack_flags = rng.binomial(1, 0.20, size=n_samples)
        flow_iat = rng.exponential(scale=15.0, size=n_samples) + 1.0
        pkt_len_var = rng.uniform(10, 500, size=n_samples)

    elif attack_type == "Port Scan":
        dest_ports = rng.randint(1, 65535, size=n_samples)
        flow_duration = rng.uniform(10, 800, size=n_samples)
        total_fwd_packets = rng.choice([1, 2], size=n_samples, p=[0.85, 0.15])
        total_bwd_packets = rng.choice([0, 1], size=n_samples, p=[0.75, 0.25])
        fwd_packet_length_mean = rng.normal(loc=44, scale=5, size=n_samples).clip(40, 60)
        bwd_packet_length_mean = np.zeros(n_samples)
        syn_flags = np.ones(n_samples, dtype=int)
        rst_flags = rng.binomial(1, 0.45, size=n_samples)
        psh_flags = np.zeros(n_samples, dtype=int)
        ack_flags = rng.binomial(1, 0.10, size=n_samples)
        flow_iat = rng.uniform(5, 50, size=n_samples)
        pkt_len_var = rng.uniform(0, 50, size=n_samples)

    elif attack_type == "Botnet":
        dest_ports = rng.choice([6667, 8080, 4444, 1337, 9001], size=n_samples)
        flow_duration = rng.normal(loc=60000, scale=5000, size=n_samples).clip(10000, 120000)
        total_fwd_packets = rng.poisson(lam=8, size=n_samples) + 2
        total_bwd_packets = rng.poisson(lam=6, size=n_samples) + 1
        fwd_packet_length_mean = rng.normal(loc=200, scale=40, size=n_samples).clip(60, 400)
        bwd_packet_length_mean = rng.normal(loc=180, scale=35, size=n_samples).clip(60, 400)
        syn_flags = rng.binomial(1, 0.2, size=n_samples)
        rst_flags = np.zeros(n_samples, dtype=int)
        psh_flags = rng.binomial(1, 0.70, size=n_samples)
        ack_flags = np.ones(n_samples, dtype=int)
        flow_iat = rng.normal(loc=15000, scale=1000, size=n_samples).clip(5000, 30000)
        pkt_len_var = rng.uniform(1000, 8000, size=n_samples)

    else:
        raise ValueError(f"Unknown attack type: {attack_type}")

    # Add realistic feature overlap and network jitter/noise (10% variance, 3% boundary overlap)
    jitter = rng.normal(loc=1.0, scale=0.15, size=n_samples).clip(0.5, 2.0)
    flow_duration = flow_duration * jitter
    total_fwd_packets = np.maximum(1, (total_fwd_packets * rng.uniform(0.8, 1.2, size=n_samples)).astype(int))
    total_bwd_packets = np.maximum(0, (total_bwd_packets * rng.uniform(0.8, 1.2, size=n_samples)).astype(int))

    total_fwd_bytes = total_fwd_packets * fwd_packet_length_mean * rng.uniform(0.9, 1.1, size=n_samples)
    total_bwd_bytes = total_bwd_packets * bwd_packet_length_mean * rng.uniform(0.9, 1.1, size=n_samples)
    total_bytes = total_fwd_bytes + total_bwd_bytes
    total_packets = total_fwd_packets + total_bwd_packets
    
    flow_duration_sec = np.maximum(flow_duration / 1e6, 1e-6)
    flow_bytes_per_sec = total_bytes / flow_duration_sec
    flow_packets_per_sec = total_packets / flow_duration_sec
    
    fwd_iat_mean = flow_iat * rng.uniform(0.8, 1.4, size=n_samples)
    bwd_iat_mean = flow_iat * rng.uniform(0.8, 1.6, size=n_samples)

    # Realistic label noise in IDS (ambiguous boundary traffic)
    labels = [attack_type] * n_samples
    if attack_type != "BENIGN":
        # 4% of attacks resemble benign edge traffic
        noise_idx = rng.choice(n_samples, size=int(n_samples * 0.04), replace=False)
        for idx in noise_idx:
            labels[idx] = "BENIGN"
    else:
        # 2% of benign high-traffic events look like suspicious anomaly
        noise_idx = rng.choice(n_samples, size=int(n_samples * 0.02), replace=False)
        for idx in noise_idx:
            labels[idx] = "Port Scan"

    df = pd.DataFrame({
        "flow_duration": flow_duration,
        "total_fwd_packets": total_fwd_packets,
        "total_bwd_packets": total_bwd_packets,
        "total_fwd_bytes": total_fwd_bytes,
        "total_bwd_bytes": total_bwd_bytes,
        "fwd_packet_length_mean": fwd_packet_length_mean,
        "bwd_packet_length_mean": bwd_packet_length_mean,
        "flow_bytes_per_sec": flow_bytes_per_sec,
        "flow_packets_per_sec": flow_packets_per_sec,
        "flow_iat_mean": flow_iat,
        "fwd_iat_mean": fwd_iat_mean,
        "bwd_iat_mean": bwd_iat_mean,
        "syn_flag_count": syn_flags,
        "rst_flag_count": rst_flags,
        "psh_flag_count": psh_flags,
        "ack_flag_count": ack_flags,
        "dest_port": dest_ports,
        "packet_length_variance": pkt_len_var,
        "label": labels,
    })
    return df

def generate_ids_benchmark_dataset(
    output_dir: str = "./ml/datasets",
    total_samples: int = 12000,
    seed: int = 42
) -> Dict[str, str]:
    """
    Creates a full realistic IDS benchmark dataset and partitions it:
    - Central Test/Validation Set: 20%
    - Client 1 (DMZ Gateway): 30% (Heavy on Port Scan & DDoS)
    - Client 2 (Financial Branch): 25% (Heavy on Brute Force & Benign)
    - Client 3 (Cloud App VPC): 25% (Heavy on Botnet & Benign)
    """
    os.makedirs(output_dir, exist_ok=True)
    rng = np.random.RandomState(seed)

    # Global distribution
    proportions = {
        "BENIGN": 0.60,
        "Brute Force": 0.12,
        "DDoS": 0.12,
        "Port Scan": 0.10,
        "Botnet": 0.06,
    }

    dfs = []
    for attack, prop in proportions.items():
        n = int(total_samples * prop)
        dfs.append(generate_flow_samples(n, attack, rng))

    full_df = pd.concat(dfs, ignore_index=True)
    full_df = full_df.sample(frac=1.0, random_state=rng).reset_index(drop=True)

    # 20% Held-Out Global Evaluation Set
    test_size = int(len(full_df) * 0.20)
    test_df = full_df.iloc[:test_size].copy()
    train_pool = full_df.iloc[test_size:].copy().reset_index(drop=True)

    # Partition remaining 80% among 3 Federated Clients
    # Client 1: DMZ Gateway (more external scans & volumetric floods)
    c1_benign = train_pool[train_pool["label"] == "BENIGN"].sample(frac=0.33, random_state=rng)
    c1_portscan = train_pool[train_pool["label"] == "Port Scan"].sample(frac=0.60, random_state=rng)
    c1_ddos = train_pool[train_pool["label"] == "DDoS"].sample(frac=0.50, random_state=rng)
    c1_bf = train_pool[train_pool["label"] == "Brute Force"].sample(frac=0.20, random_state=rng)
    c1_bot = train_pool[train_pool["label"] == "Botnet"].sample(frac=0.20, random_state=rng)
    client1_df = pd.concat([c1_benign, c1_portscan, c1_ddos, c1_bf, c1_bot]).sample(frac=1.0, random_state=rng)

    # Client 2: Financial Branch (more authentication attacks and internal traffic)
    remaining_pool = train_pool.drop(client1_df.index, errors="ignore")
    c2_benign = remaining_pool[remaining_pool["label"] == "BENIGN"].sample(frac=0.50, random_state=rng)
    c2_bf = remaining_pool[remaining_pool["label"] == "Brute Force"].sample(frac=0.70, random_state=rng)
    c2_portscan = remaining_pool[remaining_pool["label"] == "Port Scan"].sample(frac=0.50, random_state=rng)
    c2_ddos = remaining_pool[remaining_pool["label"] == "DDoS"].sample(frac=0.30, random_state=rng)
    c2_bot = remaining_pool[remaining_pool["label"] == "Botnet"].sample(frac=0.30, random_state=rng)
    client2_df = pd.concat([c2_benign, c2_bf, c2_portscan, c2_ddos, c2_bot]).sample(frac=1.0, random_state=rng)

    # Client 3: Cloud App VPC (remaining items, botnet beaconing)
    client3_df = remaining_pool.drop(client2_df.index, errors="ignore").sample(frac=1.0, random_state=rng)

    paths = {
        "full_dataset": os.path.join(output_dir, "ids_full_benchmark.csv"),
        "test_eval": os.path.join(output_dir, "ids_eval_heldout.csv"),
        "client_1": os.path.join(output_dir, "client_1_train.csv"),
        "client_2": os.path.join(output_dir, "client_2_train.csv"),
        "client_3": os.path.join(output_dir, "client_3_train.csv"),
    }

    full_df.to_csv(paths["full_dataset"], index=False)
    test_df.to_csv(paths["test_eval"], index=False)
    client1_df.to_csv(paths["client_1"], index=False)
    client2_df.to_csv(paths["client_2"], index=False)
    client3_df.to_csv(paths["client_3"], index=False)

    metadata = {
        "dataset_name": "CIC-IDS-Benchmark-Privacy-Preserving",
        "total_samples": len(full_df),
        "test_eval_samples": len(test_df),
        "client_1_samples": len(client1_df),
        "client_2_samples": len(client2_df),
        "client_3_samples": len(client3_df),
        "features": FEATURE_NAMES,
        "classes": ATTACK_CLASSES,
        "class_counts": full_df["label"].value_counts().to_dict(),
    }
    with open(os.path.join(output_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    return paths

if __name__ == "__main__":
    paths = generate_ids_benchmark_dataset()
    print("IDS Benchmark dataset generation complete.")
    for k, v in paths.items():
        print(f"  {k}: {v}")
