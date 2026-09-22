"""
Feature Engineering and Normalization Pipeline
Extracts, computes, and standardizes the 18 benchmark network flow features.
"""

from typing import Dict, Any, List
import numpy as np

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

def extract_flow_features(features_dict: Dict[str, Any], metadata: Dict[str, Any] = None) -> np.ndarray:
    """
    Normalizes input feature dictionary into a clean 1D numpy array aligned with FEATURE_NAMES.
    Computes derived rates (bytes/sec, packets/sec, IAT) if not directly supplied.
    """
    if metadata is None:
        metadata = {}

    values = []
    
    # 1. Base counts & duration
    duration = float(features_dict.get("flow_duration", 1000.0))
    fwd_pkts = float(features_dict.get("total_fwd_packets", 2.0))
    bwd_pkts = float(features_dict.get("total_bwd_packets", 1.0))
    fwd_len_mean = float(features_dict.get("fwd_packet_length_mean", 100.0))
    bwd_len_mean = float(features_dict.get("bwd_packet_length_mean", 100.0))

    fwd_bytes = float(features_dict.get("total_fwd_bytes", fwd_pkts * fwd_len_mean))
    bwd_bytes = float(features_dict.get("total_bwd_bytes", bwd_pkts * bwd_len_mean))
    total_bytes = fwd_bytes + bwd_bytes
    total_pkts = fwd_pkts + bwd_pkts

    duration_sec = max(duration / 1e6, 1e-6)
    bytes_sec = float(features_dict.get("flow_bytes_per_sec", total_bytes / duration_sec))
    pkts_sec = float(features_dict.get("flow_packets_per_sec", total_pkts / duration_sec))

    flow_iat = float(features_dict.get("flow_iat_mean", duration / max(total_pkts, 1)))
    fwd_iat = float(features_dict.get("fwd_iat_mean", flow_iat * 1.1))
    bwd_iat = float(features_dict.get("bwd_iat_mean", flow_iat * 1.3))

    syn = float(features_dict.get("syn_flag_count", 0))
    rst = float(features_dict.get("rst_flag_count", 0))
    psh = float(features_dict.get("psh_flag_count", 0))
    ack = float(features_dict.get("ack_flag_count", 1))

    dest_port = float(features_dict.get("dest_port", metadata.get("dest_port", 80)))
    pkt_var = float(features_dict.get("packet_length_variance", 500.0))

    vec = [
        duration,
        fwd_pkts,
        bwd_pkts,
        fwd_bytes,
        bwd_bytes,
        fwd_len_mean,
        bwd_len_mean,
        bytes_sec,
        pkts_sec,
        flow_iat,
        fwd_iat,
        bwd_iat,
        syn,
        rst,
        psh,
        ack,
        dest_port,
        pkt_var,
    ]

    arr = np.array(vec, dtype=np.float64).reshape(1, -1)
    # Clean infinities or nans
    arr = np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=-1e9)
    return arr
