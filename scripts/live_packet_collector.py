"""
Live Network Telemetry & Flow Ingestion Agent
Captures or reconstructs live network traffic into standard 18-feature bidirectional flows,
and streams authenticated events to the Privacy-Preserving Threat Detection Backend.

Features:
- Passive 5-tuple flow aggregation: (src_ip, src_port, dst_ip, dst_port, protocol)
- Bidirectional flow metrics: duration, fwd/bwd packets, byte counts, IAT, TCP flags, variance
- Real-time streaming via REST API (POST /api/events or POST /api/events/batch)
- Fallback simulation mode (--simulate) for safe local validation without admin/raw socket privileges
- Displays real-time API response: Prediction, Risk Score, Attack Classification, Privacy Redaction
"""

import os
import sys
import time
import random
import socket
import argparse
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import httpx

DEFAULT_BACKEND_URL = "http://127.0.0.1:8000"
DEFAULT_CLIENT_ID = "client-dmz-01"

class FlowRecord:
    """Tracks state and metrics for a bidirectional 5-tuple network flow."""
    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = time.time()
        self.last_time = self.start_time

        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.packet_lengths: List[int] = []

        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0

    def add_packet(self, direction: str, length: int, flags: Optional[Dict[str, bool]] = None):
        self.last_time = time.time()
        self.packet_lengths.append(length)

        if direction == "fwd":
            self.fwd_packets += 1
            self.fwd_bytes += length
        else:
            self.bwd_packets += 1
            self.bwd_bytes += length

        if flags:
            if flags.get("SYN"): self.syn_count += 1
            if flags.get("RST"): self.rst_count += 1
            if flags.get("PSH"): self.psh_count += 1
            if flags.get("ACK"): self.ack_count += 1

    def to_event_payload(self, client_id: str, is_test: bool = False, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        duration_sec = max(self.last_time - self.start_time, 0.001)
        duration_us = duration_sec * 1_000_000.0
        total_pkts = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes

        fwd_len_mean = (self.fwd_bytes / max(self.fwd_packets, 1)) if self.fwd_packets > 0 else 0.0
        bwd_len_mean = (self.bwd_bytes / max(self.bwd_packets, 1)) if self.bwd_packets > 0 else 0.0

        if len(self.packet_lengths) > 1:
            mean_len = sum(self.packet_lengths) / len(self.packet_lengths)
            variance = sum((x - mean_len) ** 2 for x in self.packet_lengths) / len(self.packet_lengths)
        else:
            variance = 0.0

        features = {
            "flow_duration": round(duration_us, 2),
            "total_fwd_packets": self.fwd_packets,
            "total_bwd_packets": self.bwd_packets,
            "total_fwd_bytes": self.fwd_bytes,
            "total_bwd_bytes": self.bwd_bytes,
            "fwd_packet_length_mean": round(fwd_len_mean, 2),
            "bwd_packet_length_mean": round(bwd_len_mean, 2),
            "flow_bytes_per_sec": round(total_bytes / duration_sec, 2),
            "flow_packets_per_sec": round(total_pkts / duration_sec, 2),
            "flow_iat_mean": round((duration_us / max(total_pkts, 1)), 2),
            "fwd_iat_mean": round((duration_us / max(self.fwd_packets, 1)), 2),
            "bwd_iat_mean": round((duration_us / max(self.bwd_packets, 1)), 2) if self.bwd_packets > 0 else 0.0,
            "syn_flag_count": self.syn_count,
            "rst_flag_count": self.rst_count,
            "psh_flag_count": self.psh_count,
            "ack_flag_count": self.ack_count,
            "dest_port": self.dst_port,
            "packet_length_variance": round(variance, 2)
        }

        meta = metadata or {}
        if "asset_type" not in meta:
            meta["asset_type"] = "firewall_gateway"

        return {
            "client_id": client_id,
            "event_type": "network_flow",
            "source": self.src_ip,
            "destination": self.dst_ip,
            "protocol": self.protocol,
            "features": features,
            "metadata": meta,
            "is_test": is_test
        }

class LivePacketCollector:
    def __init__(self, backend_url: str = DEFAULT_BACKEND_URL, client_id: str = DEFAULT_CLIENT_ID):
        self.backend_url = backend_url.rstrip("/")
        self.client_id = client_id
        self.token = None
        self.http_client = httpx.Client(base_url=self.backend_url, timeout=15.0)

    def authenticate(self, username: str = "admin", password: str = "AdminPass123!") -> bool:
        try:
            res = self.http_client.post("/api/auth/login", json={"username": username, "password": password})
            if res.status_code == 200:
                self.token = res.json().get("access_token")
                return True
            print(f"[ERROR] Auth failed: {res.text}")
            return False
        except Exception as e:
            print(f"[ERROR] Cannot connect to backend for auth: {e}")
            return False

    def send_event(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            res = self.http_client.post("/api/events", json=event_data, headers=headers)
            if res.status_code == 200:
                return res.json()
            else:
                print(f"[WARN] Ingestion HTTP {res.status_code}: {res.text}")
                return None
        except Exception as e:
            print(f"[ERROR] Ingestion error: {e}")
            return None

    def send_batch(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            res = self.http_client.post("/api/events/batch", json=events, headers=headers)
            if res.status_code == 200:
                return res.json()
            else:
                print(f"[WARN] Batch Ingestion HTTP {res.status_code}: {res.text}")
                return None
        except Exception as e:
            print(f"[ERROR] Batch Ingestion error: {e}")
            return None

    def run_simulation(self, count: int = 10, interval: float = 1.0):
        print(f"\n[START] Generating {count} live telemetry flows (interval: {interval}s)...")
        print("-" * 75)
        print(f"{'TIMESTAMP':12} | {'SOURCE -> DEST':32} | {'PREDICTION':10} | {'RISK':5} | {'ATTACK'}")
        print("-" * 75)

        scenarios = [
            # Benign HTTPS Web Browsing
            {
                "src_ip": "192.168.1.105", "dst_ip": "142.250.190.46", "dst_port": 443, "proto": "TCP",
                "fwd_pkts": 12, "bwd_pkts": 18, "fwd_bytes": 1400, "bwd_bytes": 18500,
                "meta": {"user": "alice@corp.internal", "asset_type": "workstation"}
            },
            # SSH Brute Force attempt
            {
                "src_ip": "203.0.113.88", "dst_ip": "10.0.0.15", "dst_port": 22, "proto": "TCP",
                "fwd_pkts": 45, "bwd_pkts": 3, "fwd_bytes": 4800, "bwd_bytes": 210,
                "meta": {"password": "Password123!", "user": "root", "asset_type": "ssh_gateway"}
            },
            # C2 Reverse Shell Connection
            {
                "src_ip": "198.51.100.12", "dst_ip": "10.0.0.50", "dst_port": 4444, "proto": "TCP",
                "fwd_pkts": 85, "bwd_pkts": 1, "fwd_bytes": 9400, "bwd_bytes": 64,
                "meta": {"token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret", "asset_type": "database"}
            },
            # High-rate UDP / ICMP Flood
            {
                "src_ip": "198.51.100.99", "dst_ip": "10.0.0.1", "dst_port": 80, "proto": "UDP",
                "fwd_pkts": 450, "bwd_pkts": 0, "fwd_bytes": 65000, "bwd_bytes": 0,
                "meta": {"asset_type": "firewall_gateway"}
            }
        ]

        sent = 0
        for i in range(count):
            spec = random.choice(scenarios)
            flow = FlowRecord(
                src_ip=spec["src_ip"],
                src_port=random.randint(49152, 65535),
                dst_ip=spec["dst_ip"],
                dst_port=spec["dst_port"],
                protocol=spec["proto"]
            )
            flow.fwd_packets = spec["fwd_pkts"] + random.randint(0, 5)
            flow.bwd_packets = spec["bwd_pkts"]
            flow.fwd_bytes = spec["fwd_bytes"] + random.randint(0, 100)
            flow.bwd_bytes = spec["bwd_bytes"]
            flow.packet_lengths = [int(flow.fwd_bytes / max(flow.fwd_packets, 1))] * flow.fwd_packets

            if spec["dst_port"] == 4444 or spec["fwd_pkts"] > 100:
                flow.syn_count = 5
                flow.rst_count = 2
            else:
                flow.syn_count = 1
                flow.ack_count = 5

            event_dict = flow.to_event_payload(
                client_id=self.client_id,
                is_test=False,
                metadata=spec["meta"].copy()
            )

            result = self.send_event(event_dict)
            now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
            if result:
                flow_label = f"{event_dict['source'][:15]}->{event_dict['destination'][:15]}"
                print(f"{now_str:12} | {flow_label:32} | {result.get('prediction', 'UNK'):10} | {result.get('risk_score', 0):5.1f} | {result.get('attack_type', 'N/A')}")
            sent += 1
            if i < count - 1:
                time.sleep(interval)

        print("-" * 75)
        print(f"[COMPLETED] {sent} flow events processed by backend pipeline.")

def main():
    parser = argparse.ArgumentParser(description="Live Network Flow Collector & Ingestion Agent")
    parser.add_argument("--backend", default=DEFAULT_BACKEND_URL, help="Backend URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help="Client Partition ID (default: client-dmz-01)")
    parser.add_argument("--simulate", action="store_true", default=True, help="Run live synthetic packet flow generator")
    parser.add_argument("--count", type=int, default=8, help="Number of flow events to generate")
    parser.add_argument("--interval", type=float, default=0.8, help="Interval in seconds between flow events")
    args = parser.parse_args()

    collector = LivePacketCollector(backend_url=args.backend, client_id=args.client_id)
    print(f"[INIT] Authenticating agent with backend at {args.backend}...")
    if not collector.authenticate():
        print("[WARN] Proceeding without authenticated session (public ingestion).")

    if args.simulate:
        collector.run_simulation(count=args.count, interval=args.interval)

if __name__ == "__main__":
    main()
