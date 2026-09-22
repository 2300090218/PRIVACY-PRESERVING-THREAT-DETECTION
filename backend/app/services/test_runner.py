"""
Safe Local Security Test Mode Runner
Generates realistic synthetic attack telemetry and pushes it through the exact same
pipeline (Validation -> Privacy Engine -> Rule Engine -> ML Engine -> Risk Engine -> Database -> Alert -> WebSocket).
Clearly marks all events with is_test=True and TEST MODE indicator.
"""

import time
import uuid
import random
import asyncio
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import AsyncSessionLocal
from backend.app.websocket.manager import ws_manager
from backend.app.services.event_service import event_service

SYNTHETIC_SCENARIOS = [
    {
        "name": "SSH Brute Force Attack",
        "attack_type": "Brute Force",
        "client_id": "client-dmz-01",
        "event_type": "auth_attempt",
        "source": "198.51.100.42",
        "destination": "10.0.0.15",
        "protocol": "TCP",
        "features": {
            "dest_port": 22,
            "flow_duration": 4500.0,
            "total_fwd_packets": 6,
            "total_bwd_packets": 3,
            "fwd_packet_length_mean": 125.0,
            "bwd_packet_length_mean": 85.0,
            "syn_flag_count": 1,
            "rst_flag_count": 0,
            "psh_flag_count": 1,
            "ack_flag_count": 1,
            "flow_packets_per_sec": 2000.0,
            "packet_length_variance": 1200.0
        },
        "metadata": {
            "user": "admin_test@corp-internal.com",
            "password": "SuperSecretPassword123!",
            "status": "FAILURE",
            "asset_type": "internal_server",
            "auth_service": "sshd"
        }
    },
    {
        "name": "Distributed Denial of Service (DDoS Flood)",
        "attack_type": "DDoS",
        "client_id": "client-cloud-03",
        "event_type": "network_flow",
        "source": "203.0.113.88",
        "destination": "10.0.2.50",
        "protocol": "TCP",
        "features": {
            "dest_port": 443,
            "flow_duration": 1200.0,
            "total_fwd_packets": 140,
            "total_bwd_packets": 1,
            "fwd_packet_length_mean": 64.0,
            "bwd_packet_length_mean": 0.0,
            "syn_flag_count": 1,
            "rst_flag_count": 0,
            "psh_flag_count": 0,
            "ack_flag_count": 0,
            "flow_packets_per_sec": 116000.0,
            "packet_length_variance": 50.0
        },
        "metadata": {
            "client_token": "Bearer abc1234567890xyzsecretjwttoken",
            "asset_type": "database",
            "service": "web-gateway"
        }
    },
    {
        "name": "Reconnaissance Multi-Port Sweep",
        "attack_type": "Port Scan",
        "client_id": "client-finance-02",
        "event_type": "network_flow",
        "source": "192.0.2.14",
        "destination": "10.0.1.20",
        "protocol": "TCP",
        "features": {
            "dest_port": 4444, # Suspicious backdoor port
            "flow_duration": 150.0,
            "total_fwd_packets": 1,
            "total_bwd_packets": 0,
            "fwd_packet_length_mean": 44.0,
            "bwd_packet_length_mean": 0.0,
            "syn_flag_count": 1,
            "rst_flag_count": 1,
            "psh_flag_count": 0,
            "ack_flag_count": 0,
            "flow_packets_per_sec": 6600.0,
            "packet_length_variance": 0.0
        },
        "metadata": {
            "scan_technique": "SYN_STEALTH",
            "dest_port": 4444,
            "asset_type": "internal_server"
        }
    },
    {
        "name": "Command & Control Botnet Beaconing",
        "attack_type": "Botnet",
        "client_id": "client-finance-02",
        "event_type": "network_flow",
        "source": "10.0.1.45",
        "destination": "198.51.100.99",
        "protocol": "TCP",
        "features": {
            "dest_port": 6667,
            "flow_duration": 60000.0,
            "total_fwd_packets": 8,
            "total_bwd_packets": 6,
            "fwd_packet_length_mean": 210.0,
            "bwd_packet_length_mean": 190.0,
            "syn_flag_count": 0,
            "rst_flag_count": 0,
            "psh_flag_count": 1,
            "ack_flag_count": 1,
            "flow_iat_mean": 15000.0,
            "packet_length_variance": 4500.0
        },
        "metadata": {
            "c2_channel": "IRC_BOT",
            "asset_type": "workstation",
            "infected_user": "bob_finance@corp.internal"
        }
    },
    {
        "name": "Authorized Encrypted Web Traffic",
        "attack_type": "BENIGN",
        "client_id": "client-dmz-01",
        "event_type": "network_flow",
        "source": "198.51.100.12",
        "destination": "10.0.0.80",
        "protocol": "TCP",
        "features": {
            "dest_port": 443,
            "flow_duration": 850.0,
            "total_fwd_packets": 12,
            "total_bwd_packets": 14,
            "fwd_packet_length_mean": 320.0,
            "bwd_packet_length_mean": 890.0,
            "syn_flag_count": 1,
            "rst_flag_count": 0,
            "psh_flag_count": 1,
            "ack_flag_count": 1,
            "flow_packets_per_sec": 30.0,
            "packet_length_variance": 450.0
        },
        "metadata": {
            "user": "developer_lead@corp-internal.com",
            "asset_type": "workstation",
            "service": "https_api"
        }
    },
    {
        "name": "Sensitive Data Exfiltration Burst",
        "attack_type": "Data Exfiltration",
        "client_id": "client-cloud-03",
        "event_type": "network_flow",
        "source": "10.0.2.75",
        "destination": "203.0.113.199",
        "protocol": "TCP",
        "features": {
            "dest_port": 8443,
            "flow_duration": 18000.0,
            "total_fwd_packets": 450,
            "total_bwd_packets": 20,
            "total_fwd_bytes": 14500000.0,
            "fwd_packet_length_mean": 1420.0,
            "bwd_packet_length_mean": 64.0,
            "syn_flag_count": 1,
            "rst_flag_count": 0,
            "psh_flag_count": 1,
            "ack_flag_count": 1,
            "flow_packets_per_sec": 8500.0,
            "packet_length_variance": 6800.0
        },
        "metadata": {
            "user": "insider_threat@corp-internal.com",
            "access_token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitiveexfiltoken",
            "api_key": "sec_live_exfil_transfer_key_44882199",
            "asset_type": "database",
            "destination_country": "UNKNOWN_HOST",
            "transfer_protocol": "HTTPS_TUNNEL"
        }
    }
]

async def run_synthetic_security_test(
    db: AsyncSession,
    scenario_idx: int = None
) -> Dict[str, Any]:
    """
    Executes a designated or randomized safe security test scenario through the full pipeline.
    """
    if scenario_idx is not None and 0 <= scenario_idx < len(SYNTHETIC_SCENARIOS):
        scenario = SYNTHETIC_SCENARIOS[scenario_idx]
    else:
        scenario = random.choice(SYNTHETIC_SCENARIOS)

    # Randomize IP variation to simulate multi-source distributed threats
    rand_octet_src = random.randint(10, 245)
    rand_octet_dest = random.randint(10, 150)
    base_src_parts = scenario["source"].split(".")
    base_dest_parts = scenario["destination"].split(".")

    if len(base_src_parts) == 4:
        dyn_source = f"{base_src_parts[0]}.{base_src_parts[1]}.{base_src_parts[2]}.{rand_octet_src}"
    else:
        dyn_source = scenario["source"]

    if len(base_dest_parts) == 4:
        dyn_dest = f"{base_dest_parts[0]}.{base_dest_parts[1]}.{base_dest_parts[2]}.{rand_octet_dest}"
    else:
        dyn_dest = scenario["destination"]

    # Clone scenario and inject unique identifiers
    event_dict = {
        "event_id": f"TEST-{uuid.uuid4().hex[:10].upper()}",
        "client_id": scenario["client_id"],
        "event_type": scenario["event_type"],
        "source": dyn_source,
        "destination": dyn_dest,
        "protocol": scenario["protocol"],
        "features": scenario["features"].copy(),
        "metadata": scenario["metadata"].copy(),
        "is_test": True
    }

    # Pass through complete real pipeline
    sec_event, detection, summary = await event_service.process_and_ingest_event(
        db=db,
        event_dict=event_dict,
        actor="SECURITY_TEST_RUNNER"
    )

    return {
        "status": "COMPLETED",
        "mode": "TEST MODE",
        "scenario_name": scenario["name"],
        "event_id": sec_event.event_id,
        "processing_latency_ms": summary["latency_ms"],
        "privacy_transformations": summary["privacy_transformations"],
        "ml_prediction": summary["ml_prediction"]["prediction"],
        "attack_type": summary["ml_prediction"]["attack_type"],
        "confidence": summary["ml_prediction"]["confidence"],
        "rule_matches": summary["rule_matches"],
        "risk_score": summary["risk"]["risk_score"],
        "severity": summary["risk"]["severity"],
        "alert_created": summary["alert_created"]
    }


class ContinuousMonitor:
    """
    Background worker manager providing sustained, continuous security telemetry
    monitoring across randomized attack and benign scenarios.
    """
    def __init__(self):
        self.is_running: bool = False
        self._task: Optional[asyncio.Task] = None
        self.interval_seconds: float = 3.0
        self.total_scans: int = 0
        self.last_scan: Optional[Dict[str, Any]] = None
        self.started_at: Optional[float] = None

    async def _loop(self):
        print(f"[ContinuousMonitor] Started monitoring loop (interval: {self.interval_seconds}s)")
        while self.is_running:
            try:
                async with AsyncSessionLocal() as session:
                    res = await run_synthetic_security_test(session)
                    await session.commit()
                    self.total_scans += 1
                    self.last_scan = res
                    # Broadcast real-time continuous status
                    await ws_manager.broadcast("monitoring.status", self.get_status())
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[ContinuousMonitor] Error during continuous scan: {e}")

            try:
                await asyncio.sleep(self.interval_seconds)
            except asyncio.CancelledError:
                break
        print("[ContinuousMonitor] Monitoring loop stopped.")

    def start(self, interval_seconds: float = 3.0) -> Dict[str, Any]:
        if self.is_running:
            return self.get_status()
        self.is_running = True
        self.interval_seconds = max(1.5, interval_seconds)
        self.started_at = time.time()
        self._task = asyncio.create_task(self._loop())
        return self.get_status()

    def stop(self) -> Dict[str, Any]:
        self.is_running = False
        if self._task and not self._task.done():
            self._task.cancel()
            self._task = None
        return self.get_status()

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "total_scans": self.total_scans,
            "interval_seconds": self.interval_seconds,
            "started_at": self.started_at,
            "last_scan": self.last_scan
        }

continuous_monitor = ContinuousMonitor()

