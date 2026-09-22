"""
Local Organization Telemetry Collector
Collects, normalizes, and validates local security events.
Generates controlled, clearly labeled test telemetry for verification and development.
"""

import uuid
from enum import Enum
from typing import Dict, Any, List
from datetime import datetime, timezone

class TelemetrySource(str, Enum):
    REAL = "REAL"
    TEST = "TEST"
    DEMO = "DEMO"

class TelemetryCollector:
    def __init__(self, organization_id: str = "org_enterprise_a", agent_id: str = "agent-dmz-01"):
        self.organization_id = organization_id
        self.agent_id = agent_id

    def create_raw_test_event(self, event_type: str = "FAILED_LOGIN", scenario_idx: int = 0) -> Dict[str, Any]:
        """
        Constructs a raw, unminimized local security event containing sensitive PII
        (username, exact source IP, physical location, raw device ID).
        This raw event exists ONLY within the local organization boundary.
        """
        event_id = f"raw_evt_{uuid.uuid4().hex[:10]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        if event_type == "FAILED_LOGIN":
            return {
                "event_id": event_id,
                "timestamp": now_iso,
                "organization_id": self.organization_id,
                "agent_id": self.agent_id,
                "event_type": "failed_login",
                "telemetry_source": TelemetrySource.TEST.value,
                "username": "robert.analyst",
                "source_ip": "192.168.1.105",
                "device_id": "DELL-SEC-XPS9310",
                "location": "North America Regional Office, Floor 4",
                "failed_attempts": 6,
                "destination_port": 443,
                "protocol": "TCP",
                "attack_indicators": ["AUTH_FAILURE_BURST"],
                "duration_seconds": 12,
                "bytes_transferred": 2450
            }

        elif event_type == "BRUTE_FORCE":
            return {
                "event_id": event_id,
                "timestamp": now_iso,
                "organization_id": self.organization_id,
                "agent_id": self.agent_id,
                "event_type": "brute_force_attack",
                "telemetry_source": TelemetrySource.TEST.value,
                "username": "root_administrator",
                "source_ip": "10.14.88.221",
                "device_id": "ASUS-ROG-ROG703",
                "location": "Datacenter Rack D-14",
                "failed_attempts": 28,
                "destination_port": 22,
                "protocol": "TCP",
                "attack_indicators": ["RAPID_PASSWORD_SPRAY", "KNOWN_BRUTE_FORCE_PATTERN"],
                "duration_seconds": 45,
                "bytes_transferred": 18400
            }

        elif event_type == "PORT_SCAN":
            return {
                "event_id": event_id,
                "timestamp": now_iso,
                "organization_id": self.organization_id,
                "agent_id": self.agent_id,
                "event_type": "port_scan_recon",
                "telemetry_source": TelemetrySource.TEST.value,
                "username": "system_daemon",
                "source_ip": "172.16.200.45",
                "device_id": "KALILINUX-VM-01",
                "location": "DMZ External Interface",
                "failed_attempts": 0,
                "destination_port": 4444,
                "protocol": "TCP",
                "attack_indicators": ["MULTI_PORT_SWEEP", "C2_RECONNAISSANCE"],
                "duration_seconds": 4,
                "bytes_transferred": 1200
            }

        elif event_type == "SUSPICIOUS_ACTIVITY":
            return {
                "event_id": event_id,
                "timestamp": now_iso,
                "organization_id": self.organization_id,
                "agent_id": self.agent_id,
                "event_type": "exploit_attempt",
                "telemetry_source": TelemetrySource.TEST.value,
                "username": "guest_service",
                "source_ip": "10.0.5.19",
                "device_id": "UBUNTU-SRV-09",
                "location": "Secondary Cloud Bridge",
                "failed_attempts": 1,
                "destination_port": 1337,
                "protocol": "TCP",
                "attack_indicators": ["LOG4J_SIGNATURE_MATCH", "SUSPICIOUS_OUTBOUND_C2"],
                "duration_seconds": 9,
                "bytes_transferred": 95000
            }

        else: # BENIGN
            return {
                "event_id": event_id,
                "timestamp": now_iso,
                "organization_id": self.organization_id,
                "agent_id": self.agent_id,
                "event_type": "network_flow",
                "telemetry_source": TelemetrySource.TEST.value,
                "username": "normal.employee",
                "source_ip": "192.168.10.15",
                "device_id": "THINKPAD-T14S-GEN3",
                "location": "Headquarters Suite 200",
                "failed_attempts": 0,
                "destination_port": 443,
                "protocol": "TCP",
                "attack_indicators": [],
                "duration_seconds": 120,
                "bytes_transferred": 450000
            }
