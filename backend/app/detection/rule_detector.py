"""
Rule-Based Threat Detection Engine
Executes configurable deterministic heuristic checks:
1. Repeated Authentication Failures (Brute Force heuristic with sliding window)
2. Abnormal Request Volume / Burst Frequency
3. Suspicious Port Connections (e.g. Backdoors 4444, 1337, 31337)
4. Rapid Multi-Port Sweep (Port Scan heuristic)
5. Known Web / Payload Attack Indicators (SQLi, Directory Traversal, Shell)
"""

import time
from typing import Dict, Any, List, Tuple
from collections import defaultdict, deque

class RuleEngine:
    def __init__(self):
        # Sliding windows: source -> deque of timestamps
        self.auth_failures = defaultdict(lambda: deque(maxlen=20))
        self.request_window = defaultdict(lambda: deque(maxlen=200))
        self.port_sweep_window = defaultdict(lambda: deque(maxlen=50))

        # Suspicious backdoor / C2 ports
        self.suspicious_ports = {4444, 1337, 31337, 6667, 9001, 8888, 5555, 9999}

        # Payload heuristics & RCE signatures
        self.malicious_signatures = [
            "../etc/passwd", "..\\boot.ini",
            "' or '1'='1", "' or 1=1", "union select",
            "/bin/sh", "/bin/bash", "cmd.exe", "powershell -enc", "powershell.exe",
            "<script>", "eval(base64_decode",
            "${jndi:ldap", "${jndi:rmi", "${jndi:dns",
            "nc -e", "bash -i >&", "curl -s http", "wget -q http"
        ]

        # Reconnaissance & Automated Scanner User-Agents
        self.scanner_signatures = [
            "sqlmap", "nikto", "nmap", "masscan", "gobuster",
            "dirbuster", "acunetix", "nessus", "zgrab"
        ]

    def evaluate(self, event_data: Dict[str, Any]) -> Tuple[bool, List[str], str]:
        """
        Evaluates the event against deterministic heuristics.
        Returns: (is_rule_threat, matched_rules, suggested_severity)
        """
        matches = []
        now = time.time()
        source = event_data.get("source", "unknown")
        features = event_data.get("features", {})
        metadata = event_data.get("metadata", {})
        event_type = event_data.get("event_type", "network_flow")

        # 1. Rule: Authentication Failures (Brute Force)
        if event_type == "auth_attempt" and metadata.get("status") == "FAILURE":
            window = self.auth_failures[source]
            window.append(now)
            # Check failures in last 30 seconds
            recent = [t for t in window if now - t <= 30]
            if len(recent) >= 4:
                matches.append(f"RULE_AUTH_BRUTE_FORCE: {len(recent)} failed auth attempts in 30s from {source}")

        # 2. Rule: Abnormal High Frequency / Packet Flood (DDoS heuristic)
        flow_packets_sec = features.get("flow_packets_per_sec", 0)
        total_packets = features.get("total_fwd_packets", 0) + features.get("total_bwd_packets", 0)
        if flow_packets_sec > 1000 or total_packets > 100:
            matches.append(f"RULE_TRAFFIC_BURST: Excessive packet rate ({flow_packets_sec:.1f} pkts/sec)")

        # 3. Rule: Suspicious / Backdoor Ports
        dest_port = features.get("dest_port") or metadata.get("dest_port")
        if dest_port and int(dest_port) in self.suspicious_ports:
            matches.append(f"RULE_SUSPICIOUS_PORT: Connection attempt to known C2/Trojan port {dest_port}")

        # 4. Rule: Multi-Port Sweep (Port Scan)
        if dest_port:
            sweep = self.port_sweep_window[source]
            sweep.append((now, int(dest_port)))
            recent_ports = {p for t, p in sweep if now - t <= 10}
            if len(recent_ports) >= 8:
                matches.append(f"RULE_PORT_SCAN_DETECTED: Source connected to {len(recent_ports)} unique ports in 10s")

        # 5. Rule: Payload Signatures
        payload_str = str(metadata).lower() + " " + str(features).lower()
        for sig in self.malicious_signatures:
            if sig.lower() in payload_str:
                matches.append(f"RULE_MALICIOUS_PAYLOAD_SIGNATURE: Matched pattern '{sig}'")
                break

        # 6. Rule: Automated Reconnaissance Scanner User-Agent
        user_agent = str(metadata.get("user_agent", "") or metadata.get("client_user", "")).lower()
        for scanner in self.scanner_signatures:
            if scanner in user_agent or scanner in payload_str:
                matches.append(f"RULE_SCANNER_DETECTED: Matched vulnerability scanner footprint '{scanner}'")
                break

        is_threat = len(matches) > 0
        severity = "LOW"
        if len(matches) >= 3:
            severity = "CRITICAL"
        elif len(matches) == 2:
            severity = "HIGH"
        elif len(matches) == 1:
            severity = "MEDIUM"

        return is_threat, matches, severity

rule_engine = RuleEngine()
