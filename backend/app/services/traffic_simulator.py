"""
Real-Time Traffic Simulator & Federated Round Orchestrator
Generates high-fidelity benign and attack telemetry through the Privacy Gateway,
evaluates events through Dual Threat Detection (Rules + ML), scores risk,
persists records, and broadcasts live WebSocket events for real-time demonstration.
"""

import asyncio
import random
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from backend.app.config import settings
from backend.app.database import AsyncSessionLocal
from backend.app.models.all_models import (
    SecurityEvent, Detection, Alert, RiskAssessment, Agent, ModelVersion
)
from backend.app.detection.rule_detector import rule_engine
from backend.app.detection.ml_detector import ml_detector
from backend.app.services.risk_service import risk_engine
from backend.app.services.privacy_service import privacy_engine
from backend.app.websocket.manager import ws_manager

ORGANIZATIONS = ["demo_klef_vijayawada", "demo_gitam_visakhapatnam", "org_enterprise_a", "org_finance_b"]
AGENTS = {
    "demo_klef_vijayawada": "agent-kl-dmz-01",
    "demo_gitam_visakhapatnam": "agent-gitam-core-02",
    "org_enterprise_a": "agent-dmz-01",
    "org_finance_b": "agent-fin-03"
}

ATTACK_TYPES = ["Brute Force", "Port Scan", "Backdoor / C2", "DDoS Flood"]

class TrafficSimulator:
    def __init__(self):
        self.is_running: bool = False
        self._task: Optional[asyncio.Task] = None
        self.events_generated: int = 0
        self.attacks_generated: int = 0
        self.fl_rounds_completed: int = 0
        self.current_fl_round: int = 1
        self.fl_accuracy: float = 0.9729
        self.fl_epsilon: float = 0.85

    def get_status(self) -> Dict[str, Any]:
        return {
            "running": self.is_running,
            "events_generated": self.events_generated,
            "attacks_generated": self.attacks_generated,
            "fl_rounds_completed": self.fl_rounds_completed,
            "current_accuracy": round(self.fl_accuracy * 100, 2),
            "current_epsilon": round(self.fl_epsilon, 2),
            "active_clients": 3
        }

    async def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._task = asyncio.create_task(self._simulation_loop())
        print("[Simulator] Built-in real-time traffic simulator started.")

    async def stop(self):
        self.is_running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        print("[Simulator] Built-in traffic simulator stopped.")

    async def _simulation_loop(self):
        fl_timer = 0
        while self.is_running:
            try:
                # 1. Generate & Process a live telemetry event
                is_attack = random.random() < 0.35  # ~35% attacks, 65% benign
                if is_attack:
                    attack_choice = random.choice(ATTACK_TYPES)
                    await self._generate_and_process_event(attack_type=attack_choice)
                else:
                    await self._generate_and_process_event(attack_type=None)

                # 2. Every ~45 seconds, trigger a simulated federated round
                fl_timer += 1
                if fl_timer >= 15:  # ~15 ticks * 3s = 45s
                    fl_timer = 0
                    await self.trigger_federated_round()

                # Sleep before next event
                sleep_interval = max(1.5, settings.SIMULATOR_INTERVAL_SECONDS + random.uniform(-0.5, 0.5))
                await asyncio.sleep(sleep_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Keep simulator resilient
                await asyncio.sleep(3.0)

    async def trigger_federated_round(self) -> Dict[str, Any]:
        """Orchestrates a simulated decentralized federated learning round."""
        self.current_fl_round += 1
        round_num = self.current_fl_round
        nodes = ["client-dmz-01", "client-finance-02", "client-cloud-03"]

        # 1. Broadcast round started
        await ws_manager.broadcast("training.started", {
            "round_number": round_num,
            "participating_clients": nodes,
            "target_model": f"global-v{round_num}",
            "base_accuracy": round(self.fl_accuracy, 4),
            "status": "DISPATCHING_WEIGHTS"
        })

        await asyncio.sleep(1.0)

        # 2. Broadcast intermediate client training progress
        for i, node in enumerate(nodes, start=1):
            await ws_manager.broadcast("training.progress", {
                "round_number": round_num,
                "client_id": node,
                "epoch": 5,
                "samples_trained": random.randint(1200, 3500),
                "l2_norm_clipped": True,
                "dp_noise_added": True,
                "progress_percent": int((i / len(nodes)) * 100)
            })
            await asyncio.sleep(0.5)

        # 3. Simulate improvement with diminishing returns
        delta_acc = random.uniform(0.0005, 0.0025)
        self.fl_accuracy = min(0.9950, self.fl_accuracy + delta_acc)
        self.fl_epsilon = round(self.fl_epsilon + random.uniform(0.05, 0.15), 2)
        self.fl_rounds_completed += 1

        result = {
            "round_number": round_num,
            "version": f"global-v{round_num}",
            "accuracy": round(self.fl_accuracy, 4),
            "precision": round(self.fl_accuracy - 0.001, 4),
            "recall": round(self.fl_accuracy, 4),
            "f1_score": round(self.fl_accuracy - 0.0005, 4),
            "privacy_budget_epsilon": self.fl_epsilon,
            "participating_nodes": len(nodes),
            "status": "COMPLETED",
            "model_version": f"global-v{round_num}"
        }

        # 4. Broadcast round completed and model promoted
        await ws_manager.broadcast("training.completed", result)
        await ws_manager.broadcast("model.updated", {
            "version": f"global-v{round_num}",
            "status": "ACTIVE",
            "accuracy": round(self.fl_accuracy, 4),
            "promoted_at": datetime.now(timezone.utc).isoformat()
        })

        return result

    async def _generate_and_process_event(self, attack_type: Optional[str] = None):
        """Builds a realistic network flow event, sanitizes it via PrivacyGateway, and runs it through detection."""
        start_time = time.perf_counter()
        org_id = random.choice(ORGANIZATIONS)
        agent_id = AGENTS.get(org_id, "agent-dmz-01")

        # 1. Synthesize candidate raw network event
        now_iso = datetime.now(timezone.utc).isoformat()
        raw_user = f"user_{random.randint(100, 999)}@corp.internal"
        raw_ip = f"192.168.{random.randint(1, 20)}.{random.randint(2, 254)}"
        event_id = f"evt_{uuid.uuid4().hex[:12]}"

        if attack_type == "Brute Force":
            dest_port = random.choice([22, 443, 3389, 8080])
            failed_attempts = random.randint(5, 12)
            event_type = "AUTHENTICATION_FAILURE_BURST"
            protocol = "TCP"
            indicators = ["AUTH_FAILURE_BURST", "CREDENTIAL_STUFFING"]
            features = {
                "duration_sec": round(random.uniform(0.5, 4.0), 2),
                "src_bytes": random.randint(1500, 5000),
                "dst_bytes": random.randint(800, 2000),
                "src_packets": random.randint(20, 60),
                "dst_packets": random.randint(15, 45),
                "byte_rate": round(random.uniform(1000, 3000), 2),
                "packet_rate": round(random.uniform(15, 50), 2),
                "failed_logins": failed_attempts,
                "destination_port": dest_port,
                "protocol_num": 6,
                "connection_count_1m": random.randint(15, 40)
            }
        elif attack_type == "Port Scan":
            dest_port = random.choice([21, 23, 135, 445, 1433, 3306, 8080])
            failed_attempts = 0
            event_type = "NETWORK_RECONNAISSANCE"
            protocol = "TCP"
            indicators = ["PORT_SWEEP", "SYN_PROBE"]
            features = {
                "duration_sec": round(random.uniform(0.1, 1.2), 2),
                "src_bytes": random.randint(400, 1200),
                "dst_bytes": 0,
                "src_packets": random.randint(15, 30),
                "dst_packets": 0,
                "byte_rate": round(random.uniform(800, 2500), 2),
                "packet_rate": round(random.uniform(20, 60), 2),
                "failed_logins": 0,
                "destination_port": dest_port,
                "protocol_num": 6,
                "flag_syn_count": random.randint(15, 30),
                "connection_count_1m": random.randint(25, 60)
            }
        elif attack_type == "Backdoor / C2":
            dest_port = random.choice([4444, 1337, 31337, 8888, 9999])
            failed_attempts = 0
            event_type = "SUSPICIOUS_PORT_TRAFFIC"
            protocol = "TCP"
            indicators = ["BACKDOOR_PORT_TRAFFIC", "REVERSE_SHELL_PATTERN"]
            features = {
                "duration_sec": round(random.uniform(15.0, 120.0), 2),
                "src_bytes": random.randint(8000, 25000),
                "dst_bytes": random.randint(4000, 15000),
                "src_packets": random.randint(40, 150),
                "dst_packets": random.randint(30, 120),
                "byte_rate": round(random.uniform(300, 1200), 2),
                "packet_rate": round(random.uniform(2, 10), 2),
                "failed_logins": 0,
                "destination_port": dest_port,
                "protocol_num": 6,
                "connection_count_1m": random.randint(3, 8)
            }
        elif attack_type == "DDoS Flood":
            dest_port = 80
            failed_attempts = 0
            event_type = "TRAFFIC_VOLUME_ANOMALY"
            protocol = "UDP" if random.random() < 0.5 else "TCP"
            indicators = ["PACKET_RATE_BURST", "VOLUMETRIC_FLOOD"]
            features = {
                "duration_sec": round(random.uniform(0.1, 0.8), 2),
                "src_bytes": random.randint(80000, 250000),
                "dst_bytes": random.randint(500, 2000),
                "src_packets": random.randint(800, 2500),
                "dst_packets": random.randint(10, 50),
                "byte_rate": round(random.uniform(100000, 400000), 2),
                "packet_rate": round(random.uniform(1500, 5000), 2),
                "failed_logins": 0,
                "destination_port": dest_port,
                "protocol_num": 17 if protocol == "UDP" else 6,
                "connection_count_1m": random.randint(100, 400)
            }
        else:
            # Benign normal traffic
            dest_port = random.choice([80, 443, 53, 8080])
            failed_attempts = 0
            event_type = "STANDARD_APPLICATION_FLOW"
            protocol = "TCP" if dest_port != 53 else "UDP"
            indicators = []
            features = {
                "duration_sec": round(random.uniform(0.2, 5.0), 2),
                "src_bytes": random.randint(600, 4000),
                "dst_bytes": random.randint(1200, 15000),
                "src_packets": random.randint(5, 25),
                "dst_packets": random.randint(8, 35),
                "byte_rate": round(random.uniform(400, 3000), 2),
                "packet_rate": round(random.uniform(2, 15), 2),
                "failed_logins": 0,
                "destination_port": dest_port,
                "protocol_num": 17 if protocol == "UDP" else 6,
                "connection_count_1m": random.randint(1, 5)
            }

        # 2. PRIVACY GATEWAY: Apply edge sanitization
        # Transforms raw IP to pseudonym (e.g. IP-3F9A1B), strips raw user
        sanitized_source = privacy_engine.generate_pseudonym(raw_ip, prefix="IP")
        sanitized_device = privacy_engine.generate_pseudonym(f"device_{raw_ip}", prefix="DEV")

        # 3. Threat Detection (Rules + ML)
        rule_input = {
            "event_type": event_type,
            "source": sanitized_source,
            "features": features,
            "metadata": {
                "failed_attempts": failed_attempts,
                "dest_port": dest_port,
                "status": "FAILURE" if failed_attempts > 0 else "SUCCESS",
                "attack_indicators": indicators
            }
        }
        is_rule_threat, rule_matches, rule_sev = rule_engine.evaluate(rule_input)
        ml_res = ml_detector.predict(features_dict=features, metadata={"dest_port": dest_port, "event_type": event_type})

        # Calculate composite deterministic risk score
        risk_res = risk_engine.calculate_risk(
            ml_prediction=ml_res,
            rule_matches=rule_matches,
            rule_severity=rule_sev,
            frequency_count=max(1, failed_attempts or 1),
            asset_type="internal_server" if dest_port in [22, 443, 8000, 5432] else "workstation"
        )

        risk_score = risk_res.get("risk_score", 12.0)
        severity = risk_res.get("severity", "LOW")

        detected_threat = attack_type or (ml_res.get("attack_type") if ml_res.get("prediction") != "BENIGN" else "BENIGN")
        if is_rule_threat and not attack_type:
            detected_threat = "Suspicious Behavior"

        proc_ms = round((time.perf_counter() - start_time) * 1000, 2)
        detection_id = f"det_{uuid.uuid4().hex[:10]}"
        alert_id = f"alt_{uuid.uuid4().hex[:10]}" if (severity in ["MEDIUM", "HIGH", "CRITICAL"] or risk_score >= 40.0) else None

        # 4. Asynchronously persist to database
        async with AsyncSessionLocal() as session:
            try:
                event_rec = SecurityEvent(
                    event_id=event_id,
                    organization_id=org_id,
                    agent_id=agent_id,
                    client_id=agent_id,
                    event_type=event_type,
                    telemetry_source="SIMULATED",
                    source=sanitized_source,
                    destination=f"PORT_{dest_port}",
                    protocol=protocol,
                    failed_attempts=failed_attempts,
                    attack_indicators=indicators,
                    features=features,
                    metadata_payload=features,
                    privacy_metadata={"sanitized": True, "method": "HMAC-SHA256"},
                    is_test=True,
                    processing_status="PROCESSED",
                    processing_latency_ms=proc_ms
                )
                session.add(event_rec)

                det_rec = Detection(
                    detection_id=detection_id,
                    organization_id=org_id,
                    event_id=event_id,
                    prediction="MALICIOUS" if severity in ["HIGH", "CRITICAL"] else ("SUSPICIOUS" if severity == "MEDIUM" else "BENIGN"),
                    attack_type=detected_threat,
                    confidence=ml_res.get("confidence", 0.95),
                    severity=severity,
                    model_version=f"global-v{self.current_fl_round}",
                    processing_latency_ms=proc_ms,
                    rule_matches=rule_matches
                )
                session.add(det_rec)

                if alert_id:
                    alt_rec = Alert(
                        alert_id=alert_id,
                        organization_id=org_id,
                        detection_id=detection_id,
                        event_id=event_id,
                        attack_type=detected_threat,
                        severity=severity,
                        confidence=ml_res.get("confidence", 0.95),
                        risk_score=risk_score,
                        explanation=f"Threat detected: {detected_threat} on port {dest_port}. Risk Score: {risk_score}.",
                        status="NEW",
                        agent_id=agent_id,
                        client_id=agent_id,
                        is_test=True
                    )
                    session.add(alt_rec)

                await session.commit()
            except Exception:
                await session.rollback()

        # 5. Broadcast to WebSocket clients
        self.events_generated += 1
        if alert_id:
            self.attacks_generated += 1

        # Broadcast event
        await ws_manager.broadcast("event.received", {
            "event_id": event_id,
            "organization_id": org_id,
            "agent_id": agent_id,
            "event_type": event_type,
            "telemetry_source": "SIMULATED",
            "source": sanitized_source,
            "destination_port": dest_port,
            "timestamp": now_iso
        }, organization_id=org_id)

        # Broadcast detection
        detection_payload = {
            "detection_id": detection_id,
            "organization_id": org_id,
            "event_id": event_id,
            "prediction": "MALICIOUS" if severity in ["HIGH", "CRITICAL"] else ("SUSPICIOUS" if severity == "MEDIUM" else "BENIGN"),
            "attack_type": detected_threat,
            "confidence": ml_res.get("confidence", 0.95),
            "severity": severity,
            "risk_score": risk_score,
            "source": sanitized_source,
            "destination_port": dest_port,
            "protocol": protocol,
            "timestamp": now_iso,
            "processing_latency_ms": proc_ms,
            "rule_matches": rule_matches
        }
        await ws_manager.broadcast("detection.created", detection_payload, organization_id=org_id)

        # Broadcast threat feed item (directly formatted for live dashboard feed)
        await ws_manager.broadcast("threat.feed", {
            "id": detection_id,
            "timestamp": now_iso,
            "source": sanitized_source,
            "target": f"Port {dest_port} ({protocol})",
            "threat_type": detected_threat,
            "severity": severity,
            "risk_score": risk_score,
            "organization_id": org_id,
            "status": "DETECTED",
            "model_version": f"global-v{self.current_fl_round}"
        }, organization_id=org_id)

        if alert_id:
            await ws_manager.broadcast("alert.created", {
                "alert_id": alert_id,
                "organization_id": org_id,
                "detection_id": detection_id,
                "attack_type": detected_threat,
                "severity": severity,
                "risk_score": risk_score,
                "source": sanitized_source,
                "timestamp": now_iso
            }, organization_id=org_id)

traffic_simulator = TrafficSimulator()
