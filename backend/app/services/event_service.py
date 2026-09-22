"""
Event Ingestion & End-to-End Threat Processing Pipeline
Implements the core lifecycle:
Event Ingestion -> Privacy Transformation -> Rule Detection -> ML Detection -> Risk Engine -> Database -> Alert Engine -> WebSocket Broadcast -> Audit Log.
"""

import time
import uuid
from typing import Dict, Any, Tuple
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.all_models import SecurityEvent, Detection, PrivacyEvent
from backend.app.services.privacy_service import privacy_engine
from backend.app.detection.rule_detector import rule_engine
from backend.app.detection.ml_detector import ml_detector
from backend.app.detection.model_manager import model_manager
from backend.app.services.risk_service import risk_engine
from backend.app.services.alert_service import alert_service
from backend.app.services.audit_service import log_audit
from backend.app.websocket.manager import ws_manager

class EventService:
    async def process_and_ingest_event(
        self,
        db: AsyncSession,
        event_dict: Dict[str, Any],
        actor: str = "SYSTEM"
    ) -> Tuple[SecurityEvent, Detection, Dict[str, Any]]:
        """
        Executes the end-to-end detection and privacy pipeline on an incoming telemetry event.
        """
        start_time = time.perf_counter()

        # 1. Event ID and Ingestion Timestamp
        event_id = event_dict.get("event_id") or f"EVT-{uuid.uuid4().hex[:12].upper()}"
        event_dict["event_id"] = event_id
        is_test = bool(event_dict.get("is_test", False))
        client_id = event_dict.get("client_id", "client-default")

        # 2. Privacy Pipeline (Data Minimization, PII Redaction & Pseudonymization)
        sanitized_event, transformations = privacy_engine.process_telemetry_event(event_dict)

        # 3. Rule-Based Threat Detection
        is_rule_threat, rule_matches, rule_sev = rule_engine.evaluate(sanitized_event)

        # 4. Machine Learning Inference (Real Scikit-Learn Model)
        features = sanitized_event.get("features", {})
        metadata = sanitized_event.get("metadata", {})
        ml_result = ml_detector.predict(features, metadata)

        # 5. Deterministic Risk Engine
        risk_result = risk_engine.calculate_risk(
            ml_prediction=ml_result,
            rule_matches=rule_matches,
            rule_severity=rule_sev,
            frequency_count=1,
            asset_type=metadata.get("asset_type", "internal_server")
        )

        total_latency_ms = (time.perf_counter() - start_time) * 1000.0

        # 6. Database Persistence: SecurityEvent
        sec_event = SecurityEvent(
            event_id=event_id,
            timestamp=sanitized_event.get("timestamp") or datetime.now(timezone.utc),
            client_id=client_id,
            event_type=sanitized_event.get("event_type", "network_flow"),
            source=sanitized_event.get("source", "unknown"),
            destination=sanitized_event.get("destination", "unknown"),
            protocol=sanitized_event.get("protocol", "TCP"),
            features=sanitized_event.get("features", {}),
            metadata_payload=sanitized_event.get("metadata", {}),
            is_test=is_test,
            processing_status="PROCESSED",
            processing_latency_ms=round(total_latency_ms, 2)
        )
        db.add(sec_event)
        await db.flush()

        # 7. Database Persistence: Privacy Events
        if transformations:
            for t in transformations:
                pe = PrivacyEvent(
                    event_id=event_id,
                    detected_category=t.get("category", "PII"),
                    action=t.get("action", "TRANSFORMED"),
                    policy=t.get("policy", "POLICY_DATA_MINIMIZATION"),
                    pseudonym_token=t.get("pseudonym"),
                    fields_transformed=[t.get("field", "")],
                    technique=t.get("technique", "HMAC-SHA256")
                )
                db.add(pe)
            await db.flush()

        # 8. Database Persistence: Detection Record
        detection = Detection(
            event_id=event_id,
            prediction=ml_result.get("prediction", "BENIGN"),
            attack_type=ml_result.get("attack_type", "BENIGN"),
            confidence=ml_result.get("confidence", 0.0),
            severity=risk_result.get("severity", "LOW"),
            model_version=ml_result.get("model_version", "global-v1"),
            processing_latency_ms=round(total_latency_ms, 2),
            rule_matches=rule_matches
        )
        db.add(detection)
        await db.flush()

        # 9. Alert Generation & Correlation
        alert = await alert_service.process_detection_for_alert(
            db=db,
            event_id=event_id,
            client_id=client_id,
            detection_data=ml_result,
            risk_data=risk_result,
            detection_id=f"DET-{detection.id}",
            is_test=is_test
        )

        # 10. Audit Logging
        await log_audit(
            db,
            actor=actor,
            action="EVENT_INGESTED",
            resource="event",
            resource_id=event_id,
            metadata={
                "client_id": client_id,
                "is_test": is_test,
                "prediction": detection.prediction,
                "attack_type": detection.attack_type,
                "risk_score": risk_result.get("risk_score")
            }
        )

        # 11. Real-time WebSocket Broadcasts
        await ws_manager.broadcast("event.received", {
            "event_id": sec_event.event_id,
            "timestamp": sec_event.timestamp.isoformat() if hasattr(sec_event.timestamp, "isoformat") else str(sec_event.timestamp),
            "client_id": sec_event.client_id,
            "event_type": sec_event.event_type,
            "source": sec_event.source,
            "destination": sec_event.destination,
            "is_test": sec_event.is_test,
            "processing_latency_ms": sec_event.processing_latency_ms
        })

        await ws_manager.broadcast("detection.created", {
            "event_id": detection.event_id,
            "prediction": detection.prediction,
            "attack_type": detection.attack_type,
            "confidence": detection.confidence,
            "severity": detection.severity,
            "risk_score": risk_result.get("risk_score"),
            "model_version": detection.model_version,
            "rule_matches": detection.rule_matches,
            "explainability": ml_result.get("explainability"),
            "is_test": is_test
        })

        summary = {
            "event_id": event_id,
            "latency_ms": round(total_latency_ms, 2),
            "privacy_transformations": len(transformations),
            "rule_matches": rule_matches,
            "ml_prediction": ml_result,
            "risk": risk_result,
            "alert_created": alert is not None
        }

        return sec_event, detection, summary

event_service = EventService()
