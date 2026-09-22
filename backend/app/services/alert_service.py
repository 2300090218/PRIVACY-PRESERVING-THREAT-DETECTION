"""
Alert & Incident Management Service
Processes detections, generates alerts when risk thresholds are met,
correlates alerts into incidents, and broadcasts real-time updates.
"""

import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.models.all_models import Alert, Incident
from backend.app.websocket.manager import ws_manager
from backend.app.services.audit_service import log_audit
from backend.app.services.incident_service import incident_service

class AlertService:
    async def process_detection_for_alert(
        self,
        db: AsyncSession,
        event_id: str,
        client_id: str,
        detection_data: Dict[str, Any],
        risk_data: Dict[str, Any],
        detection_id: Optional[str] = None,
        is_test: bool = False
    ) -> Optional[Alert]:
        """
        Creates an alert if the detection indicates a threat (Risk >= 40.0 or prediction != BENIGN).
        Broadcasts alert over WebSocket and correlates into incidents.
        """
        prediction = detection_data.get("prediction", "BENIGN")
        risk_score = float(risk_data.get("risk_score", 0.0))
        attack_type = detection_data.get("attack_type", "BENIGN")
        severity = risk_data.get("severity", "MEDIUM")
        confidence = float(detection_data.get("confidence", 0.5))

        if prediction == "BENIGN" and risk_score < 40.0:
            return None

        alert_id = f"ALT-{uuid.uuid4().hex[:10].upper()}"
        xai_summary = detection_data.get("explainability", {}).get("summary", "")
        explanation = (
            f"Detected {attack_type} threat targeting {client_id}. "
            f"Composite Risk Score: {risk_score:.1f}/100 ({severity}), Model Confidence: {confidence*100:.1f}%."
        )
        if xai_summary:
            explanation = f"{explanation} {xai_summary}"

        alert = Alert(
            alert_id=alert_id,
            detection_id=detection_id or f"DET-{uuid.uuid4().hex[:8].upper()}",
            event_id=event_id,
            client_id=client_id,
            attack_type=attack_type,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            explanation=explanation,
            model_version=detection_data.get("model_version", "global-v1"),
            status="NEW",
            is_test=is_test
        )
        db.add(alert)
        await db.flush()

        # Correlate into Incident if severity is HIGH or CRITICAL
        if alert.severity in ("HIGH", "CRITICAL"):
            await incident_service.correlate_alert(db, alert, event_id)

        # Broadcast real-time alert event
        await ws_manager.broadcast("alert.created", {
            "alert_id": alert.alert_id,
            "event_id": alert.event_id,
            "client_id": alert.client_id,
            "attack_type": alert.attack_type,
            "severity": alert.severity,
            "confidence": alert.confidence,
            "risk_score": alert.risk_score,
            "status": alert.status,
            "explanation": alert.explanation,
            "explainability": detection_data.get("explainability"),
            "is_test": alert.is_test
        })

        await log_audit(
            db,
            actor=client_id,
            action="ALERT_CREATED",
            resource="alert",
            resource_id=alert_id,
            metadata={"severity": alert.severity, "attack_type": alert.attack_type}
        )

        return alert

    async def _correlate_incident(self, db: AsyncSession, alert: Alert, event_id: str):
        """Finds or opens an active incident for the attack type/client."""
        stmt = select(Incident).where(
            Incident.status.in_(["OPEN", "INVESTIGATING"]),
            Incident.severity.in_(["HIGH", "CRITICAL"])
        ).order_by(Incident.created_at.desc()).limit(1)
        result = await db.execute(stmt)
        active_inc = result.scalars().first()

        if active_inc:
            alerts_list = list(active_inc.related_alerts or [])
            events_list = list(active_inc.related_events or [])
            if alert.alert_id not in alerts_list:
                alerts_list.append(alert.alert_id)
            if event_id not in events_list:
                events_list.append(event_id)
            active_inc.related_alerts = alerts_list
            active_inc.related_events = events_list
            active_inc.summary = f"Aggregated {len(alerts_list)} alerts including {alert.attack_type}"
            await db.flush()
            await ws_manager.broadcast("incident.updated", {
                "incident_id": active_inc.incident_id,
                "title": active_inc.title,
                "severity": active_inc.severity,
                "status": active_inc.status,
                "alerts_count": len(alerts_list)
            })
        else:
            inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
            new_inc = Incident(
                incident_id=inc_id,
                title=f"Potential {alert.attack_type} Attack on {alert.client_id}",
                severity=alert.severity,
                status="OPEN",
                related_alerts=[alert.alert_id],
                related_events=[event_id],
                summary=f"Automated incident correlation for {alert.attack_type} (Risk: {alert.risk_score})"
            )
            db.add(new_inc)
            await db.flush()
            await ws_manager.broadcast("incident.updated", {
                "incident_id": new_inc.incident_id,
                "title": new_inc.title,
                "severity": new_inc.severity,
                "status": new_inc.status,
                "alerts_count": 1
            })

    async def acknowledge_alert(self, db: AsyncSession, alert_id: str, user_id: str) -> Optional[Alert]:
        stmt = select(Alert).where(Alert.alert_id == alert_id)
        result = await db.execute(stmt)
        alert = result.scalars().first()
        if alert:
            alert.status = "ACKNOWLEDGED"
            alert.acknowledged_by = user_id
            alert.acknowledged_at = datetime.now(timezone.utc)
            await db.flush()
            await ws_manager.broadcast("alert.updated", {
                "alert_id": alert.alert_id,
                "status": alert.status,
                "acknowledged_by": user_id
            })
            await log_audit(db, actor=user_id, action="ALERT_ACKNOWLEDGED", resource="alert", resource_id=alert_id)
        return alert

    async def resolve_alert(self, db: AsyncSession, alert_id: str, user_id: str) -> Optional[Alert]:
        stmt = select(Alert).where(Alert.alert_id == alert_id)
        result = await db.execute(stmt)
        alert = result.scalars().first()
        if alert:
            alert.status = "RESOLVED"
            alert.resolved_by = user_id
            alert.resolved_at = datetime.now(timezone.utc)
            await db.flush()
            await ws_manager.broadcast("alert.updated", {
                "alert_id": alert.alert_id,
                "status": alert.status,
                "resolved_by": user_id
            })
            await log_audit(db, actor=user_id, action="ALERT_RESOLVED", resource="alert", resource_id=alert_id)
        return alert

alert_service = AlertService()
