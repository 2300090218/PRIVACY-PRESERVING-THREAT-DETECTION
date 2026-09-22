"""
Incident Management & Correlation Service
Manages incident lifecycle: correlation, triage, updates, resolution, and real-time broadcasts.
"""

import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from backend.app.models.all_models import Incident, Alert
from backend.app.websocket.manager import ws_manager
from backend.app.services.audit_service import log_audit

class IncidentService:
    async def correlate_alert(self, db: AsyncSession, alert: Alert, event_id: str) -> Incident:
        """
        Correlates a high-severity alert into an active incident or creates a new one.
        """
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
            return active_inc
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
            await ws_manager.broadcast("incident.created", {
                "incident_id": new_inc.incident_id,
                "title": new_inc.title,
                "severity": new_inc.severity,
                "status": new_inc.status,
                "alerts_count": 1
            })
            return new_inc

    async def list_incidents(
        self,
        db: AsyncSession,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None
    ) -> List[Incident]:
        stmt = select(Incident).order_by(desc(Incident.created_at))
        if status:
            stmt = stmt.where(Incident.status == status)
        stmt = stmt.offset(offset).limit(limit)
        result = await db.execute(stmt)
        return result.scalars().all()

    async def get_incident(self, db: AsyncSession, incident_id: str) -> Optional[Incident]:
        stmt = select(Incident).where(Incident.incident_id == incident_id)
        result = await db.execute(stmt)
        return result.scalars().first()

    async def create_incident(
        self,
        db: AsyncSession,
        title: str,
        severity: str,
        related_alerts: List[str] = None,
        related_events: List[str] = None,
        summary: Optional[str] = None,
        actor: str = "SECURITY_ANALYST"
    ) -> Incident:
        inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        incident = Incident(
            incident_id=inc_id,
            title=title,
            severity=severity,
            status="OPEN",
            related_alerts=related_alerts or [],
            related_events=related_events or [],
            summary=summary
        )
        db.add(incident)
        await db.flush()
        await log_audit(
            db, actor=actor, action="INCIDENT_CREATED",
            resource="incident", resource_id=inc_id,
            metadata={"severity": severity, "title": title}
        )
        await ws_manager.broadcast("incident.created", {
            "incident_id": inc_id,
            "title": title,
            "severity": severity,
            "status": "OPEN"
        })
        return incident

    async def update_incident(
        self,
        db: AsyncSession,
        incident_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        summary: Optional[str] = None,
        actor: str = "SECURITY_ANALYST"
    ) -> Optional[Incident]:
        incident = await self.get_incident(db, incident_id)
        if not incident:
            return None

        if status is not None:
            incident.status = status
        if severity is not None:
            incident.severity = severity
        if summary is not None:
            incident.summary = summary

        await db.flush()
        await log_audit(
            db, actor=actor, action="INCIDENT_UPDATED",
            resource="incident", resource_id=incident_id,
            metadata={"status": incident.status, "severity": incident.severity}
        )
        await ws_manager.broadcast("incident.updated", {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status
        })
        return incident

    async def resolve_incident(
        self,
        db: AsyncSession,
        incident_id: str,
        actor: str = "SECURITY_ANALYST"
    ) -> Optional[Incident]:
        return await self.update_incident(
            db, incident_id, status="RESOLVED",
            summary="Incident investigated and marked as resolved by analyst.",
            actor=actor
        )

incident_service = IncidentService()
