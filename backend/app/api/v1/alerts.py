"""
API v1 Alerts Router
Manages high-severity threat alerts and operational analyst triage.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.database import get_db
from backend.app.models.all_models import Alert
from backend.app.schemas.v1_schemas import AlertResponse
from backend.app.websocket.manager import ws_manager
from backend.app.services.audit_service import log_audit

router = APIRouter(prefix="/alerts", tags=["v1 - Alerts"])

@router.get("", response_model=List[AlertResponse])
async def list_alerts(
    status_filter: Optional[str] = None,
    severity: Optional[str] = None,
    organization_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Alert).order_by(Alert.timestamp.desc()).limit(limit).offset(offset)
    if status_filter:
        stmt = stmt.where(Alert.status == status_filter.upper())
    if severity:
        stmt = stmt.where(Alert.severity == severity.upper())
    if organization_id:
        stmt = stmt.where(Alert.organization_id == organization_id)

    res = await db.execute(stmt)
    alerts = res.scalars().all()

    output = []
    for a in alerts:
        output.append(AlertResponse(
            alert_id=a.alert_id,
            organization_id=a.organization_id,
            event_id=a.event_id,
            attack_type=a.attack_type,
            severity=a.severity,
            confidence=a.confidence,
            risk_score=a.risk_score,
            explanation=a.explanation,
            status=a.status,
            acknowledged_by=a.acknowledged_by,
            acknowledged_at=a.acknowledged_at,
            resolved_by=a.resolved_by,
            resolved_at=a.resolved_at,
            timestamp=a.timestamp,
            is_test=a.is_test
        ))
    return output

@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
@router.put("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: str,
    analyst_name: str = "security_analyst",
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Alert).where(Alert.alert_id == alert_id)
    res = await db.execute(stmt)
    alert = res.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_by = analyst_name
    alert.acknowledged_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(alert)

    await log_audit(
        db,
        actor=analyst_name,
        action="ALERT_ACKNOWLEDGED",
        resource="alert",
        organization_id=alert.organization_id,
        resource_id=alert.alert_id,
        result="SUCCESS"
    )

    await ws_manager.broadcast("alert.updated", {
        "alert_id": alert.alert_id,
        "status": "ACKNOWLEDGED",
        "acknowledged_by": analyst_name
    })

    return AlertResponse(
        alert_id=alert.alert_id,
        organization_id=alert.organization_id,
        event_id=alert.event_id,
        attack_type=alert.attack_type,
        severity=alert.severity,
        confidence=alert.confidence,
        risk_score=alert.risk_score,
        explanation=alert.explanation,
        status=alert.status,
        acknowledged_by=alert.acknowledged_by,
        acknowledged_at=alert.acknowledged_at,
        resolved_by=alert.resolved_by,
        resolved_at=alert.resolved_at,
        timestamp=alert.timestamp,
        is_test=alert.is_test
    )

@router.post("/{alert_id}/resolve", response_model=AlertResponse)
@router.put("/{alert_id}/resolve", response_model=AlertResponse)
async def resolve_alert(
    alert_id: str,
    analyst_name: str = "security_analyst",
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Alert).where(Alert.alert_id == alert_id)
    res = await db.execute(stmt)
    alert = res.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    alert.status = "RESOLVED"
    alert.resolved_by = analyst_name
    alert.resolved_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(alert)

    await log_audit(
        db,
        actor=analyst_name,
        action="ALERT_RESOLVED",
        resource="alert",
        organization_id=alert.organization_id,
        resource_id=alert.alert_id,
        result="SUCCESS"
    )

    await ws_manager.broadcast("alert.updated", {
        "alert_id": alert.alert_id,
        "status": "RESOLVED",
        "resolved_by": analyst_name
    })

    return AlertResponse(
        alert_id=alert.alert_id,
        organization_id=alert.organization_id,
        event_id=alert.event_id,
        attack_type=alert.attack_type,
        severity=alert.severity,
        confidence=alert.confidence,
        risk_score=alert.risk_score,
        explanation=alert.explanation,
        status=alert.status,
        acknowledged_by=alert.acknowledged_by,
        acknowledged_at=alert.acknowledged_at,
        resolved_by=alert.resolved_by,
        resolved_at=alert.resolved_at,
        timestamp=alert.timestamp,
        is_test=alert.is_test
    )
