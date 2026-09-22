"""
API v1 Detections Router
Lists rule-based and machine-learning threat detections.
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.database import get_db
from backend.app.models.all_models import Detection, RiskAssessment
from backend.app.schemas.v1_schemas import DetectionResponse

router = APIRouter(prefix="/detections", tags=["v1 - Detections"])

@router.get("", response_model=List[DetectionResponse])
async def list_detections(
    limit: int = 50,
    offset: int = 0,
    organization_id: Optional[str] = None,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Detection).order_by(Detection.created_at.desc()).limit(limit).offset(offset)
    if organization_id:
        stmt = stmt.where(Detection.organization_id == organization_id)
    if severity:
        stmt = stmt.where(Detection.severity == severity.upper())
    if attack_type:
        stmt = stmt.where(Detection.attack_type == attack_type)

    res = await db.execute(stmt)
    detections = res.scalars().all()

    output = []
    for d in detections:
        output.append(DetectionResponse(
            detection_id=d.detection_id or f"det_{d.id}",
            event_id=d.event_id,
            organization_id=d.organization_id,
            prediction=d.prediction,
            attack_type=d.attack_type,
            confidence=d.confidence,
            severity=d.severity,
            model_version=d.model_version,
            rule_matches=d.rule_matches or [],
            processing_latency_ms=d.processing_latency_ms,
            created_at=d.created_at
        ))
    return output
