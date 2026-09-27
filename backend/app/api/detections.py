"""
Detections API Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.all_models import Detection
from backend.app.schemas.all_schemas import DetectionResponse

router = APIRouter(prefix="/api/detections", tags=["Detections"])

@router.get("", response_model=List[DetectionResponse])
async def get_detections(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Detection).order_by(desc(Detection.created_at))
    if attack_type:
        stmt = stmt.where(Detection.attack_type == attack_type)
    if severity:
        stmt = stmt.where(Detection.severity == severity)
    stmt = stmt.offset(offset).limit(limit)

    result = await db.execute(stmt)
    return result.scalars().all()

@router.get("/metrics")
async def get_detection_metrics_endpoint(db: AsyncSession = Depends(get_db)):
    """Provides detection aggregation metrics matching /api/metrics/detection."""
    from backend.app.api.metrics import get_detection_metrics
    return await get_detection_metrics(db)

@router.get("/{detection_id}", response_model=DetectionResponse)
async def get_detection(detection_id: int, db: AsyncSession = Depends(get_db)):
    stmt = select(Detection).where(Detection.id == detection_id)
    result = await db.execute(stmt)
    detection = result.scalars().first()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    return detection

