"""
Event Ingestion & Telemetry Retrieval API
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.all_models import SecurityEvent
from backend.app.schemas.all_schemas import EventIngestRequest, EventResponse
from backend.app.services.event_service import event_service

router = APIRouter(prefix="/api/events", tags=["Events"])

@router.post("", response_model=dict)
async def ingest_event(req: EventIngestRequest, db: AsyncSession = Depends(get_db)):
    """Ingests authorized telemetry event and runs the entire privacy and detection pipeline."""
    sec_event, detection, summary = await event_service.process_and_ingest_event(
        db=db,
        event_dict=req.model_dump(),
        actor=req.client_id
    )
    return {
        "status": "PROCESSED",
        "event_id": sec_event.event_id,
        "prediction": detection.prediction,
        "attack_type": detection.attack_type,
        "confidence": detection.confidence,
        "severity": detection.severity,
        "risk_score": summary["risk"]["risk_score"],
        "processing_latency_ms": sec_event.processing_latency_ms,
        "privacy_transformations": summary["privacy_transformations"],
        "alert_created": summary["alert_created"]
    }

@router.post("/batch", response_model=dict)
async def ingest_batch_events(reqs: List[EventIngestRequest], db: AsyncSession = Depends(get_db)):
    """Ingests a batch of authorized telemetry events (e.g. from live packet sniffer)."""
    results = []
    total_alerts = 0
    for req in reqs:
        sec_event, detection, summary = await event_service.process_and_ingest_event(
            db=db,
            event_dict=req.model_dump(),
            actor=req.client_id
        )
        if summary.get("alert_created"):
            total_alerts += 1
        results.append({
            "event_id": sec_event.event_id,
            "prediction": detection.prediction,
            "attack_type": detection.attack_type,
            "risk_score": summary["risk"]["risk_score"],
            "severity": detection.severity
        })
    return {
        "status": "BATCH_PROCESSED",
        "count": len(results),
        "total_alerts": total_alerts,
        "events": results
    }

@router.get("", response_model=List[EventResponse])
async def get_events(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    client_id: Optional[str] = None,
    is_test: Optional[bool] = None,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(SecurityEvent).order_by(desc(SecurityEvent.timestamp))
    if client_id:
        stmt = stmt.where(SecurityEvent.client_id == client_id)
    if is_test is not None:
        stmt = stmt.where(SecurityEvent.is_test == is_test)
    stmt = stmt.offset(offset).limit(limit)

    result = await db.execute(stmt)
    events = result.scalars().all()
    return events

@router.get("/recent", response_model=List[EventResponse])
async def get_recent_events(limit: int = 15, db: AsyncSession = Depends(get_db)):
    stmt = select(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()

@router.get("/{event_id}", response_model=EventResponse)
async def get_event_by_id(event_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(SecurityEvent).where(SecurityEvent.event_id == event_id)
    result = await db.execute(stmt)
    event = result.scalars().first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
