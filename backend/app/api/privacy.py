"""
Privacy Center API Endpoints
"""

from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.all_models import PrivacyEvent
from backend.app.schemas.all_schemas import PrivacyStatusResponse, PrivacyEventResponse
from backend.app.services.privacy_service import privacy_engine

router = APIRouter(prefix="/api/privacy", tags=["Privacy"])

@router.get("/status", response_model=PrivacyStatusResponse)
async def get_privacy_status():
    return privacy_engine.get_status_summary()

@router.get("/events", response_model=List[PrivacyEventResponse])
async def get_privacy_events(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(PrivacyEvent).order_by(desc(PrivacyEvent.timestamp)).offset(offset).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()
