"""
Model Management API Endpoints
"""

from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.all_models import ModelVersion
from backend.app.schemas.all_schemas import ModelVersionResponse
from backend.app.detection.model_manager import model_manager

router = APIRouter(prefix="/api/models", tags=["Models"])

@router.get("", response_model=List[ModelVersionResponse])
async def list_models(db: AsyncSession = Depends(get_db)):
    stmt = select(ModelVersion).order_by(desc(ModelVersion.created_at))
    result = await db.execute(stmt)
    return result.scalars().all()

@router.get("/current")
async def get_current_model():
    return model_manager.get_metadata()
