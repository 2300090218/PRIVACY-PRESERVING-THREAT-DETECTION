"""
Audit Trail API Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.all_models import AuditLog
from backend.app.schemas.all_schemas import AuditLogResponse

router = APIRouter(prefix="/api/audit", tags=["Audit"])

@router.get("", response_model=List[AuditLogResponse])
async def get_audit_logs(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    actor: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(AuditLog).order_by(desc(AuditLog.timestamp))
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    stmt = stmt.offset(offset).limit(limit)

    result = await db.execute(stmt)
    return result.scalars().all()
