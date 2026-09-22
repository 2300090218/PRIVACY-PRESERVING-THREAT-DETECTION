"""
Versioned Audit Trail API Endpoints (/api/v1/audit-logs)
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.all_models import AuditLog
from backend.app.schemas.v1_schemas import AuditLogResponse
from backend.app.security.authentication import get_current_user

router = APIRouter(prefix="/audit-logs", tags=["V1 Audit Logs"])

@router.get("", response_model=List[AuditLogResponse])
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    organization_id: Optional[str] = Query(None, description="Filter by Organization ID"),
    action: Optional[str] = Query(None, description="Filter by Action (e.g., LOGIN, INGEST_EVENT)"),
    actor: Optional[str] = Query(None, description="Filter by Actor"),
    result: Optional[str] = Query(None, description="Filter by Result (SUCCESS, FAILURE, REJECTED)"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Retrieve real database audit trail entries.
    Admins can see all logs; organization analysts are restricted to their organization.
    """
    stmt = select(AuditLog).order_by(desc(AuditLog.timestamp))
    
    # Enforce multi-tenancy authorization
    user_role = getattr(current_user, "role", None) or (current_user.get("role", "") if isinstance(current_user, dict) else "")
    user_org = getattr(current_user, "organization_id", None) or (current_user.get("organization_id", "org_enterprise_a") if isinstance(current_user, dict) else "org_enterprise_a")
    
    if user_role not in ["ADMIN", "SYSTEM_ADMIN"]:
        stmt = stmt.where(AuditLog.organization_id == user_org)
    elif organization_id:
        stmt = stmt.where(AuditLog.organization_id == organization_id)
        
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if result:
        stmt = stmt.where(AuditLog.result == result)
        
    stmt = stmt.offset(offset).limit(limit)
    res = await db.execute(stmt)
    records = res.scalars().all()
    
    return [
        AuditLogResponse(
            id=rec.id,
            timestamp=rec.timestamp,
            organization_id=getattr(rec, "organization_id", "org_enterprise_a") or "org_enterprise_a",
            actor=rec.actor,
            action=rec.action,
            resource=rec.resource,
            resource_id=rec.resource_id,
            result=rec.result,
            metadata_payload=rec.metadata_payload or {}
        )
        for rec in records
    ]
