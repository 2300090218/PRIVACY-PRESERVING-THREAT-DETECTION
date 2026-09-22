"""
Incidents API Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.all_models import Incident, User
from backend.app.schemas.all_schemas import IncidentCreateRequest, IncidentUpdateRequest, IncidentResponse
from backend.app.services.incident_service import incident_service
from backend.app.security.authentication import security_bearer
from sqlalchemy.future import select

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])

async def get_optional_analyst(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    if not credentials:
        return None
    try:
        payload = jwt.decode(credentials.credentials, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        username = payload.get("sub")
        if username:
            stmt = select(User).where(User.username == username)
            res = await db.execute(stmt)
            return res.scalars().first()
    except Exception:
        return None
    return None

@router.get("", response_model=List[IncidentResponse])
async def get_incidents(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db)
):
    return await incident_service.list_incidents(db, limit=limit, offset=offset, status=status_filter)

@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    incident = await incident_service.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.post("", response_model=IncidentResponse)
async def create_incident(
    req: IncidentCreateRequest,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_optional_analyst)
):
    if user and user.role not in ("ADMIN", "SECURITY_ANALYST"):
        raise HTTPException(status_code=403, detail="Only ADMIN or SECURITY_ANALYST can create incidents")
    actor = user.username if user else "SECURITY_ANALYST"
    return await incident_service.create_incident(
        db=db,
        title=req.title,
        severity=req.severity,
        related_alerts=req.related_alerts,
        related_events=req.related_events,
        summary=req.summary,
        actor=actor
    )

@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    req: IncidentUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_optional_analyst)
):
    if user and user.role not in ("ADMIN", "SECURITY_ANALYST"):
        raise HTTPException(status_code=403, detail="Only ADMIN or SECURITY_ANALYST can update incidents")
    actor = user.username if user else "SECURITY_ANALYST"
    incident = await incident_service.update_incident(
        db=db,
        incident_id=incident_id,
        status=req.status,
        severity=req.severity,
        summary=req.summary,
        actor=actor
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.post("/{incident_id}/resolve", response_model=IncidentResponse)
async def resolve_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_optional_analyst)
):
    if user and user.role not in ("ADMIN", "SECURITY_ANALYST"):
        raise HTTPException(status_code=403, detail="Only ADMIN or SECURITY_ANALYST can resolve incidents")
    actor = user.username if user else "SECURITY_ANALYST"
    incident = await incident_service.resolve_incident(db, incident_id, actor=actor)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
