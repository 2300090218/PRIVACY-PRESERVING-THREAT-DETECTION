"""
Alerts API Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.all_models import Alert, User
from backend.app.schemas.all_schemas import AlertResponse
from backend.app.services.alert_service import alert_service
from backend.app.security.authentication import get_current_user

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

@router.get("", response_model=List[AlertResponse])
async def get_alerts(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Alert).order_by(desc(Alert.timestamp))
    if status_filter:
        stmt = stmt.where(Alert.status == status_filter)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    stmt = stmt.offset(offset).limit(limit)

    result = await db.execute(stmt)
    return result.scalars().all()

from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt
from backend.app.config import settings
from backend.app.security.authentication import security_bearer

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

@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_optional_analyst)
):
    if user and user.role not in ("ADMIN", "SECURITY_ANALYST"):
        raise HTTPException(status_code=403, detail="Only ADMIN or SECURITY_ANALYST can acknowledge alerts")
    actor = user.username if user else "SECURITY_ANALYST"
    alert = await alert_service.acknowledge_alert(db, alert_id, user_id=actor)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.post("/{alert_id}/resolve", response_model=AlertResponse)
async def resolve_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_optional_analyst)
):
    if user and user.role not in ("ADMIN", "SECURITY_ANALYST"):
        raise HTTPException(status_code=403, detail="Only ADMIN or SECURITY_ANALYST can resolve alerts")
    actor = user.username if user else "SECURITY_ANALYST"
    alert = await alert_service.resolve_alert(db, alert_id, user_id=actor)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
