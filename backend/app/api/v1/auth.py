"""
API v1 Authentication Router
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.database import get_db
from backend.app.models.all_models import User
from backend.app.security.authentication import verify_password, create_access_token, get_current_user
from backend.app.services.audit_service import log_audit

router = APIRouter(prefix="/auth", tags=["v1 - Authentication"])

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str
    organization_id: str

@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.username == req.username)
    res = await db.execute(stmt)
    user = res.scalars().first()

    if not user or not verify_password(req.password, user.hashed_password):
        await log_audit(
            db,
            actor=req.username,
            action="LOGIN_FAILED",
            resource="auth",
            organization_id="system",
            result="FAILURE"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = create_access_token(data={
        "sub": user.username,
        "role": user.role,
        "organization_id": user.organization_id
    })

    await log_audit(
        db,
        actor=user.username,
        action="LOGIN_SUCCESS",
        resource="auth",
        organization_id=user.organization_id,
        result="SUCCESS"
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username,
        "organization_id": user.organization_id
    }

@router.get("/me")
async def get_me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "organization_id": user.organization_id,
        "created_at": user.created_at
    }
