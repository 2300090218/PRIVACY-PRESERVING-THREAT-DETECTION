"""
Authentication API Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.database import get_db
from backend.app.models.all_models import User
from backend.app.schemas.all_schemas import LoginRequest, TokenResponse, UserResponse
from backend.app.security.authentication import verify_password, create_access_token, get_current_user
from backend.app.services.audit_service import log_audit

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.username == req.username)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not verify_password(req.password, user.hashed_password):
        await log_audit(
            db, actor=req.username, action="LOGIN_FAILED",
            resource="user", result="FAILURE"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    await log_audit(
        db, actor=user.username, action="LOGIN_SUCCESS",
        resource="user", resource_id=str(user.id), result="SUCCESS"
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        role=user.role,
        username=user.username
    )

@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await log_audit(
        db, actor=current_user.username, action="LOGOUT",
        resource="user", resource_id=str(current_user.id)
    )
    return {"message": "Logged out successfully"}

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user
