"""
API v1 Authentication Router
Provides enterprise email authentication, two-step verification, and profile endpoints.
"""

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.models.all_models import User
from backend.app.schemas.all_schemas import (
    LoginRequest, LoginResponse, VerifyOtpRequest, ResendOtpRequest,
    ForgotPasswordRequest, ResetPasswordRequest, UserResponse
)
from backend.app.security.authentication import get_current_user
from backend.app.api.auth import (
    login as auth_login,
    verify_otp as auth_verify_otp,
    resend_otp as auth_resend_otp,
    logout as auth_logout,
    forgot_password as auth_forgot_password,
    reset_password as auth_reset_password
)

router = APIRouter(prefix="/auth", tags=["v1 - Authentication"])

@router.post("/login", response_model=LoginResponse)
async def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    return await auth_login(req=req, request=request, response=response, db=db)

@router.post("/verify-otp", response_model=LoginResponse)
async def verify_otp(
    req: VerifyOtpRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    return await auth_verify_otp(req=req, request=request, response=response, db=db)

@router.post("/resend-otp")
async def resend_otp(
    req: ResendOtpRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    return await auth_resend_otp(req=req, request=request, db=db)

@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    return await auth_logout(request=request, response=response, db=db)

@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
    return user

@router.post("/forgot-password")
async def forgot_password(
    req: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    return await auth_forgot_password(req=req, db=db)

@router.post("/reset-password")
async def reset_password(
    req: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    return await auth_reset_password(req=req, db=db)
