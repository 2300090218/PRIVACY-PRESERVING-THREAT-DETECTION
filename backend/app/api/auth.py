"""
Production Authentication & Two-Step Verification API Endpoints
Implements email-based authentication, cryptographic OTP two-factor verification,
secure session cookies, rate-limiting, and password reset flows.
"""

import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update
from sqlalchemy.orm import selectinload

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.all_models import (
    User, UserSession, EmailVerificationCode, PasswordResetToken
)
from backend.app.schemas.all_schemas import (
    LoginRequest, LoginResponse, VerifyOtpRequest, ResendOtpRequest,
    ForgotPasswordRequest, ResetPasswordRequest, UserResponse, TokenResponse
)
from backend.app.security.authentication import (
    verify_password, get_password_hash, hash_otp, hash_token,
    create_access_token, create_user_session, revoke_session_by_token,
    get_current_user
)
from backend.app.services.email_service import (
    send_verification_otp, send_password_reset_email, mask_email
)
from backend.app.services.rate_limiter import (
    check_rate_limit, record_login_attempt
)
from backend.app.services.audit_service import log_audit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

def to_utc(dt: datetime) -> datetime:
    """Ensures datetime is offset-aware in UTC for safe cross-platform comparisons."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def get_client_ip(request: Request) -> Optional[str]:
    """Safely extracts client IP address, checking proxy headers."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None

@router.post("/login", response_model=LoginResponse)
async def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """
    Step 1: Authenticate Email & Password.
    If 2FA is active (default), generates a cryptographically secure OTP and
    dispatches an email verification notice.
    """
    client_ip = get_client_ip(request)
    identifier = (req.email or req.username or "").strip().lower()

    if not identifier or not req.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email and password are required."
        )

    # 1. Enforce Rate Limiting
    await check_rate_limit(db, identifier=identifier, ip_address=client_ip, attempt_type="PASSWORD")

    # 2. Look up User by Email or Username
    stmt = select(User).where((User.email == identifier) | (User.username == identifier))
    result = await db.execute(stmt)
    user = result.scalars().first()

    # 3. Verify Password
    if not user or not verify_password(req.password, user.hashed_password):
        await record_login_attempt(db, identifier=identifier, ip_address=client_ip, attempt_type="PASSWORD", is_success=False)
        await log_audit(
            db, actor=identifier, action="LOGIN_FAILED",
            resource="auth", result="FAILURE",
            metadata_payload={"reason": "INVALID_CREDENTIALS", "ip": client_ip}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        await record_login_attempt(db, identifier=identifier, ip_address=client_ip, attempt_type="PASSWORD", is_success=False)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account is inactive. Please contact your SOC administrator."
        )

    await record_login_attempt(db, identifier=identifier, ip_address=client_ip, attempt_type="PASSWORD", is_success=True)

    # 4. Two-Step Verification Flow
    if user.two_factor_enabled:
        otp_code = f"{secrets.randbelow(1000000):06d}"
        session_nonce = secrets.token_urlsafe(32)
        otp_hash = hash_otp(otp_code)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.AUTH_OTP_EXPIRE_MINUTES)

        v_code = EmailVerificationCode(
            user_id=user.id,
            otp_hash=otp_hash,
            session_nonce=session_nonce,
            purpose="LOGIN_2FA",
            attempt_count=0,
            max_attempts=settings.AUTH_OTP_MAX_ATTEMPTS,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            consumed_at=None
        )
        db.add(v_code)
        await db.flush()

        # Dispatch email (safe background handling)
        await send_verification_otp(
            to_email=user.email,
            otp_code=otp_code,
            expires_minutes=settings.AUTH_OTP_EXPIRE_MINUTES,
            session_nonce=session_nonce
        )

        await log_audit(
            db, actor=user.email, action="OTP_SENT",
            resource="auth", resource_id=str(user.id), result="SUCCESS",
            metadata_payload={"purpose": "LOGIN_2FA", "session_nonce": session_nonce}
        )

        return LoginResponse(
            status="OTP_SENT",
            two_factor_required=True,
            session_nonce=session_nonce,
            email_masked=mask_email(user.email),
            expires_in_seconds=settings.AUTH_OTP_EXPIRE_MINUTES * 60,
            message="Verification code sent to registered email address."
        )

    # 5. Direct Login (if 2FA explicitly disabled on user account)
    raw_token, session_rec = await create_user_session(
        user=user, db=db, ip_address=client_ip, user_agent=request.headers.get("user-agent")
    )
    access_token = create_access_token(data={
        "sub": user.username,
        "email": user.email,
        "role": user.role,
        "organization_id": user.organization_id
    })

    # Set HttpOnly Session Cookie
    response.set_cookie(
        key="auth_session",
        value=raw_token,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        max_age=settings.AUTH_SESSION_EXPIRE_DAYS * 86400
    )

    user.last_login_at = datetime.now(timezone.utc)
    await db.flush()

    await log_audit(
        db, actor=user.email, action="LOGIN_SUCCESS",
        resource="auth", resource_id=str(user.id), result="SUCCESS",
        metadata_payload={"method": "PASSWORD_ONLY", "ip": client_ip}
    )

    return LoginResponse(
        status="AUTHENTICATED",
        access_token=access_token,
        token_type="bearer",
        role=user.role,
        username=user.username,
        email=user.email,
        display_name=user.display_name or user.username,
        organization_id=user.organization_id,
        message="Authenticated successfully."
    )

@router.post("/verify-otp", response_model=LoginResponse)
async def verify_otp(
    req: VerifyOtpRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """
    Step 2: Validates the one-time verification code and creates an authentic session.
    """
    client_ip = get_client_ip(request)
    now = datetime.now(timezone.utc)

    # 1. Rate Limit Check
    await check_rate_limit(db, identifier=req.session_nonce, ip_address=client_ip, attempt_type="OTP")

    # 2. Look up Verification Record
    stmt = (
        select(EmailVerificationCode)
        .options(selectinload(EmailVerificationCode.user))
        .where(EmailVerificationCode.session_nonce == req.session_nonce)
    )
    res = await db.execute(stmt)
    v_code = res.scalars().first()

    if not v_code or not v_code.user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification session."
        )

    if v_code.consumed_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has already been consumed."
        )

    if now > to_utc(v_code.expires_at):
        await log_audit(
            db, actor=v_code.user.email, action="OTP_EXPIRED",
            resource="auth", resource_id=str(v_code.user.id), result="FAILURE"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has expired. Please request a new code."
        )

    if v_code.attempt_count >= v_code.max_attempts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum attempts exceeded. Please request a new code."
        )

    # 3. Compare Cryptographic OTP Hash
    otp_code = (req.code or req.otp or "").strip()
    if not otp_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code is required."
        )

    provided_hash = hash_otp(otp_code)
    import hmac
    if not hmac.compare_digest(v_code.otp_hash, provided_hash):
        v_code.attempt_count += 1
        await db.flush()
        await record_login_attempt(db, identifier=req.session_nonce, ip_address=client_ip, attempt_type="OTP", is_success=False)
        await log_audit(
            db, actor=v_code.user.email, action="OTP_FAILED",
            resource="auth", resource_id=str(v_code.user.id), result="FAILURE",
            metadata_payload={"attempts": v_code.attempt_count}
        )
        remaining = v_code.max_attempts - v_code.attempt_count
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid verification code. {remaining} attempt(s) remaining."
        )

    # 4. OTP Successfully Verified
    v_code.consumed_at = now
    user = v_code.user
    user.last_login_at = now
    user.email_verified = True

    # 5. Create Session & Issue Tokens
    raw_token, session_rec = await create_user_session(
        user=user, db=db, ip_address=client_ip, user_agent=request.headers.get("user-agent")
    )
    access_token = create_access_token(data={
        "sub": user.username,
        "email": user.email,
        "role": user.role,
        "organization_id": user.organization_id
    })

    # Set Secure HttpOnly Cookie
    response.set_cookie(
        key="auth_session",
        value=raw_token,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        max_age=settings.AUTH_SESSION_EXPIRE_DAYS * 86400
    )

    await record_login_attempt(db, identifier=req.session_nonce, ip_address=client_ip, attempt_type="OTP", is_success=True)
    await log_audit(
        db, actor=user.email, action="OTP_VERIFIED",
        resource="auth", resource_id=str(user.id), result="SUCCESS"
    )
    await log_audit(
        db, actor=user.email, action="LOGIN_SUCCESS",
        resource="auth", resource_id=str(user.id), result="SUCCESS",
        metadata_payload={"method": "EMAIL_2FA", "ip": client_ip}
    )

    return LoginResponse(
        status="AUTHENTICATED",
        access_token=access_token,
        token_type="bearer",
        role=user.role,
        username=user.username,
        email=user.email,
        display_name=user.display_name or user.username,
        organization_id=user.organization_id,
        message="Authenticated successfully. Welcome back!"
    )

@router.post("/resend-otp")
async def resend_otp(
    req: ResendOtpRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Generates a fresh OTP for an active verification session with cooldown protections."""
    client_ip = get_client_ip(request)
    now = datetime.now(timezone.utc)

    stmt = (
        select(EmailVerificationCode)
        .options(selectinload(EmailVerificationCode.user))
        .where(EmailVerificationCode.session_nonce == req.session_nonce)
    )
    res = await db.execute(stmt)
    v_code = res.scalars().first()

    if not v_code or not v_code.user or v_code.consumed_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification session."
        )

    # 30-second resend cooldown
    age_seconds = (now - to_utc(v_code.created_at)).total_seconds()
    if age_seconds < 30:
        wait_seconds = int(30 - age_seconds)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Please wait {wait_seconds} seconds before requesting a new code."
        )

    # Issue fresh code
    new_otp = f"{secrets.randbelow(1000000):06d}"
    v_code.otp_hash = hash_otp(new_otp)
    v_code.attempt_count = 0
    v_code.created_at = now
    v_code.expires_at = now + timedelta(minutes=settings.AUTH_OTP_EXPIRE_MINUTES)
    await db.flush()

    await send_verification_otp(
        to_email=v_code.user.email,
        otp_code=new_otp,
        expires_minutes=settings.AUTH_OTP_EXPIRE_MINUTES,
        session_nonce=v_code.session_nonce
    )
    await log_audit(
        db, actor=v_code.user.email, action="OTP_SENT",
        resource="auth", resource_id=str(v_code.user.id), result="SUCCESS",
        metadata_payload={"type": "RESEND", "ip": client_ip}
    )

    return {
        "status": "OTP_SENT",
        "message": "A new verification code has been dispatched to your email.",
        "expires_in_seconds": settings.AUTH_OTP_EXPIRE_MINUTES * 60
    }

@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """Terminates the session server-side and clears authentication cookies."""
    cookie_token = request.cookies.get("auth_session")
    if cookie_token:
        await revoke_session_by_token(cookie_token, db)
        response.delete_cookie("auth_session")

    try:
        user = await get_current_user(request=request, credentials=None, db=db)
        await log_audit(
            db, actor=user.email, action="LOGOUT",
            resource="auth", resource_id=str(user.id), result="SUCCESS"
        )
    except Exception:
        pass

    return {"message": "Logged out successfully."}

@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
    """Returns the authenticated user's profile and security attributes."""
    return user

@router.post("/forgot-password")
async def forgot_password(
    req: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    """Issues a single-use password reset token via email."""
    email_clean = req.email.strip().lower()
    stmt = select(User).where(User.email == email_clean)
    res = await db.execute(stmt)
    user = res.scalars().first()

    if user and user.is_active:
        raw_token = secrets.token_urlsafe(32)
        t_hash = hash_token(raw_token)
        expires = datetime.now(timezone.utc) + timedelta(minutes=15)

        reset_rec = PasswordResetToken(
            user_id=user.id,
            token_hash=t_hash,
            created_at=datetime.now(timezone.utc),
            expires_at=expires,
            consumed_at=None
        )
        db.add(reset_rec)
        await db.flush()

        await send_password_reset_email(to_email=user.email, reset_token=raw_token)
        await log_audit(
            db, actor=user.email, action="PASSWORD_RESET_REQUESTED",
            resource="auth", resource_id=str(user.id), result="SUCCESS"
        )

    # Always return generic message to prevent account enumeration
    return {
        "message": "If an active account exists for this email, password reset instructions have been sent."
    }

@router.post("/reset-password")
async def reset_password(
    req: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    """Verifies reset token and updates the user's password with modern bcrypt."""
    now = datetime.now(timezone.utc)
    t_hash = hash_token(req.token)

    if len(req.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )

    stmt = (
        select(PasswordResetToken)
        .options(selectinload(PasswordResetToken.user))
        .where(PasswordResetToken.token_hash == t_hash)
    )
    res = await db.execute(stmt)
    rec = res.scalars().first()

    if not rec or not rec.user or rec.consumed_at is not None or now > to_utc(rec.expires_at):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset token is invalid or has expired."
        )

    rec.consumed_at = now
    user = rec.user
    user.hashed_password = get_password_hash(req.new_password)
    user.updated_at = now

    # Invalidate all existing sessions for this user
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id)
        .values(is_revoked=True)
    )
    await db.flush()

    await log_audit(
        db, actor=user.email, action="PASSWORD_RESET_COMPLETED",
        resource="auth", resource_id=str(user.id), result="SUCCESS"
    )

    return {"message": "Password updated successfully. You may now sign in with your new password."}
