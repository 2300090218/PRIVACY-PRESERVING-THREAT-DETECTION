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
from sqlalchemy.orm import selectinload, joinedload

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.all_models import (
    User, UserSession, EmailVerificationCode, PasswordResetToken
)
from backend.app.schemas.all_schemas import (
    LoginRequest, LoginResponse, VerifyOtpRequest, ResendOtpRequest,
    ForgotPasswordRequest, ResetPasswordRequest, UserResponse, TokenResponse,
    RegisterRequest
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

@router.post("/register", response_model=LoginResponse)
@router.post("/signup", response_model=LoginResponse)
async def register(
    req: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Account Registration:
    Registers a new user and sends a 6-digit confirmation OTP to their email address.
    """
    client_ip = get_client_ip(request)
    email_clean = (req.email or "").strip().lower()

    if not email_clean or "@" not in email_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid email address is required."
        )

    if len(req.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )

    # Check for existing user
    stmt = select(User).where(User.email == email_clean)
    res = await db.execute(stmt)
    existing_user = res.scalars().first()

    if existing_user and existing_user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists. Please sign in."
        )

    username_clean = (req.username or email_clean.split("@")[0]).strip().lower()
    # Ensure username is unique if new user
    if not existing_user:
        u_stmt = select(User).where(User.username == username_clean)
        u_res = await db.execute(u_stmt)
        if u_res.scalars().first():
            username_clean = f"{username_clean}_{secrets.randbelow(1000):03d}"

        user = User(
            username=username_clean,
            email=email_clean,
            hashed_password=get_password_hash(req.password),
            display_name=req.display_name or (req.username or email_clean.split("@")[0]),
            role=req.role or "ANALYST",
            organization_id=req.organization_id or "org_enterprise_a",
            is_active=False,
            email_verified=False,
            two_factor_enabled=True,
            created_at=datetime.now(timezone.utc)
        )
        db.add(user)
        await db.flush()
    else:
        user = existing_user
        user.hashed_password = get_password_hash(req.password)
        if req.display_name:
            user.display_name = req.display_name

    # Generate 6-digit confirmation OTP
    otp_code = f"{secrets.randbelow(1000000):06d}"
    session_nonce = secrets.token_urlsafe(32)
    otp_hash = hash_otp(otp_code)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.AUTH_OTP_EXPIRE_MINUTES)

    v_code = EmailVerificationCode(
        user_id=user.id,
        otp_hash=otp_hash,
        session_nonce=session_nonce,
        purpose="SIGNUP_VERIFY",
        attempt_count=0,
        max_attempts=settings.AUTH_OTP_MAX_ATTEMPTS,
        created_at=datetime.now(timezone.utc),
        expires_at=expires_at,
        consumed_at=None
    )
    db.add(v_code)
    await db.flush()

    # Dispatch confirmation OTP email
    success, smtp_err = await send_verification_otp(
        to_email=user.email,
        otp_code=otp_code,
        expires_minutes=settings.AUTH_OTP_EXPIRE_MINUTES,
        session_nonce=session_nonce,
        purpose="SIGNUP_VERIFY"
    )

    await log_audit(
        db, actor=user.email, action="SIGNUP_OTP_SENT",
        resource="auth", resource_id=str(user.id), result="SUCCESS" if success else "WARNING",
        metadata_payload={"purpose": "SIGNUP_VERIFY", "session_nonce": session_nonce, "ip": client_ip}
    )

    msg = "Account created. A 6-digit verification code has been dispatched to your email address."
    if not success and smtp_err:
        msg = f"Account created, but SMTP delivery warning: {smtp_err}. Please check your email or resend."

    return LoginResponse(
        status="OTP_SENT",
        two_factor_required=True,
        session_nonce=session_nonce,
        email_masked=mask_email(user.email),
        expires_in_seconds=settings.AUTH_OTP_EXPIRE_MINUTES * 60,
        message=msg
    )

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

    # If user account is inactive but exists, check if email was unverified
    if not user.is_active and user.email_verified:
        await record_login_attempt(db, identifier=identifier, ip_address=client_ip, attempt_type="PASSWORD", is_success=False)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account is inactive. Please contact your SOC administrator."
        )

    await record_login_attempt(db, identifier=identifier, ip_address=client_ip, attempt_type="PASSWORD", is_success=True)

    # 4. Two-Step Verification Flow (or signup verification if not yet verified)
    if user.two_factor_enabled or not user.email_verified:
        otp_code = f"{secrets.randbelow(1000000):06d}"
        session_nonce = secrets.token_urlsafe(32)
        otp_hash = hash_otp(otp_code)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.AUTH_OTP_EXPIRE_MINUTES)
        purpose = "SIGNUP_VERIFY" if not user.email_verified else "LOGIN_2FA"

        v_code = EmailVerificationCode(
            user_id=user.id,
            otp_hash=otp_hash,
            session_nonce=session_nonce,
            purpose=purpose,
            attempt_count=0,
            max_attempts=settings.AUTH_OTP_MAX_ATTEMPTS,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            consumed_at=None
        )
        db.add(v_code)
        await db.flush()

        # Dispatch email
        success, smtp_err = await send_verification_otp(
            to_email=user.email,
            otp_code=otp_code,
            expires_minutes=settings.AUTH_OTP_EXPIRE_MINUTES,
            session_nonce=session_nonce,
            purpose=purpose
        )

        await log_audit(
            db, actor=user.email, action="OTP_SENT",
            resource="auth", resource_id=str(user.id), result="SUCCESS" if success else "WARNING",
            metadata_payload={"purpose": purpose, "session_nonce": session_nonce}
        )

        feedback_msg = "Verification code sent to registered email address."
        if not success and smtp_err:
            feedback_msg = f"Verification code generated, but SMTP notice: {smtp_err}"

        return LoginResponse(
            status="OTP_SENT",
            two_factor_required=True,
            session_nonce=session_nonce,
            email_masked=mask_email(user.email),
            expires_in_seconds=settings.AUTH_OTP_EXPIRE_MINUTES * 60,
            message=feedback_msg
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
@router.post("/verify-signup", response_model=LoginResponse)
async def verify_otp(
    req: VerifyOtpRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """
    Step 2: Validates the one-time verification code and creates an authentic session.
    Works for both Login 2FA and Account Registration Confirmation.
    Supports lookup via session_nonce or user email.
    """
    client_ip = get_client_ip(request)
    now = datetime.now(timezone.utc)
    rate_identifier = req.session_nonce or (req.email.strip().lower() if req.email else client_ip)

    # 1. Rate Limit Check
    await check_rate_limit(db, identifier=rate_identifier, ip_address=client_ip, attempt_type="OTP")

    # 2. Look up Verification Record
    if req.session_nonce:
        stmt = (
            select(EmailVerificationCode)
            .options(joinedload(EmailVerificationCode.user))
            .where(EmailVerificationCode.session_nonce == req.session_nonce)
        )
    elif req.email:
        clean_email = req.email.strip().lower()
        stmt = (
            select(EmailVerificationCode)
            .join(User)
            .options(joinedload(EmailVerificationCode.user))
            .where(User.email == clean_email, EmailVerificationCode.consumed_at.is_(None))
            .order_by(EmailVerificationCode.id.desc())
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session nonce or email address is required for verification."
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
        await record_login_attempt(db, identifier=rate_identifier, ip_address=client_ip, attempt_type="OTP", is_success=False)
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
    user_id = user.id
    user_email = user.email
    user_username = user.username
    user_role = user.role
    user_org = user.organization_id
    user_display = user.display_name or user.username
    purpose = v_code.purpose

    user.last_login_at = now
    user.email_verified = True
    user.is_active = True

    # 5. Create Session & Issue Tokens
    raw_token, session_rec = await create_user_session(
        user=user, db=db, ip_address=client_ip, user_agent=request.headers.get("user-agent")
    )
    access_token = create_access_token(data={
        "sub": user_username,
        "email": user_email,
        "role": user_role,
        "organization_id": user_org
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

    await record_login_attempt(db, identifier=rate_identifier, ip_address=client_ip, attempt_type="OTP", is_success=True)
    await log_audit(
        db, actor=user_email, action="OTP_VERIFIED",
        resource="auth", resource_id=str(user_id), result="SUCCESS",
        metadata_payload={"purpose": purpose}
    )
    await log_audit(
        db, actor=user_email, action="LOGIN_SUCCESS",
        resource="auth", resource_id=str(user_id), result="SUCCESS",
        metadata_payload={"method": purpose, "ip": client_ip}
    )

    welcome_msg = (
        "Account confirmed and authenticated successfully! Welcome to the console."
        if purpose in ["SIGNUP", "SIGNUP_VERIFY"]
        else "Authenticated successfully. Welcome back!"
    )

    return LoginResponse(
        status="AUTHENTICATED",
        access_token=access_token,
        token_type="bearer",
        role=user_role,
        username=user_username,
        email=user_email,
        display_name=user_display,
        organization_id=user_org,
        message=welcome_msg,
        email_verified=True
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

    success, smtp_err = await send_verification_otp(
        to_email=v_code.user.email,
        otp_code=new_otp,
        expires_minutes=settings.AUTH_OTP_EXPIRE_MINUTES,
        session_nonce=v_code.session_nonce,
        purpose=v_code.purpose or "LOGIN_2FA"
    )
    await log_audit(
        db, actor=v_code.user.email, action="OTP_SENT",
        resource="auth", resource_id=str(v_code.user.id), result="SUCCESS" if success else "WARNING",
        metadata_payload={"type": "RESEND", "ip": client_ip, "purpose": v_code.purpose}
    )

    msg = "A new verification code has been dispatched to your email."
    if not success and smtp_err:
        msg = f"New verification code generated, but SMTP notice: {smtp_err}"

    return {
        "status": "OTP_SENT",
        "message": msg,
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
    """Issues a 6-digit password reset OTP and reset token via email."""
    email_clean = req.email.strip().lower()
    stmt = select(User).where(User.email == email_clean)
    res = await db.execute(stmt)
    user = res.scalars().first()

    session_nonce = secrets.token_urlsafe(32)
    if user and user.is_active:
        raw_token = secrets.token_urlsafe(32)
        t_hash = hash_token(raw_token)
        otp_code = f"{secrets.randbelow(1000000):06d}"
        otp_hash = hash_otp(otp_code)
        expires = datetime.now(timezone.utc) + timedelta(minutes=15)

        reset_rec = PasswordResetToken(
            user_id=user.id,
            token_hash=t_hash,
            created_at=datetime.now(timezone.utc),
            expires_at=expires,
            consumed_at=None
        )
        db.add(reset_rec)

        v_code = EmailVerificationCode(
            user_id=user.id,
            otp_hash=otp_hash,
            session_nonce=session_nonce,
            purpose="PASSWORD_RESET",
            attempt_count=0,
            max_attempts=5,
            created_at=datetime.now(timezone.utc),
            expires_at=expires,
            consumed_at=None
        )
        db.add(v_code)
        await db.flush()

        await send_password_reset_email(to_email=user.email, reset_token=raw_token, otp_code=otp_code)
        await log_audit(
            db, actor=user.email, action="PASSWORD_RESET_REQUESTED",
            resource="auth", resource_id=str(user.id), result="SUCCESS"
        )

    # Always return standard message with session_nonce to prevent account enumeration
    return {
        "status": "RESET_SENT",
        "session_nonce": session_nonce,
        "message": "If an active account exists for this email, password reset instructions and a 6-digit code have been sent."
    }

@router.post("/reset-password")
async def reset_password(
    req: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    """Verifies reset code or token and updates the user's password with modern bcrypt."""
    now = datetime.now(timezone.utc)
    code_or_token = (req.token or req.otp or req.code or "").strip()

    if not code_or_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token or 6-digit verification code is required."
        )

    if len(req.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )

    user = None
    target_reset_rec = None
    target_v_code = None

    # Check 6-digit OTP code in EmailVerificationCode first
    if len(code_or_token) == 6 and code_or_token.isdigit():
        provided_otp_hash = hash_otp(code_or_token)
        v_stmt = (
            select(EmailVerificationCode)
            .options(selectinload(EmailVerificationCode.user))
            .where(
                EmailVerificationCode.otp_hash == provided_otp_hash,
                EmailVerificationCode.purpose == "PASSWORD_RESET",
                EmailVerificationCode.consumed_at == None
            )
        )
        v_res = await db.execute(v_stmt)
        v_rec = v_res.scalars().first()
        if v_rec and now <= to_utc(v_rec.expires_at):
            user = v_rec.user
            target_v_code = v_rec

    # Fallback to checking PasswordResetToken by token hash
    if not user:
        t_hash = hash_token(code_or_token)
        t_stmt = (
            select(PasswordResetToken)
            .options(selectinload(PasswordResetToken.user))
            .where(
                PasswordResetToken.token_hash == t_hash,
                PasswordResetToken.consumed_at == None
            )
        )
        t_res = await db.execute(t_stmt)
        t_rec = t_res.scalars().first()
        if t_rec and now <= to_utc(t_rec.expires_at):
            user = t_rec.user
            target_reset_rec = t_rec

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset code or token is invalid or has expired."
        )

    if target_v_code:
        target_v_code.consumed_at = now
    if target_reset_rec:
        target_reset_rec.consumed_at = now

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
