"""
Authentication, Session Management & Role-Based Access Control
Native bcrypt password hashing, cryptographic HMAC OTP hashing,
and persistent server-side session tracking with dual Cookie + Bearer JWT support.
"""

import hmac
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple
import bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.all_models import User, UserSession

security_bearer = HTTPBearer(auto_error=False)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a bcrypt hash."""
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    """Generates a salt and hashes the password with bcrypt."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode("utf-8")

def hash_otp(code: str) -> str:
    """Computes a cryptographically keyed HMAC-SHA256 hash of the OTP."""
    secret = (settings.SECRET_KEY or "fl-threat-detection-key").encode("utf-8")
    return hmac.new(secret, code.strip().encode("utf-8"), hashlib.sha256).hexdigest()

def hash_token(raw_token: str) -> str:
    """Computes a SHA-256 hash of a session or reset token for database persistence."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Issues a signed JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

async def create_user_session(
    user: User,
    db: AsyncSession,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> Tuple[str, UserSession]:
    """Creates a persistent server-side session, storing only the token hash."""
    raw_token = secrets.token_urlsafe(48)
    token_hash = hash_token(raw_token)
    expires = datetime.now(timezone.utc) + timedelta(days=settings.AUTH_SESSION_EXPIRE_DAYS)

    session_record = UserSession(
        session_token_hash=token_hash,
        user_id=user.id,
        created_at=datetime.now(timezone.utc),
        expires_at=expires,
        last_active_at=datetime.now(timezone.utc),
        is_revoked=False,
        ip_address=ip_address,
        user_agent=user_agent[:255] if user_agent else None
    )
    db.add(session_record)
    await db.flush()
    return raw_token, session_record

async def revoke_session_by_token(raw_token: str, db: AsyncSession) -> bool:
    """Revokes a session by raw session token."""
    token_hash = hash_token(raw_token)
    stmt = select(UserSession).where(UserSession.session_token_hash == token_hash)
    res = await db.execute(stmt)
    sess = res.scalars().first()
    if sess:
        sess.is_revoked = True
        await db.flush()
        return True
    return False

async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Authenticates the caller via either:
    1. Authorization: Bearer <JWT>
    2. Cookie: auth_session=<raw_session_token>
    """
    now = datetime.now(timezone.utc)

    # 1. Check Bearer JWT token
    if credentials and credentials.credentials:
        token = credentials.credentials
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
            sub: str = payload.get("sub")
            if sub:
                stmt = select(User).where((User.username == sub) | (User.email == sub.lower()))
                result = await db.execute(stmt)
                user = result.scalars().first()
                if user:
                    if not user.is_active:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Inactive user account"
                        )
                    return user
        except JWTError:
            pass

    # 2. Check HttpOnly Session Cookie
    cookie_token = request.cookies.get("auth_session")
    if cookie_token:
        token_hash = hash_token(cookie_token)
        stmt = (
            select(UserSession)
            .options(selectinload(UserSession.user))
            .where(
                UserSession.session_token_hash == token_hash,
                UserSession.is_revoked == False,
                UserSession.expires_at > now
            )
        )
        res = await db.execute(stmt)
        sess = res.scalars().first()
        if sess and sess.user:
            if not sess.user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Inactive user account"
                )
            sess.last_active_at = now
            await db.flush()
            return sess.user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication credentials were not provided or have expired",
        headers={"WWW-Authenticate": "Bearer"}
    )

def require_role(allowed_roles: List[str]):
    """Enforces role-based authorization for protected endpoints."""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_role = (current_user.role or "").upper()
        norm_allowed = [r.upper() for r in allowed_roles]
        if user_role not in norm_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Role '{user_role}' is not authorized. Allowed: {norm_allowed}."
            )
        return current_user
    return role_checker
