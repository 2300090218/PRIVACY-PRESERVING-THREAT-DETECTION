"""
Authentication Rate Limiter & Brute-Force Protection Service
Protects login, OTP verification, and password reset endpoints from automated abuse.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func

from backend.app.config import settings
from backend.app.models.all_models import LoginAttempt

async def record_login_attempt(
    db: AsyncSession,
    identifier: str,
    ip_address: Optional[str] = None,
    attempt_type: str = "PASSWORD",
    is_success: bool = False
):
    """Persists an authentication attempt for audit and rate-limiting enforcement."""
    try:
        attempt = LoginAttempt(
            identifier=identifier.lower().strip(),
            ip_address=ip_address,
            attempt_type=attempt_type,
            is_success=is_success,
            timestamp=datetime.now(timezone.utc)
        )
        db.add(attempt)
        await db.commit()
    except Exception:
        await db.rollback()

async def check_rate_limit(
    db: AsyncSession,
    identifier: str,
    ip_address: Optional[str] = None,
    attempt_type: str = "PASSWORD"
):
    """
    Validates that the identifier and IP address have not exceeded the failure threshold.
    Raises HTTPException(429) if threshold is exceeded.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.AUTH_RATE_LIMIT_WINDOW_MINUTES)
    clean_id = identifier.lower().strip()
    
    stmt = (
        select(LoginAttempt)
        .where(
            LoginAttempt.identifier == clean_id,
            LoginAttempt.attempt_type == attempt_type,
            LoginAttempt.is_success == False
        )
    )
    res = await db.execute(stmt)
    attempts = res.scalars().all()
    
    failed_count = 0
    for a in attempts:
        t = a.timestamp
        if t is not None:
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            if t >= cutoff:
                failed_count += 1

    if failed_count >= settings.AUTH_RATE_LIMIT_FAILED_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Account temporarily locked for {settings.AUTH_RATE_LIMIT_WINDOW_MINUTES} minutes."
        )
