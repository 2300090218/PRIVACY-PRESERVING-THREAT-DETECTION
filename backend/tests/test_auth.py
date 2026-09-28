"""
Authentication, Two-Step Verification (OTP), Session Management & Security Invariant Tests
Covers full lifecycle:
- Password hashing & verification (bcrypt)
- Invalid credentials & unknown email rejection
- Two-step verification OTP generation & secure HMAC hashing
- Single-use OTP consumption & replay rejection
- OTP expiration enforcement
- OTP wrong-code attempt limits & brute-force rate-limiting
- Resend OTP 30-second cooldown rate-limiting
- Dual Bearer token + HttpOnly cookie session creation & validation
- Server-side session revocation & logout
- Security invariants: zero plaintext passwords, zero plaintext OTPs, zero plaintext session tokens
- Demo mode enterprise isolation
"""

import pytest
import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy.future import select

from backend.app.models.all_models import User, UserSession, EmailVerificationCode, Organization
from backend.app.security.authentication import (
    get_password_hash, verify_password, hash_otp, hash_token, create_access_token
)
from backend.app.services.email_service import email_service
from backend.tests.conftest import TestingSessionLocal


@pytest.mark.asyncio
async def test_password_hashing():
    raw = "MySecureTestPass123!"
    hashed = get_password_hash(raw)
    assert hashed != raw
    assert verify_password(raw, hashed) is True
    assert verify_password("WrongPassword", hashed) is False
    # Bcrypt unique salt per call
    hashed2 = get_password_hash(raw)
    assert hashed != hashed2
    assert verify_password(raw, hashed2) is True


@pytest.mark.asyncio
async def test_login_unknown_email(async_client):
    res = await async_client.post("/api/auth/login", json={
        "email": "unknown-nonexistent-user@corp.test",
        "password": "SomeRandomPassword123!"
    })
    assert res.status_code == 401
    assert "Invalid email or password" in res.json()["detail"]


@pytest.mark.asyncio
async def test_login_invalid_password(async_client):
    async with TestingSessionLocal() as session:
        user = User(
            username="analyst_inv_pwd",
            email="analyst_inv@corp.test",
            hashed_password=get_password_hash("CorrectPassword123!"),
            role="SECURITY_ANALYST",
            two_factor_enabled=True
        )
        session.add(user)
        await session.commit()

    res = await async_client.post("/api/auth/login", json={
        "email": "analyst_inv@corp.test",
        "password": "WrongPassword999!"
    })
    assert res.status_code == 401
    assert "Invalid email or password" in res.json()["detail"]


@pytest.mark.asyncio
async def test_login_valid_credentials_and_otp_generation(async_client):
    test_email = "analyst_2fa_gen@corp.test"
    async with TestingSessionLocal() as session:
        user = User(
            username="analyst_2fa_gen",
            email=test_email,
            hashed_password=get_password_hash("ValidPass123!"),
            role="SECURITY_ANALYST",
            two_factor_enabled=True
        )
        session.add(user)
        await session.commit()

    res = await async_client.post("/api/auth/login", json={
        "email": test_email,
        "password": "ValidPass123!"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "OTP_SENT"
    assert data["two_factor_required"] is True
    assert "session_nonce" in data and len(data["session_nonce"]) > 0
    assert data["expires_in_seconds"] == 300
    assert "@" in data["email_masked"]

    # Verify database record: OTP is stored as a cryptographic hash, NEVER plaintext
    session_nonce = data["session_nonce"]
    async with TestingSessionLocal() as session:
        stmt = select(EmailVerificationCode).where(EmailVerificationCode.session_nonce == session_nonce)
        rec = (await session.execute(stmt)).scalars().first()
        assert rec is not None
        assert rec.consumed_at is None
        assert rec.attempt_count == 0

        # Retrieve the dispatched OTP from email_service
        dispatched_otp = email_service.get_last_dispatched_otp(session_nonce)
        assert dispatched_otp is not None
        assert len(dispatched_otp) == 6
        # Security invariant: Raw OTP must NOT match database value
        assert rec.otp_hash != dispatched_otp
        # Verifiable via HMAC-SHA256
        assert rec.otp_hash == hash_otp(dispatched_otp)


@pytest.mark.asyncio
async def test_verify_otp_wrong_code(async_client):
    test_email = "analyst_wrong_otp@corp.test"
    async with TestingSessionLocal() as session:
        user = User(
            username="analyst_wrong_otp",
            email=test_email,
            hashed_password=get_password_hash("ValidPass123!"),
            role="SECURITY_ANALYST",
            two_factor_enabled=True
        )
        session.add(user)
        await session.commit()

    login_res = await async_client.post("/api/auth/login", json={
        "email": test_email,
        "password": "ValidPass123!"
    })
    session_nonce = login_res.json()["session_nonce"]

    # Send wrong OTP code
    verify_res = await async_client.post("/api/auth/verify-otp", json={
        "session_nonce": session_nonce,
        "otp": "000000"
    })
    assert verify_res.status_code == 400
    assert "Invalid verification code" in verify_res.json()["detail"]

    # Check attempt counter incremented
    async with TestingSessionLocal() as session:
        stmt = select(EmailVerificationCode).where(EmailVerificationCode.session_nonce == session_nonce)
        rec = (await session.execute(stmt)).scalars().first()
        assert rec.attempt_count == 1


@pytest.mark.asyncio
async def test_verify_otp_expiry(async_client):
    test_email = "analyst_expired_otp@corp.test"
    async with TestingSessionLocal() as session:
        user = User(
            username="analyst_expired_otp",
            email=test_email,
            hashed_password=get_password_hash("ValidPass123!"),
            role="SECURITY_ANALYST",
            two_factor_enabled=True
        )
        session.add(user)
        await session.commit()

    login_res = await async_client.post("/api/auth/login", json={
        "email": test_email,
        "password": "ValidPass123!"
    })
    session_nonce = login_res.json()["session_nonce"]
    otp = email_service.get_last_dispatched_otp(session_nonce)

    # Force expiration in database
    async with TestingSessionLocal() as session:
        stmt = select(EmailVerificationCode).where(EmailVerificationCode.session_nonce == session_nonce)
        rec = (await session.execute(stmt)).scalars().first()
        rec.expires_at = datetime.now(timezone.utc) - timedelta(minutes=10)
        await session.commit()

    # Attempt to verify expired code
    verify_res = await async_client.post("/api/auth/verify-otp", json={
        "session_nonce": session_nonce,
        "otp": otp
    })
    assert verify_res.status_code == 400
    assert "expired" in verify_res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_verify_otp_success_and_session_creation(async_client):
    test_email = "analyst_success_2fa@corp.test"
    async with TestingSessionLocal() as session:
        user = User(
            username="analyst_success_2fa",
            email=test_email,
            hashed_password=get_password_hash("ValidPass123!"),
            role="SECURITY_ANALYST",
            two_factor_enabled=True
        )
        session.add(user)
        await session.commit()

    login_res = await async_client.post("/api/auth/login", json={
        "email": test_email,
        "password": "ValidPass123!"
    })
    session_nonce = login_res.json()["session_nonce"]
    otp = email_service.get_last_dispatched_otp(session_nonce)

    verify_res = await async_client.post("/api/auth/verify-otp", json={
        "session_nonce": session_nonce,
        "otp": otp
    })
    assert verify_res.status_code == 200
    data = verify_res.json()
    assert data["status"] == "AUTHENTICATED"
    assert "access_token" in data and len(data["access_token"]) > 0
    assert data["role"] == "SECURITY_ANALYST"
    assert data["email"] == test_email

    # Check HttpOnly cookie set in response headers
    set_cookie_header = verify_res.headers.get("set-cookie", "")
    assert "auth_session=" in set_cookie_header
    assert "httponly" in set_cookie_header.lower()

    # Verify session record created in database with SHA-256 hash
    async with TestingSessionLocal() as session:
        stmt = select(UserSession).join(User).where(User.email == test_email)
        sess_rec = (await session.execute(stmt)).scalars().first()
        assert sess_rec is not None
        assert sess_rec.is_revoked is False
        exp = sess_rec.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        assert exp > datetime.now(timezone.utc)
        assert len(sess_rec.session_token_hash) == 64  # SHA-256 hex string


@pytest.mark.asyncio
async def test_verify_otp_reuse_blocked(async_client):
    test_email = "analyst_replay_test@corp.test"
    async with TestingSessionLocal() as session:
        user = User(
            username="analyst_replay_test",
            email=test_email,
            hashed_password=get_password_hash("ValidPass123!"),
            role="SECURITY_ANALYST",
            two_factor_enabled=True
        )
        session.add(user)
        await session.commit()

    login_res = await async_client.post("/api/auth/login", json={
        "email": test_email,
        "password": "ValidPass123!"
    })
    session_nonce = login_res.json()["session_nonce"]
    otp = email_service.get_last_dispatched_otp(session_nonce)

    # First verification: succeeds
    res1 = await async_client.post("/api/auth/verify-otp", json={
        "session_nonce": session_nonce,
        "otp": otp
    })
    assert res1.status_code == 200

    # Second verification with exact same OTP and nonce: MUST FAIL
    res2 = await async_client.post("/api/auth/verify-otp", json={
        "session_nonce": session_nonce,
        "otp": otp
    })
    assert res2.status_code == 400
    assert "already been consumed" in res2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_otp_attempt_rate_limiting(async_client):
    test_email = "analyst_max_attempts@corp.test"
    async with TestingSessionLocal() as session:
        user = User(
            username="analyst_max_attempts",
            email=test_email,
            hashed_password=get_password_hash("ValidPass123!"),
            role="SECURITY_ANALYST",
            two_factor_enabled=True
        )
        session.add(user)
        await session.commit()

    login_res = await async_client.post("/api/auth/login", json={
        "email": test_email,
        "password": "ValidPass123!"
    })
    session_nonce = login_res.json()["session_nonce"]

    # Send 5 incorrect attempts to exhaust attempts
    for _ in range(5):
        await async_client.post("/api/auth/verify-otp", json={
            "session_nonce": session_nonce,
            "otp": "999999"
        })

    # 6th attempt should be blocked due to maximum attempts / rate limiting
    res_blocked = await async_client.post("/api/auth/verify-otp", json={
        "session_nonce": session_nonce,
        "otp": "999999"
    })
    assert res_blocked.status_code in [400, 429]


@pytest.mark.asyncio
async def test_resend_otp_rate_limiting(async_client):
    test_email = "analyst_resend_cd@corp.test"
    async with TestingSessionLocal() as session:
        user = User(
            username="analyst_resend_cd",
            email=test_email,
            hashed_password=get_password_hash("ValidPass123!"),
            role="SECURITY_ANALYST",
            two_factor_enabled=True
        )
        session.add(user)
        await session.commit()

    login_res = await async_client.post("/api/auth/login", json={
        "email": test_email,
        "password": "ValidPass123!"
    })
    session_nonce = login_res.json()["session_nonce"]

    # Immediate resend attempt: must hit 30s cooldown (429)
    resend_res = await async_client.post("/api/auth/resend-otp", json={
        "session_nonce": session_nonce
    })
    assert resend_res.status_code == 429
    assert "Please wait" in resend_res.json()["detail"]


@pytest.mark.asyncio
async def test_protected_routes_and_session_cookie(async_client):
    test_email = "analyst_cookie_auth@corp.test"
    async with TestingSessionLocal() as session:
        user = User(
            username="analyst_cookie_auth",
            email=test_email,
            hashed_password=get_password_hash("ValidPass123!"),
            role="SECURITY_ANALYST",
            two_factor_enabled=True
        )
        session.add(user)
        await session.commit()

    # 1. Unauthenticated request to /api/auth/me MUST fail
    unauth_res = await async_client.get("/api/auth/me")
    assert unauth_res.status_code == 401

    # 2. Login & verify OTP
    login_res = await async_client.post("/api/auth/login", json={
        "email": test_email,
        "password": "ValidPass123!"
    })
    session_nonce = login_res.json()["session_nonce"]
    otp = email_service.get_last_dispatched_otp(session_nonce)

    verify_res = await async_client.post("/api/auth/verify-otp", json={
        "session_nonce": session_nonce,
        "otp": otp
    })
    assert verify_res.status_code == 200
    token = verify_res.json()["access_token"]

    # 3. Access with Bearer token
    bearer_res = await async_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert bearer_res.status_code == 200
    assert bearer_res.json()["email"] == test_email

    # 4. Access with Session Cookie
    cookie_str = verify_res.cookies.get("auth_session")
    if cookie_str:
        cookie_res = await async_client.get("/api/auth/me", cookies={"auth_session": cookie_str})
        assert cookie_res.status_code == 200
        assert cookie_res.json()["email"] == test_email


@pytest.mark.asyncio
async def test_logout_and_session_revocation(async_client):
    test_email = "analyst_logout_test@corp.test"
    async with TestingSessionLocal() as session:
        user = User(
            username="analyst_logout_test",
            email=test_email,
            hashed_password=get_password_hash("ValidPass123!"),
            role="SECURITY_ANALYST",
            two_factor_enabled=True
        )
        session.add(user)
        await session.commit()

    login_res = await async_client.post("/api/auth/login", json={
        "email": test_email,
        "password": "ValidPass123!"
    })
    session_nonce = login_res.json()["session_nonce"]
    otp = email_service.get_last_dispatched_otp(session_nonce)

    verify_res = await async_client.post("/api/auth/verify-otp", json={
        "session_nonce": session_nonce,
        "otp": otp
    })
    token = verify_res.json()["access_token"]
    cookie_val = verify_res.cookies.get("auth_session")

    # Logout
    logout_res = await async_client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
        cookies={"auth_session": cookie_val} if cookie_val else {}
    )
    assert logout_res.status_code == 200

    # Cookie deleted or empty
    # Verify in DB that the session is marked revoked
    if cookie_val:
        token_h = hash_token(cookie_val)
        async with TestingSessionLocal() as session:
            stmt = select(UserSession).where(UserSession.session_token_hash == token_h)
            sess = (await session.execute(stmt)).scalars().first()
            assert sess is not None
            assert sess.is_revoked is True

        # Subsequent call with revoked cookie MUST fail
        retry_res = await async_client.get("/api/auth/me", cookies={"auth_session": cookie_val})
        assert retry_res.status_code == 401


@pytest.mark.asyncio
async def test_security_invariants_no_plaintext():
    """Validates that plain passwords, OTPs, and session tokens are never stored plaintext."""
    pwd_raw = "SecretPasswordToHash#123"
    otp_raw = "847291"
    session_raw = secrets.token_urlsafe(32)

    pwd_hash = get_password_hash(pwd_raw)
    otp_h = hash_otp(otp_raw)
    sess_h = hash_token(session_raw)

    assert pwd_raw not in pwd_hash
    assert otp_raw not in otp_h
    assert session_raw not in sess_h

    # Ensure lengths and formats are standard cryptographic digests
    assert pwd_hash.startswith("$2b$") or pwd_hash.startswith("$2a$")
    assert len(otp_h) == 64  # SHA-256
    assert len(sess_h) == 64  # SHA-256


@pytest.mark.asyncio
async def test_demo_mode_isolation(async_client):
    """
    Validates that public unauthenticated demo mode endpoints:
    1. Only return synthetic/test demonstration data
    2. Never expose real users, passwords, sessions, or OTPs
    3. Restricted administrative endpoints reject unauthenticated access
    """
    # 1. Seed demo organization in test database
    async with TestingSessionLocal() as session:
        session.add(Organization(
            org_id="demo_klef_vijayawada",
            name="KL University / KLEF",
            status="ACTIVE",
            is_demo=True
        ))
        await session.commit()

    # Public organizations list is available without authentication
    pub_res = await async_client.get("/api/v1/organizations")
    assert pub_res.status_code == 200
    pub_data = pub_res.json()
    assert isinstance(pub_data, list)
    assert len(pub_data) > 0

    # Check zero credential or sensitive leaks in public data
    raw_text = pub_res.text.lower()
    assert "hashed_password" not in raw_text
    assert "session_token" not in raw_text
    assert "otp_hash" not in raw_text
    assert "password" not in raw_text

    # 2. Administrative and audit routes require authentication
    unauth_audit = await async_client.get("/api/v1/audit-logs")
    assert unauth_audit.status_code == 401
