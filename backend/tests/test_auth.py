import pytest
from backend.app.security.authentication import get_password_hash, verify_password, create_access_token
from backend.app.models.all_models import User
from backend.tests.conftest import TestingSessionLocal

@pytest.mark.asyncio
async def test_password_hashing():
    raw = "MySecureTestPass123!"
    hashed = get_password_hash(raw)
    assert hashed != raw
    assert verify_password(raw, hashed) is True
    assert verify_password("WrongPassword", hashed) is False

@pytest.mark.asyncio
async def test_login_flow(async_client):
    # Seed test user
    async with TestingSessionLocal() as session:
        user = User(
            username="analyst_test",
            email="analyst@corp.test",
            hashed_password=get_password_hash("TestAnalystPass!"),
            role="SECURITY_ANALYST"
        )
        session.add(user)
        await session.commit()

    # Successful login
    res = await async_client.post("/api/auth/login", json={
        "username": "analyst_test",
        "password": "TestAnalystPass!"
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["role"] == "SECURITY_ANALYST"

    # Failed login
    res_bad = await async_client.post("/api/auth/login", json={
        "username": "analyst_test",
        "password": "BadPassword123"
    })
    assert res_bad.status_code == 401
