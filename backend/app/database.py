"""
Database Connection and Session Management
Supports async SQLite for local development and PostgreSQL (asyncpg) for production.
"""

from typing import AsyncGenerator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from backend.app.config import settings

def get_engine_url(raw_url: str) -> str:
    """Normalizes database connection string for SQLAlchemy async drivers."""
    if raw_url.startswith("postgres://"):
        return raw_url.replace("postgres://", "postgresql+asyncpg://", 1)
    if raw_url.startswith("postgresql://") and not raw_url.startswith("postgresql+"):
        return raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return raw_url

db_url = get_engine_url(settings.DATABASE_URL)
is_sqlite = db_url.startswith("sqlite")

# Engine configuration
connect_args = {}
if is_sqlite:
    connect_args["check_same_thread"] = False
    connect_args["timeout"] = 30.0

engine = create_async_engine(
    db_url,
    echo=False,
    connect_args=connect_args,
    future=True
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

Base = declarative_base()

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for obtaining an asynchronous database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def init_db():
    """Initializes all database tables registered on Base and optimizes SQLite for concurrency."""
    async with engine.begin() as conn:
        if is_sqlite:
            await conn.execute(text("PRAGMA journal_mode=WAL;"))
            await conn.execute(text("PRAGMA synchronous=NORMAL;"))
            await conn.execute(text("PRAGMA busy_timeout=30000;"))
        await conn.run_sync(Base.metadata.create_all)
