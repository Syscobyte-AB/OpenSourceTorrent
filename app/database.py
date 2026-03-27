"""
TorrentVault — Database engine, session factory, and base model.
Supports SQLite (dev) and PostgreSQL (prod) via DATABASE_URL env var.
"""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=False,
    # SQLite needs this; PostgreSQL ignores it
    connect_args={"check_same_thread": False}
    if settings.database_url.startswith("sqlite")
    else {},
)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    """FastAPI dependency — yields an async DB session."""
    async with async_session() as session:
        yield session


async def init_db():
    """Create all tables (called on app startup)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
