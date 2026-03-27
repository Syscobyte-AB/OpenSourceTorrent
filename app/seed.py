"""Seed default data on first startup."""

import logging
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import SubscriptionPlan, User

logger = logging.getLogger("torrentvault.seed")


async def seed_defaults(db: AsyncSession) -> None:
    """Seed admin user and default subscription plans."""
    # Admin user
    result = await db.execute(select(User).where(User.username == "admin"))
    if result.scalar_one_or_none() is None:
        admin = User(
            username="admin",
            password_hash=settings.admin_password_hash,
            is_admin=True,
            tier="premium",
            max_active_torrents=-1,
            speed_cap_kbps=-1,
        )
        db.add(admin)
        await db.commit()
        logger.info("Seeded default admin user (premium)")

    # Default plans
    result = await db.execute(select(SubscriptionPlan))
    if not result.scalars().first():
        plans = [
            SubscriptionPlan(
                name="Free",
                tier="free",
                max_active_torrents=settings.free_tier_max_torrents,
                speed_cap_kbps=settings.free_tier_speed_cap_kbps,
                price_cents=0,
                billing_period=None,
            ),
            SubscriptionPlan(
                name="Premium Monthly",
                tier="premium",
                max_active_torrents=-1,
                speed_cap_kbps=-1,
                price_cents=999,
                billing_period="monthly",
            ),
            SubscriptionPlan(
                name="Premium Annual",
                tier="premium",
                max_active_torrents=-1,
                speed_cap_kbps=-1,
                price_cents=7999,
                billing_period="annual",
            ),
        ]
        db.add_all(plans)
        await db.commit()
        logger.info("Seeded default subscription plans")
