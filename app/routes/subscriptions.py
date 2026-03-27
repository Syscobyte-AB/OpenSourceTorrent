"""Subscription plan management and tier changes."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_action
from app.database import get_db
from app.models import SubscriptionPlan, User

router = APIRouter(tags=["subscriptions"])


class ChangePlanRequest(BaseModel):
    plan_id: int


def _require_admin(request: Request):
    from app.main import verify_token
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    data = verify_token(auth.split(" ", 1)[1])
    if not data.get("admin"):
        raise HTTPException(403, "Admin access required")
    return data


def _get_user_data(request: Request):
    from app.main import verify_token
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    return verify_token(auth.split(" ", 1)[1])


@router.get("/api/plans")
async def list_plans(db: AsyncSession = Depends(get_db)):
    """List available subscription plans (public)."""
    result = await db.execute(select(SubscriptionPlan).where(SubscriptionPlan.is_active == True))
    plans = result.scalars().all()
    return [
        {
            "id": p.id, "name": p.name, "tier": p.tier,
            "max_active_torrents": p.max_active_torrents,
            "speed_cap_kbps": p.speed_cap_kbps,
            "price_cents": p.price_cents,
            "billing_period": p.billing_period,
        }
        for p in plans
    ]


@router.get("/api/subscription")
async def get_subscription(request: Request, db: AsyncSession = Depends(get_db)):
    """Get own subscription status."""
    user_data = _get_user_data(request)
    result = await db.execute(select(User).where(User.username == user_data["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(401, "User not found")
    return {
        "username": user.username,
        "tier": user.tier,
        "max_active_torrents": user.max_active_torrents,
        "speed_cap_kbps": user.speed_cap_kbps,
        "subscription_status": user.subscription_status,
        "subscription_started_at": user.subscription_started_at.isoformat() if user.subscription_started_at else None,
        "subscription_expires_at": user.subscription_expires_at.isoformat() if user.subscription_expires_at else None,
    }


@router.put("/api/admin/users/{username}/subscription")
async def change_user_plan(
    username: str, body: ChangePlanRequest, request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Admin: change a user's subscription plan."""
    admin = _require_admin(request)

    result = await db.execute(select(SubscriptionPlan).where(SubscriptionPlan.id == body.plan_id))
    plan = result.scalar_one_or_none()
    if not plan:
        raise HTTPException(404, "Plan not found")

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")

    user.tier = plan.tier
    user.max_active_torrents = plan.max_active_torrents
    user.speed_cap_kbps = plan.speed_cap_kbps
    user.subscription_status = "active"
    user.subscription_started_at = datetime.utcnow()
    await db.commit()

    ip = request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
    await log_action(
        db, username=admin["sub"], action="subscription_change", target=username,
        detail={"plan": plan.name, "tier": plan.tier}, ip_address=ip,
    )
    return {"status": "updated", "tier": plan.tier, "plan": plan.name}


@router.post("/api/webhooks/stripe")
async def stripe_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    """Stub endpoint for future Stripe webhook integration."""
    body = await request.body()
    await log_action(
        db, username="stripe", action="webhook_received",
        detail={"size": len(body)},
        ip_address=request.headers.get("X-Real-IP", request.client.host if request.client else "unknown"),
    )
    return {"status": "received"}
