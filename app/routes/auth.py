"""API key management + self-registration."""

import secrets
from datetime import datetime
from typing import Optional

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_action
from app.config import settings
from app.database import get_db
from app.models import ApiKey, InviteCode, User

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ── Request models ──
class RegisterRequest(BaseModel):
    username: str
    password: str
    invite_code: Optional[str] = None


class ApiKeyCreateRequest(BaseModel):
    name: str


# ── Self-registration ──
@router.post("/register", status_code=201)
async def register(body: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Register a new user. Invite code required if configured."""
    if settings.require_invite_code:
        if not body.invite_code:
            raise HTTPException(400, "Invite code required")
        result = await db.execute(select(InviteCode).where(InviteCode.code == body.invite_code))
        invite = result.scalar_one_or_none()
        if not invite or not invite.is_active:
            raise HTTPException(400, "Invalid invite code")
        if invite.expires_at and invite.expires_at < datetime.utcnow():
            raise HTTPException(400, "Invite code expired")
        if invite.use_count >= invite.max_uses:
            raise HTTPException(400, "Invite code fully used")
        invite.use_count += 1

    existing = await db.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(409, "Username already exists")

    hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    user = User(
        username=body.username,
        password_hash=hashed,
        tier="free",
        max_active_torrents=settings.free_tier_max_torrents,
        speed_cap_kbps=settings.free_tier_speed_cap_kbps,
        invited_by_code=body.invite_code,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    ip = request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
    await log_action(db, username=body.username, action="register", ip_address=ip)
    return {"id": user.id, "username": user.username, "tier": user.tier}


# ── API Key management ──
@router.post("/api-keys", status_code=201)
async def create_api_key(
    body: ApiKeyCreateRequest, request: Request,
    user_data: dict = Depends(lambda: None),  # replaced at import
    db: AsyncSession = Depends(get_db),
):
    """Generate a new API key. The raw key is returned ONCE."""
    # Resolve user from auth — injected from main.py
    from app.main import get_current_user
    user_data = await get_current_user(
        token=request.headers.get("Authorization", "").replace("Bearer ", "")
    )
    result = await db.execute(select(User).where(User.username == user_data["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(401, "User not found")

    raw_key = "tvk_" + secrets.token_hex(24)
    key_hash = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt()).decode()

    api_key = ApiKey(
        user_id=user.id,
        key_hash=key_hash,
        key_prefix=raw_key[:12],
        name=body.name,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    await log_action(
        db, username=user.username, action="api_key_create",
        target=raw_key[:12] + "...",
        ip_address=request.headers.get("X-Real-IP", request.client.host if request.client else "unknown"),
    )
    return {"id": api_key.id, "name": body.name, "key": raw_key, "prefix": raw_key[:12]}


@router.get("/api-keys")
async def list_api_keys(request: Request, db: AsyncSession = Depends(get_db)):
    from app.main import get_current_user
    user_data = await get_current_user(
        token=request.headers.get("Authorization", "").replace("Bearer ", "")
    )
    result = await db.execute(select(User).where(User.username == user_data["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(401, "User not found")

    result = await db.execute(
        select(ApiKey).where(ApiKey.user_id == user.id).order_by(ApiKey.id.desc())
    )
    keys = result.scalars().all()
    return [
        {
            "id": k.id,
            "name": k.name,
            "prefix": k.key_prefix,
            "is_active": k.is_active,
            "created_at": k.created_at.isoformat() if k.created_at else None,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
        }
        for k in keys
    ]


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    from app.main import get_current_user
    user_data = await get_current_user(
        token=request.headers.get("Authorization", "").replace("Bearer ", "")
    )
    result = await db.execute(select(User).where(User.username == user_data["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(401, "User not found")

    result = await db.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user.id)
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(404, "API key not found")

    key.is_active = False
    await db.commit()
    await log_action(
        db, username=user.username, action="api_key_revoke", target=key.key_prefix,
        ip_address=request.headers.get("X-Real-IP", request.client.host if request.client else "unknown"),
    )
    return {"status": "revoked"}
