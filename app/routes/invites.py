"""Invite code management — admin only."""

import secrets
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_action
from app.database import get_db
from app.models import InviteCode

router = APIRouter(prefix="/api/invites", tags=["invites"])


class InviteCreateRequest(BaseModel):
    max_uses: int = 1
    expires_in_hours: Optional[int] = None


def _require_admin(request: Request):
    from app.main import verify_token
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    data = verify_token(auth.split(" ", 1)[1])
    if not data.get("admin"):
        raise HTTPException(403, "Admin access required")
    return data


@router.post("", status_code=201)
async def create_invite(
    body: InviteCreateRequest, request: Request, db: AsyncSession = Depends(get_db),
):
    admin = _require_admin(request)
    code = secrets.token_urlsafe(8)
    expires_at = None
    if body.expires_in_hours:
        from datetime import timedelta
        expires_at = datetime.utcnow() + timedelta(hours=body.expires_in_hours)

    invite = InviteCode(
        code=code,
        created_by=admin["sub"],
        max_uses=body.max_uses,
        expires_at=expires_at,
    )
    db.add(invite)
    await db.commit()
    await db.refresh(invite)

    ip = request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
    await log_action(db, username=admin["sub"], action="invite_create", target=code, ip_address=ip)
    return {
        "code": code,
        "max_uses": body.max_uses,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }


@router.get("")
async def list_invites(request: Request, db: AsyncSession = Depends(get_db)):
    _require_admin(request)
    result = await db.execute(select(InviteCode).order_by(InviteCode.id.desc()))
    invites = result.scalars().all()
    return [
        {
            "id": i.id,
            "code": i.code,
            "created_by": i.created_by,
            "max_uses": i.max_uses,
            "use_count": i.use_count,
            "is_active": i.is_active,
            "created_at": i.created_at.isoformat() if i.created_at else None,
            "expires_at": i.expires_at.isoformat() if i.expires_at else None,
        }
        for i in invites
    ]


@router.delete("/{code}")
async def deactivate_invite(code: str, request: Request, db: AsyncSession = Depends(get_db)):
    admin = _require_admin(request)
    result = await db.execute(select(InviteCode).where(InviteCode.code == code))
    invite = result.scalar_one_or_none()
    if not invite:
        raise HTTPException(404, "Invite code not found")
    invite.is_active = False
    await db.commit()
    ip = request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
    await log_action(db, username=admin["sub"], action="invite_deactivate", target=code, ip_address=ip)
    return {"status": "deactivated"}
