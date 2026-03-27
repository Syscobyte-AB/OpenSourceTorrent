"""Session management — list and revoke active sessions."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_action
from app.database import get_db
from app.models import User, UserSession

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


def _get_user_data(request: Request):
    from app.main import get_current_user, verify_token
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return verify_token(auth.split(" ", 1)[1])
    raise HTTPException(401, "Missing token")


@router.get("")
async def list_sessions(request: Request, db: AsyncSession = Depends(get_db)):
    """List own active sessions."""
    user_data = _get_user_data(request)
    result = await db.execute(select(User).where(User.username == user_data["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(401, "User not found")

    result = await db.execute(
        select(UserSession)
        .where(UserSession.user_id == user.id, UserSession.is_revoked == False)
        .order_by(UserSession.last_active_at.desc())
    )
    sessions = result.scalars().all()
    current_jti = user_data.get("jti")
    return [
        {
            "id": s.id,
            "ip_address": s.ip_address,
            "user_agent": s.user_agent,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "last_active_at": s.last_active_at.isoformat() if s.last_active_at else None,
            "is_current": s.token_jti == current_jti,
        }
        for s in sessions
    ]


@router.delete("/{session_id}")
async def revoke_session(session_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Revoke a specific session."""
    user_data = _get_user_data(request)
    result = await db.execute(select(User).where(User.username == user_data["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(401, "User not found")

    result = await db.execute(
        select(UserSession).where(UserSession.id == session_id, UserSession.user_id == user.id)
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Session not found")

    session.is_revoked = True
    await db.commit()
    ip = request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
    await log_action(db, username=user.username, action="session_revoke", target=str(session_id), ip_address=ip)
    return {"status": "revoked"}


@router.delete("")
async def revoke_all_sessions(request: Request, db: AsyncSession = Depends(get_db)):
    """Revoke all sessions except current."""
    user_data = _get_user_data(request)
    current_jti = user_data.get("jti")
    result = await db.execute(select(User).where(User.username == user_data["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(401, "User not found")

    result = await db.execute(
        select(UserSession).where(
            UserSession.user_id == user.id,
            UserSession.is_revoked == False,
            UserSession.token_jti != current_jti,
        )
    )
    sessions = result.scalars().all()
    for s in sessions:
        s.is_revoked = True
    await db.commit()
    ip = request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
    await log_action(db, username=user.username, action="session_revoke_all", detail={"count": len(sessions)}, ip_address=ip)
    return {"status": "revoked", "count": len(sessions)}
