"""
TorrentVault - Advanced Torrent Downloader Backend
FastAPI + libtorrent | Security-first | SQLAlchemy | Tiers | Audit
"""

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import bcrypt
import libtorrent as lt
from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_action
from app.config import settings
from app.database import get_db, init_db, async_session
from app.models import (
    AdSlot, AuditLog, ApiKey, InviteCode,
    SubscriptionPlan, TorrentRecord, User, UserSession,
)
from app.session_manager import TorrentSessionManager

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("torrentvault")

# ─── Rate limiting ───────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ─── Auth helpers ────────────────────────────────────────────────────────────
SECRET_KEY = settings.secret_key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24


class Token(BaseModel):
    access_token: str
    token_type: str


class LoginRequest(BaseModel):
    username: str
    password: str


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    to_encode["jti"] = str(uuid.uuid4())
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM), to_encode["jti"]


def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)


async def get_current_user(
    request: Request,
    token: str | None = Depends(_oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Authenticate via Bearer JWT or X-API-Key header."""
    # Try API key first
    api_key_raw = request.headers.get(settings.api_key_header)
    if api_key_raw:
        result = await db.execute(
            select(ApiKey).where(ApiKey.key_prefix == api_key_raw[:12], ApiKey.is_active == True)
        )
        api_key = result.scalar_one_or_none()
        if api_key and bcrypt.checkpw(api_key_raw.encode(), api_key.key_hash.encode()):
            api_key.last_used_at = datetime.utcnow()
            await db.commit()
            result = await db.execute(select(User).where(User.id == api_key.user_id))
            user = result.scalar_one_or_none()
            if user and user.is_active:
                return {"sub": user.username, "admin": user.is_admin, "tier": user.tier, "uid": user.id}
        raise HTTPException(401, "Invalid API key")

    # JWT auth
    if not token:
        raise HTTPException(401, "Missing authentication")
    payload = verify_token(token)

    # Check session not revoked
    jti = payload.get("jti")
    if jti:
        result = await db.execute(select(UserSession).where(UserSession.token_jti == jti))
        session = result.scalar_one_or_none()
        if session and session.is_revoked:
            raise HTTPException(401, "Session revoked")
        if session:
            session.last_active_at = datetime.utcnow()
            await db.commit()

    # Check IP allowlist
    result = await db.execute(select(User).where(User.username == payload.get("sub")))
    user = result.scalar_one_or_none()
    if user and user.ip_allowlist:
        allowed_ips = json.loads(user.ip_allowlist)
        client_ip = _client_ip(request)
        if allowed_ips and client_ip not in allowed_ips:
            raise HTTPException(403, "IP not in allowlist")

    return payload


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")


async def require_admin(user=Depends(get_current_user)):
    if not user.get("admin"):
        raise HTTPException(403, "Admin access required")
    return user


# ─── Pydantic request models ────────────────────────────────────────────────
class MagnetRequest(BaseModel):
    magnet_uri: str
    save_path: Optional[str] = None
    max_download_rate: Optional[int] = -1
    max_upload_rate: Optional[int] = -1
    sequential: bool = False

    @field_validator("magnet_uri")
    @classmethod
    def validate_magnet(cls, v: str) -> str:
        if not v.startswith("magnet:?"):
            raise ValueError("Invalid magnet URI")
        return v


class FileSelectionRequest(BaseModel):
    info_hash: str
    file_indices: list[int]


class SpeedLimitRequest(BaseModel):
    info_hash: str
    download_kbps: int = -1
    upload_kbps: int = -1


class PriorityRequest(BaseModel):
    info_hash: str
    priority: int


class UserCreateRequest(BaseModel):
    username: str
    password: str
    is_admin: bool = False


class UserUpdateRequest(BaseModel):
    password: Optional[str] = None
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None
    ip_allowlist: Optional[list[str]] = None


# ─── Tier enforcement helper ────────────────────────────────────────────────
async def _check_tier_limit(username: str, db: AsyncSession) -> User:
    """Check user exists and return User object."""
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(401, "User not found")
    return user


async def _enforce_torrent_limit(user: User, db: AsyncSession):
    """Raise 403 if free-tier user is at torrent limit."""
    if user.max_active_torrents == -1:
        return
    count_q = select(sa_func.count(TorrentRecord.id)).where(
        TorrentRecord.added_by == user.username, TorrentRecord.status == "active"
    )
    count = (await db.execute(count_q)).scalar() or 0
    if count >= user.max_active_torrents:
        raise HTTPException(
            403,
            f"Free tier limit reached ({user.max_active_torrents} active torrents). Upgrade to Premium for unlimited."
        )


def _apply_speed_cap(user: User, rate: int) -> int:
    """Cap speed to user's tier limit."""
    if user.speed_cap_kbps == -1:
        return rate
    cap = user.speed_cap_kbps * 1024
    if rate == -1 or rate > cap:
        return cap
    return rate


# ─── App lifespan ────────────────────────────────────────────────────────────
session_manager: TorrentSessionManager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global session_manager
    await init_db()
    logger.info("Database tables ready")

    from app.seed import seed_defaults
    async with async_session() as db:
        await seed_defaults(db)

    session_manager = TorrentSessionManager(download_dir=settings.download_dir, listen_ports=settings.listen_ports)
    await session_manager.start()
    logger.info("TorrentVault session started")
    yield
    await session_manager.stop()
    logger.info("TorrentVault session stopped")


# ─── App factory ─────────────────────────────────────────────────────────────
app = FastAPI(title="TorrentVault API", version="2.0.0", docs_url="/api/docs", redoc_url=None, lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    if request.url.path.startswith("/api/docs") or request.url.path.startswith("/docs"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com *; connect-src 'self' ws: wss:;"
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: *; connect-src 'self' ws: wss:;"
        )
    return response


# ── Register route modules ──
from app.routes.auth import router as auth_router
from app.routes.sessions import router as sessions_router
from app.routes.invites import router as invites_router
from app.routes.ads import router as ads_router
from app.routes.subscriptions import router as subs_router

app.include_router(auth_router)
app.include_router(sessions_router)
app.include_router(invites_router)
app.include_router(ads_router)
app.include_router(subs_router)


# ═════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═════════════════════════════════════════════════════════════════════════════

async def _do_login(username: str, password: str, request: Request, db: AsyncSession) -> Token:
    """Shared login logic for JSON and OAuth2 form endpoints."""
    ip = _client_ip(request)
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()

    # Check lockout
    if user and user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(423, "Account locked. Try again later.")

    if not user or not user.is_active or not bcrypt.checkpw(
        password.encode("utf-8"), user.password_hash.encode("utf-8")
    ):
        if user:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= settings.max_failed_logins:
                user.locked_until = datetime.utcnow() + timedelta(minutes=settings.lockout_duration_minutes)
            await db.commit()
        await log_action(db, username=username, action="login_failed", ip_address=ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Reset lockout on success
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    await db.commit()

    token_str, jti = create_access_token({"sub": user.username, "admin": user.is_admin, "tier": user.tier, "uid": user.id})

    # Track session
    ua = request.headers.get("User-Agent", "")[:256]
    sess = UserSession(user_id=user.id, token_jti=jti, ip_address=ip, user_agent=ua)
    db.add(sess)
    await db.commit()

    await log_action(db, username=username, action="login", ip_address=ip)
    return Token(access_token=token_str, token_type="bearer")


@app.post("/api/auth/login", response_model=Token, tags=["auth"])
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest, db: AsyncSession = Depends(get_db)):
    return await _do_login(body.username, body.password, request, db)


@app.post("/api/auth/token", response_model=Token, tags=["auth"])
@limiter.limit("10/minute")
async def login_oauth2(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    """OAuth2-compatible token endpoint (Swagger Authorize dialog)."""
    return await _do_login(form.username, form.password, request, db)


# ═════════════════════════════════════════════════════════════════════════════
# TORRENT ROUTES (tier-enforced + audited)
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/torrents", tags=["torrents"])
async def list_torrents(user=Depends(get_current_user)):
    return session_manager.get_all_torrents()


@app.get("/api/torrents/history", tags=["torrents"])
async def torrent_history(
    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    admin=Depends(require_admin), db: AsyncSession = Depends(get_db),
):
    q = select(TorrentRecord).order_by(TorrentRecord.id.desc())
    if status_filter:
        q = q.where(TorrentRecord.status == status_filter)
    result = await db.execute(q.offset(offset).limit(limit))
    return [
        {"id": r.id, "info_hash": r.info_hash, "name": r.name, "source": r.source,
         "added_by": r.added_by, "status": r.status,
         "created_at": r.created_at.isoformat() if r.created_at else None,
         "completed_at": r.completed_at.isoformat() if r.completed_at else None,
         "removed_at": r.removed_at.isoformat() if r.removed_at else None}
        for r in result.scalars().all()
    ]


@app.post("/api/torrents/add/magnet", tags=["torrents"])
@limiter.limit("30/minute")
async def add_magnet(request: Request, body: MagnetRequest, user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    db_user = await _check_tier_limit(user["sub"], db)
    await _enforce_torrent_limit(db_user, db)

    dl_rate = _apply_speed_cap(db_user, body.max_download_rate or -1)
    ul_rate = _apply_speed_cap(db_user, body.max_upload_rate or -1)

    result = await session_manager.add_magnet(
        magnet_uri=body.magnet_uri, save_path=body.save_path or settings.download_dir,
        max_download_rate=dl_rate, max_upload_rate=ul_rate, sequential=body.sequential,
    )
    record = TorrentRecord(info_hash=result["info_hash"], name=result.get("name"), magnet_uri=body.magnet_uri, source="magnet", added_by=user["sub"])
    db.add(record)
    await db.commit()
    await log_action(db, username=user["sub"], action="add_magnet", target=result["info_hash"], ip_address=_client_ip(request))
    return result


@app.post("/api/torrents/add/file", tags=["torrents"])
@limiter.limit("30/minute")
async def add_torrent_file(request: Request, file: UploadFile = File(...), save_path: Optional[str] = None, user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not file.filename.endswith(".torrent"):
        raise HTTPException(400, "Only .torrent files are accepted")
    if file.size and file.size > 10 * 1024 * 1024:
        raise HTTPException(400, "Torrent file too large")

    db_user = await _check_tier_limit(user["sub"], db)
    await _enforce_torrent_limit(db_user, db)

    data = await file.read()
    result = await session_manager.add_torrent_file(torrent_data=data, save_path=save_path or settings.download_dir)
    record = TorrentRecord(info_hash=result["info_hash"], name=result.get("name"), source="file", added_by=user["sub"])
    db.add(record)
    await db.commit()
    await log_action(db, username=user["sub"], action="add_file", target=result["info_hash"], detail={"filename": file.filename}, ip_address=_client_ip(request))
    return result


@app.get("/api/torrents/{info_hash}", tags=["torrents"])
async def get_torrent(info_hash: str, user=Depends(get_current_user)):
    torrent = session_manager.get_torrent(info_hash)
    if not torrent:
        raise HTTPException(404, "Torrent not found")
    return torrent


@app.post("/api/torrents/{info_hash}/pause", tags=["torrents"])
async def pause_torrent(info_hash: str, request: Request, user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not session_manager.pause(info_hash):
        raise HTTPException(404, "Torrent not found")
    await log_action(db, username=user["sub"], action="pause", target=info_hash, ip_address=_client_ip(request))
    return {"status": "paused"}


@app.post("/api/torrents/{info_hash}/resume", tags=["torrents"])
async def resume_torrent(info_hash: str, request: Request, user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not session_manager.resume(info_hash):
        raise HTTPException(404, "Torrent not found")
    await log_action(db, username=user["sub"], action="resume", target=info_hash, ip_address=_client_ip(request))
    return {"status": "resumed"}


@app.delete("/api/torrents/{info_hash}", tags=["torrents"])
async def delete_torrent(info_hash: str, request: Request, delete_files: bool = False, user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not session_manager.remove(info_hash, delete_files=delete_files):
        raise HTTPException(404, "Torrent not found")
    result = await db.execute(select(TorrentRecord).where(TorrentRecord.info_hash == info_hash))
    rec = result.scalar_one_or_none()
    if rec:
        rec.status = "removed"
        rec.removed_at = datetime.utcnow()
        await db.commit()
    await log_action(db, username=user["sub"], action="delete", target=info_hash, detail={"delete_files": delete_files}, ip_address=_client_ip(request))
    return {"status": "removed"}


@app.put("/api/torrents/files", tags=["torrents"])
async def select_files(body: FileSelectionRequest, request: Request, user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not session_manager.set_file_priorities(body.info_hash, body.file_indices):
        raise HTTPException(404, "Torrent not found")
    await log_action(db, username=user["sub"], action="set_files", target=body.info_hash, detail={"file_indices": body.file_indices}, ip_address=_client_ip(request))
    return {"status": "updated"}


@app.put("/api/torrents/speed", tags=["torrents"])
async def set_speed_limit(body: SpeedLimitRequest, request: Request, user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    db_user = await _check_tier_limit(user["sub"], db)
    dl = _apply_speed_cap(db_user, body.download_kbps * 1024)
    ul = _apply_speed_cap(db_user, body.upload_kbps * 1024)
    if not session_manager.set_speed_limits(body.info_hash, dl, ul):
        raise HTTPException(404, "Torrent not found")
    await log_action(db, username=user["sub"], action="set_speed", target=body.info_hash, detail={"dl_kbps": body.download_kbps, "ul_kbps": body.upload_kbps}, ip_address=_client_ip(request))
    return {"status": "updated"}


@app.put("/api/torrents/priority", tags=["torrents"])
async def set_priority(body: PriorityRequest, request: Request, user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not session_manager.set_priority(body.info_hash, body.priority):
        raise HTTPException(404, "Torrent not found")
    await log_action(db, username=user["sub"], action="set_priority", target=body.info_hash, detail={"priority": body.priority}, ip_address=_client_ip(request))
    return {"status": "updated"}


@app.get("/api/stats", tags=["system"])
async def global_stats(user=Depends(get_current_user)):
    return session_manager.global_stats()


@app.get("/api/dashboard", tags=["system"])
async def dashboard(user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    lt_stats = session_manager.global_stats()
    total_users = (await db.execute(select(sa_func.count(User.id)))).scalar() or 0
    active_users = (await db.execute(select(sa_func.count(User.id)).where(User.is_active == True))).scalar() or 0
    premium_users = (await db.execute(select(sa_func.count(User.id)).where(User.tier == "premium"))).scalar() or 0
    total_records = (await db.execute(select(sa_func.count(TorrentRecord.id)))).scalar() or 0
    active_records = (await db.execute(select(sa_func.count(TorrentRecord.id)).where(TorrentRecord.status == "active"))).scalar() or 0
    removed_records = (await db.execute(select(sa_func.count(TorrentRecord.id)).where(TorrentRecord.status == "removed"))).scalar() or 0
    total_audit = (await db.execute(select(sa_func.count(AuditLog.id)))).scalar() or 0
    recent_result = await db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(10))
    recent_audit = [{"timestamp": r.timestamp.isoformat() if r.timestamp else None, "username": r.username, "action": r.action, "target": r.target} for r in recent_result.scalars().all()]

    return {
        "libtorrent": lt_stats,
        "users": {"total": total_users, "active": active_users, "premium": premium_users},
        "torrents_db": {"total": total_records, "active": active_records, "removed": removed_records},
        "audit": {"total_entries": total_audit, "recent": recent_audit},
    }


# ═════════════════════════════════════════════════════════════════════════════
# USER MANAGEMENT (admin only)
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/users", tags=["users"])
async def list_users(admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).order_by(User.id))
    return [
        {"id": u.id, "username": u.username, "is_admin": u.is_admin, "is_active": u.is_active,
         "tier": u.tier, "max_active_torrents": u.max_active_torrents, "speed_cap_kbps": u.speed_cap_kbps,
         "subscription_status": u.subscription_status,
         "created_at": u.created_at.isoformat() if u.created_at else None,
         "last_login": u.last_login.isoformat() if u.last_login else None}
        for u in result.scalars().all()
    ]


@app.post("/api/users", tags=["users"], status_code=201)
async def create_user(body: UserCreateRequest, request: Request, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(409, "Username already exists")
    hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    user = User(username=body.username, password_hash=hashed, is_admin=body.is_admin)
    if body.is_admin:
        user.tier = "premium"
        user.max_active_torrents = -1
        user.speed_cap_kbps = -1
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await log_action(db, username=admin["sub"], action="user_create", target=body.username, detail={"is_admin": body.is_admin}, ip_address=_client_ip(request))
    return {"id": user.id, "username": user.username, "is_admin": user.is_admin, "tier": user.tier}


@app.put("/api/users/{username}", tags=["users"])
async def update_user(username: str, body: UserUpdateRequest, request: Request, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if body.password is not None:
        user.password_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    if body.is_admin is not None:
        user.is_admin = body.is_admin
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.ip_allowlist is not None:
        user.ip_allowlist = json.dumps(body.ip_allowlist) if body.ip_allowlist else None
    await db.commit()
    await log_action(db, username=admin["sub"], action="user_update", target=username, ip_address=_client_ip(request))
    return {"status": "updated"}


@app.delete("/api/users/{username}", tags=["users"])
async def delete_user(username: str, request: Request, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if username == "admin":
        raise HTTPException(400, "Cannot delete the default admin user")
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    await db.delete(user)
    await db.commit()
    await log_action(db, username=admin["sub"], action="user_delete", target=username, ip_address=_client_ip(request))
    return {"status": "deleted"}


# ═════════════════════════════════════════════════════════════════════════════
# AUDIT LOG
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/audit", tags=["audit"])
async def get_audit_log(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
    action: Optional[str] = None, username: Optional[str] = None,
    admin=Depends(require_admin), db: AsyncSession = Depends(get_db),
):
    q = select(AuditLog).order_by(AuditLog.id.desc())
    count_q = select(sa_func.count(AuditLog.id))
    if action:
        q = q.where(AuditLog.action == action)
        count_q = count_q.where(AuditLog.action == action)
    if username:
        q = q.where(AuditLog.username == username)
        count_q = count_q.where(AuditLog.username == username)
    total = (await db.execute(count_q)).scalar()
    result = await db.execute(q.offset(offset).limit(limit))
    return {
        "total": total, "offset": offset, "limit": limit,
        "entries": [
            {"id": r.id, "timestamp": r.timestamp.isoformat() if r.timestamp else None,
             "username": r.username, "action": r.action, "target": r.target,
             "detail": r.detail, "ip_address": r.ip_address}
            for r in result.scalars().all()
        ],
    }


# ═════════════════════════════════════════════════════════════════════════════
# WEBSOCKET
# ═════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws/torrents")
async def torrent_updates(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return
    try:
        verify_token(token)
    except HTTPException:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    try:
        while True:
            await websocket.send_json({
                "torrents": session_manager.get_all_torrents(),
                "stats": session_manager.global_stats(),
                "ts": int(time.time()),
            })
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        logger.info("WS client disconnected")


@app.get("/api/health", tags=["system"])
async def health():
    return {"status": "ok", "version": "2.0.0"}


# ─── Frontend ────────────────────────────────────────────────────────────────
STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
