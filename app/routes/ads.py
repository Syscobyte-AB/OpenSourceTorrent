"""Ad slot management."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_action
from app.database import get_db
from app.models import AdSlot

router = APIRouter(tags=["ads"])


class AdCreateRequest(BaseModel):
    name: str
    position: str  # header, sidebar, footer, inline
    ad_type: str = "text"  # text, image
    content: str
    link_url: Optional[str] = None


class AdUpdateRequest(BaseModel):
    name: Optional[str] = None
    position: Optional[str] = None
    ad_type: Optional[str] = None
    content: Optional[str] = None
    link_url: Optional[str] = None
    is_active: Optional[bool] = None


def _require_admin(request: Request):
    from app.main import verify_token
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    data = verify_token(auth.split(" ", 1)[1])
    if not data.get("admin"):
        raise HTTPException(403, "Admin access required")
    return data


# Public endpoint — free users fetch ads
@router.get("/api/ads")
async def get_ads(
    position: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(AdSlot).where(AdSlot.is_active == True)
    if position:
        q = q.where(AdSlot.position == position)
    result = await db.execute(q)
    ads = result.scalars().all()
    return [
        {
            "id": a.id,
            "name": a.name,
            "position": a.position,
            "ad_type": a.ad_type,
            "content": a.content,
            "link_url": a.link_url,
        }
        for a in ads
    ]


# Admin CRUD
@router.post("/api/admin/ads", status_code=201)
async def create_ad(body: AdCreateRequest, request: Request, db: AsyncSession = Depends(get_db)):
    admin = _require_admin(request)
    ad = AdSlot(
        name=body.name, position=body.position, ad_type=body.ad_type,
        content=body.content, link_url=body.link_url,
    )
    db.add(ad)
    await db.commit()
    await db.refresh(ad)
    ip = request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
    await log_action(db, username=admin["sub"], action="ad_create", target=body.name, ip_address=ip)
    return {"id": ad.id, "name": ad.name}


@router.get("/api/admin/ads")
async def list_ads_admin(request: Request, db: AsyncSession = Depends(get_db)):
    _require_admin(request)
    result = await db.execute(select(AdSlot).order_by(AdSlot.id.desc()))
    ads = result.scalars().all()
    return [
        {
            "id": a.id, "name": a.name, "position": a.position, "ad_type": a.ad_type,
            "content": a.content, "link_url": a.link_url, "is_active": a.is_active,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in ads
    ]


@router.put("/api/admin/ads/{ad_id}")
async def update_ad(ad_id: int, body: AdUpdateRequest, request: Request, db: AsyncSession = Depends(get_db)):
    admin = _require_admin(request)
    result = await db.execute(select(AdSlot).where(AdSlot.id == ad_id))
    ad = result.scalar_one_or_none()
    if not ad:
        raise HTTPException(404, "Ad not found")
    for field in ["name", "position", "ad_type", "content", "link_url", "is_active"]:
        val = getattr(body, field, None)
        if val is not None:
            setattr(ad, field, val)
    ad.updated_at = datetime.utcnow()
    await db.commit()
    ip = request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
    await log_action(db, username=admin["sub"], action="ad_update", target=str(ad_id), ip_address=ip)
    return {"status": "updated"}


@router.delete("/api/admin/ads/{ad_id}")
async def delete_ad(ad_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    admin = _require_admin(request)
    result = await db.execute(select(AdSlot).where(AdSlot.id == ad_id))
    ad = result.scalar_one_or_none()
    if not ad:
        raise HTTPException(404, "Ad not found")
    await db.delete(ad)
    await db.commit()
    ip = request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
    await log_action(db, username=admin["sub"], action="ad_delete", target=str(ad_id), ip_address=ip)
    return {"status": "deleted"}
