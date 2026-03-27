"""
TorrentVault — Audit logging helper.
"""

import json
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog

logger = logging.getLogger("torrentvault.audit")


async def log_action(
    db: AsyncSession,
    *,
    username: str,
    action: str,
    target: str | None = None,
    detail: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> None:
    """Write one row to the audit_log table."""
    entry = AuditLog(
        username=username,
        action=action,
        target=target,
        detail=json.dumps(detail) if detail else None,
        ip_address=ip_address,
    )
    db.add(entry)
    await db.commit()
    logger.info("AUDIT | %s | %s | %s | %s", username, action, target or "-", ip_address or "-")
