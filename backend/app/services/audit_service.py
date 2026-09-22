"""
Audit Logging Service
Records immutable, append-only security actions for complete operational transparency.
"""

from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.models.all_models import AuditLog

async def log_audit(
    db: AsyncSession,
    actor: str,
    action: str,
    resource: str,
    resource_id: Optional[str] = None,
    result: str = "SUCCESS",
    metadata: Optional[Dict[str, Any]] = None
) -> AuditLog:
    """Creates and commits an immutable audit trail record."""
    audit_entry = AuditLog(
        actor=actor,
        action=action,
        resource=resource,
        resource_id=resource_id,
        result=result,
        metadata_payload=metadata or {}
    )
    db.add(audit_entry)
    await db.flush()
    return audit_entry
