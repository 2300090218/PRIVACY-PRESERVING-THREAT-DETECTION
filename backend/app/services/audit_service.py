"""
Audit Logging Service
Records immutable, append-only security actions for complete operational transparency
with multi-organization boundary isolation.
"""

from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.models.all_models import AuditLog

async def log_audit(
    db: AsyncSession,
    actor: str,
    action: str,
    resource: str,
    organization_id: str = "org_enterprise_a",
    resource_id: Optional[str] = None,
    result: str = "SUCCESS",
    metadata: Optional[Dict[str, Any]] = None,
    metadata_payload: Optional[Dict[str, Any]] = None
) -> AuditLog:
    """Creates and commits an immutable audit trail record."""
    payload = metadata_payload or metadata or {}
    audit_entry = AuditLog(
        organization_id=organization_id,
        actor=actor,
        action=action,
        resource=resource,
        resource_id=resource_id,
        result=result,
        metadata_payload=payload
    )
    db.add(audit_entry)
    await db.flush()
    return audit_entry
