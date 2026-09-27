"""
API v1 Agents Router
Manages local edge agent registration, health status, and API credentials.
"""

import uuid
import hashlib
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime, timezone

from backend.app.database import get_db
from backend.app.models.all_models import Agent, ApiCredential, Organization, SecurityEvent
from backend.app.schemas.v1_schemas import AgentRegisterRequest, AgentRegisterResponse
from backend.app.services.audit_service import log_audit

router = APIRouter(prefix="/agents", tags=["v1 - Agents"])

def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

@router.post("", response_model=AgentRegisterResponse, status_code=status.HTTP_201_CREATED)
@router.post("/register", response_model=AgentRegisterResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(
    req: AgentRegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    # Verify organization exists
    org_res = await db.execute(select(Organization).where(Organization.org_id == req.organization_id))
    if not org_res.scalars().first():
        # Auto-create if not yet registered
        new_org = Organization(org_id=req.organization_id, name=f"{req.organization_id.replace('_', ' ').title()}")
        db.add(new_org)

    # Generate secure random API key
    raw_key = f"agkey_{uuid.uuid4().hex}"
    key_hash = hash_api_key(raw_key)

    # Check existing agent
    stmt = select(Agent).where(Agent.agent_id == req.agent_id)
    res = await db.execute(stmt)
    agent = res.scalars().first()

    if agent:
        agent.name = req.name
        agent.status = "ONLINE"
        agent.api_key_hash = key_hash
        agent.version = req.version
        agent.last_seen = datetime.now(timezone.utc)
    else:
        agent = Agent(
            agent_id=req.agent_id,
            organization_id=req.organization_id,
            name=req.name,
            status="ONLINE",
            api_key_hash=key_hash,
            version=req.version
        )
        db.add(agent)

    # Store credential record
    cred = ApiCredential(
        organization_id=req.organization_id,
        agent_id=req.agent_id,
        key_prefix=raw_key[:10],
        hashed_secret=key_hash,
        name=f"Key for {req.name}"
    )
    db.add(cred)

    await db.commit()
    await db.refresh(agent)

    await log_audit(
        db,
        actor=req.agent_id,
        action="AGENT_REGISTERED",
        resource="agent",
        organization_id=req.organization_id,
        resource_id=req.agent_id,
        result="SUCCESS"
    )

    return AgentRegisterResponse(
        agent_id=agent.agent_id,
        organization_id=agent.organization_id,
        name=agent.name,
        status=agent.status,
        api_key=raw_key,
        created_at=agent.created_at
    )

@router.get("")
async def list_agents(
    organization_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Agent)
    if organization_id:
        stmt = stmt.where(Agent.organization_id == organization_id)
    res = await db.execute(stmt)
    agents = res.scalars().all()

    output = []
    for a in agents:
        output.append({
            "agent_id": a.agent_id,
            "organization_id": a.organization_id,
            "name": a.name,
            "status": a.status,
            "version": a.version,
            "last_seen": a.last_seen,
            "created_at": a.created_at
        })
    return output

@router.get("/{agent_id}")
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Agent).where(Agent.agent_id == agent_id)
    res = await db.execute(stmt)
    agent = res.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    return {
        "agent_id": agent.agent_id,
        "organization_id": agent.organization_id,
        "name": agent.name,
        "status": agent.status,
        "version": agent.version,
        "last_seen": agent.last_seen,
        "created_at": agent.created_at
    }
