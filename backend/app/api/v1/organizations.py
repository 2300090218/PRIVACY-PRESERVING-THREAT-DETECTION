"""
API v1 Organizations Router
Manages enterprise organizations, isolation boundaries, and active agent fleets.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func

from backend.app.database import get_db
from backend.app.models.all_models import Organization, Agent, SecurityEvent, Detection, PrivacyPolicyRecord, User
from backend.app.schemas.v1_schemas import OrganizationCreate, OrganizationResponse
from backend.app.security.authentication import get_current_user
from backend.app.services.audit_service import log_audit
from privacy_gateway.policy_engine import create_default_policy_config

router = APIRouter(prefix="/organizations", tags=["v1 - Organizations"])

@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
@router.post("/register", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def register_organization(
    req: OrganizationCreate,
    db: AsyncSession = Depends(get_db)
):
    # Check if org already exists
    stmt = select(Organization).where(Organization.org_id == req.org_id)
    res = await db.execute(stmt)
    if res.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Organization with ID '{req.org_id}' already registered."
        )

    org = Organization(
        org_id=req.org_id,
        name=req.name,
        contact_email=req.contact_email,
        status="ACTIVE"
    )
    db.add(org)

    # Seed baseline field privacy policies for this new organization
    default_cfg = create_default_policy_config(organization_id=req.org_id)
    for field_name, policy in default_cfg.field_policies.items():
        pol_rec = PrivacyPolicyRecord(
            policy_id=f"pol_{req.org_id}_{field_name}",
            organization_id=req.org_id,
            name=f"{field_name.capitalize()} Policy",
            field_name=field_name,
            action=policy.action.value,
            parameters=policy.parameters,
            is_active=True
        )
        db.add(pol_rec)

    await db.commit()
    await db.refresh(org)

    await log_audit(
        db,
        actor="SYSTEM",
        action="ORGANIZATION_REGISTERED",
        resource="organization",
        organization_id=req.org_id,
        resource_id=req.org_id,
        result="SUCCESS",
        metadata={"name": req.name}
    )

    return OrganizationResponse(
        id=org.id,
        org_id=org.org_id,
        name=org.name,
        status=org.status,
        contact_email=org.contact_email,
        created_at=org.created_at,
        active_agents=0,
        total_events=0,
        total_detections=0
    )

@router.get("", response_model=List[OrganizationResponse])
async def list_organizations(
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Organization)
    res = await db.execute(stmt)
    orgs = res.scalars().all()

    output = []
    for org in orgs:
        # Aggregate stats
        agent_cnt_res = await db.execute(select(func.count(Agent.id)).where(Agent.organization_id == org.org_id, Agent.status == "ONLINE"))
        active_agents = agent_cnt_res.scalar() or 0

        evt_cnt_res = await db.execute(select(func.count(SecurityEvent.id)).where(SecurityEvent.organization_id == org.org_id))
        total_events = evt_cnt_res.scalar() or 0

        det_cnt_res = await db.execute(select(func.count(Detection.id)).where(Detection.organization_id == org.org_id))
        total_detections = det_cnt_res.scalar() or 0

        output.append(OrganizationResponse(
            id=org.id,
            org_id=org.org_id,
            name=org.name,
            status=org.status,
            contact_email=org.contact_email,
            created_at=org.created_at,
            active_agents=active_agents,
            total_events=total_events,
            total_detections=total_detections
        ))

    return output
