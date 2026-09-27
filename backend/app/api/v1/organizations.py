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
from backend.app.models.all_models import Organization, Agent, SecurityEvent, Detection, PrivacyPolicyRecord, User, SyntheticRecord
from backend.app.schemas.v1_schemas import OrganizationCreate, OrganizationResponse, OrganizationRecordsResponse, SyntheticRecordResponse
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
        total_detections=0,
        location=getattr(org, "location", "Andhra Pradesh, India") or "Andhra Pradesh, India",
        is_demo=getattr(org, "is_demo", False),
        demo_status=getattr(org, "demo_status", "DEMO") or "DEMO",
        security_status=getattr(org, "security_status", "SHIELDED") or "SHIELDED",
        record_counts=getattr(org, "record_counts", {}) or {}
    )

@router.get("", response_model=List[OrganizationResponse])
async def list_organizations(
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Organization)
    res = await db.execute(stmt)
    orgs = res.scalars().all()

    # Pre-configured metadata defaults for known demo organizations
    DEMO_METADATA = {
        "demo_klef_vijayawada": {
            "location": "Vijayawada, Andhra Pradesh, India",
            "is_demo": True,
            "demo_status": "DEMO",
            "security_status": "ACTIVE / SHIELDED",
            "record_counts": {
                "students": 15420,
                "faculty": 1120,
                "it_staff": 85,
                "security_staff": 42,
                "administrators": 28,
                "security_agents": 14,
                "total_records": 16709
            }
        },
        "demo_gitam_visakhapatnam": {
            "location": "Visakhapatnam, Andhra Pradesh, India",
            "is_demo": True,
            "demo_status": "DEMO",
            "security_status": "ACTIVE / SHIELDED",
            "record_counts": {
                "students": 12850,
                "faculty": 940,
                "it_staff": 65,
                "security_staff": 38,
                "administrators": 24,
                "security_agents": 12,
                "total_records": 13929
            }
        },
        "org_enterprise_a": {
            "location": "Hyderabad, Telangana, India",
            "is_demo": True,
            "demo_status": "ENTERPRISE DEMO",
            "security_status": "ACTIVE / PROTECTED",
            "record_counts": {
                "students": 0,
                "faculty": 0,
                "it_staff": 120,
                "security_staff": 54,
                "administrators": 32,
                "security_agents": 8,
                "total_records": 214
            }
        },
        "org_finance_b": {
            "location": "Mumbai, Maharashtra, India",
            "is_demo": True,
            "demo_status": "FINANCIAL DEMO",
            "security_status": "ACTIVE / REGULATED",
            "record_counts": {
                "students": 0,
                "faculty": 0,
                "it_staff": 80,
                "security_staff": 60,
                "administrators": 20,
                "security_agents": 6,
                "total_records": 166
            }
        },
        "org_cloud_c": {
            "location": "Bengaluru, Karnataka, India",
            "is_demo": True,
            "demo_status": "CLOUD DEMO",
            "security_status": "ACTIVE / HARDENED",
            "record_counts": {
                "students": 0,
                "faculty": 0,
                "it_staff": 95,
                "security_staff": 45,
                "administrators": 18,
                "security_agents": 10,
                "total_records": 168
            }
        }
    }

    output = []
    for org in orgs:
        # Ignore legacy scratch/test records if any exist
        if org.org_id in {"org_local_test_1", "org_local_test_2", "org_local_test_3"}:
            continue

        # Aggregate stats
        agent_cnt_res = await db.execute(select(func.count(Agent.id)).where(Agent.organization_id == org.org_id, Agent.status == "ONLINE"))
        active_agents = agent_cnt_res.scalar() or 0

        evt_cnt_res = await db.execute(select(func.count(SecurityEvent.id)).where(SecurityEvent.organization_id == org.org_id))
        total_events = evt_cnt_res.scalar() or 0

        det_cnt_res = await db.execute(select(func.count(Detection.id)).where(Detection.organization_id == org.org_id))
        total_detections = det_cnt_res.scalar() or 0

        meta = DEMO_METADATA.get(org.org_id, {})
        loc = getattr(org, "location", None) or meta.get("location", "Andhra Pradesh, India")
        is_demo = getattr(org, "is_demo", None) if getattr(org, "is_demo", None) is not None else meta.get("is_demo", False)
        demo_status = getattr(org, "demo_status", None) or meta.get("demo_status", "DEMO")
        sec_status = getattr(org, "security_status", None) or meta.get("security_status", "ACTIVE / SHIELDED")
        record_counts = getattr(org, "record_counts", None) or meta.get("record_counts", {})

        output.append(OrganizationResponse(
            id=org.id,
            org_id=org.org_id,
            name=org.name,
            status=org.status,
            contact_email=org.contact_email,
            created_at=org.created_at,
            active_agents=active_agents or (record_counts.get("security_agents") if record_counts else 1),
            total_events=total_events,
            total_detections=total_detections,
            location=loc,
            is_demo=is_demo,
            demo_status=demo_status,
            security_status=sec_status,
            record_counts=record_counts
        ))

    return output

@router.get("/{org_id}/records", response_model=OrganizationRecordsResponse)
async def get_organization_records(
    org_id: str,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Organization).where(Organization.org_id == org_id)
    res = await db.execute(stmt)
    org = res.scalars().first()
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization '{org_id}' not found.")

    # Query synthetic records
    s_stmt = select(SyntheticRecord).where(SyntheticRecord.organization_id == org_id)
    s_res = await db.execute(s_stmt)
    db_records = s_res.scalars().all()

    records_out = []
    if db_records:
        for r in db_records:
            records_out.append(SyntheticRecordResponse(
                record_id=r.record_id,
                organization_id=r.organization_id,
                role=r.role,
                pseudonym=r.pseudonym,
                department=r.department,
                campus=r.campus,
                status=r.status,
                is_synthetic=True
            ))
    else:
        # Generate standard synthetic representative records on demand
        sample_roles = [
            ("STUDENT", "SYNTH-STU-001", "Computer Science & Engineering", "Main Campus"),
            ("STUDENT", "SYNTH-STU-002", "Electronics & Communication", "Main Campus"),
            ("STUDENT", "SYNTH-STU-003", "Cybersecurity & IoT", "Technology Block"),
            ("FACULTY", "SYNTH-FAC-101", "Department of CSE", "Faculty Block A"),
            ("FACULTY", "SYNTH-FAC-102", "Information Technology", "Faculty Block B"),
            ("IT_STAFF", "SYNTH-IT-201", "Campus Network Operations Center", "Admin Central"),
            ("SECURITY_STAFF", "SYNTH-SEC-301", "Campus Physical & Cyber Security", "Security Operations"),
            ("ADMINISTRATOR", "SYNTH-ADM-401", "Office of Academic Registrar", "Main Administration"),
            ("SECURITY_AGENT", "SYNTH-AGT-501", "Edge Network Gateway Sensor", "DMZ Server Room"),
            ("SECURITY_AGENT", "SYNTH-AGT-502", "Host Intrusion Detection Probe", "Datacenter Rack 4"),
        ]
        for role, pseudo, dept, campus in sample_roles:
            records_out.append(SyntheticRecordResponse(
                record_id=f"rec_{org_id}_{pseudo.lower()}",
                organization_id=org_id,
                role=role,
                pseudonym=pseudo,
                department=dept,
                campus=campus,
                status="ACTIVE",
                is_synthetic=True
            ))

    # Retrieve record counts
    meta_counts = getattr(org, "record_counts", None) or {}
    if not meta_counts:
        if org_id == "demo_klef_vijayawada":
            meta_counts = {
                "students": 15420, "faculty": 1120, "it_staff": 85,
                "security_staff": 42, "administrators": 28, "security_agents": 14,
                "total_records": 16709
            }
        elif org_id == "demo_gitam_visakhapatnam":
            meta_counts = {
                "students": 12850, "faculty": 940, "it_staff": 65,
                "security_staff": 38, "administrators": 24, "security_agents": 12,
                "total_records": 13929
            }
        else:
            meta_counts = {
                "students": 0, "faculty": 0, "it_staff": 50,
                "security_staff": 25, "administrators": 10, "security_agents": 5,
                "total_records": 90
            }

    loc = getattr(org, "location", None) or ("Vijayawada, Andhra Pradesh, India" if "klef" in org_id else "Visakhapatnam, Andhra Pradesh, India")

    return OrganizationRecordsResponse(
        organization_id=org.org_id,
        org_id=org.org_id,
        organization_name=org.name,
        location=loc,
        demo_status=getattr(org, "demo_status", "DEMO") or "DEMO",
        security_status=getattr(org, "security_status", "ACTIVE / SHIELDED") or "ACTIVE / SHIELDED",
        record_counts=meta_counts,
        records=records_out
    )
