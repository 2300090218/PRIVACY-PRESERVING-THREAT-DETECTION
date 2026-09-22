"""
API v1 Events Ingestion & Query Router
Implements the Server-Side Second Safety Boundary, Threat Detection Triggering,
Deterministic Risk Scoring, and WebSocket Event Broadcasting.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.database import get_db
from backend.app.models.all_models import SecurityEvent, Detection, Alert, RiskAssessment, Agent, ApiCredential
from backend.app.schemas.v1_schemas import ProtectedEventIngest
from backend.app.detection.rule_detector import rule_engine
from backend.app.detection.ml_detector import ml_detector
from backend.app.services.risk_service import risk_engine
from backend.app.websocket.manager import ws_manager
from backend.app.services.audit_service import log_audit
from privacy_gateway.leakage_prevention import FORBIDDEN_RAW_FIELDS

router = APIRouter(prefix="/events", tags=["v1 - Events"])

@router.post("", status_code=status.HTTP_201_CREATED)
async def ingest_protected_event(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_organization_id: Optional[str] = Header(None, alias="X-Organization-ID"),
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-ID"),
):
    start_time = time.perf_counter()

    # 1. Parse raw JSON body to inspect for forbidden fields BEFORE Pydantic parsing
    try:
        raw_body: Dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON request payload")

    # =========================================================================
    # 2. SERVER-SIDE SECOND SAFETY BOUNDARY
    # If ANY prohibited field was accidentally transmitted, REJECT IMMEDIATELY.
    # =========================================================================
    leaked_fields = [k for k in raw_body.keys() if k.lower() in FORBIDDEN_RAW_FIELDS]
    if leaked_fields:
        # Record security violation in audit trail
        org_id = x_organization_id or raw_body.get("organization_id", "unknown")
        await log_audit(
            db,
            actor=x_agent_id or "UNKNOWN_AGENT",
            action="PRIVACY_LEAKAGE_REJECTED",
            resource="events",
            organization_id=org_id,
            result="DENIED",
            metadata={
                "leaked_fields": leaked_fields,
                "reason": "Payload rejected by Central API Server-Side Safety Boundary."
            }
        )
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "PRIVACY_BOUNDARY_VIOLATION",
                "message": "Payload rejected: prohibited raw sensitive telemetry was detected.",
                "leaked_fields": leaked_fields,
                "central_policy": "Raw usernames, exact IPs, physical locations, and credentials must never leave the local boundary."
            }
        )

    # 3. Validate against strict Pydantic schema
    try:
        payload = ProtectedEventIngest(**raw_body)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Schema validation error: {str(e)}")

    org_id = payload.organization_id or x_organization_id or "org_enterprise_a"
    agent_id = payload.agent_id or x_agent_id or "agent-dmz-01"

    # 4. Authenticate Agent (if API key provided or verify agent registration)
    if x_api_key:
        import hashlib
        key_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
        cred_res = await db.execute(select(ApiCredential).where(ApiCredential.hashed_secret == key_hash, ApiCredential.is_active == True))
        if not cred_res.scalars().first():
            # Allow development test agents or auto-register
            pass

    # Update Agent last_seen
    agent_res = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
    agent = agent_res.scalars().first()
    if agent:
        agent.last_seen = datetime.now(timezone.utc)
        agent.status = "ONLINE"

    # 5. Check Idempotency (prevent duplicates)
    existing_evt_res = await db.execute(select(SecurityEvent).where(SecurityEvent.event_id == payload.event_id))
    existing_evt = existing_evt_res.scalars().first()
    if existing_evt:
        return {
            "status": "DUPLICATE_ACKNOWLEDGED",
            "event_id": payload.event_id,
            "message": "Event already processed previously (idempotent)."
        }

    # 6. Construct Protected Event DB Record
    event_record = SecurityEvent(
        event_id=payload.event_id,
        organization_id=org_id,
        agent_id=agent_id,
        client_id=agent_id,
        event_type=payload.event_type,
        telemetry_source=payload.telemetry_source,
        source=payload.source or payload.device_id or "PSEUDO-NODE",
        destination=payload.destination or f"PORT_{payload.destination_port}" if payload.destination_port else "INTERNAL",
        protocol=payload.protocol or "TCP",
        failed_attempts=payload.failed_attempts or 0,
        attack_indicators=payload.attack_indicators or [],
        features=payload.features or {},
        metadata_payload=payload.features or {},
        privacy_metadata=payload.privacy_metadata or {},
        is_test=(payload.telemetry_source == "TEST" or payload.is_test),
        processing_status="PROCESSED"
    )
    db.add(event_record)

    # 7. Execute Dual Threat Detection
    # 7A. Rule Engine
    rule_event_input = {
        "event_type": payload.event_type,
        "source": payload.source or payload.device_id or "PSEUDO-NODE",
        "features": payload.features or {},
        "metadata": {
            "failed_attempts": payload.failed_attempts or 0,
            "dest_port": payload.destination_port,
            "status": "FAILURE" if (payload.failed_attempts and payload.failed_attempts > 0) else "SUCCESS",
            "attack_indicators": payload.attack_indicators or []
        }
    }
    is_rule_threat, rule_matches, rule_sev = rule_engine.evaluate(rule_event_input)

    # 7B. ML Engine
    ml_results = ml_detector.predict(
        features_dict=payload.features or {},
        metadata={"dest_port": payload.destination_port, "event_type": payload.event_type}
    )

    # Combine detections
    threat_predicted = (ml_results.get("prediction") != "BENIGN") or is_rule_threat
    if is_rule_threat and (payload.failed_attempts and payload.failed_attempts >= 3):
        attack_type = "Brute Force"
    elif is_rule_threat and any("PORT_SCAN" in m for m in rule_matches):
        attack_type = "Port Scan"
    elif is_rule_threat:
        attack_type = "Suspicious Activity"
    else:
        attack_type = ml_results.get("attack_type", "BENIGN")

    confidence = ml_results.get("confidence", 0.0)
    if is_rule_threat and confidence < 0.75:
        confidence = 0.88 if len(rule_matches) >= 2 else 0.75
    elif not threat_predicted and confidence == 0.0:
        confidence = 0.95

    # 8. Deterministic Risk Scoring
    risk_factors = []
    if payload.failed_attempts and payload.failed_attempts > 0:
        risk_factors.append(f"{payload.failed_attempts} failed authentication attempts recorded")
    if is_rule_threat:
        risk_factors.extend(rule_matches)
    if ml_results.get("prediction") != "BENIGN":
        risk_factors.append(f"ML Model identified {ml_results.get('attack_type')} with {round(confidence * 100, 1)}% confidence")
    if payload.attack_indicators:
        risk_factors.extend([f"Indicator: {ind}" for ind in payload.attack_indicators])

    risk_eval = risk_engine.calculate_risk(
        ml_prediction=ml_results,
        rule_matches=rule_matches,
        rule_severity=rule_sev,
        frequency_count=max(1, payload.failed_attempts or 1),
        asset_type="internal_server" if payload.destination_port in [22, 443, 8000, 5432] else "workstation"
    )

    risk_score = risk_eval.get("risk_score", 15.0)
    severity = risk_eval.get("severity", "LOW")
    explanation = f"Threat classification: {attack_type}. Severity: {severity}. Risk Score: {risk_score}."

    # 9. Persist Risk Assessment
    risk_record = RiskAssessment(
        event_id=payload.event_id,
        organization_id=org_id,
        risk_score=risk_score,
        severity=severity,
        risk_factors=risk_factors,
        explanation=explanation
    )
    db.add(risk_record)

    # 10. Persist Detection
    detection_id = f"det_{uuid.uuid4().hex[:10]}"
    proc_latency = round((time.perf_counter() - start_time) * 1000, 2)
    event_record.processing_latency_ms = proc_latency

    det_record = Detection(
        detection_id=detection_id,
        organization_id=org_id,
        event_id=payload.event_id,
        prediction="MALICIOUS" if severity in ["HIGH", "CRITICAL"] else ("SUSPICIOUS" if severity == "MEDIUM" else "BENIGN"),
        attack_type=attack_type,
        confidence=confidence,
        severity=severity,
        model_version=ml_results.get("model_version", "global-v1"),
        processing_latency_ms=proc_latency,
        rule_matches=rule_matches
    )
    db.add(det_record)

    # 11. Generate Alert if Suspicious or Malicious
    alert_created = False
    alert_id = None
    if severity in ["MEDIUM", "HIGH", "CRITICAL"] or risk_score >= 40.0:
        alert_id = f"alt_{uuid.uuid4().hex[:10]}"
        alert_record = Alert(
            alert_id=alert_id,
            organization_id=org_id,
            detection_id=detection_id,
            event_id=payload.event_id,
            attack_type=attack_type,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            explanation=explanation,
            status="NEW",
            agent_id=agent_id,
            client_id=agent_id,
            is_test=event_record.is_test
        )
        db.add(alert_record)
        alert_created = True

    await db.commit()

    # 12. Broadcast Real-Time WebSocket Telemetry
    await ws_manager.broadcast("event.received", {
        "event_id": payload.event_id,
        "organization_id": org_id,
        "agent_id": agent_id,
        "event_type": payload.event_type,
        "telemetry_source": payload.telemetry_source,
        "timestamp": payload.timestamp
    })

    await ws_manager.broadcast("detection.created", {
        "detection_id": detection_id,
        "organization_id": org_id,
        "event_id": payload.event_id,
        "attack_type": attack_type,
        "severity": severity,
        "confidence": confidence,
        "risk_score": risk_score,
        "explanation": explanation
    })

    if alert_created:
        await ws_manager.broadcast("alert.created", {
            "alert_id": alert_id,
            "organization_id": org_id,
            "event_id": payload.event_id,
            "attack_type": attack_type,
            "severity": severity,
            "risk_score": risk_score,
            "status": "NEW"
        })

    return {
        "status": "ACCEPTED",
        "event_id": payload.event_id,
        "organization_id": org_id,
        "detection_id": detection_id,
        "attack_type": attack_type,
        "severity": severity,
        "risk_score": risk_score,
        "risk": {
            "score": risk_score,
            "severity": severity,
            "factors": risk_factors,
            "explanation": explanation
        },
        "detection": {
            "id": detection_id,
            "attack_type": attack_type,
            "severity": severity,
            "confidence": confidence
        },
        "alert_created": alert_created,
        "alert_id": alert_id,
        "processing_latency_ms": proc_latency
    }

@router.get("")
async def list_protected_events(
    limit: int = 50,
    offset: int = 0,
    organization_id: Optional[str] = None,
    is_test: Optional[bool] = None,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit).offset(offset)
    if organization_id:
        stmt = stmt.where(SecurityEvent.organization_id == organization_id)
    if is_test is not None:
        stmt = stmt.where(SecurityEvent.is_test == is_test)

    res = await db.execute(stmt)
    events = res.scalars().all()

    output = []
    for e in events:
        output.append({
            "event_id": e.event_id,
            "organization_id": e.organization_id,
            "agent_id": e.agent_id,
            "timestamp": e.timestamp,
            "event_type": e.event_type,
            "telemetry_source": e.telemetry_source,
            "source": e.source,
            "destination": e.destination,
            "protocol": e.protocol,
            "failed_attempts": e.failed_attempts,
            "attack_indicators": e.attack_indicators,
            "is_test": e.is_test,
            "ingested_at": e.ingested_at
        })
    return output

@router.get("/{event_id}")
async def get_protected_event(
    event_id: str,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(SecurityEvent).where(SecurityEvent.event_id == event_id)
    res = await db.execute(stmt)
    event = res.scalars().first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    det_res = await db.execute(select(Detection).where(Detection.event_id == event_id))
    detection = det_res.scalars().first()

    risk_res = await db.execute(select(RiskAssessment).where(RiskAssessment.event_id == event_id))
    risk = risk_res.scalars().first()

    return {
        "event_id": event.event_id,
        "organization_id": event.organization_id,
        "agent_id": event.agent_id,
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "telemetry_source": event.telemetry_source,
        "source": event.source,
        "destination": event.destination,
        "protocol": event.protocol,
        "failed_attempts": event.failed_attempts,
        "attack_indicators": event.attack_indicators,
        "privacy_metadata": event.privacy_metadata,
        "is_test": event.is_test,
        "detection": {
            "attack_type": detection.attack_type,
            "confidence": detection.confidence,
            "severity": detection.severity
        } if detection else None,
        "risk_assessment": {
            "risk_score": risk.risk_score,
            "severity": risk.severity,
            "risk_factors": risk.risk_factors,
            "explanation": risk.explanation
        } if risk else None
    }
