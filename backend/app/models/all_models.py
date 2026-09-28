"""
SQLAlchemy Models for Privacy-Preserving Threat Detection Platform
Includes full relational schema for multi-organization isolation, agents,
api_credentials, privacy_policies, protected_events, detections, alerts,
risk_assessments, incidents, audit_logs, and system_metrics.

Zero-raw-data central storage principle:
Raw sensitive telemetry (usernames, exact IP addresses, physical locations,
raw device IDs, complete raw logs) is NEVER persisted in these tables.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from backend.app.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(128), nullable=False)
    status = Column(String(32), default="ACTIVE", index=True) # ACTIVE, SUSPENDED
    contact_email = Column(String(128), nullable=True)
    location = Column(String(128), default="Andhra Pradesh, India", nullable=True)
    is_demo = Column(Boolean, default=True)
    demo_status = Column(String(32), default="DEMO")
    security_status = Column(String(32), default="ACTIVE / SHIELDED")
    record_counts = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utcnow)

class SyntheticRecord(Base):
    """
    Synthetic demonstration records for academic entities (Students, Faculty, IT Staff,
    Security Staff, Administrators, and Security Agents).
    Purely synthetic and pseudonymous; contains zero real personal data.
    """
    __tablename__ = "synthetic_records"

    id = Column(Integer, primary_key=True, index=True)
    record_id = Column(String(64), unique=True, index=True, nullable=False)
    organization_id = Column(String(64), index=True, nullable=False)
    role = Column(String(32), index=True, nullable=False) # STUDENT, FACULTY, IT_STAFF, SECURITY_STAFF, ADMINISTRATOR, SECURITY_AGENT
    pseudonym = Column(String(128), nullable=False)
    department = Column(String(64), nullable=True)
    campus = Column(String(64), nullable=True)
    status = Column(String(32), default="ACTIVE")
    is_synthetic = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(String(64), default="org_enterprise_a", index=True, nullable=False)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(32), default="VIEWER", nullable=False) # ADMIN, SECURITY_ANALYST, AGENT_USER, VIEWER
    display_name = Column(String(128), nullable=True)
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=True)
    two_factor_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    last_login_at = Column(DateTime, nullable=True)

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_token_hash = Column(String(128), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, index=True, nullable=False)
    last_active_at = Column(DateTime, default=utcnow)
    is_revoked = Column(Boolean, default=False, index=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)

    user = relationship("User", backref="sessions")

class EmailVerificationCode(Base):
    __tablename__ = "email_verification_codes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    otp_hash = Column(String(128), nullable=False)
    session_nonce = Column(String(64), unique=True, index=True, nullable=False)
    purpose = Column(String(32), default="LOGIN_2FA", index=True) # LOGIN_2FA, EMAIL_VERIFY, PASSWORD_RESET
    attempt_count = Column(Integer, default=0)
    max_attempts = Column(Integer, default=5)
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, index=True, nullable=False)
    consumed_at = Column(DateTime, nullable=True)

    user = relationship("User", backref="verification_codes")

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash = Column(String(128), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, index=True, nullable=False)
    consumed_at = Column(DateTime, nullable=True)

    user = relationship("User", backref="password_resets")

class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    identifier = Column(String(128), index=True, nullable=False) # email or username
    ip_address = Column(String(64), nullable=True)
    attempt_type = Column(String(32), default="PASSWORD", index=True) # PASSWORD, OTP
    is_success = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=utcnow, index=True)

class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), unique=True, index=True, nullable=False)
    organization_id = Column(String(64), index=True, nullable=False, default="org_enterprise_a")
    name = Column(String(128), nullable=False)
    status = Column(String(32), default="ONLINE", index=True) # ONLINE, OFFLINE, ERROR
    api_key_hash = Column(String(128), nullable=True)
    version = Column(String(64), default="1.0.0")
    last_seen = Column(DateTime, default=utcnow, index=True)
    created_at = Column(DateTime, default=utcnow)

# Backward-compatible Client model for federated learning sensor nodes
class Client(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(128), nullable=False)
    status = Column(String(32), default="OFFLINE", index=True) # ONLINE, OFFLINE, TRAINING, ERROR
    last_seen = Column(DateTime, default=utcnow, index=True)
    model_version = Column(String(64), default="global-v1")
    training_status = Column(String(32), default="IDLE")
    local_metrics = Column(JSON, default=dict)
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utcnow)

class ApiCredential(Base):
    __tablename__ = "api_credentials"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(String(64), index=True, nullable=False)
    agent_id = Column(String(64), index=True, nullable=False)
    key_prefix = Column(String(32), nullable=False)
    hashed_secret = Column(String(128), nullable=False)
    name = Column(String(128), default="Default Agent API Key")
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)

class PrivacyPolicyRecord(Base):
    __tablename__ = "privacy_policies"

    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(String(64), unique=True, index=True, nullable=False)
    organization_id = Column(String(64), index=True, nullable=False, default="org_enterprise_a")
    name = Column(String(128), default="Enterprise Boundary Policy")
    field_name = Column(String(64), index=True, nullable=False)
    action = Column(String(32), nullable=False) # ALLOW, REMOVE, MASK, PSEUDONYMIZE, AGGREGATE
    parameters = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    version = Column(String(32), default="1.0.0")
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

class SecurityEvent(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    organization_id = Column(String(64), index=True, nullable=False, default="org_enterprise_a")
    agent_id = Column(String(64), index=True, nullable=True, default="agent-dmz-01")
    client_id = Column(String(64), index=True, nullable=True)
    timestamp = Column(DateTime, default=utcnow, index=True, nullable=False)
    event_type = Column(String(64), index=True, nullable=False) # e.g., network_flow, failed_login, brute_force_attack
    telemetry_source = Column(String(32), default="TEST", index=True) # REAL, TEST, DEMO
    source = Column(String(128), nullable=True) # Pseudonymized identifier, e.g. DEV-8F31
    destination = Column(String(128), nullable=True)
    protocol = Column(String(32), default="TCP")
    failed_attempts = Column(Integer, default=0)
    attack_indicators = Column(JSON, default=list)
    features = Column(JSON, default=dict)
    metadata_payload = Column(JSON, default=dict)
    privacy_metadata = Column(JSON, default=dict)
    is_test = Column(Boolean, default=False, index=True)
    processing_status = Column(String(32), default="PROCESSED")
    ingested_at = Column(DateTime, default=utcnow)
    processing_latency_ms = Column(Float, default=0.0)

    detections = relationship("Detection", back_populates="event", cascade="all, delete-orphan")
    privacy_events = relationship("PrivacyEvent", back_populates="event", cascade="all, delete-orphan")
    risk_assessment = relationship("RiskAssessment", back_populates="event", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_events_org_time", "organization_id", "timestamp"),
        Index("idx_events_client_time", "client_id", "timestamp"),
        Index("idx_events_type_time", "event_type", "timestamp"),
    )

# Alias ProtectedEvent to SecurityEvent for domain alignment
ProtectedEvent = SecurityEvent

class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    detection_id = Column(String(64), unique=True, index=True, nullable=True)
    organization_id = Column(String(64), index=True, nullable=False, default="org_enterprise_a")
    event_id = Column(String(64), ForeignKey("events.event_id"), index=True, nullable=False)
    prediction = Column(String(32), index=True, nullable=False) # BENIGN, SUSPICIOUS, MALICIOUS
    attack_type = Column(String(64), index=True, nullable=False) # Brute Force, DDoS, Port Scan, Botnet, BENIGN
    confidence = Column(Float, nullable=False)
    severity = Column(String(32), index=True, nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    model_version = Column(String(64), default="global-v1")
    processing_latency_ms = Column(Float, default=0.0)
    rule_matches = Column(JSON, default=list)
    created_at = Column(DateTime, default=utcnow, index=True)

    event = relationship("SecurityEvent", back_populates="detections")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, index=True, nullable=False)
    organization_id = Column(String(64), index=True, nullable=False, default="org_enterprise_a")
    detection_id = Column(String(64), nullable=True, index=True)
    event_id = Column(String(64), index=True, nullable=False)
    timestamp = Column(DateTime, default=utcnow, index=True, nullable=False)
    client_id = Column(String(64), index=True, nullable=True)
    agent_id = Column(String(64), index=True, nullable=True)
    attack_type = Column(String(64), index=True, nullable=False)
    severity = Column(String(32), index=True, nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, nullable=False)
    risk_score = Column(Float, nullable=False)
    explanation = Column(Text, nullable=True)
    model_version = Column(String(64), default="global-v1")
    status = Column(String(32), default="NEW", index=True) # NEW, ACKNOWLEDGED, RESOLVED
    acknowledged_by = Column(String(64), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(64), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    is_test = Column(Boolean, default=False, index=True)

class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), ForeignKey("events.event_id"), index=True, nullable=False)
    organization_id = Column(String(64), index=True, nullable=False, default="org_enterprise_a")
    risk_score = Column(Float, nullable=False)
    severity = Column(String(32), index=True, nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    risk_factors = Column(JSON, default=list)
    explanation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)

    event = relationship("SecurityEvent", back_populates="risk_assessment")

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), unique=True, index=True, nullable=False)
    organization_id = Column(String(64), index=True, nullable=False, default="org_enterprise_a")
    title = Column(String(255), nullable=False)
    severity = Column(String(32), index=True, nullable=False)
    status = Column(String(32), default="OPEN", index=True) # OPEN, INVESTIGATING, CONTAINED, RESOLVED
    created_at = Column(DateTime, default=utcnow, index=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    related_alerts = Column(JSON, default=list)
    related_events = Column(JSON, default=list)
    summary = Column(Text, nullable=True)

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(255), unique=True, index=True, nullable=False)
    threat_category = Column(String(64), nullable=False)
    source = Column(String(64), default="INTERNAL")
    confidence = Column(Float, default=0.8)
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)

class TrainingRound(Base):
    __tablename__ = "training_rounds"

    id = Column(Integer, primary_key=True, index=True)
    round_num = Column(Integer, unique=True, index=True, nullable=False)
    clients_selected = Column(Integer, default=0)
    clients_completed = Column(Integer, default=0)
    local_loss = Column(Float, nullable=True)
    global_loss = Column(Float, nullable=True)
    accuracy = Column(Float, nullable=False)
    precision = Column(Float, nullable=False)
    recall = Column(Float, nullable=False)
    f1 = Column(Float, nullable=False)
    training_time = Column(Float, default=0.0) # seconds
    model_version = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=utcnow)

class ModelVersion(Base):
    __tablename__ = "model_versions"

    id = Column(Integer, primary_key=True, index=True)
    model_id = Column(String(64), unique=True, index=True, nullable=False)
    version = Column(String(64), unique=True, index=True, nullable=False)
    dataset = Column(String(128), default="CIC-IDS-Benchmark")
    features = Column(JSON, default=list)
    metrics = Column(JSON, default=dict)
    status = Column(String(32), default="ACTIVE") # ACTIVE, ARCHIVED
    created_at = Column(DateTime, default=utcnow)

class ClientModelUpdate(Base):
    __tablename__ = "client_model_updates"

    id = Column(Integer, primary_key=True, index=True)
    round_num = Column(Integer, index=True, nullable=False)
    client_id = Column(String(64), index=True, nullable=False)
    update_hash = Column(String(128), nullable=False)
    sample_count = Column(Integer, nullable=False)
    local_loss = Column(Float, default=0.0)
    local_accuracy = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=utcnow)

class PrivacyEvent(Base):
    __tablename__ = "privacy_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), ForeignKey("events.event_id"), index=True, nullable=False)
    detected_category = Column(String(64), nullable=True, index=True)
    action = Column(String(32), index=True, nullable=False) # REDACTED, PSEUDONYMIZED
    policy = Column(String(64), default="DEFAULT_MINIMIZATION")
    pseudonym_token = Column(String(64), nullable=True)
    fields_transformed = Column(JSON, default=list)
    technique = Column(String(64), default="HMAC-SHA256")
    timestamp = Column(DateTime, default=utcnow, index=True)

    event = relationship("SecurityEvent", back_populates="privacy_events")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True, nullable=False)
    organization_id = Column(String(64), index=True, nullable=False, default="org_enterprise_a")
    actor = Column(String(64), index=True, nullable=False)
    action = Column(String(64), index=True, nullable=False) # LOGIN, EVENT_RECEIVED, DETECTION_CREATED, POLICY_UPDATED, etc.
    resource = Column(String(64), nullable=False)
    resource_id = Column(String(64), nullable=True)
    result = Column(String(32), default="SUCCESS")
    metadata_payload = Column(JSON, default=dict)

class SystemMetric(Base):
    __tablename__ = "system_metrics"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True, nullable=False)
    cpu_percent = Column(Float, default=0.0)
    memory_percent = Column(Float, default=0.0)
    events_per_sec = Column(Float, default=0.0)
    avg_latency_ms = Column(Float, default=0.0)
    active_clients = Column(Integer, default=0)
    websocket_connections = Column(Integer, default=0)
