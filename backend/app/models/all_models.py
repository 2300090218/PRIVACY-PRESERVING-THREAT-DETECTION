"""
SQLAlchemy Models for Privacy-Preserving Threat Detection Platform
Includes full relational schema for telemetry, detections, alerts, incidents,
federated rounds, models, clients, privacy events, audit logs, and metrics.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from backend.app.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(32), default="VIEWER", nullable=False) # ADMIN, SECURITY_ANALYST, CLIENT, VIEWER
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

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

class SecurityEvent(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=utcnow, index=True, nullable=False)
    client_id = Column(String(64), index=True, nullable=False)
    event_type = Column(String(64), index=True, nullable=False) # e.g., network_flow, auth_attempt
    source = Column(String(128), nullable=False)
    destination = Column(String(128), nullable=False)
    protocol = Column(String(32), default="TCP")
    features = Column(JSON, default=dict)
    metadata_payload = Column(JSON, default=dict)
    is_test = Column(Boolean, default=False, index=True)
    processing_status = Column(String(32), default="PROCESSED")
    ingested_at = Column(DateTime, default=utcnow)
    processing_latency_ms = Column(Float, default=0.0)

    detections = relationship("Detection", back_populates="event", cascade="all, delete-orphan")
    privacy_events = relationship("PrivacyEvent", back_populates="event", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_events_client_time", "client_id", "timestamp"),
        Index("idx_events_type_time", "event_type", "timestamp"),
    )

class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
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
    detection_id = Column(String(64), nullable=True, index=True)
    event_id = Column(String(64), index=True, nullable=False)
    timestamp = Column(DateTime, default=utcnow, index=True, nullable=False)
    client_id = Column(String(64), index=True, nullable=False)
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

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), unique=True, index=True, nullable=False)
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
    actor = Column(String(64), index=True, nullable=False)
    action = Column(String(64), index=True, nullable=False) # LOGIN, EVENT_RECEIVED, DETECTION_CREATED, etc.
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
