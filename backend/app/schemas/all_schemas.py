"""
Pydantic Schemas for Request Validation and Response Serialization
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr, ConfigDict

# Auth Schemas
class LoginRequest(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: str

class VerifyOtpRequest(BaseModel):
    session_nonce: Optional[str] = None
    email: Optional[str] = None
    code: Optional[str] = None
    otp: Optional[str] = None

class VerifySignupRequest(BaseModel):
    email: Optional[str] = None
    session_nonce: Optional[str] = None
    code: Optional[str] = None
    otp: Optional[str] = None

class ResendOtpRequest(BaseModel):
    session_nonce: str

class ForgotPasswordRequest(BaseModel):
    email: str

class RegisterRequest(BaseModel):
    email: str
    password: str
    username: Optional[str] = None
    display_name: Optional[str] = None
    role: Optional[str] = "ANALYST"
    organization_id: Optional[str] = "org_enterprise_a"

class ResetPasswordRequest(BaseModel):
    token: Optional[str] = None
    otp: Optional[str] = None
    code: Optional[str] = None
    new_password: str

class LoginResponse(BaseModel):
    status: str
    two_factor_required: bool = False
    session_nonce: Optional[str] = None
    email_masked: Optional[str] = None
    expires_in_seconds: Optional[int] = None
    access_token: Optional[str] = None
    token_type: Optional[str] = "bearer"
    role: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    display_name: Optional[str] = None
    organization_id: Optional[str] = None
    message: Optional[str] = None
    email_verified: Optional[bool] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str
    organization_id: Optional[str] = "org_enterprise_a"

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    display_name: Optional[str] = None
    role: str
    organization_id: Optional[str] = None
    is_active: bool
    email_verified: bool = True
    two_factor_enabled: bool = True
    created_at: datetime
    last_login_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

# Client Schemas
class ClientRegisterRequest(BaseModel):
    client_id: str
    name: str
    ip_address: Optional[str] = None
    model_version: Optional[str] = "global-v1"

class ClientHeartbeatRequest(BaseModel):
    status: str = "ONLINE"
    training_status: Optional[str] = "IDLE"
    local_metrics: Optional[Dict[str, Any]] = None

class ClientResponse(BaseModel):
    client_id: str
    name: str
    status: str
    last_seen: datetime
    model_version: str
    training_status: str
    local_metrics: Dict[str, Any]
    ip_address: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Telemetry & Event Ingestion Schemas
class EventIngestRequest(BaseModel):
    event_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    client_id: str
    event_type: str = "network_flow"
    source: Optional[str] = None
    destination: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    packet_count: Optional[int] = None
    byte_count: Optional[int] = None
    flow_duration: Optional[float] = None
    request_rate: Optional[float] = None
    failed_login_count: Optional[int] = None
    asset_criticality: Optional[str] = None
    features: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_test: bool = False

    def model_post_init(self, __context: Any) -> None:
        if not self.source:
            self.source = self.source_ip or "0.0.0.0"
        if not self.destination:
            self.destination = self.destination_ip or "0.0.0.0"
        if self.source_port is not None and "src_port" not in self.features:
            self.features["src_port"] = self.source_port
        if self.destination_port is not None:
            if "dest_port" not in self.features:
                self.features["dest_port"] = self.destination_port
            if "dest_port" not in self.metadata:
                self.metadata["dest_port"] = self.destination_port
        if self.flow_duration is not None and "flow_duration" not in self.features:
            self.features["flow_duration"] = self.flow_duration
        if self.packet_count is not None and "total_fwd_packets" not in self.features:
            self.features["total_fwd_packets"] = self.packet_count
        if self.byte_count is not None and "total_fwd_bytes" not in self.features:
            self.features["total_fwd_bytes"] = self.byte_count
        if self.request_rate is not None and "flow_packets_per_sec" not in self.features:
            self.features["flow_packets_per_sec"] = self.request_rate
        if self.failed_login_count is not None and "failed_login_count" not in self.metadata:
            self.metadata["failed_login_count"] = self.failed_login_count
        if self.asset_criticality is not None and "asset_type" not in self.metadata:
            self.metadata["asset_type"] = self.asset_criticality

class EventResponse(BaseModel):
    event_id: str
    timestamp: datetime
    client_id: str
    event_type: str
    source: str
    destination: str
    protocol: str
    features: Dict[str, Any]
    metadata_payload: Dict[str, Any]
    is_test: bool
    processing_status: str
    processing_latency_ms: float

    model_config = ConfigDict(from_attributes=True)

# Detection Schemas
class DetectionResponse(BaseModel):
    id: int
    event_id: str
    prediction: str
    attack_type: str
    confidence: float
    severity: str
    model_version: str
    processing_latency_ms: float
    rule_matches: List[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Alert Schemas
class AlertResponse(BaseModel):
    alert_id: str
    detection_id: Optional[str] = None
    event_id: str
    timestamp: datetime
    client_id: str
    attack_type: str
    severity: str
    confidence: float
    risk_score: float
    explanation: Optional[str] = None
    model_version: str
    status: str
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    is_test: bool

    model_config = ConfigDict(from_attributes=True)

# Incident Schemas
class IncidentCreateRequest(BaseModel):
    title: str
    severity: str
    related_alerts: List[str] = Field(default_factory=list)
    related_events: List[str] = Field(default_factory=list)
    summary: Optional[str] = None

class IncidentUpdateRequest(BaseModel):
    status: Optional[str] = None # OPEN, INVESTIGATING, CONTAINED, RESOLVED
    severity: Optional[str] = None
    summary: Optional[str] = None

class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str
    created_at: datetime
    updated_at: datetime
    related_alerts: List[str]
    related_events: List[str]
    summary: Optional[str]

    model_config = ConfigDict(from_attributes=True)

# Privacy Schemas
class PrivacyStatusResponse(BaseModel):
    status: str = "ACTIVE"
    raw_training_data_shared: str = "NO (Client Local Only)"
    data_minimization: str = "ACTIVE"
    pii_detection: str = "ACTIVE"
    pseudonymization: str = "ACTIVE"
    audit_logging: str = "ACTIVE"
    total_privacy_transformations: int
    redacted_fields_count: int
    pseudonymized_fields_count: int
    active_policy: Dict[str, str]

class PrivacyEventResponse(BaseModel):
    id: int
    event_id: str
    action: str
    fields_transformed: List[str]
    technique: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)

# Federated Learning Schemas
class FederatedStartRequest(BaseModel):
    rounds: int = 1
    min_clients: int = 3
    local_epochs: int = 1

class FederatedRoundResponse(BaseModel):
    round_num: int
    clients_selected: int
    clients_completed: int
    local_loss: Optional[float]
    global_loss: Optional[float]
    accuracy: float
    precision: float
    recall: float
    f1: float
    training_time: float
    model_version: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class FederatedStatusResponse(BaseModel):
    status: str # ACTIVE, IDLE, TRAINING, ERROR
    current_round: int
    max_rounds: int
    active_clients: int
    global_model_version: str
    latest_metrics: Dict[str, Any]
    last_aggregation: Optional[datetime]
    differential_privacy: Optional[Dict[str, Any]] = None
    historical_rounds: Optional[List[Dict[str, Any]]] = None

# Model Schemas
class ModelVersionResponse(BaseModel):
    model_id: str
    version: str
    dataset: str
    features: List[str]
    metrics: Dict[str, Any]
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Audit Schemas
class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    actor: str
    action: str
    resource: str
    resource_id: Optional[str]
    result: str
    metadata_payload: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)

# Health Schemas
class HealthCheckResponse(BaseModel):
    api: str = "ACTIVE"
    database: str = "ACTIVE"
    ml_model: str = "ACTIVE"
    websocket: str = "ACTIVE"
    federated_learning: str = "ACTIVE"
    overall_status: str = "ACTIVE"
    details: Dict[str, Any]
