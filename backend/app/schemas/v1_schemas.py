"""
Pydantic v2 Schemas for Versioned API v1
Includes strict boundary validation to reject raw PII fields.
"""

from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Dict, Any, Optional
from datetime import datetime

FORBIDDEN_RAW_KEYS = {
    "username", "user", "email", "source_ip", "ip_address",
    "exact_location", "location", "raw_device_id", "password", "secret", "api_key"
}

class ProtectedEventIngest(BaseModel):
    model_config = ConfigDict(extra="forbid") # Rejects any unexpected or undeclared fields!

    event_id: str = Field(..., description="Unique idempotency event identifier")
    organization_id: str = Field(default="org_enterprise_a", description="Originating organization ID")
    agent_id: Optional[str] = Field(default="agent-dmz-01", description="Local edge agent identifier")
    timestamp: str = Field(..., description="ISO 8601 event timestamp")
    event_type: str = Field(..., description="Classification type of the security event")
    telemetry_source: str = Field(default="TEST", description="Telemetry origin: REAL, TEST, or DEMO")
    source: Optional[str] = Field(default=None, description="Pseudonymized actor/device token, e.g. DEV-8A12")
    device_id: Optional[str] = Field(default=None, description="Pseudonymized device token, e.g. DEV-8A12")
    destination: Optional[str] = Field(default=None, description="Target host or subnet identifier")
    destination_port: Optional[int] = Field(default=None, ge=1, le=65535, description="Target network port")
    protocol: Optional[str] = Field(default="TCP", description="Network protocol")
    failed_attempts: Optional[int] = Field(default=0, ge=0, description="Count of authentication failures")
    attack_indicators: Optional[List[str]] = Field(default_factory=list, description="Extracted threat indicators")
    duration_seconds: Optional[Any] = Field(default=None, description="Session duration tier")
    bytes_transferred: Optional[Any] = Field(default=None, description="Aggregated bandwidth tier")
    privacy_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Metadata on applied minimization")
    features: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Pre-computed numeric flow features")
    is_test: Optional[bool] = Field(default=False, description="Explicit test flag")

    # Part 30 - Protected IP and Geolocation Representations
    location_zone: Optional[str] = Field(default=None, description="Coarsened regional zone identifier (e.g. AP_REGION_01)")
    latitude_encrypted: Optional[str] = Field(default=None, description="AES-256-GCM encrypted latitude")
    longitude_encrypted: Optional[str] = Field(default=None, description="AES-256-GCM encrypted longitude")
    source_ip_encrypted: Optional[str] = Field(default=None, description="AES-256-GCM encrypted source IP")
    sensitive_location: Optional[str] = Field(default=None, description="Protected sensitive location representation")
    sensitive_location_encrypted: Optional[str] = Field(default=None, description="AES-256-GCM encrypted sensitive location")

    @field_validator("source", "device_id", mode="before")
    @classmethod
    def assert_not_raw_pii(cls, v: Optional[str]) -> Optional[str]:
        if v and isinstance(v, str):
            # Check for exact IPv4 raw format
            import re
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", v.strip()):
                raise ValueError(f"Second Safety Boundary Rejection: Raw IP address '{v}' is prohibited from entering Central Server!")
            if "@" in v and not v.startswith("USER-"):
                raise ValueError(f"Second Safety Boundary Rejection: Raw email address '{v}' is prohibited from entering Central Server!")
        return v

    @field_validator("latitude_encrypted", "longitude_encrypted", "source_ip_encrypted", mode="before")
    @classmethod
    def assert_valid_encryption_format(cls, v: Optional[str]) -> Optional[str]:
        if v and isinstance(v, str):
            if not v.startswith("enc:aes256gcm:v1:"):
                raise ValueError(f"Second Safety Boundary Rejection: Field must be AES-256-GCM encrypted format (enc:aes256gcm:v1:...)!")
        return v


class OrganizationCreate(BaseModel):
    org_id: str = Field(..., min_length=3, max_length=64)
    name: str = Field(..., min_length=2, max_length=128)
    contact_email: Optional[str] = None

class OrganizationResponse(BaseModel):
    id: int
    org_id: str
    name: str
    status: str
    contact_email: Optional[str]
    created_at: datetime
    active_agents: int = 0
    total_events: int = 0
    total_detections: int = 0

class AgentRegisterRequest(BaseModel):
    agent_id: str = Field(..., min_length=3, max_length=64)
    organization_id: str = Field(..., min_length=3, max_length=64)
    name: str = Field(..., min_length=2, max_length=128)
    version: str = Field(default="1.0.0")

class AgentRegisterResponse(BaseModel):
    agent_id: str
    organization_id: str
    name: str
    status: str
    api_key: str
    created_at: datetime

class PrivacyPolicyUpdateRequest(BaseModel):
    action: str = Field(..., description="ALLOW, REMOVE, MASK, PSEUDONYMIZE, AGGREGATE")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    is_active: Optional[bool] = True

class PrivacyPolicyResponse(BaseModel):
    policy_id: str
    organization_id: str
    field_name: str
    action: str
    parameters: Dict[str, Any]
    is_active: bool
    version: str

class DetectionResponse(BaseModel):
    detection_id: Optional[str]
    event_id: str
    organization_id: str
    prediction: str
    attack_type: str
    confidence: float
    severity: str
    model_version: str
    rule_matches: List[Any]
    processing_latency_ms: float
    created_at: datetime

class AlertResponse(BaseModel):
    alert_id: str
    organization_id: str
    event_id: str
    attack_type: str
    severity: str
    confidence: float
    risk_score: float
    explanation: Optional[str]
    status: str
    acknowledged_by: Optional[str]
    acknowledged_at: Optional[datetime]
    resolved_by: Optional[str]
    resolved_at: Optional[datetime]
    timestamp: datetime
    is_test: bool

class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    organization_id: str
    actor: str
    action: str
    resource: str
    resource_id: Optional[str]
    result: str
    metadata_payload: Dict[str, Any]

class SystemHealthResponse(BaseModel):
    status: str
    timestamp: datetime
    api: Dict[str, Any]
    database: Dict[str, Any]
    websocket: Dict[str, Any]
    agents: Dict[str, Any]
    ml_model: Dict[str, Any]
    queue: Dict[str, Any]
