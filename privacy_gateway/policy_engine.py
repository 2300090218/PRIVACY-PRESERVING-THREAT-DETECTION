"""
Privacy Policy Engine
Defines configurable field-level policies: ALLOW, REMOVE, MASK, PSEUDONYMIZE, AGGREGATE.
"""

from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    REMOVE = "REMOVE"
    MASK = "MASK"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    AGGREGATE = "AGGREGATE"
    ENCRYPT = "ENCRYPT"
    COARSEN = "COARSEN"

class FieldPolicy(BaseModel):
    field_name: str
    action: PolicyAction = PolicyAction.REMOVE
    parameters: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = None

class PrivacyPolicyConfig(BaseModel):
    organization_id: str = "org_default"
    name: str = "Default Data Minimization Policy"
    version: str = "1.0.0"
    default_action: PolicyAction = PolicyAction.REMOVE
    field_policies: Dict[str, FieldPolicy] = Field(default_factory=dict)

    def get_action(self, field_name: str) -> PolicyAction:
        policy = self.field_policies.get(field_name.lower())
        if policy:
            return policy.action
        return self.default_action

    def get_policy(self, field_name: str) -> Optional[FieldPolicy]:
        return self.field_policies.get(field_name.lower())

    def set_policy(self, field_name: str, action: PolicyAction, parameters: Optional[Dict[str, Any]] = None, description: Optional[str] = None):
        self.field_policies[field_name.lower()] = FieldPolicy(
            field_name=field_name.lower(),
            action=action,
            parameters=parameters or {},
            description=description
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "organization_id": self.organization_id,
            "name": self.name,
            "version": self.version,
            "default_action": self.default_action.value,
            "field_policies": {k: v.model_dump() for k, v in self.field_policies.items()}
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PrivacyPolicyConfig":
        field_policies = {}
        for k, v in data.get("field_policies", {}).items():
            if isinstance(v, dict):
                field_policies[k] = FieldPolicy(**v)
            elif isinstance(v, FieldPolicy):
                field_policies[k] = v
        return cls(
            organization_id=data.get("organization_id", "org_default"),
            name=data.get("name", "Custom Policy"),
            version=data.get("version", "1.0.0"),
            default_action=PolicyAction(data.get("default_action", "REMOVE")),
            field_policies=field_policies
        )

def create_default_policy_config(organization_id: str = "org_enterprise_a") -> PrivacyPolicyConfig:
    config = PrivacyPolicyConfig(
        organization_id=organization_id,
        name="Enterprise Boundary Privacy Baseline",
        version="1.0.0",
        default_action=PolicyAction.REMOVE,
    )
    
    # 1. Strictly Prohibited Raw Identifiers & Plaintext Secrets
    config.set_policy("username", PolicyAction.REMOVE, description="Prohibit individual user names from leaving boundary")
    config.set_policy("user", PolicyAction.REMOVE, description="Prohibit user identity")
    config.set_policy("email", PolicyAction.REMOVE, description="Prohibit email addresses")
    config.set_policy("password", PolicyAction.REMOVE, description="Prohibit cleartext or hashed passwords")
    config.set_policy("secret", PolicyAction.REMOVE, description="Prohibit application secrets")
    config.set_policy("api_key", PolicyAction.REMOVE, description="Prohibit API keys and tokens")
    config.set_policy("destination_ip", PolicyAction.REMOVE, description="Prohibit destination IP addresses")
    config.set_policy("client_ip", PolicyAction.REMOVE, description="Prohibit client IP addresses")
    config.set_policy("hostname", PolicyAction.REMOVE, description="Prohibit workstation and server hostnames")
    config.set_policy("mac_address", PolicyAction.REMOVE, description="Prohibit hardware MAC addresses")
    config.set_policy("user_id", PolicyAction.REMOVE, description="Prohibit direct user identifier strings")
    config.set_policy("jwt", PolicyAction.REMOVE, description="Prohibit JWT tokens")
    config.set_policy("authorization", PolicyAction.REMOVE, description="Prohibit authorization headers")
    config.set_policy("raw_log", PolicyAction.REMOVE, description="Prohibit raw log strings")
    config.set_policy("raw_logs", PolicyAction.REMOVE, description="Prohibit raw log lists")
    config.set_policy("raw_network_logs", PolicyAction.REMOVE, description="Prohibit complete raw unminimized network dump")

    # 2. Field-Level IP & Geolocation Protection (Part 30 Standards)
    # Default IP Policy: Keyed HMAC-SHA-256 deterministic pseudonymization for correlation
    config.set_policy("source_ip", PolicyAction.PSEUDONYMIZE, {"algorithm": "HMAC-SHA-256", "format": "hmac-sha256:v1"}, description="HMAC-SHA-256 keyed pseudonymization for source IP")
    config.set_policy("ip_address", PolicyAction.PSEUDONYMIZE, {"algorithm": "HMAC-SHA-256", "format": "hmac-sha256:v1"}, description="HMAC-SHA-256 keyed pseudonymization for IP address")

    # Default GPS Geolocation Policy: Coarsening / generalization to regional zone
    config.set_policy("latitude", PolicyAction.COARSEN, {"target_field": "location_zone"}, description="Coarsen precise latitude to regional zone")
    config.set_policy("longitude", PolicyAction.COARSEN, {"target_field": "location_zone"}, description="Coarsen precise longitude to regional zone")
    config.set_policy("exact_location", PolicyAction.REMOVE, description="Prohibit exact physical office/branch geo-location")
    config.set_policy("location", PolicyAction.REMOVE, description="Prohibit physical locations")
    
    # Sensitive location requiring authorized recovery: AES-256-GCM encryption
    config.set_policy("sensitive_location", PolicyAction.ENCRYPT, {"algorithm": "AES-256-GCM", "key_id": "privacy-key-v1"}, description="AES-256-GCM authenticated encryption for sensitive location")

    # 3. Pseudonymized Identifiers
    config.set_policy("device_id", PolicyAction.PSEUDONYMIZE, {"prefix": "DEV", "salt_override": None}, description="Pseudonymize device IDs using salted HMAC-SHA256")
    config.set_policy("host_id", PolicyAction.PSEUDONYMIZE, {"prefix": "HOST"}, description="Pseudonymize local workstation host IDs")

    # 4. Masked Attributes
    config.set_policy("destination_subnet", PolicyAction.MASK, {"mask_char": "*", "keep_prefix_octets": 2}, description="Mask destination subnets")

    # 5. Aggregated Metrics
    config.set_policy("bytes_transferred", PolicyAction.AGGREGATE, {"buckets": [1000, 10000, 100000, 1000000]}, description="Bucketize raw byte volume into bandwidth tiers")
    config.set_policy("duration_seconds", PolicyAction.AGGREGATE, {"buckets": [1, 5, 30, 120, 600]}, description="Bucketize session duration")

    # 6. Allowlisted Non-Sensitive Threat Indicators & Protected Representations
    config.set_policy("event_id", PolicyAction.ALLOW, description="Allow idempotency event identifier")
    config.set_policy("event_type", PolicyAction.ALLOW, description="Allow threat event classification name")
    config.set_policy("timestamp", PolicyAction.ALLOW, description="Allow event timestamp")
    config.set_policy("organization_id", PolicyAction.ALLOW, description="Allow originating organization identifier")
    config.set_policy("agent_id", PolicyAction.ALLOW, description="Allow local agent identifier")
    config.set_policy("failed_attempts", PolicyAction.ALLOW, description="Allow count of failed login attempts")
    config.set_policy("attack_indicators", PolicyAction.ALLOW, description="Allow structured attack indicator tags")
    config.set_policy("protocol", PolicyAction.ALLOW, description="Allow network protocol (e.g. TCP, UDP)")
    config.set_policy("destination_port", PolicyAction.ALLOW, description="Allow targeted service port number")
    config.set_policy("telemetry_source", PolicyAction.ALLOW, description="Allow telemetry classification (REAL, TEST, DEMO)")
    config.set_policy("is_test", PolicyAction.ALLOW, description="Allow test mode flag")
    config.set_policy("location_zone", PolicyAction.ALLOW, description="Allow coarsened regional zone identifier (e.g. AP_REGION_01)")
    config.set_policy("latitude_encrypted", PolicyAction.ALLOW, description="Allow AES-256-GCM encrypted latitude")
    config.set_policy("longitude_encrypted", PolicyAction.ALLOW, description="Allow AES-256-GCM encrypted longitude")

    return config

default_policy_config = create_default_policy_config()
