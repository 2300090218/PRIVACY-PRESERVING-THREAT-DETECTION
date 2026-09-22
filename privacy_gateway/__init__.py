"""
Privacy Gateway Module
Provides data minimization, privacy policy enforcement, salted HMAC pseudonymization,
and strict privacy leakage prevention for local organization telemetry before transmission.
"""

from privacy_gateway.policy_engine import PolicyAction, FieldPolicy, PrivacyPolicyConfig, default_policy_config
from privacy_gateway.leakage_prevention import validate_protected_payload, FORBIDDEN_RAW_FIELDS
from privacy_gateway.metrics import privacy_metrics
from privacy_gateway.gateway import PrivacyGateway

__all__ = [
    "PolicyAction",
    "FieldPolicy",
    "PrivacyPolicyConfig",
    "default_policy_config",
    "validate_protected_payload",
    "FORBIDDEN_RAW_FIELDS",
    "privacy_metrics",
    "PrivacyGateway",
]
