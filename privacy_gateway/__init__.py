"""
Privacy Gateway Module
Provides data minimization, privacy policy enforcement, salted HMAC pseudonymization,
threat inspection, telemetry optimization, and strict privacy leakage prevention for local organization telemetry.
"""

from privacy_gateway.policy_engine import (
    PolicyAction,
    FieldPolicy,
    PrivacyPolicyConfig,
    default_policy_config,
    create_default_policy_config,
)
from privacy_gateway.encryption import (
    encrypt_aes_256_gcm,
    decrypt_aes_256_gcm,
    pseudonymize_hmac_sha256,
    coarsen_geolocation,
    is_valid_aes_256_gcm_token,
    is_valid_hmac_sha256_token,
    KeyManager,
    default_key_manager,
)
from privacy_gateway.leakage_prevention import (
    validate_protected_payload,
    validate_presend_security,
    evaluate_safety_decision,
    SafetyVerdict,
    FORBIDDEN_RAW_FIELDS,
)
from privacy_gateway.threat_inspector import (
    EdgeThreatInspector,
    ThreatInspectionResult,
    ThreatInspectionStatus,
)
from privacy_gateway.optimizer import (
    TelemetryOptimizer,
    OptimizationResult,
)
from privacy_gateway.metrics import privacy_metrics
from privacy_gateway.gateway import (
    PrivacyGateway,
    PrivacyViolationError,
    PreSendPipeline,
    PreSendResult,
)

__all__ = [
    "PolicyAction",
    "FieldPolicy",
    "PrivacyPolicyConfig",
    "default_policy_config",
    "create_default_policy_config",
    "encrypt_aes_256_gcm",
    "decrypt_aes_256_gcm",
    "pseudonymize_hmac_sha256",
    "coarsen_geolocation",
    "is_valid_aes_256_gcm_token",
    "is_valid_hmac_sha256_token",
    "KeyManager",
    "default_key_manager",
    "validate_protected_payload",
    "validate_presend_security",
    "evaluate_safety_decision",
    "SafetyVerdict",
    "FORBIDDEN_RAW_FIELDS",
    "EdgeThreatInspector",
    "ThreatInspectionResult",
    "ThreatInspectionStatus",
    "TelemetryOptimizer",
    "OptimizationResult",
    "privacy_metrics",
    "PrivacyGateway",
    "PrivacyViolationError",
    "PreSendPipeline",
    "PreSendResult",
]

