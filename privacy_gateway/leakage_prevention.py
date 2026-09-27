"""
Privacy Leakage Prevention & Safety Decision Engine
Defines strict boundary validation checks to ensure prohibited raw fields and sensitive PII
can NEVER pass from the local organization to the central server.
Implements Tri-State Safety Classification: SAFE, NEEDS_OPTIMIZATION, BLOCKED.
"""

import re
import json
from enum import Enum
from typing import Dict, Any, List, Tuple

class SafetyVerdict(str, Enum):
    SAFE = "SAFE"
    NEEDS_OPTIMIZATION = "NEEDS_OPTIMIZATION"
    BLOCKED = "BLOCKED"

FORBIDDEN_RAW_FIELDS = {
    "username",
    "user",
    "user_id",
    "email",
    "source_ip",
    "destination_ip",
    "client_ip",
    "ip_address",
    "hostname",
    "mac_address",
    "latitude",
    "longitude",
    "exact_location",
    "location",
    "raw_device_id",
    "password",
    "passwd",
    "secret",
    "api_key",
    "token",
    "access_token",
    "jwt",
    "private_key",
    "ssn",
    "credit_card",
    "raw_log",
    "raw_logs",
    "raw_network_logs"
}

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
IPV4_RAW_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
AWS_KEY_REGEX = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
JWT_REGEX = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
BEARER_TOKEN_REGEX = re.compile(r"\bBearer\s+[a-zA-Z0-9_\-\.]{20,}\b", re.IGNORECASE)
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")
PASSWORD_INLINE_REGEX = re.compile(r"(?:password|passwd|secret)\s*[:=]\s*['\"]?([^\s'\";,}]+)", re.IGNORECASE)

MAX_ALLOWED_PAYLOAD_SIZE = 65536

def validate_protected_payload(payload: Dict[str, Any], check_nested: bool = True) -> Tuple[bool, List[str]]:
    """
    Evaluates a candidate transmission payload against strict privacy and security boundaries.
    Returns (True, []) if the payload is safe, or (False, [violation_reasons]) if violations exist.
    """
    if not isinstance(payload, dict):
        return (False, ["Payload must be a dictionary object."])

    violations: List[str] = []

    # 1. Payload Size Check
    try:
        serialized = json.dumps(payload)
        if len(serialized.encode("utf-8")) > MAX_ALLOWED_PAYLOAD_SIZE:
            violations.append(f"Payload size ({len(serialized.encode('utf-8'))} bytes) exceeds {MAX_ALLOWED_PAYLOAD_SIZE} bytes.")
    except Exception as ex:
        violations.append(f"Payload serialization failed: {str(ex)}")

    # 2. Inspect Top-Level Keys
    for key, val in payload.items():
        key_lower = key.lower()
        if key_lower in FORBIDDEN_RAW_FIELDS:
            violations.append(f"Forbidden raw field '{key}' detected in payload root.")

        # Inspect nested dictionary structures (e.g. metadata, indicators, features)
        if check_nested and isinstance(val, dict):
            for sub_key in val.keys():
                if sub_key.lower() in FORBIDDEN_RAW_FIELDS:
                    violations.append(f"Forbidden raw field '{sub_key}' detected inside nested object '{key}'.")

    # 3. Inspect String Values for PII, Raw Credentials, Tokens, Keys
    def _inspect_values(data: Any, path: str = ""):
        if isinstance(data, str):
            # Leaked unmasked email
            if EMAIL_REGEX.search(data) and "@" in data and not data.startswith("USER-"):
                violations.append(f"Unpseudonymized email pattern found at path '{path}'.")

            # Leaked AWS/Cloud secret key
            if AWS_KEY_REGEX.search(data):
                violations.append(f"Raw AWS credential pattern found at path '{path}'.")

            # Leaked JWT Token
            if JWT_REGEX.search(data):
                violations.append(f"Raw JWT token pattern found at path '{path}'.")

            # Leaked Bearer authorization token
            if BEARER_TOKEN_REGEX.search(data):
                violations.append(f"Raw authorization bearer token found at path '{path}'.")

            # Leaked Private Key
            if PRIVATE_KEY_REGEX.search(data):
                violations.append(f"Raw cryptographic private key found at path '{path}'.")

            # Leaked inline cleartext password
            pwd_match = PASSWORD_INLINE_REGEX.search(data)
            if pwd_match:
                pwd_val = pwd_match.group(1)
                if not pwd_val.startswith("[REDACTED"):
                    violations.append(f"Inline password assignment detected at path '{path}'.")

            # Check if an exact raw IPv4 address appears in a disallowed or identity field
            if path.endswith(("source", "source_ip", "destination_ip", "client_ip", "username", "location", "device_id", "actor")):
                if IPV4_RAW_REGEX.match(data.strip()):
                    violations.append(f"Exact raw IP address detected at prohibited path '{path}'.")

        elif isinstance(data, dict):
            for k, v in data.items():
                _inspect_values(v, f"{path}.{k}" if path else k)
        elif isinstance(data, (list, tuple)):
            for idx, item in enumerate(data):
                _inspect_values(item, f"{path}[{idx}]")

    _inspect_values(payload)

    # 4. Mandatory Identification & Intelligence Attributes Check
    if not payload.get("event_id"):
        violations.append("Missing mandatory 'event_id' attribute.")
    if not payload.get("timestamp"):
        violations.append("Missing mandatory 'timestamp' attribute.")

    return (len(violations) == 0, violations)

def evaluate_safety_decision(payload: Dict[str, Any]) -> Tuple[SafetyVerdict, List[str], Dict[str, Any]]:
    """
    Tri-State Evaluation:
    - BLOCKED: Payload contains unmitigated credentials, forbidden raw fields, or invalid structure.
    - NEEDS_OPTIMIZATION: Payload is safe from hard leakage, but contains redundant, unaggregated,
      or unminimized fields that should be optimized before dispatch.
    - SAFE: Payload complies with all privacy rules, minimization standards, and schema integrity.
    """
    is_safe, violations = validate_protected_payload(payload)
    if not is_safe:
        return (SafetyVerdict.BLOCKED, violations, {})

    optimization_hints: Dict[str, Any] = {}
    needs_opt_reasons: List[str] = []

    # Check for unbucketized raw metrics
    if "bytes_transferred" in payload and isinstance(payload["bytes_transferred"], (int, float)):
        needs_opt_reasons.append("Raw bytes_transferred should be bucketized into bandwidth tiers.")
        optimization_hints["aggregate_bytes"] = True

    if "duration_seconds" in payload and isinstance(payload["duration_seconds"], (int, float)):
        needs_opt_reasons.append("Raw duration_seconds should be bucketized into interval tiers.")
        optimization_hints["aggregate_duration"] = True

    # Check for redundant or debug metadata
    debug_keys = [k for k in payload.keys() if k.lower().startswith(("_", "debug", "temp")) or k.lower() in {"trace_log", "client_env"}]
    if debug_keys:
        needs_opt_reasons.append(f"Extraneous debug fields detected: {', '.join(debug_keys)}")
        optimization_hints["purge_debug_keys"] = debug_keys

    # Check for duplicate attack indicators
    indicators = payload.get("attack_indicators")
    if isinstance(indicators, list) and len(indicators) > 1:
        if len(indicators) != len(set(str(x).upper() for x in indicators)):
            needs_opt_reasons.append("Duplicate attack indicators detected.")
            optimization_hints["dedup_indicators"] = True

    if needs_opt_reasons:
        return (SafetyVerdict.NEEDS_OPTIMIZATION, needs_opt_reasons, optimization_hints)

    return (SafetyVerdict.SAFE, [], {})
