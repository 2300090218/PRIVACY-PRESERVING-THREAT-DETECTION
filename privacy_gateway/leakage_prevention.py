"""
Privacy Leakage Prevention
Defines strict boundary validation checks to ensure prohibited raw fields and sensitive PII
can NEVER pass from the local organization to the central server.
"""

import re
from typing import Dict, Any, List, Tuple

FORBIDDEN_RAW_FIELDS = {
    "username",
    "user",
    "email",
    "source_ip",
    "ip_address",
    "exact_location",
    "location",
    "raw_device_id",
    "password",
    "passwd",
    "secret",
    "api_key",
    "token",
    "access_token",
    "private_key",
    "ssn",
    "credit_card",
    "raw_network_logs"
}

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
IPV4_RAW_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
AWS_KEY_REGEX = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
BEARER_TOKEN_REGEX = re.compile(r"\bBearer\s+[a-zA-Z0-9_\-\.]{20,}\b", re.IGNORECASE)

def validate_protected_payload(payload: Dict[str, Any], check_nested: bool = True) -> Tuple[bool, List[str]]:
    """
    Evaluates a candidate transmission payload against strict privacy boundaries.
    Returns (True, []) if the payload is safe, or (False, [violation_reasons]) if violations exist.
    """
    violations: List[str] = []

    # 1. Inspect Top-Level Keys
    for key, val in payload.items():
        key_lower = key.lower()
        if key_lower in FORBIDDEN_RAW_FIELDS:
            violations.append(f"Forbidden raw field '{key}' detected in payload root.")

        # Inspect nested dictionary structures (e.g. metadata, indicators, features)
        if check_nested and isinstance(val, dict):
            for sub_key in val.keys():
                if sub_key.lower() in FORBIDDEN_RAW_FIELDS:
                    violations.append(f"Forbidden raw field '{sub_key}' detected inside nested object '{key}'.")

    # 2. Inspect String Values for PII and Raw Credentials
    def _inspect_values(data: Any, path: str = ""):
        if isinstance(data, str):
            # Check for leaked unmasked email
            if EMAIL_REGEX.search(data) and "@" in data and not data.startswith("USER-"):
                violations.append(f"Unpseudonymized email pattern found at path '{path}'.")

            # Check for leaked AWS/Cloud secret key
            if AWS_KEY_REGEX.search(data):
                violations.append(f"Raw AWS credential pattern found at path '{path}'.")

            # Check for leaked Bearer authorization token
            if BEARER_TOKEN_REGEX.search(data):
                violations.append(f"Raw authorization bearer token found at path '{path}'.")

            # Check if an exact raw IPv4 address appears in a disallowed or identity field
            if path.endswith(("source", "source_ip", "username", "location", "device_id", "actor")):
                if IPV4_RAW_REGEX.match(data.strip()):
                    violations.append(f"Exact raw IP address detected at prohibited path '{path}'.")

        elif isinstance(data, dict):
            for k, v in data.items():
                _inspect_values(v, f"{path}.{k}" if path else k)
        elif isinstance(data, (list, tuple)):
            for idx, item in enumerate(data):
                _inspect_values(item, f"{path}[{idx}]")

    _inspect_values(payload)

    return (len(violations) == 0, violations)
