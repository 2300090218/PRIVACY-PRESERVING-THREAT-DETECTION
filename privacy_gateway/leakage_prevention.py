"""
Privacy Leakage Prevention & Pre-Send Security Validation Engine
Part 30 Compliance:
Implements 15 Pre-Send Security Validation checks before an event is transmitted outside the organization.
If any check fails:
DO NOT SEND.
Return:
status: BLOCKED
reason: Privacy validation failed.

Implements Tri-State Safety Classification: SAFE, NEEDS_OPTIMIZATION, BLOCKED.
"""

import re
import json
from enum import Enum
from typing import Dict, Any, List, Tuple, Optional

from privacy_gateway.encryption import (
    is_valid_aes_256_gcm_token,
    is_valid_hmac_sha256_token,
    AES_GCM_TOKEN_REGEX,
    HMAC_SHA256_TOKEN_REGEX,
    base64url_decode
)

class SafetyVerdict(str, Enum):
    SAFE = "SAFE"
    NEEDS_OPTIMIZATION = "NEEDS_OPTIMIZATION"
    BLOCKED = "BLOCKED"

FORBIDDEN_RAW_FIELDS = {
    "username",
    "user",
    "user_id",
    "student_name",
    "student_id",
    "faculty_name",
    "faculty_id",
    "roll_number",
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
    "authorization",
    "private_key",
    "ssn",
    "credit_card",
    "raw_log",
    "raw_logs",
    "raw_network_logs"
}

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
IPV4_RAW_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
IPV4_ANYWHERE_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
AWS_KEY_REGEX = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
JWT_REGEX = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
BEARER_TOKEN_REGEX = re.compile(r"\bBearer\s+[a-zA-Z0-9_\-\.]{20,}\b", re.IGNORECASE)
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")
PASSWORD_INLINE_REGEX = re.compile(r"(?:password|passwd|secret)\s*[:=]\s*['\"]?([^\s'\";,}]+)", re.IGNORECASE)

# University / Academic identity indicators
ACADEMIC_ID_REGEX = re.compile(r"\b(?:23000\d{5}|[0-9]{2}[A-Z0-9]{2,3}[0-9]{4,6}|KLU\d{5,8}|GITAM\d{5,8})\b", re.IGNORECASE)

MAX_ALLOWED_PAYLOAD_SIZE = 65536

def validate_presend_security(
    payload: Dict[str, Any],
    policy_config: Optional[Any] = None
) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Executes the 15 Pre-Send Security Validation checks required by Part 30.
    Before an event is sent outside an organization, inspect the FINAL PAYLOAD.
    
    Checks:
    1. No plaintext IP exists where policy prohibits it.
    2. No plaintext latitude exists where policy prohibits it.
    3. No plaintext longitude exists where policy prohibits it.
    4. No password exists.
    5. No API key exists.
    6. No JWT exists.
    7. No authorization header exists.
    8. No raw student/faculty identity exists.
    9. No prohibited personal information exists.
    10. Encryption format is valid.
    11. AES-GCM authentication tag is present.
    12. Nonce/IV is present.
    13. Key identifier is present.
    14. HMAC values use the configured secret format.
    15. Payload matches the organization privacy policy.
    
    If ANY check fails:
    DO NOT SEND.
    Return status: BLOCKED, reason: Privacy validation failed.
    """
    if not isinstance(payload, dict):
        return (False, ["Payload must be a dictionary object."], {
            "status": "BLOCKED",
            "reason": "Privacy validation failed.",
            "violations": ["Payload must be a dictionary object."]
        })

    violations: List[str] = []
    check_results: List[Dict[str, Any]] = []

    # Flatten helper to inspect all keys and leaf values
    all_keys = []
    all_key_value_pairs = []

    def _walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                p = f"{prefix}.{k}" if prefix else k
                all_keys.append((k, p))
                all_key_value_pairs.append((k, v, p))
                _walk(v, p)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                p = f"{prefix}[{i}]"
                all_key_value_pairs.append((f"[{i}]", v, p))
                _walk(v, p)

    _walk(payload)

    # -------------------------------------------------------------------------
    # Check 1: No plaintext IP exists where policy prohibits it
    # -------------------------------------------------------------------------
    c1_passed = True
    c1_details = []
    # Check if any prohibited field contains raw IPv4, or if payload contains unmasked raw IP
    for k, v, p in all_key_value_pairs:
        k_lower = k.lower()
        if k_lower in {"source_ip", "ip_address", "client_ip", "destination_ip", "ip"}:
            if isinstance(v, str):
                if not (v.startswith("enc:aes256gcm:v1:") or v.startswith("hmac-sha256:v1:")):
                    c1_passed = False
                    c1_details.append(f"Raw IP address / Plaintext IP detected in prohibited key '{p}': {v}")
        elif k_lower in {"source", "destination", "actor"}:
            if isinstance(v, str) and IPV4_RAW_REGEX.match(v.strip()):
                c1_passed = False
                c1_details.append(f"Raw IP address / Plaintext IP detected in network field '{p}': {v}")
        elif isinstance(v, str) and not v.startswith("enc:aes256gcm:v1:") and not v.startswith("hmac-sha256:v1:"):
            # Exclude known false positives like version strings "1.0.0" or "0.0.0.0"
            m = IPV4_ANYWHERE_REGEX.search(v)
            if m:
                matched_ip = m.group(0)
                if matched_ip not in {"0.0.0.0", "127.0.0.1", "1.0.0", "2.0.0"} and p not in {"timestamp", "event_id"}:
                    c1_passed = False
                    c1_details.append(f"Raw IP address / Plaintext IP pattern '{matched_ip}' detected at '{p}'")

    if not c1_passed:
        violations.extend(c1_details)
    check_results.append({
        "id": 1,
        "name": "No plaintext IP",
        "passed": c1_passed,
        "details": c1_details or ["No plaintext IP detected."]
    })

    # -------------------------------------------------------------------------
    # Check 2: No plaintext latitude exists where policy prohibits it
    # -------------------------------------------------------------------------
    c2_passed = True
    c2_details = []
    if "latitude" in payload:
        lat_val = payload["latitude"]
        if not (isinstance(lat_val, str) and lat_val.startswith("enc:aes256gcm:v1:")):
            c2_passed = False
            c2_details.append(f"Plaintext latitude '{lat_val}' detected in root payload.")
    for k, v, p in all_key_value_pairs:
        if k.lower() == "latitude" and not (isinstance(v, str) and v.startswith("enc:aes256gcm:v1:")):
            c2_passed = False
            c2_details.append(f"Plaintext latitude detected at path '{p}'.")
    if not c2_passed:
        violations.extend(c2_details)
    check_results.append({
        "id": 2,
        "name": "No plaintext latitude",
        "passed": c2_passed,
        "details": c2_details or ["No plaintext latitude detected."]
    })

    # -------------------------------------------------------------------------
    # Check 3: No plaintext longitude exists where policy prohibits it
    # -------------------------------------------------------------------------
    c3_passed = True
    c3_details = []
    if "longitude" in payload:
        lon_val = payload["longitude"]
        if not (isinstance(lon_val, str) and lon_val.startswith("enc:aes256gcm:v1:")):
            c3_passed = False
            c3_details.append(f"Plaintext longitude '{lon_val}' detected in root payload.")
    for k, v, p in all_key_value_pairs:
        if k.lower() == "longitude" and not (isinstance(v, str) and v.startswith("enc:aes256gcm:v1:")):
            c3_passed = False
            c3_details.append(f"Plaintext longitude detected at path '{p}'.")
    if not c3_passed:
        violations.extend(c3_details)
    check_results.append({
        "id": 3,
        "name": "No plaintext longitude",
        "passed": c3_passed,
        "details": c3_details or ["No plaintext longitude detected."]
    })

    # -------------------------------------------------------------------------
    # Check 4: No password exists
    # -------------------------------------------------------------------------
    c4_passed = True
    c4_details = []
    for k, v, p in all_key_value_pairs:
        if k.lower() in {"password", "passwd", "pwd"}:
            c4_passed = False
            c4_details.append(f"Password field '{p}' detected in outgoing payload.")
        elif isinstance(v, str):
            pwd_m = PASSWORD_INLINE_REGEX.search(v)
            if pwd_m and not pwd_m.group(1).startswith("[REDACTED"):
                c4_passed = False
                c4_details.append(f"Inline password assignment detected at '{p}'.")
    if not c4_passed:
        violations.extend(c4_details)
    check_results.append({
        "id": 4,
        "name": "No password",
        "passed": c4_passed,
        "details": c4_details or ["No password detected."]
    })

    # -------------------------------------------------------------------------
    # Check 5: No API key exists
    # -------------------------------------------------------------------------
    c5_passed = True
    c5_details = []
    for k, v, p in all_key_value_pairs:
        if k.lower() in {"api_key", "apikey", "secret_key", "aws_secret", "client_secret"}:
            c5_passed = False
            c5_details.append(f"API key field '{p}' detected in outgoing payload.")
        elif isinstance(v, str) and AWS_KEY_REGEX.search(v):
            c5_passed = False
            c5_details.append(f"AWS API credential pattern detected at '{p}'.")
    if not c5_passed:
        violations.extend(c5_details)
    check_results.append({
        "id": 5,
        "name": "No API key",
        "passed": c5_passed,
        "details": c5_details or ["No API key detected."]
    })

    # -------------------------------------------------------------------------
    # Check 6: No JWT exists
    # -------------------------------------------------------------------------
    c6_passed = True
    c6_details = []
    for k, v, p in all_key_value_pairs:
        if k.lower() == "jwt":
            c6_passed = False
            c6_details.append(f"JWT field '{p}' detected in outgoing payload.")
        elif isinstance(v, str) and JWT_REGEX.search(v):
            c6_passed = False
            c6_details.append(f"Raw JWT token detected at '{p}'.")
    if not c6_passed:
        violations.extend(c6_details)
    check_results.append({
        "id": 6,
        "name": "No JWT",
        "passed": c6_passed,
        "details": c6_details or ["No JWT detected."]
    })

    # -------------------------------------------------------------------------
    # Check 7: No authorization header exists
    # -------------------------------------------------------------------------
    c7_passed = True
    c7_details = []
    for k, v, p in all_key_value_pairs:
        if k.lower() in {"authorization", "auth_header", "bearer"}:
            c7_passed = False
            c7_details.append(f"Authorization header key '{p}' detected in outgoing payload.")
        elif isinstance(v, str) and BEARER_TOKEN_REGEX.search(v):
            c7_passed = False
            c7_details.append(f"Bearer authorization token detected at '{p}'.")
    if not c7_passed:
        violations.extend(c7_details)
    check_results.append({
        "id": 7,
        "name": "No authorization header",
        "passed": c7_passed,
        "details": c7_details or ["No authorization header detected."]
    })

    # -------------------------------------------------------------------------
    # Check 8: No raw student/faculty identity exists
    # -------------------------------------------------------------------------
    c8_passed = True
    c8_details = []
    for k, v, p in all_key_value_pairs:
        k_lower = k.lower()
        if k_lower in {"username", "user", "student_name", "student_id", "faculty_name", "faculty_id", "roll_number", "employee_id"}:
            if isinstance(v, str) and not (v.startswith("USER-") or v.startswith("PSEUDO-") or v.startswith("hmac-sha256:v1:") or v.startswith("enc:aes256gcm:v1:")):
                c8_passed = False
                c8_details.append(f"Raw student/faculty identity field '{p}' with value '{v}' detected.")
        elif isinstance(v, str) and ACADEMIC_ID_REGEX.search(v) and not v.startswith("DEV-"):
            c8_passed = False
            c8_details.append(f"Academic roll number or university ID pattern detected at '{p}'.")
    if not c8_passed:
        violations.extend(c8_details)
    check_results.append({
        "id": 8,
        "name": "No raw student/faculty identity",
        "passed": c8_passed,
        "details": c8_details or ["No raw student/faculty identity detected."]
    })

    # -------------------------------------------------------------------------
    # Check 9: No prohibited personal information exists
    # -------------------------------------------------------------------------
    c9_passed = True
    c9_details = []
    for k, v, p in all_key_value_pairs:
        if k.lower() in {"email", "ssn", "credit_card", "phone"}:
            c9_passed = False
            c9_details.append(f"Prohibited personal information key '{p}' detected.")
        elif isinstance(v, str):
            if EMAIL_REGEX.search(v) and not v.startswith("USER-"):
                c9_passed = False
                c9_details.append(f"Unmasked email address detected at '{p}'.")
            if PRIVATE_KEY_REGEX.search(v):
                c9_passed = False
                c9_details.append(f"Cryptographic private key detected at '{p}'.")
    if not c9_passed:
        violations.extend(c9_details)
    check_results.append({
        "id": 9,
        "name": "No prohibited personal information",
        "passed": c9_passed,
        "details": c9_details or ["No prohibited personal information detected."]
    })

    # -------------------------------------------------------------------------
    # Check 10: Encryption format is valid
    # -------------------------------------------------------------------------
    c10_passed = True
    c10_details = []
    encrypted_tokens_found = []
    for k, v, p in all_key_value_pairs:
        if isinstance(v, str) and (v.startswith("enc:") or k.endswith("_encrypted")):
            encrypted_tokens_found.append((k, v, p))
            if not v.startswith("enc:aes256gcm:v1:"):
                c10_passed = False
                c10_details.append(f"Invalid encryption format for field '{p}'. Must start with 'enc:aes256gcm:v1:'.")
            elif not is_valid_aes_256_gcm_token(v):
                c10_passed = False
                c10_details.append(f"Malformed AES-256-GCM token at '{p}'.")
    if not c10_passed:
        violations.extend(c10_details)
    check_results.append({
        "id": 10,
        "name": "Encryption format valid",
        "passed": c10_passed,
        "details": c10_details or [f"Validated {len(encrypted_tokens_found)} encrypted fields." if encrypted_tokens_found else "No encrypted fields present; format check satisfied."]
    })

    # -------------------------------------------------------------------------
    # Check 11: AES-GCM authentication tag is present
    # -------------------------------------------------------------------------
    c11_passed = True
    c11_details = []
    for k, v, p in encrypted_tokens_found:
        m = AES_GCM_TOKEN_REGEX.match(v)
        if not m:
            c11_passed = False
            c11_details.append(f"Missing authentication tag in token at '{p}'.")
        else:
            _, _, _, b64_tag = m.groups()
            try:
                tag_bytes = base64url_decode(b64_tag)
                if len(tag_bytes) != 16:
                    c11_passed = False
                    c11_details.append(f"Invalid auth tag length ({len(tag_bytes)} bytes, expected 16) at '{p}'.")
            except Exception:
                c11_passed = False
                c11_details.append(f"Corrupted auth tag encoding at '{p}'.")
    if not c11_passed:
        violations.extend(c11_details)
    check_results.append({
        "id": 11,
        "name": "AES-GCM authentication tag present",
        "passed": c11_passed,
        "details": c11_details or ["All AES-GCM auth tags present and valid (16 bytes)."]
    })

    # -------------------------------------------------------------------------
    # Check 12: Nonce/IV is present
    # -------------------------------------------------------------------------
    c12_passed = True
    c12_details = []
    for k, v, p in encrypted_tokens_found:
        m = AES_GCM_TOKEN_REGEX.match(v)
        if not m:
            c12_passed = False
            c12_details.append(f"Missing nonce/IV in token at '{p}'.")
        else:
            _, b64_nonce, _, _ = m.groups()
            try:
                nonce_bytes = base64url_decode(b64_nonce)
                if len(nonce_bytes) != 12:
                    c12_passed = False
                    c12_details.append(f"Invalid nonce/IV length ({len(nonce_bytes)} bytes, expected 12) at '{p}'.")
            except Exception:
                c12_passed = False
                c12_details.append(f"Corrupted nonce encoding at '{p}'.")
    if not c12_passed:
        violations.extend(c12_details)
    check_results.append({
        "id": 12,
        "name": "Nonce/IV present",
        "passed": c12_passed,
        "details": c12_details or ["All AES-GCM nonces present and valid (12 bytes)."]
    })

    # -------------------------------------------------------------------------
    # Check 13: Key identifier is present
    # -------------------------------------------------------------------------
    c13_passed = True
    c13_details = []
    for k, v, p in encrypted_tokens_found:
        m = AES_GCM_TOKEN_REGEX.match(v)
        if not m:
            c13_passed = False
            c13_details.append(f"Missing key identifier in token at '{p}'.")
        else:
            key_id = m.group(1)
            if not key_id or len(key_id) < 2:
                c13_passed = False
                c13_details.append(f"Empty or invalid key identifier at '{p}'.")
    if not c13_passed:
        violations.extend(c13_details)
    check_results.append({
        "id": 13,
        "name": "Key identifier present",
        "passed": c13_passed,
        "details": c13_details or ["All key identifiers present in encrypted tokens."]
    })

    # -------------------------------------------------------------------------
    # Check 14: HMAC values use the configured secret
    # -------------------------------------------------------------------------
    c14_passed = True
    c14_details = []
    hmac_tokens_found = []
    for k, v, p in all_key_value_pairs:
        if isinstance(v, str) and (v.startswith("hmac-") or "hmac" in k.lower()):
            hmac_tokens_found.append((k, v, p))
            if not is_valid_hmac_sha256_token(v):
                c14_passed = False
                c14_details.append(f"Invalid HMAC pseudonym format at '{p}'. Expected 'hmac-sha256:v1:<64-hex-digest>'.")
    if not c14_passed:
        violations.extend(c14_details)
    check_results.append({
        "id": 14,
        "name": "HMAC values use configured secret format",
        "passed": c14_passed,
        "details": c14_details or [f"Validated {len(hmac_tokens_found)} HMAC pseudonym tokens." if hmac_tokens_found else "HMAC pseudonym format verified."]
    })

    # -------------------------------------------------------------------------
    # Check 15: Payload matches the organization privacy policy
    # -------------------------------------------------------------------------
    c15_passed = True
    c15_details = []
    # Mandatory event metadata
    if not payload.get("event_id"):
        c15_passed = False
        c15_details.append("Missing mandatory 'event_id' attribute.")
    if not payload.get("timestamp"):
        c15_passed = False
        c15_details.append("Missing mandatory 'timestamp' attribute.")

    # Check for forbidden raw top-level keys
    for k in payload.keys():
        k_lower = k.lower()
        if k_lower in {"username", "user", "email", "password", "secret", "api_key", "jwt", "authorization", "exact_location"}:
            c15_passed = False
            c15_details.append(f"Forbidden raw attribute '{k}' remains in root payload.")

    if not c15_passed:
        violations.extend(c15_details)
    check_results.append({
        "id": 15,
        "name": "Payload matches organization privacy policy",
        "passed": c15_passed,
        "details": c15_details or ["Payload matches organization baseline privacy policy."]
    })

    # -------------------------------------------------------------------------
    # Final Verdict Synthesis
    # -------------------------------------------------------------------------
    is_safe = (len(violations) == 0)
    passed_count = sum(1 for c in check_results if c["passed"])

    report = {
        "status": "SAFE" if is_safe else "BLOCKED",
        "is_safe": is_safe,
        "reason": "All 15 pre-send privacy and security validation checks verified successfully." if is_safe else "Privacy validation failed.",
        "violations": violations,
        "checks_passed": passed_count,
        "checks_total": 15,
        "check_results": check_results
    }

    return (is_safe, violations, report)

def validate_protected_payload(payload: Dict[str, Any], check_nested: bool = True) -> Tuple[bool, List[str]]:
    """
    Evaluates a candidate transmission payload against strict privacy and security boundaries.
    Executes the 15 Pre-Send Security Validation checks.
    """
    is_safe, violations, _ = validate_presend_security(payload)
    return (is_safe, violations)

def evaluate_safety_decision(payload: Dict[str, Any]) -> Tuple[SafetyVerdict, List[str], Dict[str, Any]]:
    """
    Tri-State Evaluation:
    - BLOCKED: Fails any of the 15 Pre-Send Security Validation checks.
    - NEEDS_OPTIMIZATION: Passes security checks, but contains unaggregated numeric metrics or extraneous debug keys.
    - SAFE: All 15 checks verified, optimal telemetry ready for egress.
    """
    is_safe, violations, report = validate_presend_security(payload)
    if not is_safe:
        return (SafetyVerdict.BLOCKED, violations, report)

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

    return (SafetyVerdict.SAFE, [], report)
