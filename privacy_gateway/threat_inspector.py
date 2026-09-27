"""
Edge Threat & Bug Inspector
Performs edge-side pre-send inspection on raw telemetry events before privacy transformation.
Detects malformed telemetry, invalid schemas, injection patterns, secret/credential leakage,
oversized payloads, and classifies operational threat indicators.
"""

import re
import json
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

class ThreatInspectionStatus(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    UNSAFE = "UNSAFE"
    MALFORMED = "MALFORMED"

@dataclass
class ThreatInspectionResult:
    status: ThreatInspectionStatus
    is_blocking: bool
    findings: List[str] = field(default_factory=list)
    risk_indicators: List[str] = field(default_factory=list)
    secrets_detected: List[str] = field(default_factory=list)
    schema_valid: bool = True
    payload_size_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "is_blocking": self.is_blocking,
            "findings": self.findings,
            "risk_indicators": self.risk_indicators,
            "secrets_detected": self.secrets_detected,
            "schema_valid": self.schema_valid,
            "payload_size_bytes": self.payload_size_bytes,
        }

# Inspection Regex Patterns
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
BEARER_PATTERN = re.compile(r"\bBearer\s+[a-zA-Z0-9_\-\.]{20,}\b", re.IGNORECASE)
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")
PASSWORD_KEYWORD_PATTERN = re.compile(r"(?:password|passwd|pwd|secret)\s*[:=]\s*['\"]?([^\s'\";,}]+)", re.IGNORECASE)

# Injection and Corrupted Telemetry Signatures
SQLI_PATTERN = re.compile(r"(\bUNION\s+SELECT\b|'\s*OR\s*'1'='1|--\s*$|;\s*DROP\s+TABLE\b)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"<\s*script[^>]*>|javascript:\s*", re.IGNORECASE)
TRAVERSAL_PATTERN = re.compile(r"(?:\.\./|\.\.\\){2,}")
JNDI_PATTERN = re.compile(r"\$\{jndi:(?:ldap|rmi|dns):", re.IGNORECASE)
COMMAND_INJECTION_PATTERN = re.compile(r"(?:;|\||`|\$\()\s*(?:/bin/|/usr/bin/|powershell|cmd\.exe|rm\s+-rf|del\s+/f)", re.IGNORECASE)

MAX_ALLOWED_PAYLOAD_BYTES = 65536  # 64 KB limit for standard telemetry event

class EdgeThreatInspector:
    """
    Evaluates raw telemetry events inside the local boundary BEFORE privacy transformation.
    Distinguishes between:
    - SAFE: Clean telemetry with no detected threats or anomalies.
    - SUSPICIOUS: Valid telemetry that captures an attack (e.g. brute force, port scan).
    - MALFORMED: Structural invalidity, unparseable timestamp, or missing required metadata.
    - UNSAFE: Contains active injection directed at the telemetry collector, hard secrets, or corrupted payload.
    """

    def __init__(self, max_payload_bytes: int = MAX_ALLOWED_PAYLOAD_BYTES):
        self.max_payload_bytes = max_payload_bytes

    def inspect(self, raw_event: Any) -> ThreatInspectionResult:
        findings: List[str] = []
        risk_indicators: List[str] = []
        secrets_detected: List[str] = []
        schema_valid = True

        # 1. Structural and Type Validation
        if not isinstance(raw_event, dict):
            return ThreatInspectionResult(
                status=ThreatInspectionStatus.MALFORMED,
                is_blocking=True,
                findings=["Event payload is not a valid JSON/dictionary object."],
                schema_valid=False,
                payload_size_bytes=0,
            )

        # 2. Payload Size Check
        try:
            serialized = json.dumps(raw_event)
            payload_size = len(serialized.encode("utf-8"))
        except (TypeError, ValueError) as ex:
            return ThreatInspectionResult(
                status=ThreatInspectionStatus.MALFORMED,
                is_blocking=True,
                findings=[f"Serialization error: {str(ex)}"],
                schema_valid=False,
                payload_size_bytes=0,
            )

        if payload_size > self.max_payload_bytes:
            return ThreatInspectionResult(
                status=ThreatInspectionStatus.MALFORMED,
                is_blocking=True,
                findings=[f"Payload size ({payload_size} bytes) exceeds maximum limit of {self.max_payload_bytes} bytes."],
                schema_valid=False,
                payload_size_bytes=payload_size,
            )

        # 3. Schema & Key Integrity
        required_keys = ["event_id", "timestamp"]
        missing_keys = [k for k in required_keys if k not in raw_event or not raw_event[k]]
        if missing_keys:
            schema_valid = False
            findings.append(f"Missing mandatory schema keys: {', '.join(missing_keys)}")

        # Timestamp format verification
        ts = raw_event.get("timestamp")
        if ts:
            try:
                # Accept ISO format timestamps
                ts_str = str(ts).replace("Z", "+00:00")
                datetime.fromisoformat(ts_str)
            except Exception:
                schema_valid = False
                findings.append(f"Invalid timestamp format: '{ts}'. Must conform to ISO-8601/RFC-3339.")

        # Organization / Agent ID sanity
        for id_field in ["organization_id", "agent_id"]:
            val = raw_event.get(id_field)
            if val is not None and not isinstance(val, str):
                schema_valid = False
                findings.append(f"Identifier '{id_field}' must be a string.")
            elif val and not re.match(r"^[a-zA-Z0-9_\-\.]{2,64}$", str(val)):
                schema_valid = False
                findings.append(f"Identifier '{id_field}' contains invalid characters or length: '{val}'")

        if not schema_valid:
            return ThreatInspectionResult(
                status=ThreatInspectionStatus.MALFORMED,
                is_blocking=True,
                findings=findings,
                schema_valid=False,
                payload_size_bytes=payload_size,
            )

        # 4. Recursive Inspection for Secrets and Injections
        has_unsafe_injection = False

        def _scan_field_value(val: Any, path: str = ""):
            nonlocal has_unsafe_injection
            if isinstance(val, str):
                # Secrets scanning
                if AWS_KEY_PATTERN.search(val):
                    secrets_detected.append(f"AWS API Key at '{path}'")
                if JWT_PATTERN.search(val):
                    secrets_detected.append(f"JWT Token at '{path}'")
                if BEARER_PATTERN.search(val):
                    secrets_detected.append(f"Bearer Token at '{path}'")
                if PRIVATE_KEY_PATTERN.search(val):
                    secrets_detected.append(f"Private Key at '{path}'")
                if PASSWORD_KEYWORD_PATTERN.search(val):
                    secrets_detected.append(f"Embedded password credentials at '{path}'")

                # Injection & Corrupted Signatures
                if SQLI_PATTERN.search(val):
                    risk_indicators.append(f"SQL Injection pattern at '{path}'")
                if XSS_PATTERN.search(val):
                    risk_indicators.append(f"XSS / HTML script tag at '{path}'")
                if TRAVERSAL_PATTERN.search(val):
                    risk_indicators.append(f"Path traversal pattern at '{path}'")
                if JNDI_PATTERN.search(val):
                    risk_indicators.append(f"JNDI lookup injection at '{path}'")
                    has_unsafe_injection = True
                if COMMAND_INJECTION_PATTERN.search(val):
                    risk_indicators.append(f"Shell command injection at '{path}'")
                    has_unsafe_injection = True

            elif isinstance(val, dict):
                for k, v in val.items():
                    _scan_field_value(v, f"{path}.{k}" if path else k)
            elif isinstance(val, (list, tuple)):
                for idx, item in enumerate(val):
                    _scan_field_value(item, f"{path}[{idx}]")

        _scan_field_value(raw_event)

        # 5. Operational Threat Indicators
        event_type = str(raw_event.get("event_type", "")).lower()
        failed_attempts = raw_event.get("failed_attempts", 0)
        dest_port = raw_event.get("destination_port")
        attack_indicators = raw_event.get("attack_indicators", [])

        if isinstance(failed_attempts, (int, float)) and failed_attempts >= 5:
            risk_indicators.append(f"Authentication burst: {failed_attempts} failed login attempts")

        if dest_port in [4444, 1337, 31337, 8888, 9999]:
            risk_indicators.append(f"Connection directed to suspicious backdoor port: {dest_port}")

        if isinstance(attack_indicators, list) and len(attack_indicators) > 0:
            for ind in attack_indicators:
                risk_indicators.append(f"Reported indicator: {ind}")

        # 6. Status Determination
        # If payload carries an active exploit directed at telemetry ingestion (e.g. JNDI, command injection) -> UNSAFE
        if has_unsafe_injection:
            return ThreatInspectionResult(
                status=ThreatInspectionStatus.UNSAFE,
                is_blocking=True,
                findings=["Telemetry payload contains active injection attack patterns."],
                risk_indicators=risk_indicators,
                secrets_detected=secrets_detected,
                schema_valid=True,
                payload_size_bytes=payload_size,
            )

        # If attack indicators are detected, mark as SUSPICIOUS (not blocking telemetry)
        if risk_indicators or "attack" in event_type or "scan" in event_type or "brute" in event_type:
            return ThreatInspectionResult(
                status=ThreatInspectionStatus.SUSPICIOUS,
                is_blocking=False,
                findings=findings,
                risk_indicators=risk_indicators,
                secrets_detected=secrets_detected,
                schema_valid=True,
                payload_size_bytes=payload_size,
            )

        # Clean telemetry
        return ThreatInspectionResult(
            status=ThreatInspectionStatus.SAFE,
            is_blocking=False,
            findings=findings,
            risk_indicators=risk_indicators,
            secrets_detected=secrets_detected,
            schema_valid=True,
            payload_size_bytes=payload_size,
        )
