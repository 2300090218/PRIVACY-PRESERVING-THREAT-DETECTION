"""
Privacy Gateway Core Engine
Executes data minimization, field-level policy enforcement, PII sanitization,
and strict leakage prevention inside the local organization boundary.
"""

import hmac
import hashlib
import uuid
from typing import Dict, Any, Tuple, List, Optional
from datetime import datetime, timezone

from privacy_gateway.policy_engine import (
    PrivacyPolicyConfig,
    PolicyAction,
    default_policy_config
)
from privacy_gateway.leakage_prevention import (
    validate_protected_payload,
    FORBIDDEN_RAW_FIELDS,
    EMAIL_REGEX,
    AWS_KEY_REGEX,
    BEARER_TOKEN_REGEX
)
from privacy_gateway.metrics import privacy_metrics

class PrivacyViolationError(Exception):
    """Raised when raw sensitive telemetry fails privacy leakage verification."""
    pass

class PrivacyGateway:
    def __init__(
        self,
        policy_config: Optional[PrivacyPolicyConfig] = None,
        salt: str = "local-privacy-salt-isolated-hmac-32",
        organization_id: Optional[str] = None,
        pseudonym_salt: Optional[str] = None,
        **kwargs
    ):
        effective_salt = pseudonym_salt or salt
        self.policy_config = policy_config or default_policy_config
        if organization_id:
            self.policy_config.organization_id = organization_id
        self.salt = effective_salt.encode("utf-8")

    def generate_pseudonym(self, raw_value: str, prefix: str = "DEV") -> str:
        """Generates a reproducible, salted HMAC-SHA256 pseudonym token."""
        h = hmac.new(self.salt, raw_value.encode("utf-8"), hashlib.sha256).hexdigest()[:8].upper()
        return f"{prefix}-{h}"

    def mask_value(self, val: Any, params: Dict[str, Any]) -> str:
        s = str(val)
        mask_type = params.get("mask_type")
        if mask_type == "subnet" and "." in s:
            parts = s.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        mask_char = params.get("mask_char", "*")
        if len(s) <= 4:
            return mask_char * len(s)
        # Keep first 2 and last 2 characters
        return s[:2] + (mask_char * (len(s) - 4)) + s[-2:]

    def aggregate_value(self, val: Any, params: Dict[str, Any]) -> str:
        """Bucketizes numeric values into tier intervals."""
        try:
            num = float(val)
            tiers = params.get("tiers") or params.get("buckets", [100, 1000, 10000, 100000])
            for idx, bound in enumerate(tiers):
                if num < bound:
                    prev = tiers[idx - 1] if idx > 0 else 0
                    if "tiers" in params:
                        return f"{prev}-{bound}s"
                    return f"TIER_{idx}_{prev}_TO_{bound}"
            return f">{tiers[-1]}s" if "tiers" in params else f"TIER_HIGH_ABOVE_{tiers[-1]}"
        except (ValueError, TypeError):
            return "TIER_UNKNOWN"

    def transform_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes a raw local security event, applies field policies,
        sanitizes inline PII, checks leakage boundaries, and produces a protected event.
        """
        removed_count = 0
        masked_count = 0
        pseudo_count = 0
        removed_field_names = []
        masked_field_names = []
        pseudo_field_names = []

        protected: Dict[str, Any] = {}

        # 1. Process Each Field in the Raw Event
        for field, value in raw_event.items():
            field_lower = field.lower()
            action = self.policy_config.get_action(field_lower)
            policy = self.policy_config.get_policy(field_lower)
            params = policy.parameters if policy else {}

            if action == PolicyAction.REMOVE:
                removed_count += 1
                removed_field_names.append(field)
                continue

            elif action == PolicyAction.MASK:
                masked_val = self.mask_value(value, params)
                protected[field] = masked_val
                masked_count += 1
                masked_field_names.append(field)

            elif action == PolicyAction.PSEUDONYMIZE:
                prefix = params.get("prefix", "PSEUDO")
                pseudo_token = self.generate_pseudonym(str(value), prefix=prefix)
                # If the field is device_id, replace with pseudonymized key
                protected[field] = pseudo_token
                pseudo_count += 1
                pseudo_field_names.append(f"{field}->{pseudo_token}")

            elif action == PolicyAction.AGGREGATE:
                agg_val = self.aggregate_value(value, params)
                protected[field] = agg_val
                masked_count += 1
                masked_field_names.append(field)

            elif action == PolicyAction.ALLOW:
                # Value is allowed, but must be checked for inline PII
                if isinstance(value, str):
                    clean_str, inline_sub = self._sanitize_inline_string(value)
                    protected[field] = clean_str
                    if inline_sub:
                        masked_count += len(inline_sub)
                else:
                    protected[field] = value

        # 2. Ensure Required Minimum Event Metadata
        if "event_id" not in protected:
            protected["event_id"] = f"evt_{uuid.uuid4().hex[:12]}"
        if "timestamp" not in protected:
            protected["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "organization_id" not in protected:
            protected["organization_id"] = self.policy_config.organization_id

        # Attach privacy transformation summary (metadata only, no raw values)
        protected["privacy_metadata"] = {
            "policy_version": self.policy_config.version,
            "policy_name": self.policy_config.name,
            "removed_count": removed_count,
            "masked_count": masked_count,
            "pseudonymized_count": pseudo_count,
            "removed_fields": removed_field_names,
            "pseudonymized_fields": pseudo_field_names,
        }

        # 3. Pre-Flight Boundary Verification (Double Check Before Emitting)
        is_safe, violations = validate_protected_payload(protected)
        if not is_safe:
            privacy_metrics.record_violation()
            raise PrivacyViolationError(
                f"Privacy Gateway detected boundary leakage in transformed payload: {'; '.join(violations)}"
            )

        # 4. Record Success Metrics
        privacy_metrics.record_transformation(
            removed=removed_count,
            masked=masked_count,
            pseudonymized=pseudo_count,
            violation=False
        )

        return protected

    process_raw_event = transform_event

    def _sanitize_inline_string(self, text: str) -> Tuple[str, List[str]]:
        """Scans string content for unintentional embedded credentials/PII."""
        modified = False
        replaces = []
        result = text

        # Redact AWS keys
        for key in AWS_KEY_REGEX.findall(result):
            result = result.replace(key, "[REDACTED-KEY]")
            replaces.append("aws_key")
            modified = True

        # Redact Bearer tokens
        for token in BEARER_TOKEN_REGEX.findall(result):
            result = result.replace(token, "[REDACTED-TOKEN]")
            replaces.append("bearer_token")
            modified = True

        # Pseudonymize email
        for email in EMAIL_REGEX.findall(result):
            pseudo = self.generate_pseudonym(email, prefix="USER")
            result = result.replace(email, pseudo)
            replaces.append(f"email->{pseudo}")
            modified = True

        return result, replaces
