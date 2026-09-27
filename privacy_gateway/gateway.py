"""
Privacy Gateway Core Engine
Executes data minimization, field-level policy enforcement, PII sanitization,
and strict leakage prevention inside the local organization boundary.
Provides the full Pre-Send Pipeline:
Raw Event -> 1. Threat/Bug Inspection -> 2. Privacy Transformation -> 3. Optimization -> 4. Final Validation -> SAFE/BLOCKED.
"""

import hmac
import hashlib
import uuid
from typing import Dict, Any, Tuple, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field

from privacy_gateway.policy_engine import (
    PrivacyPolicyConfig,
    PolicyAction,
    default_policy_config
)
from privacy_gateway.leakage_prevention import (
    validate_protected_payload,
    evaluate_safety_decision,
    SafetyVerdict,
    FORBIDDEN_RAW_FIELDS,
    EMAIL_REGEX,
    AWS_KEY_REGEX,
    JWT_REGEX,
    BEARER_TOKEN_REGEX,
    PRIVATE_KEY_REGEX,
    PASSWORD_INLINE_REGEX
)
from privacy_gateway.threat_inspector import (
    EdgeThreatInspector,
    ThreatInspectionResult,
    ThreatInspectionStatus
)
from privacy_gateway.optimizer import (
    TelemetryOptimizer,
    OptimizationResult
)
from privacy_gateway.metrics import privacy_metrics

class PrivacyViolationError(Exception):
    """Raised when raw sensitive telemetry fails privacy leakage verification."""
    pass

@dataclass
class PreSendResult:
    verdict: SafetyVerdict
    is_safe_to_send: bool
    safe_artifact: Optional[Dict[str, Any]]
    threat_inspection: ThreatInspectionResult
    optimization: OptimizationResult
    violations: List[str] = field(default_factory=list)
    decision_log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "is_safe_to_send": self.is_safe_to_send,
            "safe_artifact": self.safe_artifact,
            "threat_inspection": self.threat_inspection.to_dict(),
            "optimization": self.optimization.to_dict(),
            "violations": self.violations,
            "decision_log": self.decision_log,
        }

class PreSendPipeline:
    """
    Executes the Complete Pre-Send Privacy & Security Pipeline:
    1. Edge Threat / Bug Inspection
    2. Privacy Transformation
    3. Telemetry Optimization
    4. Final Privacy + Security Validation
    5. Closed-Loop Tri-State Decision:
       - SAFE -> Send
       - NEEDS_OPTIMIZATION -> Optimize & Re-check
       - BLOCKED -> Do Not Send
    """

    def __init__(
        self,
        gateway: Optional["PrivacyGateway"] = None,
        threat_inspector: Optional[EdgeThreatInspector] = None,
        optimizer: Optional[TelemetryOptimizer] = None,
        max_optimization_loops: int = 3
    ):
        self.gateway = gateway or PrivacyGateway()
        self.threat_inspector = threat_inspector or EdgeThreatInspector()
        self.optimizer = optimizer or TelemetryOptimizer()
        self.max_optimization_loops = max_optimization_loops

    def process(self, raw_event: Dict[str, Any]) -> PreSendResult:
        decision_log: List[str] = []

        # =====================================================================
        # STAGE 1: Edge Threat / Bug Inspection (on raw event)
        # =====================================================================
        inspection = self.threat_inspector.inspect(raw_event)
        decision_log.append(f"Stage 1 Threat Inspection: status={inspection.status.value}, blocking={inspection.is_blocking}")

        if inspection.is_blocking:
            return PreSendResult(
                verdict=SafetyVerdict.BLOCKED,
                is_safe_to_send=False,
                safe_artifact=None,
                threat_inspection=inspection,
                optimization=OptimizationResult(optimized_event={}),
                violations=inspection.findings or ["Blocked by Edge Threat/Bug Inspector"],
                decision_log=decision_log
            )

        # =====================================================================
        # STAGE 2: Privacy Transformation
        # =====================================================================
        try:
            transformed = self.gateway.transform_event(raw_event)
            decision_log.append(f"Stage 2 Privacy Transformation: minimized {len(transformed.get('privacy_metadata', {}).get('removed_fields', []))} fields")
        except PrivacyViolationError as pve:
            decision_log.append(f"Stage 2 Privacy Transformation Failed: {str(pve)}")
            return PreSendResult(
                verdict=SafetyVerdict.BLOCKED,
                is_safe_to_send=False,
                safe_artifact=None,
                threat_inspection=inspection,
                optimization=OptimizationResult(optimized_event={}),
                violations=[str(pve)],
                decision_log=decision_log
            )

        # =====================================================================
        # STAGE 3 & 4: Telemetry Optimization & Closed-Loop Validation
        # =====================================================================
        candidate = transformed
        last_opt_result = OptimizationResult(optimized_event=candidate)

        for iteration in range(self.max_optimization_loops):
            # Run Telemetry Optimizer
            opt_result = self.optimizer.optimize(candidate)
            candidate = opt_result.optimized_event
            last_opt_result = opt_result
            decision_log.append(f"Stage 3 Optimization Pass {iteration + 1}: {len(opt_result.optimization_actions)} actions taken")

            # Stage 4: Final Privacy & Security Validation
            verdict, reasons, hints = evaluate_safety_decision(candidate)
            decision_log.append(f"Stage 4 Safety Evaluation: verdict={verdict.value}")

            if verdict == SafetyVerdict.SAFE:
                decision_log.append("Decision: SAFE TO SEND. Candidate artifact verified.")
                return PreSendResult(
                    verdict=SafetyVerdict.SAFE,
                    is_safe_to_send=True,
                    safe_artifact=candidate,
                    threat_inspection=inspection,
                    optimization=last_opt_result,
                    violations=[],
                    decision_log=decision_log
                )

            elif verdict == SafetyVerdict.BLOCKED:
                decision_log.append(f"Decision: BLOCKED. Violations: {'; '.join(reasons)}")
                return PreSendResult(
                    verdict=SafetyVerdict.BLOCKED,
                    is_safe_to_send=False,
                    safe_artifact=None,
                    threat_inspection=inspection,
                    optimization=last_opt_result,
                    violations=reasons,
                    decision_log=decision_log
                )

            elif verdict == SafetyVerdict.NEEDS_OPTIMIZATION:
                decision_log.append(f"Status: NEEDS_OPTIMIZATION ({'; '.join(reasons)}). Re-running optimizer...")
                continue

        # If loops exhausted and still not SAFE
        decision_log.append("Decision: BLOCKED (Exceeded maximum optimization passes without achieving SAFE state)")
        return PreSendResult(
            verdict=SafetyVerdict.BLOCKED,
            is_safe_to_send=False,
            safe_artifact=None,
            threat_inspection=inspection,
            optimization=last_opt_result,
            violations=["Failed to satisfy privacy boundaries after maximum optimization iterations."],
            decision_log=decision_log
        )

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
        self.pre_send_pipeline = PreSendPipeline(gateway=self)

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
                protected[field] = pseudo_token
                pseudo_count += 1
                pseudo_field_names.append(f"{field}->{pseudo_token}")

            elif action == PolicyAction.AGGREGATE:
                agg_val = self.aggregate_value(value, params)
                protected[field] = agg_val
                masked_count += 1
                masked_field_names.append(field)

            elif action == PolicyAction.ALLOW:
                # Value is allowed, but must be checked for inline PII and credentials
                clean_val, inline_sub = self._sanitize_inline_value(value)
                protected[field] = clean_val
                if inline_sub:
                    masked_count += len(inline_sub)

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

    def process_presend_pipeline(self, raw_event: Dict[str, Any]) -> PreSendResult:
        """Executes the full edge pre-send pipeline including threat inspection, optimization and loop."""
        return self.pre_send_pipeline.process(raw_event)

    def _sanitize_inline_value(self, val: Any) -> Tuple[Any, List[str]]:
        """Recursively scans and sanitizes strings inside lists and nested dictionaries."""
        if isinstance(val, str):
            return self._sanitize_inline_string(val)
        elif isinstance(val, list):
            cleaned_list = []
            all_subs = []
            for item in val:
                c_item, subs = self._sanitize_inline_value(item)
                cleaned_list.append(c_item)
                all_subs.extend(subs)
            return cleaned_list, all_subs
        elif isinstance(val, dict):
            cleaned_dict = {}
            all_subs = []
            for k, v in val.items():
                c_v, subs = self._sanitize_inline_value(v)
                cleaned_dict[k] = c_v
                all_subs.extend(subs)
            return cleaned_dict, all_subs
        return val, []

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

        # Redact JWT tokens
        for jwt_token in JWT_REGEX.findall(result):
            result = result.replace(jwt_token, "[REDACTED-JWT]")
            replaces.append("jwt_token")
            modified = True

        # Redact Bearer tokens
        for token in BEARER_TOKEN_REGEX.findall(result):
            result = result.replace(token, "[REDACTED-TOKEN]")
            replaces.append("bearer_token")
            modified = True

        # Redact Private keys
        for pkey in PRIVATE_KEY_REGEX.findall(result):
            result = result.replace(pkey, "[REDACTED-KEY]")
            replaces.append("private_key")
            modified = True

        # Redact inline passwords
        for match in PASSWORD_INLINE_REGEX.finditer(result):
            full_match = match.group(0)
            pwd_val = match.group(1)
            sanitized = full_match.replace(pwd_val, "[REDACTED-PASSWORD]")
            result = result.replace(full_match, sanitized)
            replaces.append("inline_password")
            modified = True

        # Pseudonymize email
        for email in EMAIL_REGEX.findall(result):
            pseudo = self.generate_pseudonym(email, prefix="USER")
            result = result.replace(email, pseudo)
            replaces.append(f"email->{pseudo}")
            modified = True

        return result, replaces
