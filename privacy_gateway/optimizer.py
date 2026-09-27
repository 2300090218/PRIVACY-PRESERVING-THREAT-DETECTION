"""
Telemetry Optimizer
Performs payload optimization and data minimization on transformed security events:
- Removes non-essential, duplicate, or debug metadata
- Minimizes identifying information while preserving critical threat intelligence features
- Normalizes protocol, casing, and bucketizes unbucketized metric values
- Reduces transmission payload size
"""

import json
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set

# Essential threat detection fields that MUST be preserved
ESSENTIAL_THREAT_FIELDS: Set[str] = {
    "event_id",
    "timestamp",
    "organization_id",
    "agent_id",
    "event_type",
    "telemetry_source",
    "device_id",
    "source",
    "destination",
    "destination_port",
    "protocol",
    "failed_attempts",
    "attack_indicators",
    "duration_seconds",
    "bytes_transferred",
    "features",
    "privacy_metadata",
    "is_test",
}

# Unnecessary, redundant, or debug metadata keys to purge
UNNECESSARY_KEYS: Set[str] = {
    "debug",
    "trace_log",
    "local_scratch",
    "client_env",
    "temp_id",
    "unprocessed_raw",
    "stack_trace_raw",
    "internal_notes",
    "agent_local_memory",
    "raw_scratchpad",
    "session_cache",
    "local_path",
    "system_pid",
    "thread_name",
}

@dataclass
class OptimizationResult:
    optimized_event: Dict[str, Any]
    optimization_actions: List[str] = field(default_factory=list)
    removed_fields: List[str] = field(default_factory=list)
    retained_fields: List[str] = field(default_factory=list)
    reason: str = "Standard telemetry minimization and feature normalization"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "optimization_actions": self.optimization_actions,
            "removed_fields": self.removed_fields,
            "retained_fields": self.retained_fields,
            "reason": self.reason,
            "optimized_event": self.optimized_event,
        }

class TelemetryOptimizer:
    """
    Minimizes payload footprint while retaining 100% of threat-relevant indicators.
    Executes between Privacy Transformation and Final Validation.
    """

    def __init__(self, max_text_len: int = 256):
        self.max_text_len = max_text_len

    def optimize(self, payload: Dict[str, Any], hints: Optional[Dict[str, Any]] = None) -> OptimizationResult:
        if not isinstance(payload, dict):
            return OptimizationResult(optimized_event={}, reason="Invalid payload object")

        actions: List[str] = []
        removed: List[str] = []
        optimized: Dict[str, Any] = {}

        # 1. Purge Unnecessary Debug & Ephemeral Keys
        for k, v in payload.items():
            k_lower = k.lower()
            if k_lower in UNNECESSARY_KEYS or k_lower.startswith(("_", "debug_", "temp_")):
                removed.append(k)
                actions.append(f"Purged non-essential telemetry field '{k}'")
                continue

            # Remove null or empty string fields that add no threat intelligence value
            if v is None or (isinstance(v, str) and v.strip() == ""):
                # Do not delete essential fields like failed_attempts or destination_port
                if k_lower not in ESSENTIAL_THREAT_FIELDS:
                    removed.append(k)
                    actions.append(f"Purged empty/null field '{k}'")
                    continue

            optimized[k] = v

        # 2. De-duplicate and Normalize Attack Indicators
        if "attack_indicators" in optimized and isinstance(optimized["attack_indicators"], list):
            orig_indicators = optimized["attack_indicators"]
            # Deduplicate preserving order and strip whitespace
            seen = set()
            deduped = []
            for item in orig_indicators:
                clean_item = str(item).strip().upper()
                if clean_item and clean_item not in seen:
                    seen.add(clean_item)
                    deduped.append(clean_item)
            if len(deduped) != len(orig_indicators):
                actions.append(f"Deduplicated attack indicators from {len(orig_indicators)} to {len(deduped)}")
            optimized["attack_indicators"] = deduped

        # 3. Protocol & Port Normalization
        if "protocol" in optimized and isinstance(optimized["protocol"], str):
            proto = optimized["protocol"].strip().upper()
            if proto != optimized["protocol"]:
                actions.append(f"Normalized protocol '{optimized['protocol']}' -> '{proto}'")
            optimized["protocol"] = proto

        if "destination_port" in optimized and optimized["destination_port"] is not None:
            try:
                port_num = int(optimized["destination_port"])
                if 0 <= port_num <= 65535:
                    optimized["destination_port"] = port_num
            except (ValueError, TypeError):
                actions.append(f"Removed malformed destination_port '{optimized['destination_port']}'")
                optimized.pop("destination_port", None)

        # 4. Metric Bucketization / Aggregation if Still Raw Numeric
        # If duration_seconds is still a raw float/int, aggregate it
        dur = optimized.get("duration_seconds")
        if isinstance(dur, (int, float)):
            bucket = self._bucketize_metric(float(dur), [1, 5, 30, 120, 600])
            optimized["duration_seconds"] = bucket
            actions.append(f"Aggregated raw duration {dur}s into tier '{bucket}'")

        # If bytes_transferred is still a raw number, aggregate it
        bytes_val = optimized.get("bytes_transferred")
        if isinstance(bytes_val, (int, float)):
            byte_bucket = self._bucketize_metric(float(bytes_val), [1000, 10000, 100000, 1000000])
            optimized["bytes_transferred"] = byte_bucket
            actions.append(f"Aggregated raw bytes {bytes_val} into tier '{byte_bucket}'")

        # 5. Truncate Excessive Text Lengths in Non-Essential String Attributes
        for k, v in list(optimized.items()):
            if isinstance(v, str) and len(v) > self.max_text_len and k not in {"timestamp", "event_id"}:
                truncated = v[: self.max_text_len] + "...[TRUNCATED]"
                optimized[k] = truncated
                actions.append(f"Truncated oversized string at '{k}' to {self.max_text_len} chars")

        retained = list(optimized.keys())

        # Update or record optimization metadata
        if "privacy_metadata" in optimized and isinstance(optimized["privacy_metadata"], dict):
            optimized["privacy_metadata"]["optimization_actions_count"] = len(actions)
            optimized["privacy_metadata"]["removed_by_optimizer"] = removed

        return OptimizationResult(
            optimized_event=optimized,
            optimization_actions=actions,
            removed_fields=removed,
            retained_fields=retained,
            reason=f"Minimized payload: removed {len(removed)} fields, performed {len(actions)} optimization actions while preserving {len(retained)} threat attributes",
        )

    def _bucketize_metric(self, val: float, tiers: List[int]) -> str:
        for idx, bound in enumerate(tiers):
            if val < bound:
                prev = tiers[idx - 1] if idx > 0 else 0
                return f"TIER_{idx}_{prev}_TO_{bound}"
        return f"TIER_HIGH_ABOVE_{tiers[-1]}"
