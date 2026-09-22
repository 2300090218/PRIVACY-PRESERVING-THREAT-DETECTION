"""
Privacy Metrics Tracker
Calculates live metrics from actual privacy transformations:
processed_events, protected_events, removed_fields, masked_fields,
pseudonymized_fields, privacy_violations, transmission_failures.
"""

import threading
from typing import Dict, Any

class PrivacyMetricsTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self.processed_events: int = 0
        self.protected_events: int = 0
        self.removed_fields: int = 0
        self.masked_fields: int = 0
        self.pseudonymized_fields: int = 0
        self.privacy_violations: int = 0
        self.transmission_failures: int = 0

    def record_transformation(self, removed: int = 0, masked: int = 0, pseudonymized: int = 0, violation: bool = False, violations: int = 0, transmitted: bool = True, **kwargs):
        with self._lock:
            self.processed_events += 1
            if transmitted:
                self.protected_events += 1
            self.removed_fields += removed
            self.masked_fields += masked
            self.pseudonymized_fields += pseudonymized
            if violation or violations > 0:
                self.privacy_violations += 1

    def record_violation(self):
        with self._lock:
            self.privacy_violations += 1

    def record_transmission_failure(self):
        with self._lock:
            self.transmission_failures += 1

    def get_metrics(self) -> Dict[str, int]:
        with self._lock:
            return {
                "processed_events": self.processed_events,
                "protected_events": self.protected_events,
                "removed_fields": self.removed_fields,
                "masked_fields": self.masked_fields,
                "pseudonymized_fields": self.pseudonymized_fields,
                "privacy_violations": self.privacy_violations,
                "transmission_failures": self.transmission_failures,
            }

    get_summary = get_metrics

    def reset(self):
        with self._lock:
            self.processed_events = 0
            self.protected_events = 0
            self.removed_fields = 0
            self.masked_fields = 0
            self.pseudonymized_fields = 0
            self.privacy_violations = 0
            self.transmission_failures = 0

privacy_metrics = PrivacyMetricsTracker()
