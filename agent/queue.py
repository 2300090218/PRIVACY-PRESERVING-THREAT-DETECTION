"""
Local Resilient Event Queue
Maintains local delivery states: PENDING, SENT, ACKNOWLEDGED, FAILED, RETRYING.
Ensures idempotency, exponential backoff retries, and prevents telemetry loss when central API is unreachable.
"""

import time
import threading
from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

class DeliveryStatus(str, Enum):
    PENDING = "PENDING"
    SENT = "SENT"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FAILED = "FAILED"
    RETRYING = "RETRYING"

class QueueItem:
    def __init__(self, event_id: str, payload: Dict[str, Any], max_attempts: int = 3, backoff_factor: float = 1.5):
        self.event_id = event_id
        self.payload = payload
        self.status = DeliveryStatus.PENDING
        self.attempts = 0
        self.max_attempts = max_attempts
        self.backoff_factor = backoff_factor
        self.created_at = time.time()
        self.last_attempt_at: Optional[float] = None
        self.next_retry_at: float = self.created_at
        self.error_message: Optional[str] = None

    def can_attempt(self) -> bool:
        now = time.time()
        return self.status in (DeliveryStatus.PENDING, DeliveryStatus.RETRYING) and now >= self.next_retry_at

    def record_attempt(self):
        self.attempts += 1
        self.last_attempt_at = time.time()
        self.status = DeliveryStatus.SENT

    def mark_success(self):
        self.status = DeliveryStatus.ACKNOWLEDGED
        self.error_message = None
        self.acknowledged_at = time.time()

    def mark_failure(self, error: str):
        self.error_message = error
        if self.attempts >= self.max_attempts:
            self.status = DeliveryStatus.FAILED
        else:
            self.status = DeliveryStatus.RETRYING
            # Exponential backoff: 1.0 * (backoff_factor ** attempts)
            delay = 1.0 * (self.backoff_factor ** self.attempts)
            self.next_retry_at = time.time() + delay

    @property
    def last_error(self) -> Optional[str]:
        return self.error_message

class LocalEventQueue:
    def __init__(self, max_attempts: int = 3, backoff_factor: float = 1.5):
        self._lock = threading.Lock()
        self._items: Dict[str, QueueItem] = {}
        self.max_attempts = max_attempts
        self.backoff_factor = backoff_factor

    def size(self) -> int:
        with self._lock:
            return len(self._items)

    def enqueue(self, payload: Dict[str, Any]) -> QueueItem:
        with self._lock:
            event_id = payload.get("event_id")
            if not event_id:
                raise ValueError("Payload missing required event_id")
            
            # Idempotency check: do not duplicate already queued/acked event
            if event_id in self._items:
                return self._items[event_id]

            item = QueueItem(event_id, payload, self.max_attempts, self.backoff_factor)
            self._items[event_id] = item
            return item

    def get_dispatchable(self) -> List[QueueItem]:
        with self._lock:
            return [item for item in self._items.values() if item.can_attempt()]

    def get_pending(self) -> List[QueueItem]:
        with self._lock:
            return [item for item in self._items.values() if item.status != DeliveryStatus.ACKNOWLEDGED]

    def mark_sending(self, event_id: str) -> Optional[QueueItem]:
        with self._lock:
            if event_id in self._items:
                item = self._items[event_id]
                item.record_attempt()
                return item
            return None

    def mark_acknowledged(self, event_id: str) -> Optional[QueueItem]:
        with self._lock:
            if event_id in self._items:
                item = self._items[event_id]
                item.mark_success()
                return item
            return None

    def mark_failed(self, event_id: str, error: str) -> Optional[QueueItem]:
        with self._lock:
            if event_id in self._items:
                item = self._items[event_id]
                item.mark_failure(error)
                return item
            return None

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            counts = {status.value: 0 for status in DeliveryStatus}
            for item in self._items.values():
                counts[item.status.value] += 1
            return {
                "total_queued": len(self._items),
                **counts
            }

    def clear(self):
        with self._lock:
            self._items.clear()
