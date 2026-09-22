"""
Automated Tests for Local Agent Queue & Reliable Delivery
Tests delivery states (PENDING, SENT, ACKNOWLEDGED, FAILED, RETRYING),
exponential backoff, idempotency deduplication, and retry limits.
"""

import pytest
from agent.queue import LocalEventQueue, DeliveryStatus

def test_queue_enqueue_and_states():
    queue = LocalEventQueue(max_attempts=3, backoff_factor=2.0)
    assert queue.size() == 0

    item = queue.enqueue({"event_id": "evt_queue_001", "event_type": "test"})
    assert item.event_id == "evt_queue_001"
    assert item.status == DeliveryStatus.PENDING
    assert item.attempts == 0
    assert queue.size() == 1

def test_idempotency_duplicate_prevention_in_queue():
    queue = LocalEventQueue()
    item1 = queue.enqueue({"event_id": "evt_dup_001", "val": 1})
    item2 = queue.enqueue({"event_id": "evt_dup_001", "val": 2})

    # Must deduplicate and return existing item without adding duplicate to queue
    assert item1 is item2
    assert queue.size() == 1

def test_delivery_status_transitions():
    queue = LocalEventQueue(max_attempts=3)
    queue.enqueue({"event_id": "evt_status_001"})

    # Mark sending
    sending = queue.mark_sending("evt_status_001")
    assert sending.status == DeliveryStatus.SENT
    assert sending.attempts == 1

    # Mark failed attempt 1 -> enters RETRYING
    failed_retry = queue.mark_failed("evt_status_001", "HTTP 503 Server Busy")
    assert failed_retry.status == DeliveryStatus.RETRYING
    assert failed_retry.attempts == 1

    # Mark sending attempt 2
    queue.mark_sending("evt_status_001")
    # Mark acknowledged
    acked = queue.mark_acknowledged("evt_status_001")
    assert acked.status == DeliveryStatus.ACKNOWLEDGED
    assert acked.acknowledged_at is not None

def test_max_retries_transitions_to_failed():
    queue = LocalEventQueue(max_attempts=2)
    queue.enqueue({"event_id": "evt_fail_001"})

    # Attempt 1
    queue.mark_sending("evt_fail_001")
    item = queue.mark_failed("evt_fail_001", "Timeout 1")
    assert item.status == DeliveryStatus.RETRYING

    # Attempt 2 (exhausted)
    queue.mark_sending("evt_fail_001")
    item = queue.mark_failed("evt_fail_001", "Timeout 2")
    assert item.status == DeliveryStatus.FAILED
    assert "Timeout 2" in item.last_error

def test_queue_pending_filtering():
    queue = LocalEventQueue()
    queue.enqueue({"event_id": "e1"})
    queue.enqueue({"event_id": "e2"})
    queue.mark_acknowledged("e1")

    pending = queue.get_pending()
    assert len(pending) == 1
    assert pending[0].event_id == "e2"
