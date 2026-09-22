"""
Local Organization Agent Client
Integrates telemetry collection, local Privacy Gateway minimization,
resilient local queuing, and authenticated HTTPS transmission to the Central API.
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, Tuple, Optional
from datetime import datetime, timezone

from agent.config import AgentConfig, agent_config
from agent.collector import TelemetryCollector, TelemetrySource
from agent.queue import LocalEventQueue, DeliveryStatus, QueueItem
from privacy_gateway.gateway import PrivacyGateway, PrivacyViolationError
from privacy_gateway.metrics import privacy_metrics

logger = logging.getLogger("agent.client")

class LocalAgentClient:
    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or agent_config
        self.collector = TelemetryCollector(
            organization_id=self.config.ORGANIZATION_ID,
            agent_id=self.config.AGENT_ID
        )
        self.gateway = PrivacyGateway()
        self.queue = LocalEventQueue(
            max_attempts=self.config.RETRY_MAX_ATTEMPTS,
            backoff_factor=self.config.RETRY_BACKOFF_FACTOR
        )
        self.events_collected = 0
        self.events_transmitted = 0
        self.events_failed = 0
        self.last_transmission_time: Optional[str] = None

    def process_and_transmit(self, raw_event: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        The Core Architectural Invariant:
        1. Raw event exists only locally.
        2. Raw event MUST pass through local Privacy Gateway for data minimization.
        3. Only verified protected event is enqueued and transmitted.
        4. Central server never receives raw prohibited fields.
        """
        self.events_collected += 1

        # 1. Privacy Gateway Transformation (Data Minimization)
        try:
            protected_event = self.gateway.transform_event(raw_event)
        except PrivacyViolationError as pve:
            self.events_failed += 1
            return False, {"error": "PRIVACY_VIOLATION", "detail": str(pve)}

        # 2. Resilient Local Queueing
        queue_item = self.queue.enqueue(protected_event)

        # 3. Authenticated Transmission to Central API
        success, res = self._dispatch_queue_item(queue_item)
        return success, res

    def _dispatch_queue_item(self, item: QueueItem) -> Tuple[bool, Dict[str, Any]]:
        item.record_attempt()
        target_url = f"{self.config.CENTRAL_API_URL}/api/v1/events"
        data_bytes = json.dumps(item.payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "X-Organization-ID": self.config.ORGANIZATION_ID,
            "X-Agent-ID": self.config.AGENT_ID,
            "X-API-Key": self.config.AGENT_API_KEY,
        }

        req = urllib.request.Request(target_url, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.config.REQUEST_TIMEOUT_SECONDS) as response:
                resp_body = response.read().decode("utf-8")
                resp_data = json.loads(resp_body) if resp_body else {"status": "SUCCESS"}
                self.queue.mark_acknowledged(item.event_id)
                self.events_transmitted += 1
                self.last_transmission_time = datetime.now(timezone.utc).isoformat()
                return True, resp_data

        except urllib.error.HTTPError as he:
            err_text = he.read().decode("utf-8")
            self.queue.mark_failed(item.event_id, f"HTTP {he.code}: {err_text}")
            self.events_failed += 1
            privacy_metrics.record_transmission_failure()
            return False, {"error": f"HTTP_{he.code}", "detail": err_text}

        except Exception as ex:
            self.queue.mark_failed(item.event_id, f"Network error: {str(ex)}")
            self.events_failed += 1
            privacy_metrics.record_transmission_failure()
            return False, {"error": "CONNECTION_FAILED", "detail": str(ex)}

    def flush_retry_queue(self) -> int:
        """Attempts to retransmit any queued events currently eligible for retry."""
        dispatchable = self.queue.get_dispatchable()
        succeeded = 0
        for item in dispatchable:
            success, _ = self._dispatch_queue_item(item)
            if success:
                succeeded += 1
        return succeeded

    def get_health_status(self) -> Dict[str, Any]:
        return {
            "agent_id": self.config.AGENT_ID,
            "organization_id": self.config.ORGANIZATION_ID,
            "agent_name": self.config.AGENT_NAME,
            "status": "ONLINE",
            "central_api_url": self.config.CENTRAL_API_URL,
            "events_collected": self.events_collected,
            "events_transmitted": self.events_transmitted,
            "events_failed": self.events_failed,
            "last_transmission": self.last_transmission_time,
            "queue_summary": self.queue.get_summary(),
            "privacy_metrics": privacy_metrics.get_metrics()
        }
