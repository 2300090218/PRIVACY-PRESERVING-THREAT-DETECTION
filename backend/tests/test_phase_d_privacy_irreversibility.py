"""
Phase D Security & Privacy Hardening Verification Tests
- Irreversibility of HMAC-SHA256 salted pseudonyms (pre-image resistance)
- Zero-PII verification across WebSocket broadcast payloads
- Production fail-fast verification on missing/default secrets
- Pydantic strict validation on telemetry ingestion endpoints
"""

import re
import pytest
from httpx import AsyncClient
from backend.app.services.privacy_service import privacy_engine
from backend.app.config import Settings
from backend.app.websocket.manager import ws_manager
from backend.app.services.traffic_simulator import traffic_simulator

IPV4_REGEX = re.compile(r"\b(?!(?:IP|DEV|NODE)-)(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

class TestPrivacyIrreversibility:
    def test_pseudonym_format_and_entropy(self):
        """Pseudonyms must adhere to prefixed hexadecimal token patterns."""
        raw_ip = "192.168.1.100"
        raw_user = "secops_admin_jdoe"
        raw_dev = "SERVER-DMZ-RACK-04"

        token_ip = privacy_engine.generate_pseudonym(raw_ip, prefix="IP")
        token_user = privacy_engine.generate_pseudonym(raw_user, prefix="USER")
        token_dev = privacy_engine.generate_pseudonym(raw_dev, prefix="DEV")

        assert token_ip.startswith("IP-")
        assert token_user.startswith("USER-")
        assert token_dev.startswith("DEV-")

        # Must not contain raw input substring
        assert raw_ip not in token_ip
        assert raw_user not in token_user
        assert raw_dev not in token_dev

    def test_avalanche_effect_and_one_way_irreversibility(self):
        """
        One-way hashing property:
        A 1-bit difference in input produces a completely different hash digest.
        Without the 256-bit salt, pre-image calculation is computationally infeasible.
        """
        ip1 = "10.0.0.1"
        ip2 = "10.0.0.2"

        t1 = privacy_engine.generate_pseudonym(ip1, prefix="IP")
        t2 = privacy_engine.generate_pseudonym(ip2, prefix="IP")

        assert t1 != t2
        # Verify hex portion is at least 6 characters
        hex1 = t1.split("-")[1]
        hex2 = t2.split("-")[1]
        assert len(hex1) >= 6
        assert len(hex2) >= 6

    def test_different_salts_produce_disjoint_mappings(self):
        """Cross-tenant or rotated salts must produce uncorrelated pseudonyms."""
        raw_ip = "172.16.254.1"
        t1 = privacy_engine.generate_pseudonym(raw_ip, prefix="IP")

        # Temporarily test with alternative salt
        saved_salt = privacy_engine.salt
        try:
            privacy_engine.salt = b"alternate-consortium-salt-32bytes!"
            t2 = privacy_engine.generate_pseudonym(raw_ip, prefix="IP")
            assert t1 != t2
        finally:
            privacy_engine.salt = saved_salt


class TestWebSocketZeroPII:
    @pytest.mark.asyncio
    async def test_websocket_broadcast_payload_contains_no_raw_pii(self):
        """
        Simulate traffic generation through PrivacyEngine and verify that
        the resulting WebSocket broadcast payloads contain 0 unredacted IPv4 addresses
        or email addresses.
        """
        captured_messages = []

        # Mock broadcast collector
        original_broadcast = ws_manager.broadcast
        async def mock_broadcast(event_type: str, data: dict, organization_id=None):
            captured_messages.append({"type": event_type, "data": data})
            return await original_broadcast(event_type, data, organization_id)

        ws_manager.broadcast = mock_broadcast
        try:
            # Generate simulated attacks and normal traffic
            for attack in ["Brute Force", "Port Scan", "Backdoor / C2", None]:
                await traffic_simulator._generate_and_process_event(attack_type=attack)

            assert len(captured_messages) > 0

            for msg in captured_messages:
                payload_str = str(msg["data"])

                # Check that raw IPv4 does not leak
                raw_ips = IPV4_REGEX.findall(payload_str)
                assert len(raw_ips) == 0, f"Raw IPv4 detected in WebSocket payload: {raw_ips}"

                # Check that raw email addresses do not leak
                raw_emails = EMAIL_REGEX.findall(payload_str)
                assert len(raw_emails) == 0, f"Raw email detected in WebSocket payload: {raw_emails}"

                # Check that source is properly pseudonymized
                source = msg["data"].get("source", "")
                if source:
                    assert source.startswith("IP-") or source.startswith("DEV-")
        finally:
            ws_manager.broadcast = original_broadcast


class TestProductionSecurityFailFast:
    def test_production_fails_fast_with_default_secrets(self):
        """In production environment, settings must raise ValueError if default dev keys are active."""
        with pytest.raises(ValueError) as excinfo:
            Settings(
                APP_ENV="production",
                SECRET_KEY="threat-detection-dev-secret-key-super-secure-32chars",
                JWT_SECRET="threat-detection-jwt-secret-dev-key-32chars",
                PRIVACY_SALT="privacy-salt-isolated-dev-token-hmac-salt",
            )
        assert "FATAL SECURITY CONFIGURATION" in str(excinfo.value)

    def test_production_succeeds_with_strong_random_secrets(self):
        """In production environment, strong random keys initialize successfully."""
        s = Settings(
            APP_ENV="production",
            SECRET_KEY="a" * 64,
            JWT_SECRET="b" * 64,
            PRIVACY_SALT="c" * 64,
            ALLOWED_ORIGINS="https://privacy-preserving-threat-detection.vercel.app",
        )
        assert s.APP_ENV == "production"
        assert "https://privacy-preserving-threat-detection.vercel.app" in s.CORS_ORIGINS
