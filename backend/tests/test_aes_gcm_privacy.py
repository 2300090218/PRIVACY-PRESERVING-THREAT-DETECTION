"""
Unit and Integration Tests for Part 30:
AES-256-GCM Protection for IP and Geolocation, HMAC-SHA-256 Pseudonymization,
and 15 Pre-Send Security Validation Checks.
"""

import pytest
import re
from privacy_gateway.encryption import (
    encrypt_aes_256_gcm,
    decrypt_aes_256_gcm,
    pseudonymize_hmac_sha256,
    coarsen_geolocation,
    is_valid_aes_256_gcm_token,
    is_valid_hmac_sha256_token,
    KeyManager,
    base64url_decode
)
from privacy_gateway.gateway import PrivacyGateway
from privacy_gateway.policy_engine import PrivacyPolicyConfig, PolicyAction
from privacy_gateway.leakage_prevention import (
    validate_presend_security,
    validate_protected_payload,
    evaluate_safety_decision,
    SafetyVerdict
)

class TestAes256GcmEncryption:
    def test_aes_gcm_encryption_format_and_decryption(self):
        """Test AES-256-GCM encryption format and authenticated decryption."""
        raw_val = "192.168.25.44"
        token = encrypt_aes_256_gcm(raw_val, key_id="privacy-key-v1")

        # Format: enc:aes256gcm:v1:<key-id>:<nonce>:<ciphertext>:<auth-tag>
        assert token.startswith("enc:aes256gcm:v1:privacy-key-v1:")
        parts = token.split(":")
        assert len(parts) == 7
        key_id, b64_nonce, b64_cipher, b64_tag = parts[3], parts[4], parts[5], parts[6]

        assert key_id == "privacy-key-v1"
        assert len(base64url_decode(b64_nonce)) == 12 # 96-bit GCM nonce
        assert len(base64url_decode(b64_tag)) == 16 # 128-bit authentication tag
        assert len(base64url_decode(b64_cipher)) > 0

        # Authenticated decryption succeeds
        decrypted = decrypt_aes_256_gcm(token)
        assert decrypted == raw_val

    def test_nonce_uniqueness_never_reused(self):
        """Ensure each encryption operation generates a unique nonce (zero reuse)."""
        raw_val = "192.168.25.44"
        tokens = [encrypt_aes_256_gcm(raw_val) for _ in range(50)]
        nonces = [t.split(":")[4] for t in tokens]
        ciphertexts = [t.split(":")[5] for t in tokens]

        # All 50 nonces must be completely unique
        assert len(set(nonces)) == 50
        assert len(set(ciphertexts)) == 50

        # All 50 tokens must decrypt to the exact same original value
        for t in tokens:
            assert decrypt_aes_256_gcm(t) == raw_val

    def test_tampered_ciphertext_fails_auth(self):
        """Ensure tampering with ciphertext or auth tag raises ValueError."""
        token = encrypt_aes_256_gcm("192.168.25.44")
        parts = token.split(":")

        # Tamper with ciphertext by flipping a byte
        from privacy_gateway.encryption import base64url_encode
        cipher_bytes = bytearray(base64url_decode(parts[5]))
        cipher_bytes[0] ^= 0x01 # flip a bit
        tampered_cipher = base64url_encode(bytes(cipher_bytes))
        tampered_token = f"{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}:{parts[4]}:{tampered_cipher}:{parts[6]}"

        with pytest.raises(ValueError) as excinfo:
            decrypt_aes_256_gcm(tampered_token)

        assert "authentication verification or decryption failed" in str(excinfo.value)

    def test_key_rotation_support(self):
        """Support multiple key versions for future key rotation."""
        km = KeyManager(default_key_id="privacy-key-v1")
        km.register_key("key-02", "rotated-secret-key-32-chars-long!!")

        t1 = encrypt_aes_256_gcm("Secret Location", key_id="privacy-key-v1", key_manager=km)
        t2 = encrypt_aes_256_gcm("Secret Location", key_id="key-02", key_manager=km)

        assert t1.split(":")[3] == "privacy-key-v1"
        assert t2.split(":")[3] == "key-02"

        assert decrypt_aes_256_gcm(t1, key_manager=km) == "Secret Location"
        assert decrypt_aes_256_gcm(t2, key_manager=km) == "Secret Location"



class TestHmacSha256Pseudonymization:
    def test_deterministic_correlation(self):
        """Ensure HMAC-SHA-256 enables deterministic correlation without exposing raw IP."""
        ip1 = "192.168.25.44"
        ip2 = "192.168.25.45"

        h1a = pseudonymize_hmac_sha256(ip1)
        h1b = pseudonymize_hmac_sha256(ip1)
        h2 = pseudonymize_hmac_sha256(ip2)

        # Token format: hmac-sha256:v1:<64-char-hex-digest>
        assert h1a.startswith("hmac-sha256:v1:")
        assert len(h1a.split(":")[2]) == 64
        assert is_valid_hmac_sha256_token(h1a)

        # Same IP -> Same pseudonym
        assert h1a == h1b
        # Different IP -> Different pseudonym
        assert h1a != h2
        # Original IP must not be visible in token
        assert ip1 not in h1a


class TestGeolocationCoarsening:
    def test_kl_university_coarsening(self):
        """KL University coordinates 16.5062, 80.6480 coarsen to AP_REGION_01."""
        zone = coarsen_geolocation(16.5062, 80.6480)
        assert zone == "AP_REGION_01"

    def test_gitam_visakhapatnam_coarsening(self):
        """GITAM coordinates 17.78, 83.38 coarsen to AP_REGION_02."""
        zone = coarsen_geolocation(17.78, 83.38)
        assert zone == "AP_REGION_02"

    def test_hyderabad_coarsening(self):
        """Hyderabad coordinates coarsen to TS_REGION_01."""
        zone = coarsen_geolocation(17.3850, 78.4867)
        assert zone == "TS_REGION_01"

    def test_frankfurt_coarsening(self):
        """Frankfurt coordinates coarsen to EU_WEST_REGION_01."""
        zone = coarsen_geolocation(50.1109, 8.6821)
        assert zone == "EU_WEST_REGION_01"


class TestPreSendSecurityValidation:
    def test_safe_event_passes_all_15_checks(self):
        """A properly protected event passes all 15 pre-send checks."""
        safe_event = {
            "event_id": "evt_kl_1001",
            "timestamp": "2026-09-27T10:00:00Z",
            "organization_id": "org_kl_univ",
            "event_type": "port_scan",
            "source": pseudonymize_hmac_sha256("192.168.25.44"),
            "location_zone": "AP_REGION_01",
            "device_id": "DEV-8F12",
            "sensitive_location_encrypted": encrypt_aes_256_gcm("KL Datacenter"),
            "severity": "HIGH",
            "failed_attempts": 0
        }

        is_safe, violations, report = validate_presend_security(safe_event)
        assert is_safe, f"Violations: {violations}"
        assert report["status"] == "SAFE"
        assert report["checks_passed"] == 15
        assert report["checks_total"] == 15

    def test_leaked_plaintext_ip_blocked(self):
        """Check 1 blocks transmission if a plaintext IP is present."""
        leaked_ip_event = {
            "event_id": "evt_leak_ip",
            "timestamp": "2026-09-27T10:00:00Z",
            "event_type": "port_scan",
            "source": "192.168.25.44" # Raw IP leaked
        }

        is_safe, violations, report = validate_presend_security(leaked_ip_event)
        assert not is_safe
        assert report["status"] == "BLOCKED"
        assert report["reason"] == "Privacy validation failed."
        assert any("Plaintext IP" in v for v in violations)

    def test_leaked_plaintext_gps_blocked(self):
        """Checks 2 and 3 block transmission if plaintext latitude or longitude is present."""
        leaked_gps_event = {
            "event_id": "evt_leak_gps",
            "timestamp": "2026-09-27T10:00:00Z",
            "event_type": "port_scan",
            "latitude": 16.5062, # Raw GPS leaked
            "longitude": 80.6480
        }

        is_safe, violations, report = validate_presend_security(leaked_gps_event)
        assert not is_safe
        assert report["status"] == "BLOCKED"
        assert any("latitude" in v.lower() for v in violations)

    def test_leaked_credentials_and_jwt_blocked(self):
        """Checks 4, 5, 6, 7 block passwords, API keys, JWTs, and auth headers."""
        bad_creds_event = {
            "event_id": "evt_bad_creds",
            "timestamp": "2026-09-27T10:00:00Z",
            "event_type": "failed_login",
            "password": "SuperSecretPassword123!",
            "api_key": "AKIAIOSFODNN7EXAMPLE",
            "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fake_signature",
            "authorization": "Bearer token_secret_12345"
        }

        is_safe, violations, report = validate_presend_security(bad_creds_event)
        assert not is_safe
        assert report["status"] == "BLOCKED"
        assert report["reason"] == "Privacy validation failed."


class TestPrivacyGatewayEndToEnd:
    def test_kl_university_event_transformation(self):
        """
        Complete Part 30 Flow:
        KL University raw event:
        source_ip: 192.168.25.44 -> HMAC-SHA-256
        latitude: 16.5062, longitude: 80.6480 -> AP_REGION_01
        username: Demo Student -> REMOVED
        sensitive_location -> AES-256-GCM
        """
        gateway = PrivacyGateway(organization_id="kl_university")

        raw_event = {
            "username": "Demo Student",
            "source_ip": "192.168.25.44",
            "device_id": "device-123",
            "latitude": 16.5062,
            "longitude": 80.6480,
            "sensitive_location": "Regional Datacenter KL",
            "event_type": "Port Scan",
            "severity": "HIGH",
            "destination_port": 4444,
            "protocol": "TCP"
        }

        protected = gateway.transform_event(raw_event)

        # 1. Raw sensitive fields must NOT exist in protected payload
        assert "username" not in protected
        assert "source_ip" not in protected
        assert "latitude" not in protected
        assert "longitude" not in protected

        # 2. Raw values must not appear anywhere in the stringified payload
        str_repr = str(protected)
        assert "Demo Student" not in str_repr
        assert "192.168.25.44" not in str_repr

        # 3. Source IP is pseudonymized with HMAC-SHA-256 for correlation
        assert protected["source"].startswith("hmac-sha256:v1:")
        assert is_valid_hmac_sha256_token(protected["source"])

        # 4. Geolocation is coarsened to AP_REGION_01
        assert protected["location_zone"] == "AP_REGION_01"

        # 5. Sensitive location is encrypted with AES-256-GCM
        assert protected["sensitive_location_encrypted"].startswith("enc:aes256gcm:v1:")
        assert is_valid_aes_256_gcm_token(protected["sensitive_location_encrypted"])

        # 6. Verify 15 pre-send checks pass
        is_safe, violations, report = validate_presend_security(protected)
        assert is_safe
        assert report["status"] == "SAFE"
        assert report["checks_passed"] == 15
