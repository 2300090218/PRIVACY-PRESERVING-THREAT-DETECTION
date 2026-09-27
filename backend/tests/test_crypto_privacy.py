"""
=============================================================================
PART 31 — CRYPTOGRAPHIC PRIVACY TEST SUITE
=============================================================================
Comprehensive automated test suite covering all 15 cryptographic and privacy
invariants mandated by Part 31:

1.  AES-256-GCM encryption/decryption round trip.
2.  Ciphertext must not equal plaintext.
3.  Encrypting the same plaintext twice must produce different ciphertext (fresh nonce).
4.  Modified ciphertext must fail authentication.
5.  Modified authentication tag must fail.
6.  Wrong encryption key must fail.
7.  HMAC-SHA-256 must produce the same pseudonym for the same normalized input and secret.
8.  Different IP addresses must produce different HMAC values.
9.  HMAC output must not contain the original IP.
10. Final outgoing telemetry must not contain plaintext sensitive fields.
11. Secrets must never appear in frontend JavaScript.
12. Secrets must never appear in NEXT_PUBLIC_* variables.
13. Secrets must never appear in Git-tracked files.
14. Cross-organization receiver must only see the protected representation.
15. Public DEMO mode must never expose encryption keys or plaintext personal telemetry.
=============================================================================
"""

import os
import re
import subprocess
import pytest
from pathlib import Path

from privacy_gateway.encryption import (
    encrypt_aes_256_gcm,
    decrypt_aes_256_gcm,
    pseudonymize_hmac_sha256,
    coarsen_geolocation,
    KeyManager,
    base64url_decode,
    base64url_encode,
    is_valid_aes_256_gcm_token,
    is_valid_hmac_sha256_token
)
from privacy_gateway.gateway import PrivacyGateway
from privacy_gateway.leakage_prevention import validate_presend_security

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class TestPart31CryptographicPrivacy:

    # -------------------------------------------------------------------------
    # 1. AES-256-GCM encryption/decryption round trip
    # -------------------------------------------------------------------------
    def test_01_aes_256_gcm_roundtrip(self):
        """
        1. AES-256-GCM encryption/decryption round trip.
           original -> encrypt -> ciphertext -> decrypt -> original
        """
        test_payloads = [
            "192.168.25.44",
            "16.5062,80.6480",
            "Regional Datacenter KL",
            "Sensitive Device Node-77X",
            "{\"gps\": [16.5062, 80.6480], \"site\": \"KL Campus\"}"
        ]

        for original in test_payloads:
            token = encrypt_aes_256_gcm(original, key_id="privacy-key-v1")
            assert is_valid_aes_256_gcm_token(token)
            
            # Format validation
            parts = token.split(":")
            assert len(parts) == 7
            assert parts[0] == "enc"
            assert parts[1] == "aes256gcm"
            assert parts[2] == "v1"
            assert parts[3] == "privacy-key-v1"

            decrypted = decrypt_aes_256_gcm(token)
            assert decrypted == original, f"Round trip failed for {original}"

    # -------------------------------------------------------------------------
    # 2. Ciphertext must not equal plaintext
    # -------------------------------------------------------------------------
    def test_02_ciphertext_must_not_equal_plaintext(self):
        """
        2. Ciphertext must not equal plaintext.
        """
        original = "192.168.25.44"
        token = encrypt_aes_256_gcm(original)
        parts = token.split(":")
        b64_ciphertext = parts[5]
        raw_ciphertext = base64url_decode(b64_ciphertext)

        assert b64_ciphertext != original
        assert raw_ciphertext != original.encode("utf-8")
        assert original not in token

    # -------------------------------------------------------------------------
    # 3. Encrypting the same plaintext twice produces different ciphertext
    # -------------------------------------------------------------------------
    def test_03_fresh_nonce_per_encryption(self):
        """
        3. Encrypting the same plaintext twice must produce different ciphertext
           because a fresh nonce is generated.
        """
        original = "16.5062, 80.6480"
        t1 = encrypt_aes_256_gcm(original)
        t2 = encrypt_aes_256_gcm(original)

        assert t1 != t2, "Two encryptions produced identical tokens"

        nonce1 = t1.split(":")[4]
        nonce2 = t2.split(":")[4]
        assert nonce1 != nonce2, "Nonce was reused across encryptions!"

        cipher1 = t1.split(":")[5]
        cipher2 = t2.split(":")[5]
        assert cipher1 != cipher2, "Ciphertexts are identical despite different operations"

        # Both must still decrypt cleanly to the original
        assert decrypt_aes_256_gcm(t1) == original
        assert decrypt_aes_256_gcm(t2) == original

    # -------------------------------------------------------------------------
    # 4. Modified ciphertext must fail authentication
    # -------------------------------------------------------------------------
    def test_04_modified_ciphertext_fails_authentication(self):
        """
        4. Modified ciphertext must fail authentication.
        """
        original = "TopSecretDatacenterCoordinates"
        token = encrypt_aes_256_gcm(original)
        parts = token.split(":")

        # Corrupt a byte in the ciphertext component
        cipher_bytes = bytearray(base64url_decode(parts[5]))
        cipher_bytes[0] ^= 0xFF  # Flip bits
        corrupted_b64 = base64url_encode(bytes(cipher_bytes))

        tampered_token = f"{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}:{parts[4]}:{corrupted_b64}:{parts[6]}"

        with pytest.raises(ValueError) as exc:
            decrypt_aes_256_gcm(tampered_token)

        assert "authentication verification or decryption failed" in str(exc.value)

    # -------------------------------------------------------------------------
    # 5. Modified authentication tag must fail
    # -------------------------------------------------------------------------
    def test_05_modified_auth_tag_fails(self):
        """
        5. Modified authentication tag must fail.
        """
        original = "192.168.25.44"
        token = encrypt_aes_256_gcm(original)
        parts = token.split(":")

        # Corrupt the 16-byte authentication tag
        tag_bytes = bytearray(base64url_decode(parts[6]))
        tag_bytes[-1] ^= 0x01  # Flip one bit in tag
        corrupted_tag = base64url_encode(bytes(tag_bytes))

        tampered_token = f"{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}:{parts[4]}:{parts[5]}:{corrupted_tag}"

        with pytest.raises(ValueError) as exc:
            decrypt_aes_256_gcm(tampered_token)

        assert "authentication verification or decryption failed" in str(exc.value)

    # -------------------------------------------------------------------------
    # 6. Wrong encryption key must fail
    # -------------------------------------------------------------------------
    def test_06_wrong_encryption_key_fails(self):
        """
        6. Wrong encryption key must fail.
        """
        km1 = KeyManager()
        km1.register_key("privacy-key-v1", "primary-super-secret-key-32-bt!!")
        
        km2 = KeyManager()
        km2.register_key("privacy-key-v1", "completely-different-wrong-key!!")

        original = "Sensitive Telemetry Location"
        token = encrypt_aes_256_gcm(original, key_id="privacy-key-v1", key_manager=km1)

        # Attempting decryption with km2 (which has the wrong key for the same key-id)
        with pytest.raises(ValueError) as exc:
            decrypt_aes_256_gcm(token, key_manager=km2)

        assert "authentication verification or decryption failed" in str(exc.value)

    # -------------------------------------------------------------------------
    # 7. HMAC-SHA-256 produces same pseudonym for same normalized input & secret
    # -------------------------------------------------------------------------
    def test_07_hmac_sha256_deterministic_pseudonym(self):
        """
        7. HMAC-SHA-256 must produce the same pseudonym for the same
           normalized input and secret.
        """
        ip = "192.168.25.44"
        ip_with_spaces = "  192.168.25.44 \n"

        p1 = pseudonymize_hmac_sha256(ip)
        p2 = pseudonymize_hmac_sha256(ip)
        p3 = pseudonymize_hmac_sha256(ip_with_spaces)

        assert is_valid_hmac_sha256_token(p1)
        assert p1 == p2, "HMAC-SHA-256 was not deterministic"
        assert p1 == p3, "HMAC-SHA-256 did not normalize input whitespace"

    # -------------------------------------------------------------------------
    # 8. Different IP addresses produce different HMAC values
    # -------------------------------------------------------------------------
    def test_08_different_ips_produce_different_hmac(self):
        """
        8. Different IP addresses must produce different HMAC values.
        """
        ips = [
            "192.168.25.44",
            "192.168.25.45",
            "10.0.0.1",
            "10.0.0.2",
            "172.16.0.100"
        ]

        pseudonyms = [pseudonymize_hmac_sha256(ip) for ip in ips]

        # All pseudonyms must be unique
        assert len(set(pseudonyms)) == len(ips), "Collisions found in HMAC pseudonyms"

    # -------------------------------------------------------------------------
    # 9. HMAC output must not contain the original IP
    # -------------------------------------------------------------------------
    def test_09_hmac_output_never_contains_original_ip(self):
        """
        9. HMAC output must not contain the original IP.
        """
        raw_ip = "192.168.25.44"
        token = pseudonymize_hmac_sha256(raw_ip)

        assert raw_ip not in token
        for octet in raw_ip.split("."):
            # Ensure full octet sequence is not leaked
            assert f"{octet}." not in token
        assert "192.168" not in token

    # -------------------------------------------------------------------------
    # 10. Final outgoing telemetry must not contain plaintext sensitive fields
    # -------------------------------------------------------------------------
    def test_10_outgoing_telemetry_contains_no_plaintext_sensitive_fields(self):
        """
        10. Final outgoing telemetry must not contain plaintext sensitive fields.
        """
        gateway = PrivacyGateway()
        raw_event = {
            "username": "Demo Student",
            "source_ip": "192.168.25.44",
            "latitude": 16.5062,
            "longitude": 80.6480,
            "device_id": "device-123",
            "password": "Password123!",
            "api_key": "AKIA1234567890ABCDEF",
            "event_type": "Port Scan",
            "severity": "HIGH"
        }

        protected = gateway.transform_event(raw_event)

        # Prohibited fields must be removed
        for forbidden in ["username", "source_ip", "latitude", "longitude", "password", "api_key"]:
            assert forbidden not in protected, f"Prohibited field '{forbidden}' found in protected payload"

        # Outgoing string representation must not contain plaintext secrets
        str_out = str(protected)
        assert "Demo Student" not in str_out
        assert "192.168.25.44" not in str_out
        assert "Password123!" not in str_out
        assert "AKIA1234567890ABCDEF" not in str_out

        # Pre-send validation must pass
        is_safe, violations, report = validate_presend_security(protected)
        assert is_safe, f"Pre-send validation failed: {violations}"
        assert report["checks_passed"] == 15

    # -------------------------------------------------------------------------
    # 11. Secrets must never appear in frontend JavaScript
    # -------------------------------------------------------------------------
    def test_11_secrets_never_in_frontend_javascript(self):
        """
        11. Secrets must never appear in frontend JavaScript.
        """
        frontend_dirs = [
            PROJECT_ROOT / "app",
            PROJECT_ROOT / "components",
            PROJECT_ROOT / "lib",
            PROJECT_ROOT / "frontend" / "app",
            PROJECT_ROOT / "frontend" / "components",
            PROJECT_ROOT / "frontend" / "lib",
        ]

        forbidden_patterns = [
            re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
            re.compile(r"PRIVACY_ENCRYPTION_KEY\s*=\s*['\"][a-zA-Z0-9_\-\+]{16,}['\"]"),
            re.compile(r"JWT_SECRET\s*=\s*['\"][a-zA-Z0-9_\-\+]{16,}['\"]"),
            re.compile(r"SECRET_KEY\s*=\s*['\"][a-zA-Z0-9_\-\+]{16,}['\"]"),
            re.compile(r"DATABASE_URL\s*=\s*['\"]postgres"),
        ]

        scanned_count = 0
        for fdir in frontend_dirs:
            if not fdir.exists():
                continue
            for ext in ("*.ts", "*.tsx", "*.js", "*.jsx"):
                for filepath in fdir.rglob(ext):
                    scanned_count += 1
                    content = filepath.read_text(encoding="utf-8", errors="ignore")
                    for pattern in forbidden_patterns:
                        match = pattern.search(content)
                        assert match is None, (
                            f"Hardcoded secret pattern found in frontend file: {filepath.relative_to(PROJECT_ROOT)}"
                        )

        assert scanned_count > 0, "No frontend files were scanned"

    # -------------------------------------------------------------------------
    # 12. Secrets must never appear in NEXT_PUBLIC_* variables
    # -------------------------------------------------------------------------
    def test_12_secrets_never_in_next_public_variables(self):
        """
        12. Secrets must never appear in NEXT_PUBLIC_* variables.
        """
        # Scan all .env files and code for NEXT_PUBLIC_* definitions
        allowed_public_prefixes = {
            "NEXT_PUBLIC_API_URL",
            "NEXT_PUBLIC_WS_URL",
            "NEXT_PUBLIC_DEMO_MODE",
            "NEXT_PUBLIC_APP_NAME",
            "NEXT_PUBLIC_BASE_PATH"
        }

        # Check .env files
        env_files = list(PROJECT_ROOT.glob(".env*"))
        for env_file in env_files:
            content = env_file.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("NEXT_PUBLIC_"):
                    var_name = line.split("=")[0].strip()
                    assert var_name in allowed_public_prefixes, (
                        f"Unrecognized or potentially sensitive NEXT_PUBLIC variable in {env_file.name}: {var_name}"
                    )
                    # Value must never contain 'key', 'secret', or 'password'
                    val = line.split("=", 1)[1].strip().lower()
                    for bad in ["secret", "private", "passwd", "key_id_vault"]:
                        assert bad not in val, f"Sensitive keyword in {var_name} value"

    # -------------------------------------------------------------------------
    # 13. Secrets must never appear in Git-tracked files
    # -------------------------------------------------------------------------
    def test_13_secrets_never_in_git_tracked_files(self):
        """
        13. Secrets must never appear in Git-tracked files.
        """
        # Run git ls-files to verify tracked files
        try:
            res = subprocess.run(
                ["git", "ls-files"],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                check=True
            )
            tracked_files = res.stdout.splitlines()
        except Exception:
            pytest.skip("Git command unavailable in this environment")

        prohibited_tracked = [
            ".env",
            ".env.local",
            ".env.production",
            ".env.development",
            "id_rsa",
            "id_ed25519",
            "threat_detection.db"
        ]

        for tf in tracked_files:
            tf_lower = tf.lower()
            for p in prohibited_tracked:
                assert tf_lower != p, f"Security violation: Prohibited file '{tf}' is tracked in git!"
            assert not tf_lower.endswith(".pem"), f"Security violation: PEM file '{tf}' tracked in git!"
            assert not tf_lower.endswith(".key"), f"Security violation: Key file '{tf}' tracked in git!"

    # -------------------------------------------------------------------------
    # 14. Cross-organization receiver sees only protected representation
    # -------------------------------------------------------------------------
    def test_14_cross_org_receiver_sees_only_protected_representation(self):
        """
        14. Cross-organization receiver must only see the protected
            representation.
            KL University -> Privacy Gateway -> Central Server -> GITAM
        """
        gateway = PrivacyGateway(organization_id="kl_university")

        raw_event = {
            "source_ip": "192.168.25.44",
            "latitude": 16.5062,
            "longitude": 80.6480,
            "sensitive_location": "KL Datacenter Vault",
            "event_type": "port_scan",
            "severity": "HIGH"
        }

        # 1. Privacy Gateway transforms raw event
        protected_payload = gateway.transform_event(raw_event)

        # 2. Central Server delivers to peer organization (GITAM)
        peer_view = {
            "protected_identifier": protected_payload["source"],
            "location_zone": protected_payload["location_zone"],
            "event_type": protected_payload["event_type"],
            "severity": protected_payload["severity"]
        }

        # Assert peer view has ZERO raw identifiers
        assert "192.168.25.44" not in str(peer_view)
        assert "16.5062" not in str(peer_view)
        assert "80.6480" not in str(peer_view)
        assert "KL Datacenter Vault" not in str(peer_view)

        # Assert peer view contains valid pseudonym and region identifier
        assert is_valid_hmac_sha256_token(peer_view["protected_identifier"])
        assert peer_view["location_zone"] == "AP_REGION_01"

    # -------------------------------------------------------------------------
    # 15. Public DEMO mode must never expose encryption keys or personal telemetry
    # -------------------------------------------------------------------------
    def test_15_public_demo_mode_never_exposes_keys_or_personal_telemetry(self):
        """
        15. Public DEMO mode must never expose encryption keys or
            plaintext personal telemetry.
        """
        from backend.app.api.v1.privacy import demonstrate_privacy_transformation

        gateway = PrivacyGateway()
        raw_demo_event = {
            "username": "Demo Student",
            "source_ip": "192.168.25.44",
            "latitude": 16.5062,
            "longitude": 80.6480,
            "sensitive_location": "Regional Datacenter KL",
            "device_id": "device-123",
            "event_type": "port_scan",
            "severity": "HIGH"
        }

        # Gateway transforms demo event
        demo_protected = gateway.transform_event(raw_demo_event)
        is_safe, violations, report = validate_presend_security(demo_protected)

        assert is_safe
        assert report["status"] == "SAFE"

        # Public representation verification
        public_demo_str = str(demo_protected)
        # AES key must NEVER appear in output
        real_key = os.getenv("PRIVACY_ENCRYPTION_KEY", "development-secret-encryption-key-32b!")
        assert real_key not in public_demo_str
        assert "AES hashing" not in public_demo_str  # Terminology accuracy

        # No raw personal telemetry in demo view
        assert "Demo Student" not in public_demo_str
        assert "192.168.25.44" not in public_demo_str
        assert "16.5062" not in public_demo_str
        assert "80.6480" not in public_demo_str
