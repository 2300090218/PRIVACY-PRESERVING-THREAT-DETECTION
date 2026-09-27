"""
Automated Test Suite for Demo Organizations & Cross-Organization Threat Sharing
Covers All 15 Required Tests from Part 6:
1. Both demo organizations load.
2. Synthetic people records load.
3. Duplicate organization seeding is prevented.
4. KL-to-GITAM sharing works.
5. GITAM-to-KL sharing works.
6. Raw IP is not transmitted when prohibited.
7. Precise GPS is not transmitted when prohibited.
8. AES-GCM encryption/decryption works.
9. Modified ciphertext fails authentication.
10. A wrong key fails decryption.
11. AES-GCM uses a fresh nonce.
12. HMAC pseudonyms are stable for the same input and key.
13. Credentials are blocked before transmission.
14. The receiver cannot access the original sensitive data.
15. Public demo mode cannot access private organization data.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.future import select
from sqlalchemy import func

from backend.tests.conftest import TestingSessionLocal
from backend.app.models.all_models import Organization, SyntheticRecord, User
from backend.app.main import initialize_platform
from privacy_gateway.encryption import (
    KeyManager,
    encrypt_aes_256_gcm,
    decrypt_aes_256_gcm,
    pseudonymize_hmac_sha256,
    coarsen_geolocation,
    base64url_encode,
    base64url_decode,
    AES_GCM_TOKEN_REGEX
)
from privacy_gateway.leakage_prevention import validate_presend_security


@pytest.fixture(autouse=True)
async def seed_demo_data():
    """Ensure demo organizations and synthetic records are seeded in test database."""
    async with TestingSessionLocal() as session:
        # Check if demo orgs exist
        res = await session.execute(
            select(Organization).where(Organization.org_id.in_(["demo_klef_vijayawada", "demo_gitam_visakhapatnam"]))
        )
        existing = {o.org_id: o for o in res.scalars().all()}

        if "demo_klef_vijayawada" not in existing:
            klef = Organization(
                org_id="demo_klef_vijayawada",
                name="KL University / KLEF",
                location="Vijayawada, Andhra Pradesh, India",
                status="ACTIVE",
                is_demo=True,
                demo_status="DEMO",
                security_status="ACTIVE / SHIELDED",
                contact_email="infosec@kluniversity.edu.in",
                record_counts={
                    "students": 15420,
                    "faculty": 1120,
                    "it_staff": 85,
                    "security_staff": 42,
                    "administrators": 28,
                    "security_agents": 14,
                    "total_records": 16709
                }
            )
            session.add(klef)

        if "demo_gitam_visakhapatnam" not in existing:
            gitam = Organization(
                org_id="demo_gitam_visakhapatnam",
                name="GITAM",
                location="Visakhapatnam, Andhra Pradesh, India",
                status="ACTIVE",
                is_demo=True,
                demo_status="DEMO",
                security_status="ACTIVE / SHIELDED",
                contact_email="infosec@gitam.edu",
                record_counts={
                    "students": 12850,
                    "faculty": 940,
                    "it_staff": 65,
                    "security_staff": 38,
                    "administrators": 24,
                    "security_agents": 12,
                    "total_records": 13929
                }
            )
            session.add(gitam)

        # Seed sample synthetic records
        sample_records = [
            # KL University records
            SyntheticRecord(record_id="REC-KLEF-STU-01", organization_id="demo_klef_vijayawada", role="Student", pseudonym="STU-KLEF-7A91", department="Computer Science & Engineering", campus="Vaddeswaram, Vijayawada", status="Active", is_synthetic=True),
            SyntheticRecord(record_id="REC-KLEF-FAC-01", organization_id="demo_klef_vijayawada", role="Faculty", pseudonym="FAC-KLEF-11B2", department="Cyber Security & IoT", campus="Vaddeswaram, Vijayawada", status="Active", is_synthetic=True),
            SyntheticRecord(record_id="REC-KLEF-IT-01", organization_id="demo_klef_vijayawada", role="IT Staff", pseudonym="IT-KLEF-40C9", department="Enterprise IT Services", campus="Vaddeswaram, Vijayawada", status="Active", is_synthetic=True),
            SyntheticRecord(record_id="REC-KLEF-SEC-01", organization_id="demo_klef_vijayawada", role="Security Staff", pseudonym="SEC-KLEF-88F4", department="Campus Security Operations", campus="Vaddeswaram, Vijayawada", status="Active", is_synthetic=True),
            SyntheticRecord(record_id="REC-KLEF-ADM-01", organization_id="demo_klef_vijayawada", role="Administrator", pseudonym="ADM-KLEF-01D5", department="Academic Administration", campus="Vaddeswaram, Vijayawada", status="Active", is_synthetic=True),
            SyntheticRecord(record_id="REC-KLEF-AGN-01", organization_id="demo_klef_vijayawada", role="Security Agent", pseudonym="AGN-KLEF-001A", department="Edge SOC Sensor Node", campus="Vaddeswaram, Vijayawada", status="Active", is_synthetic=True),

            # GITAM records
            SyntheticRecord(record_id="REC-GITAM-STU-01", organization_id="demo_gitam_visakhapatnam", role="Student", pseudonym="STU-GITAM-3C84", department="School of Technology", campus="Rushikonda, Visakhapatnam", status="Active", is_synthetic=True),
            SyntheticRecord(record_id="REC-GITAM-FAC-01", organization_id="demo_gitam_visakhapatnam", role="Faculty", pseudonym="FAC-GITAM-92A3", department="Information Technology", campus="Rushikonda, Visakhapatnam", status="Active", is_synthetic=True),
            SyntheticRecord(record_id="REC-GITAM-IT-01", organization_id="demo_gitam_visakhapatnam", role="IT Staff", pseudonym="IT-GITAM-55E1", department="Network Operations Center", campus="Rushikonda, Visakhapatnam", status="Active", is_synthetic=True),
            SyntheticRecord(record_id="REC-GITAM-SEC-01", organization_id="demo_gitam_visakhapatnam", role="Security Staff", pseudonym="SEC-GITAM-77D2", department="Threat Intel & Monitoring", campus="Rushikonda, Visakhapatnam", status="Active", is_synthetic=True),
            SyntheticRecord(record_id="REC-GITAM-ADM-01", organization_id="demo_gitam_visakhapatnam", role="Administrator", pseudonym="ADM-GITAM-12B6", department="University Registrar", campus="Rushikonda, Visakhapatnam", status="Active", is_synthetic=True),
            SyntheticRecord(record_id="REC-GITAM-AGN-01", organization_id="demo_gitam_visakhapatnam", role="Security Agent", pseudonym="AGN-GITAM-001B", department="Campus Boundary Firewall Sensor", campus="Rushikonda, Visakhapatnam", status="Active", is_synthetic=True),
        ]
        session.add_all(sample_records)
        await session.commit()


# ==============================================================================
# TEST 1: Both demo organizations load.
# ==============================================================================
@pytest.mark.asyncio
async def test_both_demo_organizations_load(async_client: AsyncClient):
    res = await async_client.get("/api/v1/organizations")
    assert res.status_code == 200
    orgs = res.json()
    org_map = {o["org_id"]: o for o in orgs}

    # KL University verification
    assert "demo_klef_vijayawada" in org_map
    klef = org_map["demo_klef_vijayawada"]
    assert "KL University" in klef["name"]
    assert "Vijayawada" in klef["location"]
    assert klef["is_demo"] is True
    assert klef["demo_status"] == "DEMO"
    assert klef["security_status"] == "ACTIVE / SHIELDED"

    # GITAM verification
    assert "demo_gitam_visakhapatnam" in org_map
    gitam = org_map["demo_gitam_visakhapatnam"]
    assert "GITAM" in gitam["name"]
    assert "Visakhapatnam" in gitam["location"]
    assert gitam["is_demo"] is True
    assert gitam["demo_status"] == "DEMO"
    assert gitam["security_status"] == "ACTIVE / SHIELDED"


# ==============================================================================
# TEST 2: Synthetic people records load.
# ==============================================================================
@pytest.mark.asyncio
async def test_synthetic_people_records_load(async_client: AsyncClient):
    # KL University records endpoint
    res_klef = await async_client.get("/api/v1/organizations/demo_klef_vijayawada/records")
    assert res_klef.status_code == 200
    data_klef = res_klef.json()
    assert data_klef["org_id"] == "demo_klef_vijayawada"
    records_klef = data_klef["records"]
    assert len(records_klef) >= 6

    roles_klef = {r["role"] for r in records_klef}
    assert {"Student", "Faculty", "IT Staff", "Security Staff", "Administrator", "Security Agent"}.issubset(roles_klef)
    for rec in records_klef:
        assert rec["is_synthetic"] is True

    # GITAM records endpoint
    res_gitam = await async_client.get("/api/v1/organizations/demo_gitam_visakhapatnam/records")
    assert res_gitam.status_code == 200
    data_gitam = res_gitam.json()
    assert data_gitam["org_id"] == "demo_gitam_visakhapatnam"
    records_gitam = data_gitam["records"]
    assert len(records_gitam) >= 6

    roles_gitam = {r["role"] for r in records_gitam}
    assert {"Student", "Faculty", "IT Staff", "Security Staff", "Administrator", "Security Agent"}.issubset(roles_gitam)
    for rec in records_gitam:
        assert rec["is_synthetic"] is True


# ==============================================================================
# TEST 3: Duplicate organization seeding is prevented.
# ==============================================================================
@pytest.mark.asyncio
async def test_duplicate_organization_seeding_prevented():
    # Calling initialize_platform twice should not duplicate demo organizations
    await initialize_platform()
    await initialize_platform()

    async with TestingSessionLocal() as session:
        klef_count = (await session.execute(
            select(func.count(Organization.id)).where(Organization.org_id == "demo_klef_vijayawada")
        )).scalar()
        gitam_count = (await session.execute(
            select(func.count(Organization.id)).where(Organization.org_id == "demo_gitam_visakhapatnam")
        )).scalar()

        assert klef_count == 1, "Duplicate KL University records detected in database"
        assert gitam_count == 1, "Duplicate GITAM records detected in database"


# ==============================================================================
# TEST 4: KL-to-GITAM sharing works.
# ==============================================================================
@pytest.mark.asyncio
async def test_kl_to_gitam_sharing_works(async_client: AsyncClient):
    payload = {
        "sender_org_id": "demo_klef_vijayawada",
        "receiver_org_id": "demo_gitam_visakhapatnam"
    }
    res = await async_client.post("/api/v1/privacy/cross-org-share", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["decision"] == "SEND"
    assert data["sender_organization"]["org_id"] == "demo_klef_vijayawada"
    assert data["receiver_organization"]["org_id"] == "demo_gitam_visakhapatnam"
    assert data["final_outgoing_payload"] is not None

    receiver_view = data["receiver_view"]
    assert receiver_view is not None
    assert receiver_view["receiver_org_id"] == "demo_gitam_visakhapatnam"
    assert "KL University" in receiver_view["received_from"]
    assert receiver_view["raw_ip_accessible"] is False
    assert receiver_view["raw_gps_accessible"] is False


# ==============================================================================
# TEST 5: GITAM-to-KL sharing works.
# ==============================================================================
@pytest.mark.asyncio
async def test_gitam_to_kl_sharing_works(async_client: AsyncClient):
    payload = {
        "sender_org_id": "demo_gitam_visakhapatnam",
        "receiver_org_id": "demo_klef_vijayawada"
    }
    res = await async_client.post("/api/v1/privacy/cross-org-share", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["decision"] == "SEND"
    assert data["sender_organization"]["org_id"] == "demo_gitam_visakhapatnam"
    assert data["receiver_organization"]["org_id"] == "demo_klef_vijayawada"
    assert data["final_outgoing_payload"] is not None

    receiver_view = data["receiver_view"]
    assert receiver_view is not None
    assert receiver_view["receiver_org_id"] == "demo_klef_vijayawada"
    assert "GITAM" in receiver_view["received_from"]
    assert receiver_view["raw_ip_accessible"] is False
    assert receiver_view["raw_gps_accessible"] is False


# ==============================================================================
# TEST 6: Raw IP is not transmitted when prohibited.
# ==============================================================================
@pytest.mark.asyncio
async def test_raw_ip_not_transmitted_when_prohibited(async_client: AsyncClient):
    raw_ip = "172.16.42.88"
    res = await async_client.post("/api/v1/privacy/cross-org-share", json={
        "sender_org_id": "demo_klef_vijayawada",
        "receiver_org_id": "demo_gitam_visakhapatnam"
    })
    assert res.status_code == 200
    data = res.json()
    outgoing = data["final_outgoing_payload"]

    # Verify raw IP is nowhere in outgoing payload values
    outgoing_values_str = str(outgoing)
    assert raw_ip not in outgoing_values_str
    assert "source_ip" not in outgoing

    # Verify source is HMAC-SHA-256 token
    assert outgoing["source"].startswith("hmac-sha256:v1:")

    # When raw IP is explicitly injected into transmission, pre-send check BLOCKS it
    blocked_res = await async_client.post("/api/v1/privacy/cross-org-share", json={
        "sender_org_id": "demo_klef_vijayawada",
        "receiver_org_id": "demo_gitam_visakhapatnam",
        "inject_sensitive_field": "raw_ip"
    })
    assert blocked_res.status_code == 200
    blocked_data = blocked_res.json()
    assert blocked_data["decision"] == "BLOCK"
    assert blocked_data["final_outgoing_payload"] is None
    assert blocked_data["receiver_view"] is None


# ==============================================================================
# TEST 7: Precise GPS is not transmitted when prohibited.
# ==============================================================================
@pytest.mark.asyncio
async def test_precise_gps_not_transmitted_when_prohibited(async_client: AsyncClient):
    res = await async_client.post("/api/v1/privacy/cross-org-share", json={
        "sender_org_id": "demo_klef_vijayawada",
        "receiver_org_id": "demo_gitam_visakhapatnam"
    })
    assert res.status_code == 200
    data = res.json()
    outgoing = data["final_outgoing_payload"]

    # Verify latitude/longitude coordinates are stripped from outgoing payload
    assert "latitude" not in outgoing
    assert "longitude" not in outgoing
    assert "exact_location" not in outgoing

    # Location is coarsened to generalized region code
    assert outgoing["location_zone"] == "AP_REGION_01"

    # When precise GPS is injected into transmission, pre-send check BLOCKS it
    blocked_res = await async_client.post("/api/v1/privacy/cross-org-share", json={
        "sender_org_id": "demo_klef_vijayawada",
        "receiver_org_id": "demo_gitam_visakhapatnam",
        "inject_sensitive_field": "precise_gps"
    })
    assert blocked_res.status_code == 200
    blocked_data = blocked_res.json()
    assert blocked_data["decision"] == "BLOCK"
    assert blocked_data["final_outgoing_payload"] is None


# ==============================================================================
# TEST 8: AES-GCM encryption/decryption works.
# ==============================================================================
def test_aes_gcm_encryption_decryption_works():
    plaintext = "DC-KLEF-VJA-SEC-01:ConfidentialInfrastructure"
    token = encrypt_aes_256_gcm(plaintext, key_id="privacy-key-v1")

    # Format verification
    assert token.startswith("enc:aes256gcm:v1:privacy-key-v1:")
    assert plaintext not in token

    # Decrypt round trip
    decrypted = decrypt_aes_256_gcm(token)
    assert decrypted == plaintext


# ==============================================================================
# TEST 9: Modified ciphertext fails authentication.
# ==============================================================================
def test_modified_ciphertext_fails_authentication():
    plaintext = "SensitiveUniversityAssetTelemetry"
    token = encrypt_aes_256_gcm(plaintext, key_id="privacy-key-v1")

    parts = token.split(":")
    assert len(parts) == 7
    # parts: ["enc", "aes256gcm", "v1", key_id, nonce, ciphertext, auth_tag]
    cipher_bytes = bytearray(base64url_decode(parts[5]))
    # Mutate last byte of ciphertext
    cipher_bytes[-1] ^= 0xFF
    tampered_cipher = base64url_encode(bytes(cipher_bytes))
    tampered_token = f"enc:aes256gcm:v1:{parts[3]}:{parts[4]}:{tampered_cipher}:{parts[6]}"

    with pytest.raises(ValueError, match="authentication verification or decryption failed"):
        decrypt_aes_256_gcm(tampered_token)


# ==============================================================================
# TEST 10: A wrong key fails decryption.
# ==============================================================================
def test_wrong_key_fails_decryption():
    km_original = KeyManager(primary_key="primary-secret-key-for-test-32bytes!")
    km_wrong = KeyManager(primary_key="completely-different-wrong-key-32b!!")

    plaintext = "ClassifiedInterTenantTelemetry"
    token = encrypt_aes_256_gcm(plaintext, key_id="privacy-key-v1", key_manager=km_original)

    with pytest.raises(ValueError, match="authentication verification or decryption failed"):
        decrypt_aes_256_gcm(token, key_manager=km_wrong)


# ==============================================================================
# TEST 11: AES-GCM uses a fresh nonce.
# ==============================================================================
def test_aes_gcm_uses_fresh_nonce():
    plaintext = "IdenticalPlaintextSecurityEvent"
    tokens = [encrypt_aes_256_gcm(plaintext, key_id="privacy-key-v1") for _ in range(5)]

    nonces = set()
    ciphertexts = set()

    for token in tokens:
        parts = token.split(":")
        nonce = parts[4]
        ciphertext = parts[5]
        nonces.add(nonce)
        ciphertexts.add(ciphertext)

    # Every single encryption must use a distinct 12-byte nonce
    assert len(nonces) == 5, "Nonce reuse detected in AES-256-GCM"
    assert len(ciphertexts) == 5, "Identical ciphertexts detected for repeated encryption"


# ==============================================================================
# TEST 12: HMAC pseudonyms are stable for the same input and key.
# ==============================================================================
def test_hmac_pseudonyms_stable_for_same_input_and_key():
    ip_1 = "172.16.42.88"
    ip_2 = "10.200.14.5"
    salt = "academic-cross-tenant-shared-salt-2026"

    pseudo_1a = pseudonymize_hmac_sha256(ip_1, secret=salt)
    pseudo_1b = pseudonymize_hmac_sha256(ip_1, secret=salt)
    pseudo_2 = pseudonymize_hmac_sha256(ip_2, secret=salt)

    # Stable & deterministic
    assert pseudo_1a == pseudo_1b
    assert pseudo_1a.startswith("hmac-sha256:v1:")
    # Different inputs produce different pseudonyms
    assert pseudo_1a != pseudo_2
    # Output does not leak the raw IP
    assert ip_1 not in pseudo_1a
    assert ip_2 not in pseudo_2


# ==============================================================================
# TEST 13: Credentials are blocked before transmission.
# ==============================================================================
@pytest.mark.asyncio
async def test_credentials_blocked_before_transmission(async_client: AsyncClient):
    # Test 1: Injected password
    res_pass = await async_client.post("/api/v1/privacy/cross-org-share", json={
        "sender_org_id": "demo_klef_vijayawada",
        "receiver_org_id": "demo_gitam_visakhapatnam",
        "inject_sensitive_field": "password"
    })
    assert res_pass.status_code == 200
    data_pass = res_pass.json()
    assert data_pass["decision"] == "BLOCK"
    assert "password" in data_pass["reason"].lower() or "violation" in data_pass["reason"].lower()
    assert data_pass["final_outgoing_payload"] is None
    assert data_pass["receiver_view"] is None

    # Test 2: Injected JWT
    res_jwt = await async_client.post("/api/v1/privacy/cross-org-share", json={
        "sender_org_id": "demo_klef_vijayawada",
        "receiver_org_id": "demo_gitam_visakhapatnam",
        "inject_sensitive_field": "jwt"
    })
    assert res_jwt.status_code == 200
    data_jwt = res_jwt.json()
    assert data_jwt["decision"] == "BLOCK"
    assert data_jwt["final_outgoing_payload"] is None
    assert data_jwt["receiver_view"] is None


# ==============================================================================
# TEST 14: The receiver cannot access the original sensitive data.
# ==============================================================================
@pytest.mark.asyncio
async def test_receiver_cannot_access_original_sensitive_data(async_client: AsyncClient):
    res = await async_client.post("/api/v1/privacy/cross-org-share", json={
        "sender_org_id": "demo_klef_vijayawada",
        "receiver_org_id": "demo_gitam_visakhapatnam"
    })
    assert res.status_code == 200
    data = res.json()
    receiver_view = data["receiver_view"]

    assert receiver_view is not None
    assert receiver_view["raw_ip_accessible"] is False
    assert receiver_view["raw_gps_accessible"] is False
    assert receiver_view["raw_identity_accessible"] is False
    assert receiver_view["can_decrypt_without_key"] is False

    # Check that receiver only receives pseudonymized and coarsened representations
    assert receiver_view["protected_identifier"].startswith("hmac-sha256:v1:")
    assert receiver_view["location_zone"] == "AP_REGION_01"
    assert receiver_view["encrypted_datacenter_token"].startswith("enc:aes256gcm:v1:")


# ==============================================================================
# TEST 15: Public demo mode cannot access private organization data.
# ==============================================================================
@pytest.mark.asyncio
async def test_public_demo_mode_cannot_access_private_organization_data(async_client: AsyncClient):
    # 1. Unauthenticated requests to private organization audit logs must be rejected with 401
    res_audit = await async_client.get("/api/v1/audit-logs")
    assert res_audit.status_code == 401, "Private organization audit trail must require authentication"

    # 2. Unauthenticated requests to private user/operator identity must be rejected with 401
    res_me = await async_client.get("/api/v1/auth/me")
    assert res_me.status_code == 401, "Private organization session identity must require authentication"

    # 3. Public demo mode sharing view must redact all private organization raw network and geolocation data
    res_share = await async_client.post("/api/v1/privacy/cross-org-share", json={
        "sender_org_id": "demo_klef_vijayawada",
        "receiver_org_id": "demo_gitam_visakhapatnam"
    })
    assert res_share.status_code == 200
    share_data = res_share.json()
    receiver_view = share_data["receiver_view"]

    # Strict isolation verification
    assert receiver_view["raw_ip_accessible"] is False
    assert receiver_view["raw_gps_accessible"] is False
    assert receiver_view["raw_identity_accessible"] is False
    assert receiver_view["can_decrypt_without_key"] is False
    assert "source_ip" not in share_data["final_outgoing_payload"]
    assert "latitude" not in share_data["final_outgoing_payload"]
    assert "username" not in share_data["final_outgoing_payload"]

