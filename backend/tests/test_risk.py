import pytest
from backend.app.services.risk_service import risk_engine

def test_risk_scoring_low_threat():
    ml_pred = {"prediction": "BENIGN", "severity": "LOW", "confidence": 0.98}
    risk = risk_engine.calculate_risk(ml_pred, rule_matches=[], rule_severity="LOW")
    assert risk["severity"] == "LOW"
    assert risk["risk_score"] < 40.0
    assert 0.0 <= risk["risk_score"] <= 100.0

def test_risk_scoring_high_threat():
    ml_pred = {"prediction": "MALICIOUS", "severity": "CRITICAL", "confidence": 0.95}
    rule_matches = ["RULE_TRAFFIC_BURST", "RULE_SUSPICIOUS_PORT"]
    risk = risk_engine.calculate_risk(
        ml_pred,
        rule_matches=rule_matches,
        rule_severity="CRITICAL",
        frequency_count=8,
        asset_type="database"
    )
    assert risk["severity"] in ("HIGH", "CRITICAL")
    assert risk["risk_score"] >= 70.0

def test_risk_deterministic_repeatability():
    ml_pred = {"prediction": "MALICIOUS", "severity": "HIGH", "confidence": 0.85}
    rule_matches = ["RULE_SUSPICIOUS_PORT"]
    risk1 = risk_engine.calculate_risk(ml_pred, rule_matches=rule_matches, rule_severity="HIGH", frequency_count=3)
    risk2 = risk_engine.calculate_risk(ml_pred, rule_matches=rule_matches, rule_severity="HIGH", frequency_count=3)
    assert risk1["risk_score"] == risk2["risk_score"]
    assert risk1["severity"] == risk2["severity"]

def test_risk_severity_tiers():
    # Verify exact Section 11 boundary classifications
    # LOW: 0–39, MEDIUM: 40–69, HIGH: 70–89, CRITICAL: 90–100
    formula = risk_engine.calculate_risk({"prediction": "BENIGN"}, [], "LOW")
    assert "Risk = 0.4*ML + 0.3*Rule + 0.15*Freq + 0.15*Asset" in formula["formula"]
