"""
Deterministic Risk Engine
Calculates quantifiable composite risk scores based on:
1. Machine Learning Confidence and Severity Weight (40%)
2. Rule Heuristic Matches and Severity Weight (30%)
3. Event Frequency / Burst Repetition Multiplier (15%)
4. Target Asset Criticality (15%)
Outputs: Deterministic 0-100 Float and Categorical Severity (LOW, MEDIUM, HIGH, CRITICAL).
"""

from typing import Dict, Any, List

SEVERITY_WEIGHTS = {
    "LOW": 25.0,
    "MEDIUM": 50.0,
    "HIGH": 75.0,
    "CRITICAL": 100.0,
}

ASSET_IMPORTANCE_MAP = {
    "public": 30.0,
    "workstation": 50.0,
    "internal_server": 75.0,
    "database": 95.0,
    "domain_controller": 100.0,
}

class RiskEngine:
    def calculate_risk(
        self,
        ml_prediction: Dict[str, Any],
        rule_matches: List[str],
        rule_severity: str,
        frequency_count: int = 1,
        asset_type: str = "internal_server"
    ) -> Dict[str, Any]:
        """
        Computes composite risk score and categorical tier.
        """
        # 1. ML Component (40%)
        ml_conf = float(ml_prediction.get("confidence", 0.5))
        ml_sev_str = ml_prediction.get("severity", "LOW")
        ml_sev_weight = SEVERITY_WEIGHTS.get(ml_sev_str, 25.0)
        # If model classified as BENIGN, suppress ML risk weight
        if ml_prediction.get("prediction") == "BENIGN":
            ml_component = 0.0
        else:
            ml_component = ml_conf * ml_sev_weight

        # 2. Rule Component (30%)
        rule_sev_weight = SEVERITY_WEIGHTS.get(rule_severity, 0.0)
        rule_multiplier = min(1.0, 0.4 + 0.3 * len(rule_matches)) if rule_matches else 0.0
        rule_component = rule_sev_weight * rule_multiplier

        # 3. Frequency / Repetition Component (15%)
        # Frequency scale: 1 event -> 10, 5 events -> 50, >=10 events -> 100
        frequency_component = min(100.0, max(1, frequency_count) * 10.0)

        # 4. Asset Criticality Component (15%)
        asset_weight = ASSET_IMPORTANCE_MAP.get(asset_type.lower(), 60.0)

        # Composite Calculation
        raw_score = (
            (0.40 * ml_component) +
            (0.30 * rule_component) +
            (0.15 * frequency_component) +
            (0.15 * asset_weight)
        )
        
        # If neither ML nor rules found a threat, cap at LOW threshold
        if ml_prediction.get("prediction") == "BENIGN" and not rule_matches:
            final_score = min(raw_score * 0.3, 20.0)
        else:
            final_score = min(100.0, max(0.0, raw_score))

        # Categorical Severity Classification per Section 11:
        # LOW: 0–39, MEDIUM: 40–69, HIGH: 70–89, CRITICAL: 90–100
        if final_score >= 90.0:
            severity = "CRITICAL"
        elif final_score >= 70.0:
            severity = "HIGH"
        elif final_score >= 40.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "risk_score": round(final_score, 1),
            "severity": severity,
            "components": {
                "ml_score": round(ml_component, 1),
                "rule_score": round(rule_component, 1),
                "frequency_score": round(frequency_component, 1),
                "asset_criticality": round(asset_weight, 1)
            },
            "formula": "Risk = 0.4*ML + 0.3*Rule + 0.15*Freq + 0.15*Asset"
        }

risk_engine = RiskEngine()
