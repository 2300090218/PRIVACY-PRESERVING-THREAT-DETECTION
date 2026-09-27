"""
Machine Learning Threat Detection Engine
Executes real scikit-learn inference against normalized flow features.
Returns prediction category, attack type, confidence, severity, and processing latency.
"""

import time
from typing import Dict, Any
try:
    import numpy as np
except ImportError:
    np = None

from backend.app.detection.feature_engineering import extract_flow_features
from backend.app.detection.model_manager import model_manager

SEVERITY_MAP = {
    "BENIGN": "LOW",
    "Port Scan": "MEDIUM",
    "Brute Force": "HIGH",
    "Botnet": "HIGH",
    "DDoS": "CRITICAL"
}

class MLDetector:
    def __init__(self):
        self.manager = model_manager

    def predict(self, features_dict: Dict[str, Any], metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Runs ML model inference on the telemetry event.
        Calculates execution latency and formats the standardized output.
        """
        start_time = time.perf_counter()

        if self.manager.model is None or self.manager.scaler is None or self.manager.label_encoder is None:
            # Fallback if model is not loaded: strictly reflect actual status per Section 9
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return {
                "prediction": "MODEL NOT TRAINED",
                "attack_type": "MODEL NOT TRAINED",
                "confidence": 0.0,
                "severity": "LOW",
                "model_version": "MODEL NOT TRAINED",
                "processing_latency_ms": round(latency_ms, 2)
            }

        # 1. Feature extraction
        feature_vector = extract_flow_features(features_dict, metadata)

        # 2. Scale features
        scaled_vector = self.manager.scaler.transform(feature_vector)

        # 3. Predict probabilities
        probabilities = self.manager.model.predict_proba(scaled_vector)[0]
        max_idx = int(np.argmax(probabilities))
        confidence = float(probabilities[max_idx])
        attack_type = str(self.manager.label_encoder.classes_[max_idx])

        # 4. Determine prediction status
        if attack_type == "BENIGN":
            prediction = "BENIGN"
            severity = "LOW"
        else:
            if confidence >= 0.70:
                prediction = "MALICIOUS"
            else:
                prediction = "SUSPICIOUS"
            severity = SEVERITY_MAP.get(attack_type, "HIGH")

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        # 5. Compute Explainable AI (XAI) Feature Attribution
        from backend.app.detection.feature_engineering import FEATURE_NAMES
        raw_vals = feature_vector[0]
        z_scores = np.abs(scaled_vector[0])
        importances = getattr(self.manager.model, "feature_importances_", np.ones(len(raw_vals)) / len(raw_vals))

        # Relative contribution: |z_score| * global_feature_importance
        contributions = z_scores * importances
        total_contrib = np.sum(contributions)
        if total_contrib > 0:
            norm_contribs = contributions / total_contrib
        else:
            norm_contribs = importances

        top_indices = np.argsort(norm_contribs)[::-1][:4]
        top_features = []
        for idx in top_indices:
            feat_name = FEATURE_NAMES[idx]
            weight = float(norm_contribs[idx])
            raw_val = float(raw_vals[idx])
            impact = "CRITICAL" if weight >= 0.35 else ("HIGH" if weight >= 0.20 else "MODERATE")
            top_features.append({
                "feature": feat_name,
                "contribution": round(weight, 4),
                "percentage": f"{weight * 100:.1f}%",
                "impact": impact,
                "value": round(raw_val, 2)
            })

        # Generate human-readable explanation summary
        if attack_type == "BENIGN":
            explanation = "Traffic flow metrics conform to nominal baseline distribution."
        else:
            primary_feat = top_features[0]["feature"].replace("_", " ")
            explanation = f"Flagged as {attack_type} driven by anomalous {primary_feat} ({top_features[0]['percentage']}) and {top_features[1]['feature'].replace('_', ' ')}."

        return {
            "prediction": prediction,
            "attack_type": attack_type,
            "confidence": round(confidence, 4),
            "severity": severity,
            "model_version": self.manager.active_version,
            "processing_latency_ms": round(latency_ms, 2),
            "all_probabilities": {
                cls_name: round(float(prob), 4)
                for cls_name, prob in zip(self.manager.label_encoder.classes_, probabilities)
            },
            "explainability": {
                "top_features": top_features,
                "summary": explanation
            }
        }

ml_detector = MLDetector()
