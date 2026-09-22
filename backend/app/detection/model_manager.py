"""
Model Manager
Tracks active model versions, loads serialized model weights/scalers,
and handles hot-swapping when federated aggregation updates the global model.
"""

import os
import json
import joblib
from typing import Dict, Any, Optional
from backend.app.config import settings

class ModelManager:
    def __init__(self, models_dir: str = settings.MODEL_DIR):
        self.models_dir = models_dir
        self.active_version = "global-v1"
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.metrics = {}
        self.load_active_model()

    def load_active_model(self, version: Optional[str] = None):
        """Loads model weights, scaler, and metadata from disk."""
        target_version = version or self.active_version
        model_path = os.path.join(self.models_dir, "baseline_rf.joblib")
        scaler_path = os.path.join(self.models_dir, "scaler.joblib")
        encoder_path = os.path.join(self.models_dir, "label_encoder.joblib")
        metrics_path = os.path.join(self.models_dir, "model_metrics_v1.json")

        # Check if version-specific artifact exists
        ver_model_path = os.path.join(self.models_dir, f"{target_version}_rf.joblib")
        ver_metrics_path = os.path.join(self.models_dir, f"{target_version}_metrics.json")

        if os.path.exists(ver_model_path):
            model_path = ver_model_path
        if os.path.exists(ver_metrics_path):
            metrics_path = ver_metrics_path

        if os.path.exists(model_path) and os.path.exists(scaler_path) and os.path.exists(encoder_path):
            try:
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self.label_encoder = joblib.load(encoder_path)
                self.active_version = target_version
                if os.path.exists(metrics_path):
                    with open(metrics_path, "r") as f:
                        self.metrics = json.load(f)
                print(f"[ModelManager] Loaded active model '{self.active_version}' from {model_path}")
            except Exception as e:
                print(f"[ModelManager] Error loading model artifacts: {e}")
        else:
            print(f"[ModelManager] Artifacts not found at {model_path}. Model will need initialization.")

    def set_active_model(self, model, version: str, metrics: Dict[str, Any]):
        """Hot-swaps the in-memory global model with a newly aggregated federated model."""
        self.model = model
        self.active_version = version
        self.metrics = metrics
        
        # Persist version
        versioned_path = os.path.join(self.models_dir, f"{version}_rf.joblib")
        metrics_path = os.path.join(self.models_dir, f"{version}_metrics.json")
        try:
            joblib.dump(model, versioned_path)
            with open(metrics_path, "w") as f:
                json.dump(metrics, f, indent=2)
            print(f"[ModelManager] Promoted and saved new global model '{version}'")
        except Exception as e:
            print(f"[ModelManager] Could not persist new model: {e}")

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "model_version": self.active_version,
            "is_loaded": self.model is not None,
            "algorithm": self.metrics.get("algorithm", "RandomForestClassifier"),
            "accuracy": self.metrics.get("accuracy"),
            "precision": self.metrics.get("precision"),
            "recall": self.metrics.get("recall"),
            "f1": self.metrics.get("f1"),
            "classes": self.label_encoder.classes_.tolist() if self.label_encoder is not None else [],
            "features": self.metrics.get("features", [])
        }

model_manager = ModelManager()
