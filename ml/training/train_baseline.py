"""
Baseline ML Intrusion Detection Training Pipeline
Trains an initial Random Forest model on the benchmark training pool, evaluates on held-out test data,
and persists the model artifacts and metrics as 'global-v1'.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ml.datasets.ids_dataset import generate_ids_benchmark_dataset, FEATURE_NAMES, ATTACK_CLASSES

def train_baseline_model(
    data_dir: str = "./ml/datasets",
    models_dir: str = "./ml/models",
    n_estimators: int = 100,
    random_state: int = 42
):
    os.makedirs(models_dir, exist_ok=True)
    eval_csv = os.path.join(data_dir, "ids_eval_heldout.csv")
    full_csv = os.path.join(data_dir, "ids_full_benchmark.csv")

    if not os.path.exists(eval_csv) or not os.path.exists(full_csv):
        print("Generating IDS benchmark dataset...")
        generate_ids_benchmark_dataset(output_dir=data_dir, total_samples=12000, seed=random_state)

    print("Loading datasets...")
    full_df = pd.read_csv(full_csv)
    test_df = pd.read_csv(eval_csv)

    # Train pool is full_df excluding the held-out test set
    train_df = full_df.iloc[len(test_df):].copy().reset_index(drop=True)

    X_train_raw = train_df[FEATURE_NAMES].values
    y_train_raw = train_df["label"].values

    X_test_raw = test_df[FEATURE_NAMES].values
    y_test_raw = test_df["label"].values

    # Clean any inf or nan values
    X_train_clean = np.nan_to_num(X_train_raw, nan=0.0, posinf=1e9, neginf=-1e9)
    X_test_clean = np.nan_to_num(X_test_raw, nan=0.0, posinf=1e9, neginf=-1e9)

    # Fit label encoder
    le = LabelEncoder()
    le.fit(ATTACK_CLASSES)
    y_train = le.transform(y_train_raw)
    y_test = le.transform(y_test_raw)

    # Strict featurization ordering: fit scaler ONLY on train data
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_clean)
    X_test = scaler.transform(X_test_clean)

    print(f"Training baseline Random Forest ({n_estimators} estimators) on {len(X_train)} samples...")
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=16,
        min_samples_split=4,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    print(f"Evaluating on {len(X_test)} held-out test samples...")
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)

    acc = float(accuracy_score(y_test, y_pred))
    prec_weighted = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec_weighted = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1_weighted = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    # Per-class metrics
    per_class = {}
    for idx, class_name in enumerate(le.classes_):
        class_mask = (y_test == idx)
        class_pred_mask = (y_pred == idx)
        tp = np.sum(class_mask & class_pred_mask)
        total_class = np.sum(class_mask)
        per_class[class_name] = {
            "support": int(total_class),
            "true_positive": int(tp),
            "accuracy": float(tp / total_class) if total_class > 0 else 0.0
        }

    metrics = {
        "model_version": "global-v1",
        "algorithm": "RandomForestClassifier",
        "sample_count_train": len(X_train),
        "sample_count_test": len(X_test),
        "accuracy": round(acc, 4),
        "precision": round(prec_weighted, 4),
        "recall": round(rec_weighted, 4),
        "f1": round(f1_weighted, 4),
        "confusion_matrix": cm,
        "classes": le.classes_.tolist(),
        "per_class": per_class,
        "features": FEATURE_NAMES
    }

    print("\n--- Actual Baseline Evaluation Metrics ---")
    print(f"Accuracy:  {metrics['accuracy']*100:.2f}%")
    print(f"Precision: {metrics['precision']*100:.2f}%")
    print(f"Recall:    {metrics['recall']*100:.2f}%")
    print(f"F1-Score:  {metrics['f1']*100:.2f}%")

    model_path = os.path.join(models_dir, "baseline_rf.joblib")
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    encoder_path = os.path.join(models_dir, "label_encoder.joblib")
    metrics_path = os.path.join(models_dir, "model_metrics_v1.json")

    joblib.dump(clf, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(le, encoder_path)

    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"Model artifacts successfully persisted to {models_dir}")
    return metrics

if __name__ == "__main__":
    train_baseline_model()
