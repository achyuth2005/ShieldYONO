"""Model training pipeline.

Trains XGBoost (primary) and Logistic Regression (fallback) models
on extracted features. Includes train/val/test split, evaluation,
and model artifact saving.
"""

import csv
import pickle
import sys
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.feature_extractor import ML_FEATURE_NAMES

SEED = 42
MODELS_DIR = PROJECT_ROOT / "ml" / "models"
EVAL_DIR = PROJECT_ROOT / "ml" / "evaluation"


def load_features(path: str = "data/processed/features_dataset.csv"):
    """Load feature dataset from CSV."""
    filepath = Path(path)
    if not filepath.exists():
        print(f"❌ Feature file not found: {filepath}")
        print("   Run 'python scripts/extract_features.py' first")
        sys.exit(1)

    with open(filepath) as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    X = np.array([
        [float(row.get(name, 0)) for name in ML_FEATURE_NAMES]
        for row in rows
    ])
    y = np.array([int(row["label"]) for row in rows])

    return X, y


def train_and_evaluate():
    """Full training pipeline."""
    print("=" * 60)
    print("🛡️  ShieldYONO — Model Training Pipeline")
    print("=" * 60)

    # 1. Load data
    print("\n📂 Loading features...")
    X, y = load_features()
    print(f"   Samples: {len(X)}")
    print(f"   Features: {X.shape[1]}")
    print(f"   Phishing: {sum(y)} ({100 * sum(y) / len(y):.1f}%)")
    print(f"   Legitimate: {len(y) - sum(y)} ({100 * (len(y) - sum(y)) / len(y):.1f}%)")

    # 2. Handle missing values (-1 for unknown)
    # Replace -1s in domain_age_days and ssl_age_days with median of known values
    for i, name in enumerate(ML_FEATURE_NAMES):
        if name in ("domain_age_days", "ssl_age_days"):
            col = X[:, i]
            known = col[col >= 0]
            median = np.median(known) if len(known) > 0 else 365
            X[:, i] = np.where(col < 0, median, col)

    # 3. Train/Val/Test split (60/20/20) - stratified
    # First split: 80% train+val, 20% test
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )
    # Second split: 75% train, 25% val (of the 80% = 60/20 overall)
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval, test_size=0.25, random_state=SEED, stratify=y_trainval
    )

    print(f"\n📊 Data splits:")
    print(f"   Train: {len(X_train)} samples")
    print(f"   Val:   {len(X_val)} samples")
    print(f"   Test:  {len(X_test)} samples")

    # 4. Feature scaling (for Logistic Regression)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    # ============================================================
    # 5. Train XGBoost
    # ============================================================
    print("\n🌲 Training XGBoost...")
    try:
        from xgboost import XGBClassifier

        # Calculate scale_pos_weight for class imbalance
        n_pos = sum(y_train)
        n_neg = len(y_train) - n_pos
        scale_pos_weight = n_neg / n_pos if n_pos > 0 else 1

        xgb_model = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            scale_pos_weight=scale_pos_weight,
            min_child_weight=3,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_alpha=0.1,
            reg_lambda=1.0,
            random_state=SEED,
            eval_metric="logloss",
            use_label_encoder=False,
        )

        xgb_model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=False,
        )

        # Evaluate on validation set
        print("\n  📈 XGBoost Validation Results:")
        _evaluate(xgb_model, X_val, y_val, "XGBoost-Val")

        # Evaluate on test set
        print("\n  📈 XGBoost Test Results:")
        _evaluate(xgb_model, X_test, y_test, "XGBoost-Test")

        # Save model
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        xgb_path = MODELS_DIR / "xgboost_model.pkl"
        with open(xgb_path, "wb") as f:
            pickle.dump(xgb_model, f)
        print(f"\n  💾 XGBoost model saved → {xgb_path}")

        # Feature importance
        _print_feature_importance(xgb_model, "XGBoost")

    except ImportError:
        print("  ⚠️  XGBoost not installed, skipping...")
        xgb_model = None

    # ============================================================
    # 6. Train Logistic Regression
    # ============================================================
    print("\n📐 Training Logistic Regression...")

    lr_model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",  # Handle imbalance
        C=0.5,
        random_state=SEED,
        solver="lbfgs",
    )

    lr_model.fit(X_train_scaled, y_train)

    print("\n  📈 LogReg Validation Results:")
    _evaluate(lr_model, X_val_scaled, y_val, "LogReg-Val")

    print("\n  📈 LogReg Test Results:")
    _evaluate(lr_model, X_test_scaled, y_test, "LogReg-Test")

    # Save model
    lr_path = MODELS_DIR / "logistic_regression_model.pkl"
    with open(lr_path, "wb") as f:
        pickle.dump(lr_model, f)
    print(f"\n  💾 LogReg model saved → {lr_path}")

    # Save scaler
    scaler_path = MODELS_DIR / "scaler.pkl"
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    print(f"  💾 Scaler saved → {scaler_path}")

    # ============================================================
    # 7. Save evaluation report
    # ============================================================
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    report_path = EVAL_DIR / "training_report.txt"
    with open(report_path, "w") as f:
        f.write("ShieldYONO Model Training Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Total samples: {len(X)}\n")
        f.write(f"Train: {len(X_train)} | Val: {len(X_val)} | Test: {len(X_test)}\n\n")

        if xgb_model:
            f.write("XGBoost Test Results:\n")
            y_pred = xgb_model.predict(X_test)
            f.write(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))
            f.write("\n\n")

        f.write("Logistic Regression Test Results:\n")
        y_pred = lr_model.predict(X_test_scaled)
        f.write(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))

    print(f"\n📝 Report saved → {report_path}")
    print("\n✅ Training complete!")


def _evaluate(model, X, y, name: str):
    """Print evaluation metrics."""
    y_pred = model.predict(X)
    y_prob = model.predict_proba(X)[:, 1]

    acc = accuracy_score(y, y_pred)
    prec = precision_score(y, y_pred, zero_division=0)
    rec = recall_score(y, y_pred, zero_division=0)
    f1 = f1_score(y, y_pred, zero_division=0)
    auc = roc_auc_score(y, y_prob)
    cm = confusion_matrix(y, y_pred)

    print(f"    Accuracy:  {acc:.4f}")
    print(f"    Precision: {prec:.4f}")
    print(f"    Recall:    {rec:.4f}  ← (phishing detection rate)")
    print(f"    F1-Score:  {f1:.4f}")
    print(f"    AUC-ROC:   {auc:.4f}")
    print(f"    Confusion Matrix:")
    print(f"      TN={cm[0][0]:4d}  FP={cm[0][1]:4d}")
    print(f"      FN={cm[1][0]:4d}  TP={cm[1][1]:4d}")


def _print_feature_importance(model, name: str):
    """Print top features by importance."""
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    print(f"\n  🔍 Top 10 Features ({name}):")
    for i in range(min(10, len(indices))):
        idx = indices[i]
        print(f"    {i+1:2d}. {ML_FEATURE_NAMES[idx]:30s} {importances[idx]:.4f}")


if __name__ == "__main__":
    train_and_evaluate()
