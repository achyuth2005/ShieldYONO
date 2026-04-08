"""ML model loader and predictor.

Loads trained XGBoost (primary) and Logistic Regression (fallback) models.
Falls back to a heuristic scorer if no trained model is available.
"""

import logging
import os
import pickle
from pathlib import Path
from typing import Optional

from typing import Optional
from backend.app.services.feature_extractor import ML_FEATURE_NAMES

logger = logging.getLogger(__name__)

_xgb_model = None
_lr_model = None
_models_loaded = False


def _load_models():
    """Load saved models from disk."""
    global _xgb_model, _lr_model, _models_loaded

    if _models_loaded:
        return

    xgb_path = ML_MODELS_DIR / "xgboost_model.pkl"
    lr_path = ML_MODELS_DIR / "logistic_regression_model.pkl"

    if xgb_path.exists():
        try:
            with open(xgb_path, "rb") as f:
                _xgb_model = pickle.load(f)
            logger.info("XGBoost model loaded from %s", xgb_path)
        except Exception as e:
            logger.error("Failed to load XGBoost model: %s", e)

    if lr_path.exists():
        try:
            with open(lr_path, "rb") as f:
                _lr_model = pickle.load(f)
            logger.info("Logistic Regression model loaded from %s", lr_path)
        except Exception as e:
            logger.error("Failed to load LogReg model: %s", e)

    _models_loaded = True

    if _xgb_model is None and _lr_model is None:
        logger.warning(
            "No trained models found in %s. Using heuristic fallback.", ML_MODELS_DIR
        )


def predict_phishing_probability(feature_vector: list[float]) -> tuple[float, str]:
    """
    Predict phishing probability from feature vector.
    
    Returns:
        (probability, model_used) tuple
    """
    # Load models
    _load_models()

    if _xgb_model is not None or _lr_model is not None:
        try:
            import numpy as np
            features = np.array(feature_vector).reshape(1, -1)

            # Try XGBoost first
            if _xgb_model is not None:
                try:
                    prob = _xgb_model.predict_proba(features)[0][1]
                    return float(prob), "xgboost"
                except Exception as e:
                    logger.error("XGBoost prediction failed: %s", e)

            # Fallback to Logistic Regression
            if _lr_model is not None:
                try:
                    prob = _lr_model.predict_proba(features)[0][1]
                    return float(prob), "logistic_regression"
                except Exception as e:
                    logger.error("LogReg prediction failed: %s", e)
        except ImportError:
            logger.warning("ML libraries missing. Falling back to heuristic scorer.")

    # Heuristic fallback
    return _heuristic_score(feature_vector), "heuristic"


def _heuristic_score(feature_vector: list[float]) -> float:
    """
    Rule-based heuristic when no ML model is available.
    Uses key features to estimate phishing probability.
    """
    features = dict(zip(ML_FEATURE_NAMES, feature_vector))

    score = 0.3  # Base neutral-ish score

    # URL structure signals
    if features.get("has_ip_address", 0) == 1:
        score += 0.25
    if features.get("has_https", 1) == 0:
        score += 0.1
    if features.get("entropy", 0) > 4.5:
        score += 0.1
    if features.get("url_length", 0) > 100:
        score += 0.05
    if features.get("num_subdomains", 0) >= 3:
        score += 0.1
    if features.get("at_symbol", 0) == 1:
        score += 0.15

    # Domain intelligence
    age = features.get("domain_age_days", -1)
    if 0 <= age < 30:
        score += 0.15
    if features.get("tld_risk", 0) >= 1.0:
        score += 0.1
    if features.get("ssl_valid", 0) == 0:
        score += 0.05

    # Brand impersonation
    if features.get("has_brand_keyword", 0) == 1 and features.get("is_official_sbi", 0) == 0:
        score += 0.2
    if features.get("has_homoglyphs", 0) == 1:
        score += 0.15
    if features.get("brand_in_subdomain", 0) == 1:
        score += 0.15
    typo = features.get("typo_distance_min", -1)
    if 0 < typo <= 3:
        score += 0.15

    # Official SBI domain override
    if features.get("is_official_sbi", 0) == 1:
        score = 0.02

    return min(0.99, max(0.01, score))


def get_feature_importance() -> Optional[dict]:
    """Get feature importance from the loaded model."""
    _load_models()

    if _xgb_model is not None:
        try:
            importances = _xgb_model.feature_importances_
            return dict(zip(ML_FEATURE_NAMES, [float(x) for x in importances]))
        except Exception:
            pass

    if _lr_model is not None:
        try:
            coefficients = _lr_model.coef_[0]
            return dict(zip(ML_FEATURE_NAMES, [float(x) for x in coefficients]))
        except Exception:
            pass

    return None
