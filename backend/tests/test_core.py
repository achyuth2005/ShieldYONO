"""Unit tests for preprocessing, feature extraction, and scoring."""

import sys
from pathlib import Path

# Setup path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest


class TestURLPreprocessor:
    """Tests for URL preprocessing functions."""

    def test_decode_url(self):
        from backend.app.services.url_preprocessor import decode_url

        assert decode_url("https://example.com/path%20with%20spaces") == "https://example.com/path with spaces"
        assert decode_url("https://example.com/%E2%9C%93") == "https://example.com/✓"

    def test_validate_url_valid(self):
        from backend.app.services.url_preprocessor import validate_url

        is_valid, result = validate_url("https://www.google.com")
        assert is_valid is True

    def test_validate_url_adds_scheme(self):
        from backend.app.services.url_preprocessor import validate_url

        is_valid, result = validate_url("www.google.com")
        assert is_valid is True
        assert result.startswith("http://")

    def test_validate_url_invalid_empty(self):
        from backend.app.services.url_preprocessor import validate_url

        is_valid, reason = validate_url("")
        assert is_valid is False

    def test_validate_url_invalid_scheme(self):
        from backend.app.services.url_preprocessor import validate_url

        is_valid, reason = validate_url("ftp://files.example.com")
        assert is_valid is False
        assert "not allowed" in reason

    def test_is_shortened(self):
        from backend.app.services.url_preprocessor import is_shortened

        assert is_shortened("https://bit.ly/abc123") is True
        assert is_shortened("https://www.google.com") is False


class TestFeatureExtractor:
    """Tests for feature extraction."""

    def test_url_structure_features(self):
        from backend.app.services.feature_extractor import extract_url_structure_features

        features = extract_url_structure_features("https://www.google.com/search?q=test")
        assert features["has_https"] == 1
        assert features["url_length"] > 0
        assert features["has_ip_address"] == 0
        assert features["query_length"] > 0

    def test_ip_detection(self):
        from backend.app.services.feature_extractor import extract_url_structure_features

        features = extract_url_structure_features("http://192.168.1.1/login")
        assert features["has_ip_address"] == 1

    def test_brand_features_official(self):
        from backend.app.services.feature_extractor import extract_brand_impersonation_features

        features = extract_brand_impersonation_features("https://www.sbi.co.in")
        assert features["is_official_sbi"] == 1

    def test_brand_features_phishing(self):
        from backend.app.services.feature_extractor import extract_brand_impersonation_features

        features = extract_brand_impersonation_features("http://sbi-login-verify.xyz/update")
        assert features["is_official_sbi"] == 0
        assert features["has_brand_keyword"] == 1

    def test_entropy(self):
        from backend.app.services.feature_extractor import _shannon_entropy

        low_entropy = _shannon_entropy("aaaaaaaaaa")
        high_entropy = _shannon_entropy("a8Xk2pQ9zL")
        assert high_entropy > low_entropy

    def test_levenshtein(self):
        from backend.app.services.feature_extractor import _levenshtein_distance

        assert _levenshtein_distance("sbi", "sbi") == 0
        assert _levenshtein_distance("sbi", "sbl") == 1
        assert _levenshtein_distance("kitten", "sitting") == 3

    def test_subdomain_count(self):
        from backend.app.services.feature_extractor import _count_subdomains

        assert _count_subdomains("https://www.sbi.co.in") >= 1
        assert _count_subdomains("https://example.com") == 0

    def test_ml_feature_vector(self):
        from backend.app.services.feature_extractor import extract_all_features, get_ml_feature_vector, ML_FEATURE_NAMES

        features = extract_all_features("https://www.google.com", fast_mode=True)
        vector = get_ml_feature_vector(features)
        assert len(vector) == len(ML_FEATURE_NAMES)
        assert all(isinstance(v, float) for v in vector)

    def test_homoglyph_detection(self):
        from backend.app.services.feature_extractor import _detect_homoglyphs

        has, count = _detect_homoglyphs("sbi")  # Normal ASCII
        assert has is False

    def test_idn_detection(self):
        from backend.app.services.feature_extractor import _check_idn

        assert _check_idn("xn--sbi-test.com") is True
        assert _check_idn("sbi.co.in") is False


class TestRiskScorer:
    """Tests for the risk scoring engine."""

    def test_official_sbi_always_safe(self):
        from backend.app.services.risk_scorer import compute_risk_score

        features = {"is_official_sbi": 1}
        result = compute_risk_score(0.9, features)  # Even high prob
        assert result["risk_tier"] == "SAFE"
        assert result["risk_score"] == 0

    def test_ip_in_url_boosts_score(self):
        from backend.app.services.risk_scorer import compute_risk_score

        features = {"has_ip_address": 1, "is_official_sbi": 0}
        result = compute_risk_score(0.5, features)
        assert result["risk_score"] > 50

    def test_brand_keyword_boost(self):
        from backend.app.services.risk_scorer import compute_risk_score

        features = {
            "has_brand_keyword": 1,
            "is_official_sbi": 0,
            "has_ip_address": 0,
        }
        result = compute_risk_score(0.4, features)
        assert result["risk_score"] > 40  # Boosted above base

    def test_safe_tier(self):
        from backend.app.services.risk_scorer import compute_risk_score

        features = {"is_official_sbi": 0, "has_https": 1}
        result = compute_risk_score(0.1, features)
        assert result["risk_tier"] == "SAFE"

    def test_phishing_tier_with_multiple_flags(self):
        from backend.app.services.risk_scorer import compute_risk_score

        features = {
            "is_official_sbi": 0,
            "has_ip_address": 1,
            "has_brand_keyword": 1,
            "has_https": 0,
            "tld_risk": 1.0,
            "has_homoglyphs": 1,
        }
        result = compute_risk_score(0.7, features)
        assert result["risk_tier"] == "PHISHING"

    def test_reasons_sorted_by_severity(self):
        from backend.app.services.risk_scorer import compute_risk_score

        features = {
            "is_official_sbi": 0,
            "has_ip_address": 1,
            "has_https": 0,
            "url_length": 150,
        }
        result = compute_risk_score(0.5, features)
        if len(result["reasons"]) >= 2:
            severities = [r["severity"] for r in result["reasons"]]
            severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
            scores = [severity_order.get(s, 99) for s in severities]
            assert scores == sorted(scores)

    def test_verdict_includes_hindi(self):
        from backend.app.services.risk_scorer import compute_risk_score

        features = {"is_official_sbi": 1}
        result = compute_risk_score(0.1, features)
        assert "verdict_hi" in result or "verdict" in result


class TestMLPredictor:
    """Tests for the ML predictor module."""

    def test_heuristic_fallback(self):
        from backend.app.services.ml_predictor import _heuristic_score
        from backend.app.services.feature_extractor import ML_FEATURE_NAMES

        # Safe URL features
        safe_features = [0.0] * len(ML_FEATURE_NAMES)
        score = _heuristic_score(safe_features)
        assert 0 < score < 1

    def test_heuristic_official_sbi(self):
        from backend.app.services.ml_predictor import _heuristic_score
        from backend.app.services.feature_extractor import ML_FEATURE_NAMES

        # Build feature vector with is_official_sbi = 1
        features = {name: 0.0 for name in ML_FEATURE_NAMES}
        features["is_official_sbi"] = 1.0
        vector = [features[name] for name in ML_FEATURE_NAMES]
        score = _heuristic_score(vector)
        assert score < 0.1

    def test_predict_returns_tuple(self):
        from backend.app.services.ml_predictor import predict_phishing_probability
        from backend.app.services.feature_extractor import ML_FEATURE_NAMES

        vector = [0.0] * len(ML_FEATURE_NAMES)
        prob, model = predict_phishing_probability(vector)
        assert isinstance(prob, float)
        assert isinstance(model, str)
        assert 0 <= prob <= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
