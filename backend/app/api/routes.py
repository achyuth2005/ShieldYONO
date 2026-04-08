"""API routes for URL scanning and analytics."""

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from backend.app.core.cache import get_cached_result, set_cached_result
from backend.app.core.database import insert_scan, get_recent_scans, get_analytics
from backend.app.models.schemas import (
    ScanResponse, ErrorResponse, AnalyticsResponse, RecentScanItem,
)
from backend.app.services.url_preprocessor import preprocess_url
from backend.app.services.feature_extractor import extract_all_features, get_ml_feature_vector
from backend.app.services.ml_predictor import predict_phishing_probability, get_feature_importance
from backend.app.services.risk_scorer import compute_risk_score

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/check-url", response_model=ScanResponse)
async def check_url(url: str = Query(..., description="URL to scan for phishing")):
    """
    Scan a URL for phishing indicators.
    Returns a detailed risk assessment with score, tier, verdict, and explanations.
    """
    if not url or len(url.strip()) < 4:
        raise HTTPException(status_code=400, detail="Please provide a valid URL")

    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL too long (max 2048 characters)")

    # Check cache first
    cached = get_cached_result(url)
    if cached:
        logger.info("Cache hit for URL: %s", url[:80])
        return ScanResponse(**cached)

    scan_id = str(uuid.uuid4())[:12]
    scanned_at = datetime.now(timezone.utc).isoformat()

    # 1. Preprocess URL
    preprocessed = preprocess_url(url)

    if not preprocessed["is_valid"]:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid URL: {preprocessed['error']}",
        )

    resolved_url = preprocessed["resolved_url"] or url

    # 2. Extract features
    try:
        features = extract_all_features(resolved_url, fast_mode=False)
    except Exception as e:
        logger.error("Feature extraction failed: %s", e)
        # Fallback to fast mode
        features = extract_all_features(resolved_url, fast_mode=True)

    # 3. ML prediction
    feature_vector = get_ml_feature_vector(features)
    probability, model_used = predict_phishing_probability(feature_vector)

    # 4. Risk scoring
    risk_result = compute_risk_score(probability, features)

    # 5. Build response
    # Remove non-serializable items from features display
    display_features = {k: v for k, v in features.items() if not isinstance(v, (list, dict)) or k == "brand_keywords_found"}

    response_data = {
        "url": url,
        "resolved_url": resolved_url,
        "risk_score": risk_result["risk_score"],
        "risk_tier": risk_result["risk_tier"],
        "confidence": risk_result["confidence"],
        "verdict": risk_result["verdict"],
        "verdict_hi": risk_result.get("verdict_hi", ""),
        "reasons": risk_result["reasons"],
        "features": display_features,
        "action": risk_result["action"],
        "scan_id": scan_id,
        "scanned_at": scanned_at,
        "cached": False,
        "model_used": model_used,
    }

    # 6. Cache result
    set_cached_result(url, response_data)

    # 7. Save to database
    try:
        insert_scan(response_data)
    except Exception as e:
        logger.error("Database insert failed: %s", e)

    logger.info(
        "Scan %s: %s → %s (score=%.1f, tier=%s)",
        scan_id, url[:60], risk_result["risk_tier"],
        risk_result["risk_score"], risk_result["risk_tier"],
    )

    return ScanResponse(**response_data)


@router.get("/analytics", response_model=AnalyticsResponse)
async def analytics():
    """Get scan analytics summary."""
    try:
        data = get_analytics()
        return AnalyticsResponse(**data)
    except Exception as e:
        logger.error("Analytics error: %s", e)
        raise HTTPException(status_code=500, detail="Failed to retrieve analytics")


@router.get("/recent-scans", response_model=list[RecentScanItem])
async def recent_scans(limit: int = Query(20, ge=1, le=100)):
    """Get recent scan history."""
    try:
        scans = get_recent_scans(limit)
        return [
            RecentScanItem(
                scan_id=s["scan_id"],
                url=s["url"],
                risk_score=s["risk_score"],
                risk_tier=s["risk_tier"],
                verdict=s.get("verdict", ""),
                scanned_at=s["scanned_at"],
            )
            for s in scans
        ]
    except Exception as e:
        logger.error("Recent scans error: %s", e)
        raise HTTPException(status_code=500, detail="Failed to retrieve recent scans")


@router.get("/feature-importance")
async def feature_importance():
    """Get ML model feature importance for explainability."""
    importance = get_feature_importance()
    if importance is None:
        return {"message": "No trained model available for feature importance", "features": {}}
    # Sort by absolute importance
    sorted_features = dict(sorted(importance.items(), key=lambda x: abs(x[1]), reverse=True))
    return {"features": sorted_features}


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "ShieldYONO"}


@router.get("/sample-urls")
async def sample_urls():
    """Return sample URLs for demo purposes."""
    return {
        "safe_urls": [
            "https://www.sbi.co.in",
            "https://onlinesbi.sbi",
            "https://www.google.com",
            "https://www.github.com",
            "https://www.wikipedia.org",
        ],
        "suspicious_urls": [
            "http://sbi-login-verify.com/account",
            "http://yono-update.info/login",
            "http://sbionline-banking.tk/verify",
        ],
        "phishing_urls": [
            "http://192.168.1.1/sbi-login/update-kyc",
            "http://sbi-yono-update-kyc.xyz/login?ref=urgent",
            "http://onlinesbi-secure.tk/cgi-bin/login.php",
            "http://www.sbiyono-verification.ml/account/update",
            "http://sbi.login.malicious-domain.com/verify",
        ],
    }
