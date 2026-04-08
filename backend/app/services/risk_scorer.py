"""Risk scoring engine.

Converts ML model probability to a 0-100 risk score,
applies rule-based boosters/reducers, maps to tiers,
and generates explanation reason codes.
"""

import logging
from typing import Optional

from backend.app.core.config import SAFE_THRESHOLD, SUSPICIOUS_THRESHOLD, OFFICIAL_SBI_DOMAINS

logger = logging.getLogger(__name__)


# --- Reason codes ---
REASON_CODES = {
    "IP_IN_URL": {
        "code": "IP_IN_URL",
        "message": "URL uses an IP address instead of a domain name",
        "message_hi": "URL में डोमेन नाम के बजाय IP पता उपयोग किया गया है",
        "severity": "HIGH",
        "boost": 20,
    },
    "NEW_DOMAIN": {
        "code": "NEW_DOMAIN",
        "message": "Domain was registered very recently (less than 30 days)",
        "message_hi": "डोमेन बहुत हाल ही में पंजीकृत हुआ है (30 दिनों से कम)",
        "severity": "HIGH",
        "boost": 15,
    },
    "BRAND_KEYWORD_SUSPICIOUS": {
        "code": "BRAND_KEYWORD_SUSPICIOUS",
        "message": "SBI/YONO brand keywords found in a non-official domain",
        "message_hi": "गैर-आधिकारिक डोमेन में SBI/YONO ब्रांड कीवर्ड पाए गए",
        "severity": "HIGH",
        "boost": 25,
    },
    "TYPOSQUAT_CLOSE": {
        "code": "TYPOSQUAT_CLOSE",
        "message": "Domain is very similar to an official SBI domain (possible typosquatting)",
        "message_hi": "डोमेन आधिकारिक SBI डोमेन से बहुत मिलता-जुलता है (संभावित टाइपोस्क्वैटिंग)",
        "severity": "HIGH",
        "boost": 20,
    },
    "HOMOGLYPH_DETECTED": {
        "code": "HOMOGLYPH_DETECTED",
        "message": "Domain contains look-alike characters (homoglyphs)",
        "message_hi": "डोमेन में समान दिखने वाले अक्षर (होमोग्लिफ़) हैं",
        "severity": "HIGH",
        "boost": 20,
    },
    "HIGH_RISK_TLD": {
        "code": "HIGH_RISK_TLD",
        "message": "Domain uses a high-risk top-level domain",
        "message_hi": "डोमेन एक उच्च-जोखिम वाले टॉप-लेवल डोमेन का उपयोग कर रहा है",
        "severity": "MEDIUM",
        "boost": 10,
    },
    "NO_HTTPS": {
        "code": "NO_HTTPS",
        "message": "URL does not use HTTPS encryption",
        "message_hi": "URL HTTPS एन्क्रिप्शन का उपयोग नहीं कर रहा है",
        "severity": "MEDIUM",
        "boost": 8,
    },
    "EXCESSIVE_SUBDOMAINS": {
        "code": "EXCESSIVE_SUBDOMAINS",
        "message": "URL has an unusually high number of subdomains",
        "message_hi": "URL में असामान्य रूप से अधिक सबडोमेन हैं",
        "severity": "MEDIUM",
        "boost": 10,
    },
    "HIGH_ENTROPY": {
        "code": "HIGH_ENTROPY",
        "message": "URL contains random-looking characters (high entropy)",
        "message_hi": "URL में बेतरतीब दिखने वाले अक्षर हैं (उच्च एंट्रॉपी)",
        "severity": "MEDIUM",
        "boost": 8,
    },
    "VERY_LONG_URL": {
        "code": "VERY_LONG_URL",
        "message": "URL is unusually long — often used to hide the real destination",
        "message_hi": "URL असामान्य रूप से लंबा है — अक्सर असली गंतव्य छिपाने के लिए उपयोग किया जाता है",
        "severity": "LOW",
        "boost": 5,
    },
    "BRAND_IN_SUBDOMAIN": {
        "code": "BRAND_IN_SUBDOMAIN",
        "message": "SBI/YONO brand name used as a subdomain of a different domain",
        "message_hi": "SBI/YONO ब्रांड नाम एक अलग डोमेन के सबडोमेन के रूप में उपयोग किया गया है",
        "severity": "HIGH",
        "boost": 20,
    },
    "IDN_DOMAIN": {
        "code": "IDN_DOMAIN",
        "message": "Domain uses internationalized characters (IDN) — possible spoofing",
        "message_hi": "डोमेन अंतर्राष्ट्रीय अक्षरों (IDN) का उपयोग कर रहा है — संभावित स्पूफिंग",
        "severity": "MEDIUM",
        "boost": 12,
    },
    "NO_SSL": {
        "code": "NO_SSL",
        "message": "No valid SSL certificate found",
        "message_hi": "कोई वैध SSL प्रमाणपत्र नहीं मिला",
        "severity": "MEDIUM",
        "boost": 8,
    },
    "OFFICIAL_DOMAIN": {
        "code": "OFFICIAL_DOMAIN",
        "message": "This is an official SBI/YONO domain — verified safe",
        "message_hi": "यह एक आधिकारिक SBI/YONO डोमेन है — सत्यापित सुरक्षित",
        "severity": "INFO",
        "boost": -100,
    },
}


def compute_risk_score(
    model_probability: float,
    features: dict,
) -> dict:
    """
    Compute final risk score with rule-based adjustments.
    
    Args:
        model_probability: ML model's phishing probability (0.0 to 1.0)
        features: Extracted feature dictionary
    
    Returns:
        Dict with risk_score, risk_tier, confidence, verdict, reasons, action
    """
    # Start with model's probability scaled to 0-100
    base_score = model_probability * 100
    triggered_reasons = []

    # --- Check for official SBI domain (hard whitelist) ---
    if features.get("is_official_sbi", 0) == 1:
        return {
            "risk_score": 0,
            "risk_tier": "SAFE",
            "confidence": 0.99,
            "verdict": "This is an official SBI/YONO domain. Verified safe.",
            "verdict_hi": "यह एक आधिकारिक SBI/YONO डोमेन है। सत्यापित सुरक्षित।",
            "reasons": [_make_reason("OFFICIAL_DOMAIN")],
            "action": {
                "block": False,
                "warn": False,
                "message": "Safe to proceed",
                "message_hi": "आगे बढ़ना सुरक्षित है",
            },
        }

    # --- Apply rule-based boosters ---

    # IP address in URL
    if features.get("has_ip_address", 0) == 1:
        triggered_reasons.append("IP_IN_URL")

    # Very new domain
    domain_age = features.get("domain_age_days", -1)
    if 0 <= domain_age < 30:
        triggered_reasons.append("NEW_DOMAIN")

    # Brand keyword in non-official domain
    if features.get("has_brand_keyword", 0) == 1 and features.get("is_official_sbi", 0) == 0:
        triggered_reasons.append("BRAND_KEYWORD_SUSPICIOUS")

    # Typosquatting close to official
    typo_dist = features.get("typo_distance_min", -1)
    if 0 < typo_dist <= 3:
        triggered_reasons.append("TYPOSQUAT_CLOSE")

    # Homoglyphs
    if features.get("has_homoglyphs", 0) == 1:
        triggered_reasons.append("HOMOGLYPH_DETECTED")

    # High-risk TLD
    if features.get("tld_risk", 0) >= 1.0:
        triggered_reasons.append("HIGH_RISK_TLD")

    # No HTTPS
    if features.get("has_https", 1) == 0:
        triggered_reasons.append("NO_HTTPS")

    # Excessive subdomains
    if features.get("num_subdomains", 0) >= 3:
        triggered_reasons.append("EXCESSIVE_SUBDOMAINS")

    # High entropy
    if features.get("entropy", 0) > 4.5:
        triggered_reasons.append("HIGH_ENTROPY")

    # Very long URL
    if features.get("url_length", 0) > 100:
        triggered_reasons.append("VERY_LONG_URL")

    # Brand in subdomain
    if features.get("brand_in_subdomain", 0) == 1:
        triggered_reasons.append("BRAND_IN_SUBDOMAIN")

    # IDN domain
    if features.get("is_idn", 0) == 1:
        triggered_reasons.append("IDN_DOMAIN")

    # No SSL
    if features.get("ssl_valid", 0) == 0 and features.get("has_https", 0) == 1:
        triggered_reasons.append("NO_SSL")

    # Calculate total boost
    total_boost = sum(REASON_CODES[r]["boost"] for r in triggered_reasons)

    # Final score (clamped 0-100)
    final_score = min(100, max(0, base_score + total_boost))

    # Map to tier
    if final_score <= SAFE_THRESHOLD:
        tier = "SAFE"
    elif final_score <= SUSPICIOUS_THRESHOLD:
        tier = "SUSPICIOUS"
    else:
        tier = "PHISHING"

    # Confidence based on model probability alignment with final tier
    confidence = _calculate_confidence(model_probability, final_score, tier)

    # Generate verdict
    verdict, verdict_hi = _generate_verdict(tier, triggered_reasons)

    # Action recommendation
    action = _generate_action(tier)

    # Sort reasons by severity
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    reason_objects = [_make_reason(r) for r in triggered_reasons]
    reason_objects.sort(key=lambda x: severity_order.get(x["severity"], 99))

    return {
        "risk_score": round(final_score, 1),
        "risk_tier": tier,
        "confidence": round(confidence, 3),
        "verdict": verdict,
        "verdict_hi": verdict_hi,
        "reasons": reason_objects[:5],  # Top 5 reasons
        "action": action,
    }


def _make_reason(code: str) -> dict:
    r = REASON_CODES[code]
    return {
        "code": r["code"],
        "message": r["message"],
        "message_hi": r["message_hi"],
        "severity": r["severity"],
    }


def _calculate_confidence(prob: float, score: float, tier: str) -> float:
    """Confidence = how much the model and rules agree."""
    if tier == "PHISHING" and prob > 0.7:
        return min(0.99, 0.7 + prob * 0.3)
    elif tier == "SAFE" and prob < 0.3:
        return min(0.99, 0.7 + (1 - prob) * 0.3)
    elif tier == "SUSPICIOUS":
        return 0.5 + abs(prob - 0.5) * 0.5
    return 0.6


def _generate_verdict(tier: str, reasons: list[str]) -> tuple[str, str]:
    """Generate human-readable verdict."""
    if tier == "SAFE":
        return (
            "This URL appears to be safe. No significant phishing indicators detected.",
            "यह URL सुरक्षित प्रतीत होता है। कोई महत्वपूर्ण फ़िशिंग संकेतक नहीं मिले।",
        )
    elif tier == "SUSPICIOUS":
        return (
            "This URL shows some suspicious characteristics. Exercise caution before proceeding.",
            "यह URL कुछ संदिग्ध विशेषताएँ दिखाता है। आगे बढ़ने से पहले सावधानी बरतें।",
        )
    else:
        return (
            "⚠️ WARNING: This URL is likely a phishing attempt. Do NOT enter any personal or financial information.",
            "⚠️ चेतावनी: यह URL संभवतः एक फ़िशिंग प्रयास है। कोई भी व्यक्तिगत या वित्तीय जानकारी न दें।",
        )


def _generate_action(tier: str) -> dict:
    """Generate recommended action based on tier."""
    if tier == "SAFE":
        return {
            "block": False,
            "warn": False,
            "message": "Safe to proceed",
            "message_hi": "आगे बढ़ना सुरक्षित है",
        }
    elif tier == "SUSPICIOUS":
        return {
            "block": False,
            "warn": True,
            "message": "Proceed with caution. Verify the URL before entering any information.",
            "message_hi": "सावधानी से आगे बढ़ें। कोई भी जानकारी दर्ज करने से पहले URL सत्यापित करें।",
        }
    else:
        return {
            "block": True,
            "warn": True,
            "message": "DO NOT proceed. This URL is highly likely to be a phishing site.",
            "message_hi": "आगे न बढ़ें। यह URL अत्यधिक संभावना से एक फ़िशिंग साइट है।",
        }
