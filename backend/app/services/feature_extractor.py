"""Feature extraction engine for phishing URL analysis.

Extracts three groups of features:
A. URL structure features
B. Domain intelligence features  
C. Brand impersonation features

Designed for both training and inference with graceful fallbacks.
"""

import logging
import math
import re
import socket
import ssl
from collections import Counter
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from backend.app.core.config import (
    OFFICIAL_SBI_DOMAINS, SBI_BRAND_KEYWORDS, WHOIS_TIMEOUT, DNS_TIMEOUT,
)

logger = logging.getLogger(__name__)

# --- High-risk TLDs ---
HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".link", ".buzz", ".work", ".date", ".racing", ".download",
    ".win", ".bid", ".stream", ".loan", ".trade", ".webcam",
    ".science", ".party", ".cricket", ".review",
}
MEDIUM_RISK_TLDS = {
    ".info", ".online", ".site", ".store", ".club", ".icu", ".app",
    ".dev", ".tech", ".space", ".fun", ".host", ".life", ".pw",
}

# --- Suspicious registrars ---
SUSPICIOUS_REGISTRARS = {
    "namecheap", "namesilo", "porkbun", "freenom",
}

# --- Homoglyph map ---
HOMOGLYPHS = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
    'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ω': 'w', 'ν': 'v',
    '0': 'o', '1': 'l', '!': 'i',
}


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _has_ip_address(url: str) -> bool:
    """Check if URL uses an IP address instead of a domain."""
    try:
        host = urlparse(url).hostname or ""
        # IPv4 pattern
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
            return True
        # IPv6 pattern
        if host.startswith('[') or ':' in host:
            return True
    except Exception:
        pass
    return False


def _count_subdomains(url: str) -> int:
    """Count number of subdomains."""
    try:
        host = urlparse(url).hostname or ""
        parts = host.split('.')
        # domain.tld = 0 subdomains, sub.domain.tld = 1
        return max(0, len(parts) - 2)
    except Exception:
        return 0


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _detect_homoglyphs(domain: str) -> tuple[bool, int]:
    """Check for homoglyph characters in domain."""
    count = 0
    for char in domain:
        if char in HOMOGLYPHS:
            count += 1
    return count > 0, count


def _check_idn(domain: str) -> bool:
    """Check if domain uses Internationalized Domain Name encoding."""
    try:
        return domain.startswith("xn--") or any(ord(c) > 127 for c in domain)
    except Exception:
        return False


# =====================================================================
# A. URL STRUCTURE FEATURES
# =====================================================================

def extract_url_structure_features(url: str) -> dict:
    """Extract URL structure features."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "path_depth": path.count("/") - 1 if path else 0,
        "entropy": round(_shannon_entropy(url), 4),
        "special_char_count": sum(1 for c in url if c in "@#$%^&*()=+[]{}|;:',<>?"),
        "hyphen_count": url.count("-"),
        "dot_count": url.count("."),
        "digit_count": sum(1 for c in url if c.isdigit()),
        "at_symbol": 1 if "@" in url else 0,
        "double_slash_redirect": 1 if url.count("//") > 1 else 0,
        "num_subdomains": _count_subdomains(url),
        "has_https": 1 if parsed.scheme == "https" else 0,
        "has_ip_address": 1 if _has_ip_address(url) else 0,
        "has_port": 1 if parsed.port and parsed.port not in (80, 443) else 0,
        "query_length": len(parsed.query or ""),
        "has_fragment": 1 if parsed.fragment else 0,
        "num_params": len(parsed.query.split("&")) if parsed.query else 0,
    }


# =====================================================================
# B. DOMAIN INTELLIGENCE FEATURES
# =====================================================================

def _get_domain_age_days(domain: str) -> Optional[int]:
    """Get domain age in days via WHOIS. Returns None on failure."""
    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age = (datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)).days
            return max(0, age)
    except Exception as e:
        logger.debug("WHOIS failed for %s: %s", domain, e)
    return None


def _get_ssl_info(domain: str) -> dict:
    """Get SSL certificate info. Returns dict with age_days, issuer, is_valid."""
    info = {"ssl_age_days": None, "ssl_issuer": None, "ssl_valid": 0}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            info["ssl_age_days"] = (datetime.now() - not_before).days
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            info["ssl_issuer"] = issuer_dict.get("organizationName", "Unknown")
            info["ssl_valid"] = 1
    except Exception as e:
        logger.debug("SSL check failed for %s: %s", domain, e)
    return info


def _get_tld_risk(domain: str) -> float:
    """Return TLD risk score: 0.0 = safe, 0.5 = medium, 1.0 = high."""
    tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in HIGH_RISK_TLDS:
        return 1.0
    if tld in MEDIUM_RISK_TLDS:
        return 0.5
    return 0.0


def _check_dns_anomalies(domain: str) -> dict:
    """Check for DNS anomalies."""
    anomalies = {"has_mx": 0, "has_dns": 0, "dns_anomaly_score": 0.0}
    try:
        import dns.resolver
        try:
            dns.resolver.resolve(domain, "A")
            anomalies["has_dns"] = 1
        except Exception:
            anomalies["dns_anomaly_score"] += 0.5

        try:
            dns.resolver.resolve(domain, "MX")
            anomalies["has_mx"] = 1
        except Exception:
            anomalies["dns_anomaly_score"] += 0.3
    except ImportError:
        logger.debug("dnspython not installed – skipping DNS checks")
    except Exception as e:
        logger.debug("DNS check error for %s: %s", domain, e)
    return anomalies


def extract_domain_intelligence_features(url: str) -> dict:
    """Extract domain intelligence features with graceful fallbacks."""
    parsed = urlparse(url)
    domain = parsed.hostname or ""

    features = {
        "domain_age_days": -1,  # -1 = unknown
        "tld_risk": _get_tld_risk(domain),
        "ssl_age_days": -1,
        "ssl_valid": 0,
        "has_mx": 0,
        "has_dns": 0,
        "dns_anomaly_score": 0.0,
        "registrar_suspicious": 0,
    }

    # Domain age (may be slow)
    age = _get_domain_age_days(domain)
    if age is not None:
        features["domain_age_days"] = age

    # SSL info
    ssl_info = _get_ssl_info(domain)
    features.update({
        "ssl_age_days": ssl_info["ssl_age_days"] if ssl_info["ssl_age_days"] is not None else -1,
        "ssl_valid": ssl_info["ssl_valid"],
    })

    # DNS anomalies
    dns_info = _check_dns_anomalies(domain)
    features.update(dns_info)

    return features


# =====================================================================
# C. BRAND IMPERSONATION FEATURES
# =====================================================================

def extract_brand_impersonation_features(url: str) -> dict:
    """Extract brand impersonation features for SBI/YONO detection."""
    parsed = urlparse(url)
    domain = (parsed.hostname or "").lower()
    full_url_lower = url.lower()

    # Check if this is an official SBI domain
    is_official = domain in OFFICIAL_SBI_DOMAINS

    # Brand keyword detection
    brand_keywords_found = []
    for kw in SBI_BRAND_KEYWORDS:
        if kw in full_url_lower:
            brand_keywords_found.append(kw)

    has_brand_keyword = len(brand_keywords_found) > 0

    # Typosquatting distance
    official_domains = list(OFFICIAL_SBI_DOMAINS)
    min_typo_distance = 999
    closest_official = ""
    if not is_official and domain:
        for official in official_domains:
            # Compare just the domain part (strip www.)
            d1 = domain.replace("www.", "")
            d2 = official.replace("www.", "")
            dist = _levenshtein_distance(d1, d2)
            if dist < min_typo_distance:
                min_typo_distance = dist
                closest_official = official

    # Homoglyph detection
    has_homoglyphs, homoglyph_count = _detect_homoglyphs(domain)

    # IDN detection
    is_idn = _check_idn(domain)

    # Brand in subdomain (suspicious pattern: sbi.malicious.com)
    brand_in_subdomain = 0
    domain_parts = domain.split(".")
    if len(domain_parts) > 2:
        subdomains = ".".join(domain_parts[:-2])
        for kw in SBI_BRAND_KEYWORDS:
            if kw in subdomains:
                brand_in_subdomain = 1
                break

    return {
        "is_official_sbi": 1 if is_official else 0,
        "brand_keyword_count": len(brand_keywords_found),
        "has_brand_keyword": 1 if has_brand_keyword else 0,
        "brand_keywords_found": brand_keywords_found,
        "typo_distance_min": min_typo_distance if min_typo_distance < 999 else -1,
        "closest_official_domain": closest_official,
        "has_homoglyphs": 1 if has_homoglyphs else 0,
        "homoglyph_count": homoglyph_count,
        "is_idn": 1 if is_idn else 0,
        "brand_in_subdomain": brand_in_subdomain,
    }


# =====================================================================
# COMBINED FEATURE EXTRACTION
# =====================================================================

# Features used by the ML model (numeric only)
ML_FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "path_depth",
    "entropy", "special_char_count", "hyphen_count", "dot_count",
    "digit_count", "at_symbol", "double_slash_redirect",
    "num_subdomains", "has_https", "has_ip_address", "has_port",
    "query_length", "has_fragment", "num_params",
    "domain_age_days", "tld_risk", "ssl_age_days", "ssl_valid",
    "has_mx", "has_dns", "dns_anomaly_score", "registrar_suspicious",
    "is_official_sbi", "brand_keyword_count", "has_brand_keyword",
    "typo_distance_min", "has_homoglyphs", "homoglyph_count",
    "is_idn", "brand_in_subdomain",
]


def extract_all_features(url: str, fast_mode: bool = False) -> dict:
    """
    Extract all features for a URL.
    
    Args:
        url: The URL to analyze
        fast_mode: If True, skip slow network-based features (WHOIS, SSL, DNS)
    
    Returns:
        Dict with all features (both ML-numeric and metadata)
    """
    structure = extract_url_structure_features(url)

    if fast_mode:
        domain_intel = {
            "domain_age_days": -1,
            "tld_risk": _get_tld_risk((urlparse(url).hostname or "")),
            "ssl_age_days": -1,
            "ssl_valid": 0,
            "has_mx": 0,
            "has_dns": 0,
            "dns_anomaly_score": 0.0,
            "registrar_suspicious": 0,
        }
    else:
        domain_intel = extract_domain_intelligence_features(url)

    brand = extract_brand_impersonation_features(url)

    # Merge all features
    all_features = {}
    all_features.update(structure)
    all_features.update(domain_intel)
    all_features.update(brand)

    return all_features


def get_ml_feature_vector(features: dict) -> list[float]:
    """Extract ordered numeric feature vector for ML model input."""
    return [float(features.get(name, 0)) for name in ML_FEATURE_NAMES]
