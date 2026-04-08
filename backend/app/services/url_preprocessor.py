"""URL preprocessing: decoding, unshortening, redirect following, validation."""

import logging
import re
import socket
from typing import Optional
from urllib.parse import unquote, urlparse

import requests

from backend.app.core.config import MAX_REDIRECTS, REQUEST_TIMEOUT

logger = logging.getLogger(__name__)

# URL-shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "tiny.cc", "rb.gy", "bl.ink", "soo.gd",
}

ALLOWED_SCHEMES = {"http", "https"}

# SSRF-prevention: block private/reserved IPs
BLOCKED_IP_RANGES = [
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^0\."),
    re.compile(r"^169\.254\."),
]


def _is_private_ip(host: str) -> bool:
    """Check if a hostname resolves to a private IP (SSRF protection)."""
    try:
        ip = socket.gethostbyname(host)
        return any(pat.match(ip) for pat in BLOCKED_IP_RANGES)
    except socket.gaierror:
        return False


def validate_url(url: str) -> tuple[bool, str]:
    """Validate URL scheme and structure. Returns (is_valid, reason)."""
    if not url or not isinstance(url, str):
        return False, "Empty or invalid URL"
    url = url.strip()
    # Check for non-HTTP schemes before adding default
    try:
        pre_parsed = urlparse(url)
        if pre_parsed.scheme and pre_parsed.scheme not in ALLOWED_SCHEMES:
            return False, f"Scheme '{pre_parsed.scheme}' not allowed"
    except Exception:
        pass
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed URL"
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"Scheme '{parsed.scheme}' not allowed"
    if not parsed.netloc:
        return False, "No domain in URL"
    if _is_private_ip(parsed.hostname or ""):
        return False, "URL resolves to a private/reserved IP"
    return True, url


def decode_url(url: str) -> str:
    """Decode percent-encoded URL."""
    decoded = unquote(url)
    # Double-decode in case of double encoding
    if "%" in decoded:
        decoded = unquote(decoded)
    return decoded


def is_shortened(url: str) -> bool:
    """Check if URL is from a known shortener."""
    try:
        host = urlparse(url).hostname or ""
        return host.lower() in SHORTENER_DOMAINS
    except Exception:
        return False


def resolve_url(url: str) -> dict:
    """
    Follow redirects to find the final destination URL.
    Returns dict with: original_url, resolved_url, redirect_chain, hops, error.
    """
    result = {
        "original_url": url,
        "resolved_url": url,
        "redirect_chain": [],
        "hops": 0,
        "error": None,
    }

    try:
        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

        response = session.head(
            url, allow_redirects=True, timeout=REQUEST_TIMEOUT, verify=False
        )

        if response.history:
            result["redirect_chain"] = [r.url for r in response.history]
            result["hops"] = len(response.history)

        result["resolved_url"] = response.url

    except requests.exceptions.TooManyRedirects:
        result["error"] = f"Too many redirects (>{MAX_REDIRECTS})"
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection failed"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
    except Exception as e:
        result["error"] = f"Resolution error: {str(e)[:200]}"

    return result


def preprocess_url(raw_url: str) -> dict:
    """
    Full preprocessing pipeline:
    1. Decode percent-encoding
    2. Validate URL
    3. Resolve redirects / unshorten
    4. Return preprocessed result
    """
    decoded = decode_url(raw_url)
    is_valid, validated = validate_url(decoded)

    if not is_valid:
        return {
            "original_url": raw_url,
            "decoded_url": decoded,
            "resolved_url": None,
            "is_valid": False,
            "error": validated,
            "redirect_chain": [],
            "hops": 0,
            "is_shortened": False,
        }

    shortened = is_shortened(validated)
    resolution = resolve_url(validated)

    return {
        "original_url": raw_url,
        "decoded_url": decoded,
        "resolved_url": resolution["resolved_url"],
        "is_valid": True,
        "error": resolution["error"],
        "redirect_chain": resolution["redirect_chain"],
        "hops": resolution["hops"],
        "is_shortened": shortened,
    }
