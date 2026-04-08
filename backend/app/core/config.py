"""Application configuration via environment variables."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BASE_DIR.parent
ML_MODELS_DIR = PROJECT_ROOT / "ml" / "models"
DATA_DIR = PROJECT_ROOT / "data"

# --- API ---
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
DEBUG = os.getenv("DEBUG", "true").lower() == "true"
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")

# --- Redis ---
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CACHE_TTL_SAFE = int(os.getenv("CACHE_TTL_SAFE", "3600"))        # 1 hour
CACHE_TTL_SUSPICIOUS = int(os.getenv("CACHE_TTL_SUSPICIOUS", "600"))  # 10 min
CACHE_TTL_PHISHING = int(os.getenv("CACHE_TTL_PHISHING", "300"))     # 5 min

# --- Database ---
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'shieldyono.db'}")

# --- URL Processing ---
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "5"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))
WHOIS_TIMEOUT = int(os.getenv("WHOIS_TIMEOUT", "5"))
DNS_TIMEOUT = int(os.getenv("DNS_TIMEOUT", "5"))

# --- Official SBI Domains (hard-whitelisted) ---
OFFICIAL_SBI_DOMAINS = {
    "sbi.co.in",
    "onlinesbi.sbi",
    "www.sbi.co.in",
    "www.onlinesbi.sbi",
    "retail.onlinesbi.sbi",
    "corporate.onlinesbi.sbi",
    "yonosbi.sbi",
    "www.yonosbi.sbi",
    "yono.sbi.co.in",
    "sbicard.com",
    "www.sbicard.com",
    "sbimf.com",
    "www.sbimf.com",
    "sbilife.co.in",
    "www.sbilife.co.in",
}

# --- Brand Keywords ---
SBI_BRAND_KEYWORDS = [
    "sbi", "yono", "onlinesbi", "sbiyono", "sbicard",
    "sbibank", "statebankof", "statebankofindia",
    "sbimf", "sbilife", "sbionline",
]

# --- Risk Thresholds ---
SAFE_THRESHOLD = 34
SUSPICIOUS_THRESHOLD = 69
