"""Synthetic data generator for training.

Creates a balanced dataset of:
- Legitimate URLs (negative class)
- Phishing URLs with SBI/YONO brand impersonation (positive class)
"""

import csv
import random
import string
from pathlib import Path

# Fixed random seed for reproducibility
SEED = 42
random.seed(SEED)

# --- Legitimate URL templates ---
LEGIT_DOMAINS = [
    "google.com", "github.com", "stackoverflow.com", "wikipedia.org",
    "amazon.in", "flipkart.com", "linkedin.com", "microsoft.com",
    "apple.com", "youtube.com", "reddit.com", "twitter.com",
    "facebook.com", "instagram.com", "netflix.com", "medium.com",
    "nytimes.com", "bbc.com", "reuters.com", "bloomberg.com",
    "coursera.org", "udemy.com", "khan.academy.org", "mit.edu",
    "stanford.edu", "harvard.edu", "nih.gov", "cdc.gov",
    "who.int", "un.org", "ibm.com", "oracle.com",
    "salesforce.com", "adobe.com", "zoom.us", "slack.com",
    "dropbox.com", "spotify.com", "airbnb.com", "uber.com",
]

LEGIT_PATHS = [
    "", "/about", "/contact", "/login", "/help", "/support",
    "/docs", "/api", "/blog", "/news", "/products", "/services",
    "/pricing", "/signup", "/account", "/settings", "/dashboard",
    "/search?q=test", "/category/tech", "/article/news-today",
]

# Official SBI domains
SBI_OFFICIAL = [
    "https://www.sbi.co.in",
    "https://onlinesbi.sbi",
    "https://retail.onlinesbi.sbi",
    "https://www.sbicard.com",
    "https://yonosbi.sbi",
    "https://www.sbimf.com",
    "https://www.sbilife.co.in",
]

SBI_OFFICIAL_PATHS = [
    "", "/personal-banking", "/accounts", "/loans", "/cards",
    "/investments", "/insurance", "/digital-banking",
    "/customer-care", "/branches", "/interest-rates",
]

# --- Phishing URL components ---
PHISHING_BRAND_VARIANTS = [
    "sbi", "yono", "onlinesbi", "sbiyono", "sbi-yono", "sbibank",
    "sbi-online", "sbi-net", "sbi-login", "yono-sbi", "yonosbi",
    "sbi-update", "sbi-verify", "sbi-secure", "sbi-alert",
    "sbi-banking", "yono-update", "yono-verify", "yono-secure",
    "onlinesbi-net", "sbi-kyc", "sbi-otp", "sbi-refund",
    "statebankl", "sbionline-banking", "onlinesbi-secure",
]

PHISHING_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".click", ".info", ".online", ".site", ".club",
    ".icu", ".buzz", ".work", ".link", ".pw",
    ".com", ".net", ".org",  # Some phishing uses normal TLDs
]

PHISHING_PATHS = [
    "/login", "/login.php", "/update-kyc", "/verify-account",
    "/secure-login", "/account/verify", "/otp-verify",
    "/cgi-bin/login.php", "/bank/login", "/netbanking",
    "/update-details", "/refund-process", "/kyc-update",
    "/verify-otp", "/account-suspended", "/urgent-update",
    "/security-alert", "/confirm-identity", "/re-activate",
]

PHISHING_SUBDOMAINS = [
    "sbi", "yono", "login", "secure", "verify", "update",
    "banking", "netbanking", "online", "account", "kyc",
]

PHISHING_QUERY_PARAMS = [
    "?ref=urgent", "?action=verify", "?session=expired",
    "?alert=security", "?update=required", "?otp=pending",
    "?id=1234567890", "?token=abc123def456",
    "?redirect=true&user=victim", "",
]


def _random_string(length: int) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def generate_legit_url() -> str:
    """Generate a plausible legitimate URL."""
    scheme = random.choice(["https://", "https://www."])
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    return f"{scheme}{domain}{path}"


def generate_sbi_official_url() -> str:
    """Generate official SBI URL."""
    base = random.choice(SBI_OFFICIAL)
    path = random.choice(SBI_OFFICIAL_PATHS)
    return f"{base}{path}"


def generate_phishing_url() -> str:
    """Generate a synthetic phishing URL targeting SBI/YONO."""
    strategy = random.choice([
        "brand_in_domain", "brand_in_subdomain", "typosquat",
        "ip_based", "long_url", "mixed",
    ])

    if strategy == "brand_in_domain":
        brand = random.choice(PHISHING_BRAND_VARIANTS)
        suffix = _random_string(random.randint(3, 8))
        tld = random.choice(PHISHING_TLDS)
        path = random.choice(PHISHING_PATHS)
        query = random.choice(PHISHING_QUERY_PARAMS)
        scheme = random.choice(["http://", "https://"])
        return f"{scheme}{brand}-{suffix}{tld}{path}{query}"

    elif strategy == "brand_in_subdomain":
        subdomain = random.choice(PHISHING_SUBDOMAINS)
        domain = _random_string(random.randint(5, 12))
        tld = random.choice(PHISHING_TLDS)
        path = random.choice(PHISHING_PATHS)
        scheme = random.choice(["http://", "https://"])
        return f"{scheme}{subdomain}.{domain}{tld}{path}"

    elif strategy == "typosquat":
        # Misspell official domains
        typos = [
            "sbl.co.in", "sbi.co.ln", "onlinesbl.sbi", "oniinesbi.sbi",
            "yonosbl.sbi", "sbiyono.co.in", "sbi-co.in", "onlinesbi.co",
            "sbi.c0.in", "onlinesb1.sbi", "sbii.co.in", "s-b-i.co.in",
        ]
        domain = random.choice(typos)
        path = random.choice(PHISHING_PATHS)
        return f"http://{domain}{path}"

    elif strategy == "ip_based":
        ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        path = random.choice(PHISHING_PATHS)
        brand = random.choice(["sbi", "yono", "onlinesbi", ""])
        if brand:
            path = f"/{brand}{path}"
        return f"http://{ip}{path}"

    elif strategy == "long_url":
        brand = random.choice(PHISHING_BRAND_VARIANTS)
        padding = "-".join([_random_string(random.randint(4, 8)) for _ in range(random.randint(3, 6))])
        tld = random.choice(PHISHING_TLDS)
        path = random.choice(PHISHING_PATHS)
        extra_path = "/".join([_random_string(5) for _ in range(random.randint(2, 4))])
        return f"http://{brand}-{padding}{tld}{path}/{extra_path}?token={_random_string(32)}"

    else:  # mixed
        parts = [random.choice(PHISHING_SUBDOMAINS) for _ in range(random.randint(2, 4))]
        domain = _random_string(random.randint(6, 10))
        tld = random.choice(PHISHING_TLDS)
        path = random.choice(PHISHING_PATHS)
        query = random.choice(PHISHING_QUERY_PARAMS)
        return f"http://{'.'.join(parts)}.{domain}{tld}{path}{query}"


def generate_dataset(
    n_legit: int = 2000,
    n_sbi_official: int = 500,
    n_phishing: int = 2500,
    output_path: str = "data/raw/urls_dataset.csv",
):
    """
    Generate the full training dataset.
    
    Label: 0 = legitimate, 1 = phishing
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    rows = []

    # Legitimate URLs
    for _ in range(n_legit):
        rows.append({"url": generate_legit_url(), "label": 0, "source": "synthetic_legit"})

    # Official SBI URLs (labeled safe)
    for _ in range(n_sbi_official):
        rows.append({"url": generate_sbi_official_url(), "label": 0, "source": "sbi_official"})

    # Phishing URLs
    for _ in range(n_phishing):
        rows.append({"url": generate_phishing_url(), "label": 1, "source": "synthetic_phishing"})

    # Shuffle
    random.shuffle(rows)

    # Deduplicate
    seen = set()
    unique_rows = []
    for row in rows:
        if row["url"] not in seen:
            seen.add(row["url"])
            unique_rows.append(row)

    # Write CSV
    with open(output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label", "source"])
        writer.writeheader()
        writer.writerows(unique_rows)

    print(f"✅ Generated {len(unique_rows)} URLs → {output}")
    print(f"   Legit: {sum(1 for r in unique_rows if r['label'] == 0)}")
    print(f"   Phishing: {sum(1 for r in unique_rows if r['label'] == 1)}")
    return str(output)


if __name__ == "__main__":
    generate_dataset()
