"""Feature extraction for training data.

Reads the raw URL dataset and extracts features for each URL.
Uses fast_mode=True to skip network calls during batch processing.
"""

import csv
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.feature_extractor import (
    extract_url_structure_features,
    extract_brand_impersonation_features,
    ML_FEATURE_NAMES,
)
from backend.app.services.feature_extractor import _get_tld_risk
from urllib.parse import urlparse


def extract_training_features(url: str) -> dict:
    """
    Extract features suitable for training (fast mode, no network calls).
    Domain intelligence features use defaults since we can't query WHOIS
    for thousands of URLs during data preparation.
    """
    structure = extract_url_structure_features(url)
    brand = extract_brand_impersonation_features(url)

    # Domain intelligence defaults for training
    domain = (urlparse(url).hostname or "").lower()
    domain_intel = {
        "domain_age_days": -1,
        "tld_risk": _get_tld_risk(domain),
        "ssl_age_days": -1,
        "ssl_valid": 1 if url.startswith("https") else 0,
        "has_mx": 0,
        "has_dns": 1,
        "dns_anomaly_score": 0.0,
        "registrar_suspicious": 0,
    }

    features = {}
    features.update(structure)
    features.update(domain_intel)
    features.update(brand)
    return features


def process_dataset(
    input_path: str = "data/raw/urls_dataset.csv",
    output_path: str = "data/processed/features_dataset.csv",
):
    """Extract features from raw URL dataset."""
    input_file = Path(input_path)
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    if not input_file.exists():
        print(f"❌ Input file not found: {input_file}")
        print("   Run 'python scripts/generate_data.py' first")
        return

    # Read input
    with open(input_file) as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"📊 Processing {len(rows)} URLs...")

    # Extract features
    results = []
    for i, row in enumerate(rows):
        url = row["url"]
        label = int(row["label"])

        try:
            features = extract_training_features(url)
            # Build output row: features + label
            output_row = {name: features.get(name, 0) for name in ML_FEATURE_NAMES}
            output_row["label"] = label
            output_row["url"] = url
            results.append(output_row)
        except Exception as e:
            print(f"  ⚠️  Skipping URL {i}: {e}")

        if (i + 1) % 500 == 0:
            print(f"  Processed {i + 1}/{len(rows)}...")

    # Write output
    fieldnames = ML_FEATURE_NAMES + ["label", "url"]
    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"✅ Features extracted → {output_file}")
    print(f"   Total: {len(results)} samples")
    print(f"   Features per sample: {len(ML_FEATURE_NAMES)}")


if __name__ == "__main__":
    process_dataset()
