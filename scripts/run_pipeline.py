#!/usr/bin/env python3
"""Run the full ML pipeline: generate data → extract features → train model."""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def run(cmd: str, desc: str):
    print(f"\n{'='*60}")
    print(f"  {desc}")
    print(f"{'='*60}")
    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / cmd)],
        cwd=str(PROJECT_ROOT),
    )
    if result.returncode != 0:
        print(f"❌ Failed: {desc}")
        sys.exit(1)

if __name__ == "__main__":
    run("scripts/generate_data.py", "Step 1: Generating synthetic dataset")
    run("scripts/extract_features.py", "Step 2: Extracting features")
    run("scripts/train_model.py", "Step 3: Training models")
    print("\n✅ Full pipeline complete!")
    print("   Models saved in: ml/models/")
