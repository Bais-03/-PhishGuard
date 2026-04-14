#!/usr/bin/env python3
"""
Download the latest Tranco top-1M domain list.
Run once before starting the backend:
    python scripts/download_tranco.py
"""
import os
import zipfile
import io
import urllib.request

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
OUTPUT_PATH = "data/tranco_top1m.csv"


def download_tranco():
    os.makedirs("data", exist_ok=True)

    if os.path.exists(OUTPUT_PATH):
        print(f"✓ Tranco list already exists at {OUTPUT_PATH}")
        print("  Delete it and re-run to refresh.")
        return

    print("Downloading Tranco top-1M list (~15 MB)...")
    with urllib.request.urlopen(TRANCO_URL, timeout=60) as resp:
        data = resp.read()

    print("Extracting...")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        csv_name = [n for n in z.namelist() if n.endswith(".csv")][0]
        with z.open(csv_name) as src, open(OUTPUT_PATH, "wb") as dst:
            dst.write(src.read())

    # Count lines
    with open(OUTPUT_PATH) as f:
        count = sum(1 for _ in f)

    print(f"✓ Saved {count:,} domains to {OUTPUT_PATH}")


if __name__ == "__main__":
    download_tranco()
