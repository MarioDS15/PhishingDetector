#!/usr/bin/env python3
"""
Generate an enriched URL dataset by merging the original PhiUSIIL features with
the features computed by our current phishing detector.

Usage:
    python ML/URL/generate_enriched_url_dataset.py \
        --input ML/URL/URL\ Data/PhiUSIIL_Phishing_URL_Dataset_url_only.csv \
        --output ML/URL/URL\ Data/PhiUSIIL_Phishing_URL_Dataset_enriched.csv
"""

import argparse
import os
import sys
from pathlib import Path
from typing import List

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from ML.phishing_detector import PhishingDetector  # type: ignore  # noqa: E402


DEFAULT_INPUT = os.path.join("ML", "URL", "URL Data", "URL_Set_original.csv")
DEFAULT_EXTRA = os.path.join("ML", "URL", "URL Data", "phishing_dataset.csv")
DEFAULT_OUTPUT = os.path.join("ML", "URL", "URL Data", "URL_Set_enriched.csv")


def compute_detector_features(urls: List[str]) -> pd.DataFrame:
    detector = PhishingDetector()
    feature_rows = []

    print("Extracting detector features for enriched dataset...")
    for idx, url in enumerate(urls):
        if idx % 5000 == 0:
            print(f"  Processed {idx}/{len(urls)} URLs")

        try:
            feature_rows.append(detector.extract_features(url))
        except Exception as exc:  # pragma: no cover - defensive branch
            print(f"  Warning: feature extraction failed for {url}: {exc}")
            feature_rows.append({})

    feature_df = pd.DataFrame(feature_rows)
    feature_df.index = range(len(urls))
    return feature_df


def _load_additional_dataset(path: str) -> pd.DataFrame:
    extra_path = Path(path)
    if not extra_path.exists():
        return pd.DataFrame()

    extra_df = pd.read_csv(extra_path)

    # Normalize column names
    if "url" in extra_df.columns:
        extra_df = extra_df.rename(columns={"url": "URL"})
    if "label" not in extra_df.columns:
        raise ValueError(f"Extra dataset {extra_path} must contain a 'label' column.")

    extra_df["label"] = extra_df["label"].astype(int)

    if "FILENAME" not in extra_df.columns:
        extra_df["FILENAME"] = [
            f"{extra_path.stem}_{idx}.txt" for idx in range(len(extra_df))
        ]

    # Keep only relevant columns before merging.
    keep_cols = ["FILENAME", "URL", "label"]
    existing_cols = [col for col in keep_cols if col in extra_df.columns]
    return extra_df[existing_cols]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge PhiUSIIL dataset with detector-generated features."
    )
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT,
        help=f"Path to original URL dataset (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Path to write enriched dataset (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--extra",
        default=DEFAULT_EXTRA,
        help=(
            "Optional additional dataset to append before feature extraction "
            f"(default: {DEFAULT_EXTRA} if present)"
        ),
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        fallback = Path("ML/URL/URL Data/URL_Set.csv")
        if fallback.exists():
            input_path = fallback
        else:
            raise FileNotFoundError(f"Input dataset not found: {args.input}")

    df = pd.read_csv(input_path)
    if "URL" not in df.columns:
        raise ValueError("Input dataset must contain a 'URL' column.")

    extra_df = _load_additional_dataset(args.extra)
    if not extra_df.empty:
        df = pd.concat([df, extra_df], ignore_index=True)
        df = df.drop_duplicates(subset="URL", keep="first").reset_index(drop=True)

    detector_features = compute_detector_features(df["URL"].tolist())

    # Only keep columns we can reliably regenerate.
    passthrough_cols = [col for col in ["FILENAME", "URL", "label"] if col in df.columns]
    base_df = df[passthrough_cols].reset_index(drop=True)

    enriched_df = pd.concat([base_df, detector_features], axis=1)
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    enriched_df.to_csv(args.output, index=False)

    print(f"\nEnriched dataset saved to: {args.output}")
    print(f"Total rows: {len(enriched_df):,}")
    print(f"Total columns: {len(enriched_df.columns):,}")


if __name__ == "__main__":
    main()

