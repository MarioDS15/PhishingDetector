#!/usr/bin/env python3
"""
Command-line tool for checking URL phishing risk using the trained ML model.

The script lazily trains (and caches) the RandomForest-based `PhishingDetector`
from `ML/phishing_detector.py` the first time it runs. Subsequent executions
reuse the cached model for fast predictions.
"""

import argparse
import os
import sys
from typing import Dict

import joblib
import numpy as np
import pandas as pd

# Ensure the project modules are importable when running from the repo root
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
ML_PATH = os.path.join(PROJECT_ROOT, "ML")

if ML_PATH not in sys.path:
    sys.path.append(ML_PATH)

from phishing_detector import PhishingDetector  # type: ignore  # noqa: E402

MODEL_CACHE_DIR = os.path.join(PROJECT_ROOT, "ML", "URL", "URL Results")
MODEL_CACHE_FILE = os.path.join(MODEL_CACHE_DIR, "cli_detector.joblib")
FEATURE_VERSION = 4

DATASET_CANDIDATES = [
    os.path.join(PROJECT_ROOT, "ML", "URL", "URL Data", "URL_Set.csv"),
    os.path.join(PROJECT_ROOT, "ML", "URL", "URL Data", "Enhanced_URL_Dataset.csv"),
    os.path.join(PROJECT_ROOT, "ML", "URL", "URL Data", "enhanced_phishing_dataset.csv"),
    os.path.join(PROJECT_ROOT, "ML", "URL", "URL Data", "phishing_dataset.csv"),
]


def _load_dataset() -> pd.DataFrame:
    for path in DATASET_CANDIDATES:
        if os.path.exists(path):
            print(f"[cli_url_check] Loading dataset from: {path}")
            df = pd.read_csv(path)
            print(f"[cli_url_check] Loaded {len(df):,} rows with columns: {list(df.columns)}")
            return df
    raise FileNotFoundError(
        "Could not locate any phishing dataset. "
        "Expected one of: Enhanced_URL_Dataset.csv, enhanced_phishing_dataset.csv, phishing_dataset.csv"
    )


def _train_and_cache_detector() -> PhishingDetector:
    print("[cli_url_check] Training phishing detector model (first run may take a few minutes)...")
    df = _load_dataset()
    if "url" in df.columns:
        urls = df["url"].tolist()
    elif "URL" in df.columns:
        urls = df["URL"].tolist()
    else:
        raise ValueError("Dataset must contain a 'url' or 'URL' column.")

    print(f"[cli_url_check] Preparing training data for {len(urls):,} URLs")
    detector = PhishingDetector()
    labels = df["label"].tolist()
    print("[cli_url_check] Starting feature extraction...")
    X = detector.create_dataset(urls, labels)
    print(f"[cli_url_check] Feature matrix shape: {X.shape}")
    y = np.array(labels)
    print("[cli_url_check] Starting model training...")
    detector.train_model(X, y)
    print("[cli_url_check] Model training finished, saving cache...")

    os.makedirs(MODEL_CACHE_DIR, exist_ok=True)
    joblib.dump(
        {
            "model": detector.model,
            "scaler": detector.scaler,
            "feature_names": detector.feature_names,
            "feature_version": FEATURE_VERSION,
        },
        MODEL_CACHE_FILE,
    )
    print(f"[cli_url_check] Model cached at {MODEL_CACHE_FILE}")
    return detector


def _load_detector() -> PhishingDetector:
    if os.path.exists(MODEL_CACHE_FILE):
        try:
            print(f"[cli_url_check] Loading cached model from {MODEL_CACHE_FILE}...")
            payload: Dict[str, object] = joblib.load(MODEL_CACHE_FILE)
            if payload.get("feature_version") != FEATURE_VERSION:
                raise ValueError("Outdated feature cache")
            detector = PhishingDetector()
            detector.model = payload["model"]
            detector.scaler = payload["scaler"]
            detector.feature_names = payload["feature_names"]
            print("[cli_url_check] Cached model loaded successfully.")
            return detector
        except Exception:
            print("[cli_url_check] Failed to load cached model, retraining...")
            os.remove(MODEL_CACHE_FILE)
    else:
        print("[cli_url_check] No cached model found, training a new one...")
    return _train_and_cache_detector()


def cli_predict_url(detector: PhishingDetector, url: str) -> Dict[str, object]:
    if detector.model is None:
        detector = _train_and_cache_detector()

    features = detector.extract_features(url)
    sample = pd.DataFrame([features])
    if detector.feature_names:
        sample = sample.reindex(columns=detector.feature_names, fill_value=0)

    sample_scaled = detector.scaler.transform(sample)
    prediction = detector.model.predict(sample_scaled)[0]
    proba = detector.model.predict_proba(sample_scaled)[0]

    # Dataset labels: 0=phishing, 1=legitimate (matches URL_Set.csv)
    # proba = [prob_class_0, prob_class_1] = [prob_phishing, prob_legitimate]
    is_phishing = (prediction == 0)
    phishing_prob = float(proba[0])
    legitimate_prob = float(proba[1])
    confidence = phishing_prob if is_phishing else legitimate_prob
    
    heuristics = {}
    if features.get("brand_mismatch") or features.get("brand_homograph"):
        if features.get("brand_mismatch"):
            heuristics["brand_mismatch"] = True
        if features.get("brand_homograph"):
            heuristics["brand_homograph"] = True
        is_phishing = True
        phishing_prob = max(phishing_prob, 0.95)
        legitimate_prob = 1 - phishing_prob
        confidence = phishing_prob

    return {
        "url": url,
        "is_phishing": is_phishing,
        "confidence": confidence,
        "probabilities": [legitimate_prob, phishing_prob],  # Return as [legit, phishing] for display
        "features": features,
        "heuristics": heuristics,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Predict phishing risk for a URL using the trained ML model."
    )
    parser.add_argument("url", help="URL to evaluate")
    parser.add_argument(
        "--refresh-model",
        action="store_true",
        help="Force retraining the cached model before prediction",
    )
    args = parser.parse_args()

    if args.refresh_model and os.path.exists(MODEL_CACHE_FILE):
        os.remove(MODEL_CACHE_FILE)

    detector = _load_detector()
    result = cli_predict_url(detector, args.url)

    status = "PHISHING" if result["is_phishing"] else "LEGITIMATE"
    print(f"URL: {result['url']}")
    print(f"Prediction: {status}")
    print(f"Confidence: {result['confidence']:.3f}")
    print(f"Probabilities (Legit, Phishing): {result['probabilities']}")
    if result.get("heuristics"):
        triggered = ", ".join(result["heuristics"].keys())
        print(f"Heuristics triggered: {triggered}")


if __name__ == "__main__":
    main()

