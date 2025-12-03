#!/usr/bin/env python3
"""
Train separate models for domain-only, path-only, and combined predictions
with adjustable weights (default: 75% domain, 25% path)
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ML.phishing_detector import PhishingDetector

# Paths
RESULTS_DIR = PROJECT_ROOT / "ML" / "URL" / "URL Results"
DOMAIN_DATASET_PATH = PROJECT_ROOT / "ML" / "URL" / "URL Data" / "URL_Set_domain_only.csv"
PATH_DATASET_PATH = PROJECT_ROOT / "ML" / "URL" / "URL Data" / "URL_Set_path_only.csv"
COMBINED_DATASET_PATH = PROJECT_ROOT / "ML" / "URL" / "URL Data" / "URL_Set_combined.csv"


def load_and_prepare_data():
    """Load separate datasets and prepare feature matrices"""
    # Load domain-only dataset
    print(f"Loading domain dataset from {DOMAIN_DATASET_PATH}...")
    df_domain = pd.read_csv(DOMAIN_DATASET_PATH)
    print(f"Domain dataset loaded: {len(df_domain):,} rows")
    
    # Load path-only dataset
    print(f"Loading path dataset from {PATH_DATASET_PATH}...")
    df_path = pd.read_csv(PATH_DATASET_PATH)
    print(f"Path dataset loaded: {len(df_path):,} rows")
    
    # Load combined dataset for combined model
    print(f"Loading combined dataset from {COMBINED_DATASET_PATH}...")
    df_combined = pd.read_csv(COMBINED_DATASET_PATH)
    print(f"Combined dataset loaded: {len(df_combined):,} rows")
    
    # Verify all datasets have same number of rows and same URLs
    if len(df_domain) != len(df_path) or len(df_domain) != len(df_combined):
        raise ValueError("Datasets must have the same number of rows")
    
    # Check if features are already extracted
    if 'domain_length' in df_domain.columns:
        print("Using pre-computed component-specific features...")
        
        # Extract feature columns (exclude FILENAME, URL, DOMAIN/PATH_QUERY component columns, label)
        exclude_cols_domain = ['FILENAME', 'URL', 'DOMAIN', 'label']
        exclude_cols_path = ['FILENAME', 'URL', 'PATH_QUERY', 'label']
        exclude_cols_combined = ['FILENAME', 'URL', 'DOMAIN', 'PATH_QUERY', 'label']
        
        domain_cols = [col for col in df_domain.columns if col not in exclude_cols_domain]
        path_cols = [col for col in df_path.columns if col not in exclude_cols_path]
        all_cols = [col for col in df_combined.columns if col not in exclude_cols_combined]
        
        X_domain = df_domain[domain_cols].values
        X_path = df_path[path_cols].values
        X_combined = df_combined[all_cols].values
        y = df_domain['label'].values  # Use label from any dataset (they should be the same)
        
        print(f"\nFeature counts:")
        print(f"  Domain features: {len(domain_cols)}")
        print(f"  Path features: {len(path_cols)}")
        print(f"  Combined features: {len(all_cols)}")
        
        return X_domain, X_path, X_combined, y, domain_cols, path_cols, all_cols
    else:
        raise ValueError("Datasets must have pre-computed features. Please run generate_enriched_url_dataset.py first.")


def train_model(X_train, y_train, feature_names, model_name):
    """Train a Random Forest model"""
    print(f"\nTraining {model_name} model...")
    print(f"  Features: {len(feature_names)}")
    print(f"  Training samples: {len(X_train):,}")
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        verbose=0
    )
    
    model.fit(X_train_scaled, y_train)
    print(f"  ✓ {model_name} model trained")
    
    return model, scaler, feature_names


def evaluate_model(model, scaler, X_test, y_test, feature_names, model_name):
    """Evaluate a trained model"""
    X_test_scaled = scaler.transform(X_test)
    
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred_proba[:, 1])
    cm = confusion_matrix(y_test, y_pred)
    
    print(f"\n{model_name} Performance:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  ROC AUC:   {roc_auc:.4f}")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc,
        'confusion_matrix': cm
    }


def save_model(model, scaler, feature_names, model_name, results):
    """Save model to disk"""
    output_file = RESULTS_DIR / f"{model_name}_model.joblib"
    
    payload = {
        'model': model,
        'scaler': scaler,
        'feature_names': feature_names,
        'feature_version': 5,  # New version for separate models
        'model_name': model_name,
        'results': results
    }
    
    joblib.dump(payload, output_file)
    print(f"  ✓ Saved to {output_file}")
    return output_file


def main():
    """Main training function"""
    print("=" * 70)
    print("Training Separate Domain/Path Models")
    print("=" * 70)
    
    # Load data
    X_domain, X_path, X_combined, y, domain_cols, path_cols, all_cols = load_and_prepare_data()
    
    # Split data (85% train, 15% test)
    X_domain_train, X_domain_test, X_path_train, X_path_test, X_combined_train, X_combined_test, y_train, y_test = train_test_split(
        X_domain, X_path, X_combined, y, test_size=0.15, random_state=42, stratify=y
    )
    
    print(f"\nData split:")
    print(f"  Training: {len(X_domain_train):,} samples")
    print(f"  Testing:  {len(X_domain_test):,} samples")
    
    # Train domain-only model
    domain_model, domain_scaler, domain_features = train_model(
        X_domain_train, y_train, domain_cols, "Domain-Only"
    )
    domain_results = evaluate_model(
        domain_model, domain_scaler, X_domain_test, y_test, domain_cols, "Domain-Only"
    )
    save_model(domain_model, domain_scaler, domain_cols, "domain_only", domain_results)
    
    # Train path-only model
    path_model, path_scaler, path_features = train_model(
        X_path_train, y_train, path_cols, "Path-Only"
    )
    path_results = evaluate_model(
        path_model, path_scaler, X_path_test, y_test, path_cols, "Path-Only"
    )
    save_model(path_model, path_scaler, path_cols, "path_only", path_results)
    
    # Train combined model (for comparison)
    combined_model, combined_scaler, combined_features = train_model(
        X_combined_train, y_train, all_cols, "Combined"
    )
    combined_results = evaluate_model(
        combined_model, combined_scaler, X_combined_test, y_test, all_cols, "Combined"
    )
    save_model(combined_model, combined_scaler, all_cols, "combined", combined_results)
    
    print("\n" + "=" * 70)
    print("Training Complete!")
    print("=" * 70)
    print("\nModel Summary:")
    print(f"  Domain-Only: {len(domain_cols)} features")
    print(f"  Path-Only:   {len(path_cols)} features")
    print(f"  Combined:    {len(all_cols)} features")
    print("\nTo use weighted predictions (75% domain, 25% path),")
    print("update the extension to load both models and combine predictions.")


if __name__ == "__main__":
    main()

