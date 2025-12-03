#!/usr/bin/env python3
"""
Train models with old and new path features and compare performance
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
COMBINED_DATASET_PATH = PROJECT_ROOT / "ML" / "URL" / "URL Data" / "URL_Set.csv"

def train_and_evaluate(X_train, X_test, y_train, y_test, feature_names, model_name):
    """Train and evaluate a model"""
    print(f"\n{'='*70}")
    print(f"Training {model_name}")
    print(f"{'='*70}")
    print(f"  Features: {len(feature_names)}")
    print(f"  Training samples: {len(X_train):,}")
    print(f"  Test samples: {len(X_test):,}")
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
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
    
    # Evaluate
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred_proba[:, 1])
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    results = {
        'model_name': model_name,
        'n_features': len(feature_names),
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc,
        'true_positives': tp,
        'true_negatives': tn,
        'false_positives': fp,
        'false_negatives': fn,
        'model': model,
        'scaler': scaler,
        'feature_names': feature_names
    }
    
    print(f"\n{model_name} Results:")
    print(f"  Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"  Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"  F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
    print(f"  ROC AUC:   {roc_auc:.4f} ({roc_auc*100:.2f}%)")
    print(f"  Confusion Matrix:")
    print(f"    TP: {tp:,}  FP: {fp:,}")
    print(f"    FN: {fn:,}  TN: {tn:,}")
    
    return results

def main():
    """Main comparison function"""
    print("=" * 70)
    print("Training Models with Enhanced Path Features")
    print("=" * 70)
    
    # Load datasets
    print(f"\nLoading datasets...")
    df_domain = pd.read_csv(DOMAIN_DATASET_PATH)
    df_path = pd.read_csv(PATH_DATASET_PATH)
    df_combined = pd.read_csv(COMBINED_DATASET_PATH)
    
    print(f"  Domain dataset: {len(df_domain):,} rows")
    print(f"  Path dataset: {len(df_path):,} rows")
    print(f"  Combined dataset: {len(df_combined):,} rows")
    
    # Prepare data
    exclude_cols = ['FILENAME', 'URL', 'label']
    
    domain_cols = [col for col in df_domain.columns if col not in exclude_cols]
    path_cols = [col for col in df_path.columns if col not in exclude_cols]
    all_cols = [col for col in df_combined.columns if col not in exclude_cols]
    
    X_domain = df_domain[domain_cols].values
    X_path = df_path[path_cols].values
    X_combined = df_combined[all_cols].values
    y = df_domain['label'].values
    
    # Split data
    X_domain_train, X_domain_test, X_path_train, X_path_test, X_combined_train, X_combined_test, y_train, y_test = train_test_split(
        X_domain, X_path, X_combined, y, test_size=0.15, random_state=42, stratify=y
    )
    
    # Train and evaluate models
    domain_results = train_and_evaluate(
        X_domain_train, X_domain_test, y_train, y_test,
        domain_cols, "Domain-Only (44 features)"
    )
    
    path_results = train_and_evaluate(
        X_path_train, X_path_test, y_train, y_test,
        path_cols, f"Path-Only ({len(path_cols)} features - Enhanced)"
    )
    
    combined_results = train_and_evaluate(
        X_combined_train, X_combined_test, y_train, y_test,
        all_cols, "Combined (50 features)"
    )
    
    # Save models
    print(f"\n{'='*70}")
    print("Saving Models")
    print(f"{'='*70}")
    
    domain_file = RESULTS_DIR / "domain_only_model.joblib"
    joblib.dump({
        'model': domain_results['model'],
        'scaler': domain_results['scaler'],
        'feature_names': domain_results['feature_names'],
        'feature_version': 6,
        'results': {k: v for k, v in domain_results.items() if k not in ['model', 'scaler', 'feature_names']}
    }, domain_file)
    print(f"  ✓ Saved domain model to {domain_file}")
    
    path_file = RESULTS_DIR / "path_only_model.joblib"
    joblib.dump({
        'model': path_results['model'],
        'scaler': path_results['scaler'],
        'feature_names': path_results['feature_names'],
        'feature_version': 6,
        'results': {k: v for k, v in path_results.items() if k not in ['model', 'scaler', 'feature_names']}
    }, path_file)
    print(f"  ✓ Saved path model to {path_file}")
    
    combined_file = RESULTS_DIR / "combined_model.joblib"
    joblib.dump({
        'model': combined_results['model'],
        'scaler': combined_results['scaler'],
        'feature_names': combined_results['feature_names'],
        'feature_version': 6,
        'results': {k: v for k, v in combined_results.items() if k not in ['model', 'scaler', 'feature_names']}
    }, combined_file)
    print(f"  ✓ Saved combined model to {combined_file}")
    
    # Comparison summary
    print(f"\n{'='*70}")
    print("Performance Comparison")
    print(f"{'='*70}")
    print(f"\n{'Model':<30} {'Features':<12} {'Accuracy':<12} {'F1-Score':<12} {'ROC AUC':<12}")
    print("-" * 70)
    print(f"{domain_results['model_name']:<30} {domain_results['n_features']:<12} {domain_results['accuracy']:<12.4f} {domain_results['f1']:<12.4f} {domain_results['roc_auc']:<12.4f}")
    print(f"{path_results['model_name']:<30} {path_results['n_features']:<12} {path_results['accuracy']:<12.4f} {path_results['f1']:<12.4f} {path_results['roc_auc']:<12.4f}")
    print(f"{combined_results['model_name']:<30} {combined_results['n_features']:<12} {combined_results['accuracy']:<12.4f} {combined_results['f1']:<12.4f} {combined_results['roc_auc']:<12.4f}")
    
    # Path model improvement
    print(f"\n{'='*70}")
    print("Path Model Improvement Analysis")
    print(f"{'='*70}")
    print(f"  Old path features: 6")
    print(f"  New path features: {len(path_cols)}")
    print(f"  Improvement: +{len(path_cols) - 6} features")
    print(f"\n  Path model accuracy: {path_results['accuracy']:.4f} ({path_results['accuracy']*100:.2f}%)")
    print(f"  Path model F1-Score: {path_results['f1']:.4f} ({path_results['f1']*100:.2f}%)")
    print(f"  Path model ROC AUC: {path_results['roc_auc']:.4f} ({path_results['roc_auc']*100:.2f}%)")


if __name__ == "__main__":
    main()

