#!/usr/bin/env python3
"""
Generate evaluation results for the URL phishing detection model
- Loads existing model from cache
- Evaluates on test set
- Generates feature importance, confusion matrix, and performance metrics
- Saves results to URL Results folder
"""

import os
import sys
import glob
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, confusion_matrix, classification_report
)

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ML.phishing_detector import PhishingDetector

# Paths
RESULTS_DIR = PROJECT_ROOT / "ML" / "URL" / "URL Results"
MODEL_CACHE_FILE = RESULTS_DIR / "cli_detector.joblib"
DATASET_PATH = PROJECT_ROOT / "ML" / "URL" / "URL Data" / "URL_Set.csv"


def delete_old_results():
    """Delete old result files but keep the model"""
    print("Deleting old result files...")
    patterns = [
        "confusion_matrix_*.png",
        "feature_importance_*.png",
        "feature_importance_*.csv",
        "performance_metrics_*.png",
        "feature_distribution_*.png"
    ]
    
    deleted_count = 0
    for pattern in patterns:
        files = glob.glob(str(RESULTS_DIR / pattern))
        for file in files:
            try:
                os.remove(file)
                deleted_count += 1
                print(f"  Deleted: {os.path.basename(file)}")
            except Exception as e:
                print(f"  Error deleting {file}: {e}")
    
    print(f"Deleted {deleted_count} old result files\n")
    return deleted_count


def load_model():
    """Load the cached model"""
    if not MODEL_CACHE_FILE.exists():
        raise FileNotFoundError(
            f"Model cache not found at {MODEL_CACHE_FILE}\n"
            "Please train the model first using cli_url_check.py or export_model_to_js.py"
        )
    
    print(f"Loading model from {MODEL_CACHE_FILE}...")
    payload = joblib.load(MODEL_CACHE_FILE)
    
    detector = PhishingDetector()
    detector.model = payload["model"]
    detector.scaler = payload["scaler"]
    detector.feature_names = payload["feature_names"]
    
    print("Model loaded successfully!")
    print(f"  Features: {len(detector.feature_names)}")
    print(f"  Trees: {detector.model.n_estimators}\n")
    
    return detector


def load_and_prepare_data(detector):
    """Load dataset and prepare for evaluation"""
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}")
    
    print(f"Loading dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    
    print(f"Dataset loaded: {len(df):,} rows")
    
    # Check if features are already extracted
    if 'url_length' in df.columns:
        print("Using pre-computed features from dataset...")
        exclude_cols = ['FILENAME', 'URL', 'label']
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        # Reorder columns to match model's expected feature order
        X_df = df[feature_cols]
        y = df['label'].values
        X = X_df.values
    else:
        print("Extracting features from URLs...")
        urls = df['URL'].tolist() if 'URL' in df.columns else df['url'].tolist()
        labels = df['label'].tolist()
        X = detector.create_dataset(urls, labels)
        y = np.array(labels)
    
    # Split data (same split as training: 85% train, 15% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    
    print(f"Test set: {len(X_test):,} samples")
    print(f"  Legitimate: {np.sum(y_test == 1):,}")
    print(f"  Phishing: {np.sum(y_test == 0):,}\n")
    
    return X_test, y_test


def evaluate_model(detector, X_test, y_test):
    """Evaluate the model and return results"""
    print("Evaluating model...")
    
    # Scale test features
    X_test_scaled = detector.scaler.transform(X_test)
    
    # Make predictions
    y_pred = detector.model.predict(X_test_scaled)
    y_pred_proba = detector.model.predict_proba(X_test_scaled)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred_proba[:, 1])
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-Score: {f1:.4f}")
    print(f"ROC AUC: {roc_auc:.4f}")
    print(f"\nConfusion Matrix:")
    print(f"  True Negatives (Legitimate): {tn}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  True Positives (Phishing): {tp}\n")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc,
        'confusion_matrix': cm,
        'predictions': y_pred,
        'probabilities': y_pred_proba
    }


def get_feature_importance(detector):
    """Get feature importance from the model"""
    feature_importance = pd.DataFrame({
        'feature': detector.feature_names,
        'importance': detector.model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    return feature_importance


def save_feature_importance(feature_importance, timestamp):
    """Save feature importance to CSV"""
    output_file = RESULTS_DIR / f"feature_importance_{timestamp}.csv"
    feature_importance.to_csv(output_file, index=False)
    print(f"Feature importance saved to: {output_file}")
    return output_file


def plot_feature_importance(feature_importance, timestamp):
    """Plot feature importance"""
    fig, ax = plt.subplots(figsize=(10, 12))
    
    top_features = feature_importance.head(20)
    ax.barh(range(len(top_features)), top_features['importance'])
    ax.set_yticks(range(len(top_features)))
    ax.set_yticklabels(top_features['feature'])
    ax.set_xlabel('Feature Importance')
    ax.set_title('Top 20 Feature Importances')
    ax.invert_yaxis()
    
    plt.tight_layout()
    output_file = RESULTS_DIR / f"feature_importance_{timestamp}.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Feature importance plot saved to: {output_file}")
    return output_file


def plot_confusion_matrix(results, timestamp):
    """Plot confusion matrix"""
    fig, ax = plt.subplots(figsize=(8, 6))
    
    cm = results['confusion_matrix']
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                xticklabels=['Legitimate', 'Phishing'],
                yticklabels=['Legitimate', 'Phishing'])
    ax.set_title('Confusion Matrix')
    ax.set_xlabel('Predicted')
    ax.set_ylabel('Actual')
    
    plt.tight_layout()
    output_file = RESULTS_DIR / f"confusion_matrix_{timestamp}.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Confusion matrix saved to: {output_file}")
    return output_file


def plot_performance_metrics(results, timestamp):
    """Plot performance metrics"""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC AUC']
    values = [
        results['accuracy'],
        results['precision'],
        results['recall'],
        results['f1'],
        results['roc_auc']
    ]
    
    bars = ax.bar(metrics, values, color=['skyblue', 'lightgreen', 'lightcoral', 
                                          'lightsalmon', 'plum'])
    ax.set_ylabel('Score')
    ax.set_title('Model Performance Metrics')
    ax.set_ylim([0, 1])
    
    # Add value labels on bars
    for bar, value in zip(bars, values):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
               f'{value:.4f}', ha='center', va='bottom')
    
    plt.tight_layout()
    output_file = RESULTS_DIR / f"performance_metrics_{timestamp}.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Performance metrics saved to: {output_file}")
    return output_file


def save_text_summary(results, feature_importance, X_test, y_test, timestamp):
    """Save all results to a text file"""
    output_file = RESULTS_DIR / f"evaluation_results_{timestamp}.txt"
    
    with open(output_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("URL Phishing Detection Model - Evaluation Results\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Model: cli_detector.joblib\n")
        f.write(f"Dataset: URL_Set.csv\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("DATASET INFORMATION\n")
        f.write("-" * 80 + "\n")
        f.write(f"Test Set Size: {len(X_test):,} samples\n")
        f.write(f"  Legitimate URLs: {np.sum(y_test == 1):,}\n")
        f.write(f"  Phishing URLs: {np.sum(y_test == 0):,}\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("PERFORMANCE METRICS\n")
        f.write("-" * 80 + "\n")
        f.write(f"Accuracy:  {results['accuracy']:.4f} ({results['accuracy']*100:.2f}%)\n")
        f.write(f"Precision: {results['precision']:.4f} ({results['precision']*100:.2f}%)\n")
        f.write(f"Recall:    {results['recall']:.4f} ({results['recall']*100:.2f}%)\n")
        f.write(f"F1-Score:  {results['f1']:.4f} ({results['f1']*100:.2f}%)\n")
        f.write(f"ROC AUC:   {results['roc_auc']:.4f} ({results['roc_auc']*100:.2f}%)\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("CONFUSION MATRIX\n")
        f.write("-" * 80 + "\n")
        cm = results['confusion_matrix']
        f.write(f"                    Predicted\n")
        f.write(f"                 Legitimate  Phishing\n")
        f.write(f"Actual Legitimate    {cm[0,0]:6d}    {cm[0,1]:6d}\n")
        f.write(f"        Phishing     {cm[1,0]:6d}    {cm[1,1]:6d}\n\n")
        
        tn, fp, fn, tp = cm.ravel()
        f.write(f"True Negatives (Correctly identified legitimate): {tn:,}\n")
        f.write(f"False Positives (Legitimate misclassified as phishing): {fp:,}\n")
        f.write(f"False Negatives (Phishing misclassified as legitimate): {fn:,}\n")
        f.write(f"True Positives (Correctly identified phishing): {tp:,}\n\n")
        
        # Calculate additional metrics
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0
        f.write(f"Specificity (True Negative Rate): {specificity:.4f} ({specificity*100:.2f}%)\n")
        f.write(f"Sensitivity (True Positive Rate): {sensitivity:.4f} ({sensitivity*100:.2f}%)\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("FEATURE IMPORTANCE (Top 20)\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Rank':<6} {'Feature':<40} {'Importance':<15} {'Percentage':<15}\n")
        f.write("-" * 80 + "\n")
        
        total_importance = feature_importance['importance'].sum()
        top_features = feature_importance.head(20)
        for i, (_, row) in enumerate(top_features.iterrows(), 1):
            percentage = (row['importance'] / total_importance) * 100
            f.write(f"{i:<6} {row['feature']:<40} {row['importance']:<15.6f} {percentage:<15.2f}%\n")
        
        f.write("\n" + "-" * 80 + "\n")
        f.write("ALL FEATURES (Complete List)\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Rank':<6} {'Feature':<40} {'Importance':<15} {'Percentage':<15}\n")
        f.write("-" * 80 + "\n")
        
        for i, (_, row) in enumerate(feature_importance.iterrows(), 1):
            percentage = (row['importance'] / total_importance) * 100
            f.write(f"{i:<6} {row['feature']:<40} {row['importance']:<15.6f} {percentage:<15.2f}%\n")
        
        f.write("\n" + "=" * 80 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 80 + "\n")
    
    print(f"Text summary saved to: {output_file}")
    return output_file


def main():
    """Main function"""
    print("=" * 60)
    print("URL Phishing Detection - Results Generation")
    print("=" * 60)
    print()
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Delete old results
    delete_old_results()
    
    # Load model
    detector = load_model()
    
    # Load and prepare data
    X_test, y_test = load_and_prepare_data(detector)
    
    # Ensure feature names match and reorder if needed
    if X_test.shape[1] != len(detector.feature_names):
        raise ValueError(
            f"Feature count mismatch: "
            f"Model expects {len(detector.feature_names)} features, "
            f"but data has {X_test.shape[1]} features"
        )
    
    # Note: If the dataset has features in a different order, we'd need to reorder here
    # For now, assuming the dataset columns match the model's feature_names order
    
    # Evaluate model
    results = evaluate_model(detector, X_test, y_test)
    
    # Get feature importance
    feature_importance = get_feature_importance(detector)
    
    # Save and plot results
    print("\nGenerating output files...")
    save_feature_importance(feature_importance, timestamp)
    plot_feature_importance(feature_importance, timestamp)
    plot_confusion_matrix(results, timestamp)
    plot_performance_metrics(results, timestamp)
    save_text_summary(results, feature_importance, X_test, y_test, timestamp)
    
    print("\n" + "=" * 60)
    print("Results generation completed!")
    print("=" * 60)
    print(f"\nSummary:")
    print(f"  Accuracy: {results['accuracy']:.4f}")
    print(f"  Precision: {results['precision']:.4f}")
    print(f"  Recall: {results['recall']:.4f}")
    print(f"  F1-Score: {results['f1']:.4f}")
    print(f"  ROC AUC: {results['roc_auc']:.4f}")
    print(f"\nTop 5 Features:")
    for i, (_, row) in enumerate(feature_importance.head(5).iterrows()):
        print(f"  {i+1}. {row['feature']}: {row['importance']:.4f}")


if __name__ == "__main__":
    main()

