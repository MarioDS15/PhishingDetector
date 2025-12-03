#!/usr/bin/env python3
"""
Test a specific URL and show which features contributed most to the phishing detection
"""

import sys
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.tree import _tree

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ML.phishing_detector import PhishingDetector

def analyze_url(url):
    """Analyze a URL and show top contributing features"""
    print(f"Analyzing URL: {url}\n")
    print("=" * 70)
    
    # Load model
    model_file = PROJECT_ROOT / "ML" / "URL" / "URL Results" / "cli_detector.joblib"
    if not model_file.exists():
        print(f"Error: Model not found at {model_file}")
        return
    
    print(f"Loading model from {model_file}...")
    payload = joblib.load(model_file)
    model = payload['model']
    scaler = payload['scaler']
    feature_names = payload['feature_names']
    
    # Extract features
    detector = PhishingDetector()
    features = detector.extract_features(url)
    
    # Create feature vector
    feature_vector = pd.DataFrame([features])[feature_names]
    feature_scaled = scaler.transform(feature_vector)
    
    # Get predictions from all trees
    tree_predictions = []
    tree_feature_usage = {}  # Track which features each tree used
    phishing_voting_features = {}  # Track features in trees that voted phishing
    
    for tree_idx, tree in enumerate(model.estimators_):
        # Track features used in this tree
        used_features = set()
        
        # Traverse tree and track features
        def traverse(node, depth=0):
            if tree.tree_.feature[node] != _tree.TREE_UNDEFINED:
                feature_idx = tree.tree_.feature[node]
                feature_name = feature_names[feature_idx]
                used_features.add(feature_name)
                
                threshold = tree.tree_.threshold[node]
                feature_value = feature_scaled[0][feature_idx]
                
                if feature_value <= threshold:
                    traverse(tree.tree_.children_left[node], depth + 1)
                else:
                    traverse(tree.tree_.children_right[node], depth + 1)
            else:
                # Leaf node
                value = tree.tree_.value[node]
                predicted_class = int(np.argmax(value[0]))
                return predicted_class
        
        predicted_class = traverse(0)
        tree_predictions.append(predicted_class)
        
        # Track feature usage
        for feature_name in used_features:
            if feature_name not in tree_feature_usage:
                tree_feature_usage[feature_name] = 0
            tree_feature_usage[feature_name] += 1
            
            # If this tree voted for phishing (class 0), track it
            if predicted_class == 0:
                if feature_name not in phishing_voting_features:
                    phishing_voting_features[feature_name] = 0
                phishing_voting_features[feature_name] += 1
    
    # Aggregate predictions
    phishing_votes = sum(1 for p in tree_predictions if p == 0)
    legitimate_votes = sum(1 for p in tree_predictions if p == 1)
    total_votes = len(tree_predictions)
    
    is_phishing = phishing_votes > legitimate_votes
    confidence = phishing_votes / total_votes if is_phishing else legitimate_votes / total_votes
    
    print(f"\nPrediction Results:")
    print(f"  Phishing votes: {phishing_votes}/{total_votes}")
    print(f"  Legitimate votes: {legitimate_votes}/{total_votes}")
    print(f"  Prediction: {'PHISHING' if is_phishing else 'LEGITIMATE'}")
    print(f"  Confidence: {confidence:.2%}")
    
    # Show top features that contributed to phishing detection
    print(f"\n" + "=" * 70)
    print("Top Features Contributing to Phishing Detection:")
    print("=" * 70)
    
    if is_phishing and phishing_voting_features:
        # Sort by usage count in phishing-voting trees
        sorted_features = sorted(
            phishing_voting_features.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        print(f"\nFeatures used in phishing-voting trees (out of {phishing_votes} phishing votes):")
        print(f"{'Rank':<6} {'Feature':<35} {'Usage':<10} {'Value':<15} {'% of Phishing Trees'}")
        print("-" * 70)
        
        for rank, (feature_name, usage_count) in enumerate(sorted_features[:10], 1):
            feature_value = features.get(feature_name, 'N/A')
            percentage = (usage_count / phishing_votes) * 100 if phishing_votes > 0 else 0
            print(f"{rank:<6} {feature_name:<35} {usage_count:<10} {str(feature_value):<15} {percentage:.1f}%")
        
        print(f"\nTop 4 Most Impactful Factors:")
        print("-" * 70)
        for rank, (feature_name, usage_count) in enumerate(sorted_features[:4], 1):
            feature_value = features.get(feature_name, 'N/A')
            percentage = (usage_count / phishing_votes) * 100 if phishing_votes > 0 else 0
            print(f"{rank}. {feature_name} (used in {usage_count}/{phishing_votes} phishing trees, {percentage:.1f}%)")
            print(f"   Value: {feature_value}")
    else:
        print("No phishing features detected or URL was classified as legitimate.")
    
    # Show all feature values for debugging
    print(f"\n" + "=" * 70)
    print("All Feature Values:")
    print("=" * 70)
    for feature_name in sorted(feature_names):
        value = features.get(feature_name, 'N/A')
        if value != 0 and value != 'N/A':  # Only show non-zero features
            print(f"  {feature_name}: {value}")


if __name__ == "__main__":
    test_url = "https://canvas.gmu.edu/login?needs_cookies=1"
    analyze_url(test_url)

