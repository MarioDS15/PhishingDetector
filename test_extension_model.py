#!/usr/bin/env python3
"""
Test URL with the extension's actual model (model_lite.json format)
"""

import json
import sys
import pandas as pd
import numpy as np
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ML.phishing_detector import PhishingDetector

def predict_with_tree(node, features):
    """Recursively predict using a tree node"""
    if node.get('leaf'):
        return node['class'], node['confidence']
    
    feature_name = node['feature']
    threshold = node['threshold']
    feature_value = features.get(feature_name, 0)
    
    if feature_value <= threshold:
        return predict_with_tree(node['left'], features)
    else:
        return predict_with_tree(node['right'], features)

def analyze_url_with_extension_model(url):
    """Analyze URL using the extension's model format"""
    print(f"Analyzing URL: {url}\n")
    print("=" * 70)
    
    # Load extension model
    model_file = PROJECT_ROOT / "extension" / "models" / "model_lite.json"
    if not model_file.exists():
        print(f"Error: Extension model not found at {model_file}")
        return
    
    print(f"Loading extension model from {model_file}...")
    with open(model_file, 'r') as f:
        model_data = json.load(f)
    
    # Extract features
    detector = PhishingDetector()
    features = detector.extract_features(url)
    
    # Scale features
    scaled_features = {}
    for i, feature_name in enumerate(model_data['feature_names']):
        value = features.get(feature_name, 0)
        mean = model_data['scaler']['mean'][i]
        scale = model_data['scaler']['scale'][i]
        scaled_features[feature_name] = (value - mean) / scale
    
    # Get predictions from all trees and track feature usage
    tree_predictions = []
    tree_feature_usage = {}  # Track which features each tree used
    phishing_voting_features = {}  # Track features in trees that voted phishing
    
    for tree_idx, tree in enumerate(model_data['trees']):
        used_features = set()
        
        def traverse_and_track(node, depth=0):
            if node.get('leaf'):
                return node['class'], node['confidence']
            
            feature_name = node['feature']
            used_features.add(feature_name)
            
            threshold = node['threshold']
            feature_value = scaled_features.get(feature_name, 0)
            
            if feature_value <= threshold:
                return traverse_and_track(node['left'], depth + 1)
            else:
                return traverse_and_track(node['right'], depth + 1)
        
        predicted_class, confidence = traverse_and_track(tree)
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
        
        for rank, (feature_name, usage_count) in enumerate(sorted_features[:15], 1):
            feature_value = features.get(feature_name, 'N/A')
            percentage = (usage_count / phishing_votes) * 100 if phishing_votes > 0 else 0
            print(f"{rank:<6} {feature_name:<35} {usage_count:<10} {str(feature_value):<15} {percentage:.1f}%")
        
        print(f"\n" + "=" * 70)
        print("Top 4 Most Impactful Factors:")
        print("=" * 70)
        for rank, (feature_name, usage_count) in enumerate(sorted_features[:4], 1):
            feature_value = features.get(feature_name, 'N/A')
            percentage = (usage_count / phishing_votes) * 100 if phishing_votes > 0 else 0
            print(f"\n{rank}. {feature_name}")
            print(f"   Used in: {usage_count}/{phishing_votes} phishing-voting trees ({percentage:.1f}%)")
            print(f"   Feature value: {feature_value}")
    else:
        print("No phishing features detected or URL was classified as legitimate.")


if __name__ == "__main__":
    test_url = "https://canvas.gmu.edu/login?needs_cookies=1"
    analyze_url_with_extension_model(test_url)

