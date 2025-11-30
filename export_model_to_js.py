#!/usr/bin/env python3
"""
Export trained Random Forest model to JavaScript-compatible format
This extracts the decision trees and converts them to JSON
"""

import json
import numpy as np
import pandas as pd
from sklearn.tree import _tree
import sys
import os

# Add ML directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'ML'))

from ML.phishing_detector import PhishingDetector


def export_tree_to_dict(tree, feature_names):
    """
    Convert a single decision tree to dictionary format
    """
    tree_ = tree.tree_
    feature_name = [
        feature_names[i] if i != _tree.TREE_UNDEFINED else "undefined!"
        for i in tree_.feature
    ]

    def recurse(node):
        if tree_.feature[node] != _tree.TREE_UNDEFINED:
            name = feature_name[node]
            threshold = float(tree_.threshold[node])
            return {
                'feature': name,
                'threshold': threshold,
                'left': recurse(tree_.children_left[node]),
                'right': recurse(tree_.children_right[node])
            }
        else:
            # Leaf node
            value = tree_.value[node]
            # Return the class with highest count
            class_counts = value[0]
            predicted_class = int(np.argmax(class_counts))
            confidence = float(class_counts[predicted_class] / np.sum(class_counts))
            return {
                'leaf': True,
                'class': predicted_class,
                'confidence': confidence,
                'samples': int(np.sum(class_counts))
            }

    return recurse(0)


def export_model_to_json(detector, output_file='extension/models/model.json'):
    """
    Export the trained model to JSON format
    """
    if not detector.model:
        raise ValueError("No trained model found!")

    print("Exporting Random Forest model to JSON...")

    # Extract model parameters
    model_data = {
        'model_type': 'RandomForest',
        'n_estimators': detector.model.n_estimators,
        'feature_names': detector.feature_names,
        'n_features': len(detector.feature_names),
        # Dataset convention: 0 = phishing, 1 = legitimate (matches URL_Set.csv)
        'classes': [0, 1],
        'trees': [],
        'scaler': {
            'mean': detector.scaler.mean_.tolist(),
            'scale': detector.scaler.scale_.tolist()
        }
    }

    # Export each tree
    print(f"Exporting {len(detector.model.estimators_)} trees...")
    for idx, tree in enumerate(detector.model.estimators_):
        if idx % 10 == 0:
            print(f"Exported {idx}/{len(detector.model.estimators_)} trees")

        tree_dict = export_tree_to_dict(tree, detector.feature_names)
        model_data['trees'].append(tree_dict)

    # Save to file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(model_data, f, indent=2)

    # Get file size
    file_size = os.path.getsize(output_file)
    print(f"\nModel exported successfully!")
    print(f"Output file: {output_file}")
    print(f"File size: {file_size / 1024:.2f} KB")
    print(f"Number of trees: {len(model_data['trees'])}")
    print(f"Number of features: {len(model_data['feature_names'])}")

    return model_data


def create_lightweight_model(detector, n_trees=20, output_file='extension/models/model_lite.json'):
    """
    Create a lightweight version with fewer trees for faster browser execution
    """
    if not detector.model:
        raise ValueError("No trained model found!")

    print(f"\nCreating lightweight model with {n_trees} trees...")

    # Get feature importance to select best trees
    importances = detector.model.feature_importances_

    # Select top N trees based on their contribution
    # For simplicity, just take the first N trees
    model_data = {
        'model_type': 'RandomForest',
        'n_estimators': n_trees,
        'feature_names': detector.feature_names,
        'n_features': len(detector.feature_names),
        # Dataset convention: 0 = phishing, 1 = legitimate (matches URL_Set.csv)
        'classes': [0, 1],
        'trees': [],
        'scaler': {
            'mean': detector.scaler.mean_.tolist(),
            'scale': detector.scaler.scale_.tolist()
        }
    }

    # Export only first N trees
    for idx, tree in enumerate(detector.model.estimators_[:n_trees]):
        tree_dict = export_tree_to_dict(tree, detector.feature_names)
        model_data['trees'].append(tree_dict)

    # Save to file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(model_data, f, indent=2)

    file_size = os.path.getsize(output_file)
    print(f"\nLightweight model created!")
    print(f"Output file: {output_file}")
    print(f"File size: {file_size / 1024:.2f} KB")
    print(f"Number of trees: {len(model_data['trees'])}")

    return model_data


def main():
    """
    Main function to train and export the model
    """
    print("=== Phishing Detection Model Export ===\n")

    # Load dataset
    dataset_path = 'ML/URL/URL Data/URL_Set.csv'

    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        print("Please run the training script first to create the dataset.")
        return

    print(f"Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)

    print(f"Dataset loaded: {len(df)} samples")
    print(f"Columns: {df.columns.tolist()}")

    # Prepare data
    if 'label' not in df.columns:
        print("Error: Dataset must have 'label' column")
        return

    # Check if features are already in the dataset
    if 'url_length' in df.columns:
        print("Using pre-computed features from dataset...")
        # Extract feature columns (exclude non-feature columns)
        exclude_cols = ['FILENAME', 'URL', 'label']
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        X = df[feature_cols].values

        # Note: Keep original labels from dataset (0=phishing, 1=legitimate)
        y = df['label'].values
        print("Note: Using dataset labels as-is (0=phishing, 1=legitimate)")

        # Initialize detector
        print("\nInitializing detector...")
        detector = PhishingDetector()
        detector.feature_names = feature_cols

        print(f"Features: {len(feature_cols)}")
        print(f"Samples: {len(X)}")
    else:
        print("Extracting features from URLs...")
        labels = df['label']
        urls = df['URL'] if 'URL' in df.columns else df['url']

        # Initialize detector
        detector = PhishingDetector()

        # Create feature matrix
        X = detector.create_dataset(urls.tolist(), labels.tolist())
        y = labels.values

    # Train model
    print("\nTraining model...")
    detector.train_model(X, y)

    print("\nModel training completed!")
    print(f"Number of features: {len(detector.feature_names)}")

    # Export full model
    print("\n" + "="*50)
    print("Exporting full model...")
    print("="*50)
    export_model_to_json(detector, 'extension/models/model.json')

    # Export lightweight model
    print("\n" + "="*50)
    print("Exporting lightweight model...")
    print("="*50)
    create_lightweight_model(detector, n_trees=30, output_file='extension/models/model_lite.json')

    print("\n✅ Model export completed successfully!")
    print("\nYou can now use these models in the Chrome extension:")
    print("  - extension/models/model.json (full model, 100 trees)")
    print("  - extension/models/model_lite.json (lightweight, 30 trees)")
    print("\nThe lightweight model is recommended for faster browser performance.")


if __name__ == "__main__":
    main()
