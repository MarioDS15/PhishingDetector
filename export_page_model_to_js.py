#!/usr/bin/env python3
"""
Export trained Page-Based Random Forest model to JavaScript-compatible format
Converts the page detection model to JSON for browser extension use
"""

import json
import numpy as np
import joblib
import os
from sklearn.tree import _tree


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


def export_model_to_json(model_data, output_file='extension/models/page_model.json'):
    """
    Export the trained page model to JSON format
    """
    model = model_data['model']
    scaler = model_data['scaler']
    feature_names = model_data['feature_names']

    print("Exporting Page-Based Random Forest model to JSON...")

    # Extract model parameters
    json_data = {
        'model_type': 'RandomForest',
        'detection_type': 'page',  # Indicates this is page-based detection
        'n_estimators': model.n_estimators,
        'feature_names': feature_names,
        'n_features': len(feature_names),
        # Page dataset convention: 0 = phishing, 1 = legitimate
        'classes': [0, 1],
        'class_names': ['phishing', 'legitimate'],
        'trees': [],
        'scaler': {
            'mean': scaler.mean_.tolist(),
            'scale': scaler.scale_.tolist()
        }
    }

    # Export each tree
    print(f"Exporting {len(model.estimators_)} trees...")
    for idx, tree in enumerate(model.estimators_):
        if idx % 10 == 0:
            print(f"Exported {idx}/{len(model.estimators_)} trees")

        tree_dict = export_tree_to_dict(tree, feature_names)
        json_data['trees'].append(tree_dict)

    # Save to file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(json_data, f, indent=2)

    # Get file size
    file_size = os.path.getsize(output_file)
    print(f"\nPage model exported successfully!")
    print(f"Output file: {output_file}")
    print(f"File size: {file_size / 1024:.2f} KB ({file_size / (1024*1024):.2f} MB)")
    print(f"Number of trees: {len(json_data['trees'])}")
    print(f"Number of features: {len(json_data['feature_names'])}")
    print(f"Features: {json_data['feature_names']}")

    return json_data


def create_lightweight_model(model_data, n_trees=30, output_file='extension/models/page_model_lite.json'):
    """
    Create a lightweight version with fewer trees for faster browser execution
    """
    model = model_data['model']
    scaler = model_data['scaler']
    feature_names = model_data['feature_names']

    print(f"\nCreating lightweight page model with {n_trees} trees...")

    # Create lightweight model data
    json_data = {
        'model_type': 'RandomForest',
        'detection_type': 'page',
        'n_estimators': n_trees,
        'feature_names': feature_names,
        'n_features': len(feature_names),
        'classes': [0, 1],
        'class_names': ['phishing', 'legitimate'],
        'trees': [],
        'scaler': {
            'mean': scaler.mean_.tolist(),
            'scale': scaler.scale_.tolist()
        }
    }

    # Export only first N trees
    for idx, tree in enumerate(model.estimators_[:n_trees]):
        tree_dict = export_tree_to_dict(tree, feature_names)
        json_data['trees'].append(tree_dict)

    # Save to file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(json_data, f, indent=2)

    file_size = os.path.getsize(output_file)
    print(f"\nLightweight page model created!")
    print(f"Output file: {output_file}")
    print(f"File size: {file_size / 1024:.2f} KB")
    print(f"Number of trees: {len(json_data['trees'])}")

    return json_data


def main():
    """
    Main function to load and export the page model
    """
    print("=== Page-Based Phishing Detection Model Export ===\n")

    # Load the trained model
    model_path = 'ML/Page/Page Results/cli_page_detector.joblib'

    if not os.path.exists(model_path):
        print(f"Error: Trained model not found at {model_path}")
        print("Please train the page model first using page_main.py")
        return

    print(f"Loading trained page model from {model_path}...")
    model_data = joblib.load(model_path)

    print("Model loaded successfully!")
    print(f"Model type: {type(model_data['model'])}")
    print(f"Number of features: {len(model_data['feature_names'])}")
    print(f"Number of trees: {model_data['model'].n_estimators}")
    print(f"Features: {model_data['feature_names']}")

    # Export full model
    print("\n" + "="*50)
    print("Exporting full page model...")
    print("="*50)
    export_model_to_json(model_data, 'extension/models/page_model.json')

    # Export lightweight model
    print("\n" + "="*50)
    print("Exporting lightweight page model...")
    print("="*50)
    create_lightweight_model(model_data, n_trees=30, output_file='extension/models/page_model_lite.json')

    print("\n✅ Page model export completed successfully!")
    print("\nYou can now use these models in the Chrome extension:")
    print("  - extension/models/page_model.json (full model, 100 trees)")
    print("  - extension/models/page_model_lite.json (lightweight, 30 trees)")
    print("\nThe lightweight model is recommended for faster browser performance.")
    print("\nNext steps:")
    print("  1. Create extension/js/page-features.js (extract 29 DOM features)")
    print("  2. Create extension/js/page-model.js (run RandomForest in browser)")
    print("  3. Update extension/js/content.js (extract features on page load)")
    print("  4. Update extension/js/background.js (combine URL + Page predictions)")


if __name__ == "__main__":
    main()
