#!/usr/bin/env python3
"""
Export domain-only and path-only models to JavaScript format
for use in the weighted prediction system in the extension
"""

import json
import numpy as np
import pandas as pd
from sklearn.tree import _tree
import sys
import os
import joblib
from pathlib import Path

# Add ML directory to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from export_model_to_js import export_tree_to_dict


def export_model_to_json(model, scaler, feature_names, output_file, model_name):
    """
    Export a trained model to JSON format
    """
    if not model:
        raise ValueError(f"No trained {model_name} model found!")

    print(f"Exporting {model_name} model to JSON...")

    # Extract model parameters
    model_data = {
        'model_type': 'RandomForest',
        'model_name': model_name,
        'n_estimators': model.n_estimators,
        'feature_names': feature_names,
        'n_features': len(feature_names),
        'classes': [0, 1],  # 0=phishing, 1=legitimate
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
        model_data['trees'].append(tree_dict)

    # Save to file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(model_data, f, indent=2)

    # Get file size
    file_size = os.path.getsize(output_file)
    print(f"\n{model_name} model exported successfully!")
    print(f"Output file: {output_file}")
    print(f"File size: {file_size / 1024:.2f} KB")
    print(f"Number of trees: {len(model_data['trees'])}")
    print(f"Number of features: {len(model_data['feature_names'])}")

    return model_data


def create_lightweight_model(model, scaler, feature_names, n_trees=30, output_file=None, model_name=""):
    """
    Create a lightweight version with fewer trees
    """
    if not model:
        raise ValueError(f"No trained {model_name} model found!")

    print(f"\nCreating lightweight {model_name} model with {n_trees} trees...")

    model_data = {
        'model_type': 'RandomForest',
        'model_name': model_name,
        'n_estimators': n_trees,
        'feature_names': feature_names,
        'n_features': len(feature_names),
        'classes': [0, 1],
        'trees': [],
        'scaler': {
            'mean': scaler.mean_.tolist(),
            'scale': scaler.scale_.tolist()
        }
    }

    # Export only first N trees
    for idx, tree in enumerate(model.estimators_[:n_trees]):
        tree_dict = export_tree_to_dict(tree, feature_names)
        model_data['trees'].append(tree_dict)

    # Save to file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(model_data, f, indent=2)

    file_size = os.path.getsize(output_file)
    print(f"\nLightweight {model_name} model created!")
    print(f"Output file: {output_file}")
    print(f"File size: {file_size / 1024:.2f} KB")
    print(f"Number of trees: {len(model_data['trees'])}")

    return model_data


def main():
    """
    Main function to export domain and path models
    """
    print("=== Weighted Model Export to JavaScript ===\n")

    results_dir = PROJECT_ROOT / "ML" / "URL" / "URL Results"
    
    # Load domain model
    domain_file = results_dir / "domain_only_model.joblib"
    if not domain_file.exists():
        print(f"Error: Domain model not found at {domain_file}")
        print("Please run train_separate_models.py first.")
        return

    print(f"Loading domain model from {domain_file}...")
    domain_payload = joblib.load(domain_file)
    domain_model = domain_payload['model']
    domain_scaler = domain_payload['scaler']
    domain_features = domain_payload['feature_names']

    # Load path model
    path_file = results_dir / "path_only_model.joblib"
    if not path_file.exists():
        print(f"Error: Path model not found at {path_file}")
        print("Please run train_separate_models.py first.")
        return

    print(f"Loading path model from {path_file}...")
    path_payload = joblib.load(path_file)
    path_model = path_payload['model']
    path_scaler = path_payload['scaler']
    path_features = path_payload['feature_names']

    # Export full models
    print("\n" + "="*50)
    print("Exporting full models...")
    print("="*50)
    export_model_to_json(
        domain_model, domain_scaler, domain_features,
        'extension/models/domain_model.json',
        'domain-only'
    )
    
    export_model_to_json(
        path_model, path_scaler, path_features,
        'extension/models/path_model.json',
        'path-only'
    )

    # Export lightweight models
    print("\n" + "="*50)
    print("Exporting lightweight models...")
    print("="*50)
    create_lightweight_model(
        domain_model, domain_scaler, domain_features,
        n_trees=30,
        output_file='extension/models/domain_model_lite.json',
        model_name='domain-only'
    )
    
    create_lightweight_model(
        path_model, path_scaler, path_features,
        n_trees=30,
        output_file='extension/models/path_model_lite.json',
        model_name='path-only'
    )

    print("\n✅ Model export completed successfully!")
    print("\nYou can now use these models in the Chrome extension:")
    print("  - extension/models/domain_model_lite.json (lightweight, 30 trees)")
    print("  - extension/models/path_model_lite.json (lightweight, 30 trees)")
    print("\nNext step: Update extension JavaScript to use weighted predictions")


if __name__ == "__main__":
    main()

