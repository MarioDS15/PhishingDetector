#!/usr/bin/env python3
"""
Remove or downweight path-related features from the dataset
to reduce their importance relative to domain features
"""

import pandas as pd
import numpy as np
from pathlib import Path

# Path features to remove or downweight
PATH_FEATURES = [
    'path_length',
    'path_depth',
    'num_slashes',  # Related to paths
    'trailing_slash',
    'brand_similarity_path',
    'brand_in_path_or_query'
]

def remove_path_features_from_dataset():
    """Remove path features from the dataset CSV"""
    repo_root = Path(__file__).resolve().parents[2]
    dataset_path = repo_root / "ML" / "URL" / "URL Data" / "URL_Set.csv"
    
    print(f"Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)
    
    print(f"Original dataset: {len(df):,} rows, {len(df.columns)} columns")
    
    # Check which path features exist
    existing_path_features = [f for f in PATH_FEATURES if f in df.columns]
    print(f"\nPath features found: {existing_path_features}")
    
    # Remove path features
    df_filtered = df.drop(columns=existing_path_features, errors='ignore')
    
    print(f"After removing path features: {len(df_filtered):,} rows, {len(df_filtered.columns)} columns")
    print(f"Removed {len(df.columns) - len(df_filtered.columns)} columns")
    
    # Save filtered dataset
    output_path = repo_root / "ML" / "URL" / "URL Data" / "URL_Set_no_paths.csv"
    df_filtered.to_csv(output_path, index=False)
    
    print(f"\nFiltered dataset saved to: {output_path}")
    print("\nTo use this dataset, update export_model_to_js.py or cli_url_check.py")
    print("to point to 'URL_Set_no_paths.csv' instead of 'URL_Set.csv'")
    
    return output_path

if __name__ == "__main__":
    remove_path_features_from_dataset()

