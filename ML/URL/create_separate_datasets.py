#!/usr/bin/env python3
"""
Create separate datasets for domain-only and path-only models
"""

import pandas as pd
from pathlib import Path

# Feature categories
DOMAIN_FEATURES = [
    'url_length', 'num_dots', 'num_hyphens', 'num_underscores',
    'num_question_marks', 'num_equals', 'num_ampersands', 'num_percentages',
    'domain_length', 'query_length', 'subdomain_count', 'has_subdomain',
    'domain_name_length', 'tld_length', 'has_at_symbol', 'has_port', 'has_ip',
    'has_suspicious_tld', 'has_shortener', 'has_suspicious_keywords',
    'has_numbers_in_domain', 'has_mixed_case', 'has_obfuscation',
    'num_obfuscated_chars', 'obfuscation_ratio', 'digit_ratio', 'letter_ratio',
    'special_char_ratio', 'url_entropy', 'domain_entropy', 'has_file_extension',
    'suspicious_file_ext', 'num_params', 'has_suspicious_params',
    'suspicious_brand_usage', 'brand_in_registered_domain', 'brand_in_subdomain',
    'brand_mismatch', 'brand_similarity_registered', 'brand_similarity_subdomain',
    'brand_homograph', 'double_slash', 'uses_https', 'uses_http'
]

PATH_FEATURES = [
    'path_length', 'path_depth', 'num_slashes', 'trailing_slash',
    'brand_similarity_path', 'brand_in_path_or_query'
]

def create_separate_datasets():
    """Create domain-only and path-only datasets"""
    repo_root = Path(__file__).resolve().parents[2]
    input_file = repo_root / "ML" / "URL" / "URL Data" / "URL_Set.csv"
    output_dir = repo_root / "ML" / "URL" / "URL Data"
    
    print(f"Loading dataset from {input_file}...")
    df = pd.read_csv(input_file)
    
    print(f"Original dataset: {len(df):,} rows, {len(df.columns)} columns")
    
    # Required columns
    required_cols = ['FILENAME', 'URL', 'label']
    
    # Get available features
    available_domain = [f for f in DOMAIN_FEATURES if f in df.columns]
    available_path = [f for f in PATH_FEATURES if f in df.columns]
    
    print(f"\nDomain features found: {len(available_domain)}/{len(DOMAIN_FEATURES)}")
    print(f"Path features found: {len(available_path)}/{len(PATH_FEATURES)}")
    
    # Create domain-only dataset
    domain_cols = required_cols + available_domain
    domain_df = df[domain_cols].copy()
    domain_output = output_dir / "URL_Set_domain_only.csv"
    domain_df.to_csv(domain_output, index=False)
    
    print(f"\n✓ Domain-only dataset created:")
    print(f"  File: {domain_output}")
    print(f"  Rows: {len(domain_df):,}")
    print(f"  Columns: {len(domain_df.columns)} ({len(available_domain)} domain features)")
    
    # Create path-only dataset
    path_cols = required_cols + available_path
    path_df = df[path_cols].copy()
    path_output = output_dir / "URL_Set_path_only.csv"
    path_df.to_csv(path_output, index=False)
    
    print(f"\n✓ Path-only dataset created:")
    print(f"  File: {path_output}")
    print(f"  Rows: {len(path_df):,}")
    print(f"  Columns: {len(path_df.columns)} ({len(available_path)} path features)")
    
    # Summary
    print(f"\n" + "=" * 70)
    print("Summary:")
    print(f"  Domain dataset: {len(available_domain)} features")
    print(f"  Path dataset: {len(available_path)} features")
    print(f"  Total URLs: {len(df):,}")
    print(f"\nYou can now train models using:")
    print(f"  - {domain_output.name} for domain-only model")
    print(f"  - {path_output.name} for path-only model")


if __name__ == "__main__":
    create_separate_datasets()

