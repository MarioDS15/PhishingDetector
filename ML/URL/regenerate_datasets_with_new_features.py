#!/usr/bin/env python3
"""
Regenerate domain-only and path-only datasets with new path features
"""

import pandas as pd
from pathlib import Path
import sys

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ML.phishing_detector import PhishingDetector

# Feature categories (updated with new path features)
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

# Updated path features with new additions
PATH_FEATURES = [
    'path_length', 'path_depth', 'num_slashes', 'trailing_slash',
    'brand_similarity_path', 'brand_in_path_or_query',
    # New path features
    'path_segment_count', 'avg_path_segment_length', 'max_path_segment_length',
    'path_entropy', 'path_has_numbers', 'path_has_special_chars',
    'path_digit_ratio', 'path_letter_ratio', 'has_legitimate_path',
    'legitimate_path_count', 'has_suspicious_path', 'suspicious_path_count',
    'path_starts_with_slash', 'path_ends_with_slash', 'path_has_double_slash',
    'path_has_query_in_path'
]

def regenerate_datasets():
    """Regenerate datasets with new path features"""
    repo_root = PROJECT_ROOT
    input_file = repo_root / "ML" / "URL" / "URL Data" / "URL_Set.csv"
    domain_output = repo_root / "ML" / "URL" / "URL Data" / "URL_Set_domain_only.csv"
    path_output = repo_root / "ML" / "URL" / "URL Data" / "URL_Set_path_only.csv"
    
    print("Regenerating datasets with new path features...")
    print(f"Loading base dataset from {input_file}...")
    
    # Load original dataset
    df = pd.read_csv(input_file)
    print(f"Loaded {len(df):,} rows")
    
    # Check if we need to extract new features
    if 'path_segment_count' not in df.columns:
        print("\nNew path features not found in dataset. Extracting features...")
        detector = PhishingDetector()
        
        print("Extracting features for all URLs (this may take a while)...")
        feature_rows = []
        for idx, row in df.iterrows():
            if idx % 10000 == 0:
                print(f"  Processed {idx}/{len(df)} URLs")
            
            try:
                features = detector.extract_features(row['URL'])
                feature_rows.append(features)
            except Exception as e:
                print(f"  Error processing URL {idx}: {e}")
                feature_rows.append({})
        
        # Create new feature DataFrame
        features_df = pd.DataFrame(feature_rows)
        
        # Merge with original (keep FILENAME, URL, label from original)
        df = pd.concat([
            df[['FILENAME', 'URL', 'label']],
            features_df
        ], axis=1)
        
        # Save updated combined dataset
        df.to_csv(input_file, index=False)
        print(f"\n✓ Updated combined dataset with new features")
    
    # Create domain-only dataset
    print(f"\nCreating domain-only dataset...")
    domain_cols = ['FILENAME', 'URL', 'label'] + [f for f in DOMAIN_FEATURES if f in df.columns]
    df_domain = df[domain_cols].copy()
    df_domain.to_csv(domain_output, index=False)
    print(f"  ✓ Domain dataset: {len(df_domain):,} rows, {len(domain_cols)} columns")
    print(f"    Features: {len(domain_cols) - 3} domain features")
    
    # Create path-only dataset
    print(f"\nCreating path-only dataset...")
    path_cols = ['FILENAME', 'URL', 'label'] + [f for f in PATH_FEATURES if f in df.columns]
    df_path = df[path_cols].copy()
    df_path.to_csv(path_output, index=False)
    print(f"  ✓ Path dataset: {len(df_path):,} rows, {len(path_cols)} columns")
    print(f"    Features: {len(path_cols) - 3} path features")
    
    print(f"\n" + "=" * 70)
    print("Dataset regeneration complete!")
    print(f"  Domain features: {len(domain_cols) - 3}")
    print(f"  Path features: {len(path_cols) - 3} (was 6, now {len(path_cols) - 3})")
    print(f"  New path features added: {len(path_cols) - 3 - 6}")


if __name__ == "__main__":
    regenerate_datasets()

