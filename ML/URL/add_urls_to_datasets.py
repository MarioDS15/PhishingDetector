#!/usr/bin/env python3
"""
Add new URLs to both domain-only and path-only datasets
"""

import pandas as pd
from pathlib import Path
import sys

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ML.phishing_detector import PhishingDetector

# URLs to add (legitimate)
new_urls = [
    "https://info.canvas.gmu.edu/#view_name=month&view_start=2025-12-02",
    "https://canvas.gmu.edu/login?needs_cookies=1"
]

def add_urls_to_datasets():
    """Add new URLs to both datasets"""
    repo_root = PROJECT_ROOT
    domain_file = repo_root / "ML" / "URL" / "URL Data" / "URL_Set_domain_only.csv"
    path_file = repo_root / "ML" / "URL" / "URL Data" / "URL_Set_path_only.csv"
    
    # Initialize detector
    detector = PhishingDetector()
    
    print("Adding URLs to datasets...")
    print(f"URLs to add: {len(new_urls)}")
    
    for url in new_urls:
        print(f"\nProcessing: {url}")
        
        # Extract all features
        all_features = detector.extract_features(url)
        
        # Load domain dataset
        df_domain = pd.read_csv(domain_file)
        
        # Get domain features
        domain_cols = [col for col in df_domain.columns if col not in ['FILENAME', 'URL', 'label']]
        domain_features = {col: all_features.get(col, 0) for col in domain_cols}
        
        # Create new row for domain dataset
        new_row_domain = {
            'FILENAME': f'added_{len(df_domain)}.txt',
            'URL': url,
            'label': 1,  # Legitimate
            **domain_features
        }
        df_domain = pd.concat([df_domain, pd.DataFrame([new_row_domain])], ignore_index=True)
        
        # Load path dataset
        df_path = pd.read_csv(path_file)
        
        # Get path features
        path_cols = [col for col in df_path.columns if col not in ['FILENAME', 'URL', 'label']]
        path_features = {col: all_features.get(col, 0) for col in path_cols}
        
        # Create new row for path dataset
        new_row_path = {
            'FILENAME': f'added_{len(df_path)}.txt',
            'URL': url,
            'label': 1,  # Legitimate
            **path_features
        }
        df_path = pd.concat([df_path, pd.DataFrame([new_row_path])], ignore_index=True)
    
    # Save updated datasets
    df_domain.to_csv(domain_file, index=False)
    df_path.to_csv(path_file, index=False)
    
    print(f"\n✓ Added {len(new_urls)} URLs to both datasets")
    print(f"  Domain dataset: {len(df_domain):,} rows")
    print(f"  Path dataset: {len(df_path):,} rows")

if __name__ == "__main__":
    add_urls_to_datasets()

