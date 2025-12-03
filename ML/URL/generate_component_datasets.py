#!/usr/bin/env python3
"""
Generate three component-specific datasets:
1. Domain-only: Features extracted ONLY from domain component
2. Path-only: Features extracted ONLY from path+query components
3. Combined: Features from both domain and path components

Each dataset includes:
- Full URL (reference only, not used for feature extraction)
- Component columns (domain, path+query) for feature extraction
- Component-specific features
"""

import pandas as pd
from pathlib import Path
import sys
from urllib.parse import urlparse

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ML.phishing_detector import PhishingDetector

def parse_url_components(url):
    """Parse URL into components"""
    parsed = urlparse(url)
    protocol = parsed.scheme
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    
    return {
        'protocol': protocol,
        'domain': domain,
        'path': path,
        'query': query,
        'path_query': path + ('?' + query if query else '')
    }

def generate_component_datasets():
    """Generate the three component-specific datasets"""
    repo_root = PROJECT_ROOT
    input_file = repo_root / "ML" / "URL" / "URL Data" / "URL_Set.csv"
    
    print("=" * 70)
    print("Generating Component-Specific Datasets")
    print("=" * 70)
    
    # Load base dataset
    print(f"\nLoading base dataset from {input_file}...")
    df = pd.read_csv(input_file)
    print(f"Loaded {len(df):,} rows")
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Prepare data structures
    domain_data = []
    path_data = []
    combined_data = []
    
    print(f"\nExtracting component-specific features...")
    for idx, row in df.iterrows():
        if idx % 10000 == 0:
            print(f"  Processed {idx}/{len(df)} URLs")
        
        url = row['URL']
        label = row['label']
        filename = row.get('FILENAME', f'row_{idx}.txt')
        
        try:
            # Parse URL components
            components = parse_url_components(url)
            
            # Extract domain features
            domain_features = detector.extract_domain_features(
                components['domain'], 
                components['protocol']
            )
            
            # Extract path features
            path_features = detector.extract_path_features(
                components['path'],
                components['query']
            )
            
            # Extract combined features
            combined_features = detector.extract_combined_features(
                components['domain'],
                components['path'],
                components['query'],
                components['protocol']
            )
            
            # Domain-only dataset row
            domain_row = {
                'FILENAME': filename,
                'URL': url,  # Reference only
                'DOMAIN': components['domain'],  # Component for feature extraction
                'label': label,
                **domain_features
            }
            domain_data.append(domain_row)
            
            # Path-only dataset row
            path_row = {
                'FILENAME': filename,
                'URL': url,  # Reference only
                'PATH_QUERY': components['path_query'],  # Component for feature extraction
                'label': label,
                **path_features
            }
            path_data.append(path_row)
            
            # Combined dataset row
            combined_row = {
                'FILENAME': filename,
                'URL': url,  # Reference only
                'DOMAIN': components['domain'],  # Component for feature extraction
                'PATH_QUERY': components['path_query'],  # Component for feature extraction
                'label': label,
                **combined_features
            }
            combined_data.append(combined_row)
            
        except Exception as e:
            print(f"  Error processing URL {idx}: {e}")
            continue
    
    # Create DataFrames
    print(f"\nCreating DataFrames...")
    df_domain = pd.DataFrame(domain_data)
    df_path = pd.DataFrame(path_data)
    df_combined = pd.DataFrame(combined_data)
    
    # Save datasets
    domain_output = repo_root / "ML" / "URL" / "URL Data" / "URL_Set_domain_only.csv"
    path_output = repo_root / "ML" / "URL" / "URL Data" / "URL_Set_path_only.csv"
    combined_output = repo_root / "ML" / "URL" / "URL Data" / "URL_Set_combined.csv"
    
    df_domain.to_csv(domain_output, index=False)
    df_path.to_csv(path_output, index=False)
    df_combined.to_csv(combined_output, index=False)
    
    print(f"\n{'='*70}")
    print("Dataset Generation Complete!")
    print(f"{'='*70}")
    print(f"\nDomain-Only Dataset:")
    print(f"  File: {domain_output}")
    print(f"  Rows: {len(df_domain):,}")
    print(f"  Features: {len(df_domain.columns) - 4}")  # -4 for FILENAME, URL, DOMAIN, label
    print(f"  Component column: DOMAIN")
    
    print(f"\nPath-Only Dataset:")
    print(f"  File: {path_output}")
    print(f"  Rows: {len(df_path):,}")
    print(f"  Features: {len(df_path.columns) - 4}")  # -4 for FILENAME, URL, PATH_QUERY, label
    print(f"  Component column: PATH_QUERY")
    
    print(f"\nCombined Dataset:")
    print(f"  File: {combined_output}")
    print(f"  Rows: {len(df_combined):,}")
    print(f"  Features: {len(df_combined.columns) - 5}")  # -5 for FILENAME, URL, DOMAIN, PATH_QUERY, label
    print(f"  Component columns: DOMAIN, PATH_QUERY")
    
    # Show sample feature names
    print(f"\nSample Domain Features:")
    domain_feat = [c for c in df_domain.columns if c not in ['FILENAME', 'URL', 'DOMAIN', 'label']]
    print(f"  {', '.join(domain_feat[:10])}...")
    
    print(f"\nSample Path Features:")
    path_feat = [c for c in df_path.columns if c not in ['FILENAME', 'URL', 'PATH_QUERY', 'label']]
    print(f"  {', '.join(path_feat[:10])}...")
    
    print(f"\n✓ All datasets saved successfully!")

if __name__ == "__main__":
    generate_component_datasets()

