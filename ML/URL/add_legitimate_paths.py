#!/usr/bin/env python3
"""
Add legitimate URLs with common paths (login, home, about, etc.) to training data
"""

import pandas as pd
from pathlib import Path
import sys

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ML.phishing_detector import PhishingDetector

# Trusted domains with common legitimate paths
trusted_domains = [
    'google.com', 'youtube.com', 'github.com', 'stackoverflow.com',
    'amazon.com', 'microsoft.com', 'apple.com', 'paypal.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'reddit.com',
    'wikipedia.org', 'netflix.com', 'spotify.com', 'dropbox.com',
    'adobe.com', 'salesforce.com', 'oracle.com', 'ibm.com',
    'harvard.edu', 'mit.edu', 'stanford.edu', 'berkeley.edu',
    'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com',
    'canvas.gmu.edu', 'gmu.edu', 'edu'
]

# Common legitimate paths
legitimate_paths = [
    '/login', '/home', '/about', '/contact', '/index', '/main', '/page',
    '/help', '/support', '/faq', '/terms', '/privacy', '/search', '/blog',
    '/news', '/events', '/calendar', '/directory', '/sitemap', '/signin',
    '/signup', '/register', '/account', '/profile', '/settings', '/dashboard'
]

def generate_legitimate_urls():
    """Generate legitimate URLs with common paths"""
    urls = []
    
    # Add specific URLs first
    urls.append("https://info.canvas.gmu.edu/#view_name=month&view_start=2025-12-02")
    urls.append("https://canvas.gmu.edu/login?needs_cookies=1")
    
    # Generate URLs from trusted domains with legitimate paths
    for domain in trusted_domains[:50]:  # Limit to avoid too many
        # Base domain
        urls.append(f'https://{domain}')
        urls.append(f'https://www.{domain}')
        
        # With common paths
        for path in legitimate_paths[:10]:  # Limit paths per domain
            urls.append(f'https://{domain}{path}')
            urls.append(f'https://www.{domain}{path}')
            
            # With query parameters
            urls.append(f'https://{domain}{path}?id=1')
            urls.append(f'https://www.{domain}{path}?redirect=true')
    
    # Remove duplicates
    urls = list(set(urls))
    
    return urls[:500]  # Limit to 500 URLs

def add_to_datasets():
    """Add legitimate URLs to all datasets"""
    repo_root = PROJECT_ROOT
    domain_file = repo_root / "ML" / "URL" / "URL Data" / "URL_Set_domain_only.csv"
    path_file = repo_root / "ML" / "URL" / "URL Data" / "URL_Set_path_only.csv"
    combined_file = repo_root / "ML" / "URL" / "URL Data" / "URL_Set.csv"
    
    detector = PhishingDetector()
    
    print("Generating legitimate URLs with common paths...")
    new_urls = generate_legitimate_urls()
    print(f"Generated {len(new_urls)} legitimate URLs")
    
    # Load existing datasets
    df_domain = pd.read_csv(domain_file)
    df_path = pd.read_csv(path_file)
    df_combined = pd.read_csv(combined_file)
    
    print(f"\nExtracting features and adding to datasets...")
    added_count = 0
    
    for idx, url in enumerate(new_urls):
        if idx % 50 == 0:
            print(f"  Processed {idx}/{len(new_urls)} URLs")
        
        try:
            # Check if URL already exists
            if url in df_domain['URL'].values:
                continue
            
            # Extract features
            all_features = detector.extract_features(url)
            
            # Domain dataset
            domain_cols = [col for col in df_domain.columns if col not in ['FILENAME', 'URL', 'label']]
            domain_features = {col: all_features.get(col, 0) for col in domain_cols}
            new_row_domain = {
                'FILENAME': f'legit_path_{len(df_domain)}.txt',
                'URL': url,
                'label': 1,  # Legitimate
                **domain_features
            }
            df_domain = pd.concat([df_domain, pd.DataFrame([new_row_domain])], ignore_index=True)
            
            # Path dataset
            path_cols = [col for col in df_path.columns if col not in ['FILENAME', 'URL', 'label']]
            path_features = {col: all_features.get(col, 0) for col in path_cols}
            new_row_path = {
                'FILENAME': f'legit_path_{len(df_path)}.txt',
                'URL': url,
                'label': 1,  # Legitimate
                **path_features
            }
            df_path = pd.concat([df_path, pd.DataFrame([new_row_path])], ignore_index=True)
            
            # Combined dataset
            all_cols = [col for col in df_combined.columns if col not in ['FILENAME', 'URL', 'label']]
            all_feat = {col: all_features.get(col, 0) for col in all_cols}
            new_row_combined = {
                'FILENAME': f'legit_path_{len(df_combined)}.txt',
                'URL': url,
                'label': 1,  # Legitimate
                **all_feat
            }
            df_combined = pd.concat([df_combined, pd.DataFrame([new_row_combined])], ignore_index=True)
            
            added_count += 1
        except Exception as e:
            print(f"  Error processing {url}: {e}")
            continue
    
    # Save updated datasets
    df_domain.to_csv(domain_file, index=False)
    df_path.to_csv(path_file, index=False)
    df_combined.to_csv(combined_file, index=False)
    
    print(f"\n✓ Added {added_count} legitimate URLs to all datasets")
    print(f"  Domain dataset: {len(df_domain):,} rows")
    print(f"  Path dataset: {len(df_path):,} rows")
    print(f"  Combined dataset: {len(df_combined):,} rows")

if __name__ == "__main__":
    add_to_datasets()

