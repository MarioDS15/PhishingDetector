#!/usr/bin/env python3
"""
Remove duplicate URLs from the dataset
Normalizes URLs by removing protocol, www, and trailing slashes to identify duplicates
"""

import pandas as pd
from urllib.parse import urlparse
from pathlib import Path

def normalize_url(url):
    """Normalize URL for duplicate detection"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        path = parsed.path.rstrip('/')
        query = parsed.query
        # Combine domain + path + query
        normalized = domain + path
        if query:
            normalized += '?' + query
        return normalized
    except:
        return url.lower()

def score_url(url):
    """Score URL to prefer https, www, and no trailing slash"""
    score = 0
    if url.startswith('https://'):
        score += 100
    if 'www.' in url.lower():
        score += 10
    if not url.endswith('/'):
        score += 1
    return score

def main():
    repo_root = Path(__file__).resolve().parents[2]
    dataset_path = repo_root / "ML" / "URL" / "URL Data" / "URL_Set.csv"
    
    print(f"Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)
    
    print(f"Original dataset: {len(df):,} rows")
    print(f"Original unique URLs: {df['URL'].nunique():,}")
    
    # Focus on legitimate URLs (label=1) for duplicate removal
    legit_mask = df['label'] == 1
    legit_df = df[legit_mask].copy()
    phishing_df = df[~legit_mask].copy()
    
    print(f"\nLegitimate URLs: {len(legit_df):,}")
    
    # Normalize URLs
    legit_df['normalized'] = legit_df['URL'].apply(normalize_url)
    
    # Score URLs to prefer better versions
    legit_df['url_score'] = legit_df['URL'].apply(score_url)
    
    # Remove duplicates, keeping the highest scored version
    legit_df_dedup = legit_df.sort_values('url_score', ascending=False).drop_duplicates(subset=['normalized'], keep='first')
    
    # Remove the helper columns
    legit_df_dedup = legit_df_dedup.drop(columns=['normalized', 'url_score'])
    
    print(f"After deduplication: {len(legit_df_dedup):,} legitimate URLs")
    print(f"Removed: {len(legit_df) - len(legit_df_dedup):,} duplicate legitimate URLs")
    
    # Combine back with phishing URLs
    final_df = pd.concat([phishing_df, legit_df_dedup], ignore_index=True)
    
    print(f"\nFinal dataset: {len(final_df):,} rows")
    print(f"Final unique URLs: {final_df['URL'].nunique():,}")
    
    # Save the cleaned dataset
    output_path = dataset_path
    final_df.to_csv(output_path, index=False)
    
    print(f"\nCleaned dataset saved to: {output_path}")
    print(f"Removed {len(df) - len(final_df):,} duplicate rows total")

if __name__ == "__main__":
    main()

