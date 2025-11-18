"""
URL-based Phishing Detection Module

This module provides URL-specific phishing detection functionality,
including feature extraction, model training, and analysis.
"""

from .url_features import URLFeatureExtractor, extract_all_url_features

__version__ = "1.0.0"
__author__ = "CYSE 610 Project"

__all__ = [
    'URLFeatureExtractor', 
    'extract_all_url_features'
]
