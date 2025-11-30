#!/usr/bin/env python3
"""
URL Feature Extraction Utilities
Specific functions for extracting different types of URL features
"""

import re
import urllib.parse
import tldextract
from difflib import SequenceMatcher
from urllib.parse import urlparse, parse_qs
import numpy as np

class URLFeatureExtractor:
    HOMOGRAPH_THRESHOLD = 0.6
    """Utility class for extracting specific URL features"""
    
    @staticmethod
    def extract_domain_features(url):
        """Extract domain-specific features"""
        features = {}
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Basic domain features
            features['domain_length'] = len(domain)
            features['has_www'] = 1 if domain.startswith('www.') else 0
            features['has_port'] = 1 if ':' in domain else 0
            
            # TLD extraction
            extracted = tldextract.extract(url)
            features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            features['domain_name_length'] = len(extracted.domain)
            features['tld_length'] = len(extracted.suffix)
            
            # Domain character analysis
            features['has_numbers'] = 1 if re.search(r'\d', domain) else 0
            features['has_hyphens'] = 1 if '-' in domain else 0
            features['has_underscores'] = 1 if '_' in domain else 0
            
        except Exception as e:
            # Default values if parsing fails
            features = {
                'domain_length': 0,
                'has_www': 0,
                'has_port': 0,
                'subdomain_count': 0,
                'domain_name_length': 0,
                'tld_length': 0,
                'has_numbers': 0,
                'has_hyphens': 0,
                'has_underscores': 0
            }
        
        return features
    
    @staticmethod
    def extract_path_features(url):
        """Extract path-specific features"""
        features = {}
        
        try:
            parsed = urlparse(url)
            path = parsed.path
            
            # Path structure
            features['path_length'] = len(path)
            features['path_depth'] = path.count('/') if path else 0
            features['has_file_extension'] = 1 if '.' in path.split('/')[-1] and len(path.split('/')[-1]) > 0 else 0
            features['ends_with_slash'] = 1 if path.endswith('/') else 0
            
            # File extension analysis
            if '.' in path:
                file_ext = path.split('.')[-1].lower()
                features['file_extension_length'] = len(file_ext)
                features['has_executable_ext'] = 1 if file_ext in ['exe', 'scr', 'bat', 'cmd', 'com'] else 0
            else:
                features['file_extension_length'] = 0
                features['has_executable_ext'] = 0
                
        except Exception as e:
            # Default values
            features = {
                'path_length': 0,
                'path_depth': 0,
                'has_file_extension': 0,
                'ends_with_slash': 0,
                'file_extension_length': 0,
                'has_executable_ext': 0
            }
        
        return features
    
    @staticmethod
    def extract_query_features(url):
        """Extract query parameter features"""
        features = {}
        
        try:
            parsed = urlparse(url)
            query = parsed.query
            
            # Query analysis
            features['query_length'] = len(query)
            features['has_query'] = 1 if query else 0
            
            if query:
                params = parse_qs(query)
                features['num_params'] = len(params)
                
                # Check for suspicious parameters
                suspicious_params = ['redirect', 'url', 'link', 'goto', 'target', 'ref']
                features['has_suspicious_params'] = 1 if any(param.lower() in suspicious_params for param in params.keys()) else 0
                
                # Parameter value analysis
                all_values = []
                for param_values in params.values():
                    all_values.extend(param_values)
                
                if all_values:
                    avg_param_length = sum(len(val) for val in all_values) / len(all_values)
                    features['avg_param_length'] = avg_param_length
                    features['has_long_params'] = 1 if avg_param_length > 50 else 0
                else:
                    features['avg_param_length'] = 0
                    features['has_long_params'] = 0
            else:
                features['num_params'] = 0
                features['has_suspicious_params'] = 0
                features['avg_param_length'] = 0
                features['has_long_params'] = 0
                
        except Exception as e:
            # Default values
            features = {
                'query_length': 0,
                'has_query': 0,
                'num_params': 0,
                'has_suspicious_params': 0,
                'avg_param_length': 0,
                'has_long_params': 0
            }
        
        return features
    
    @staticmethod
    def extract_suspicious_patterns(url):
        """Extract features related to suspicious patterns"""
        features = {}
        
        url_lower = url.lower()
        parsed = urlparse(url_lower)

        # Suspicious keywords
        suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'update', 'confirm',
            'validate', 'authenticate', 'bank', 'paypal', 'amazon',
            'facebook', 'google', 'apple', 'microsoft', 'support',
            'password', 'signin', 'signup', 'register'
        ]
        
        features['suspicious_keyword_count'] = sum(1 for keyword in suspicious_keywords if keyword in url_lower)
        features['has_suspicious_keywords'] = 1 if features['suspicious_keyword_count'] > 0 else 0
        
        # Brand impersonation
        brands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'ebay', 'netflix', 'twitter']
        features['brand_count'] = sum(1 for brand in brands if brand in url_lower)
        features['has_brand_names'] = 1 if features['brand_count'] > 0 else 0
        try:
            extracted = tldextract.extract(url)
            registered_domain = extracted.registered_domain or extracted.domain or ""
            registered_lower = registered_domain.lower()
            subdomain_lower = (extracted.subdomain or "").lower()
            features['brand_in_registered_domain'] = 1 if any(brand in registered_lower for brand in brands) else 0
            features['brand_in_subdomain'] = 1 if subdomain_lower and any(brand in subdomain_lower for brand in brands) else 0
        except Exception:
            extracted = None
            registered_lower = ""
            subdomain_lower = ""
            features['brand_in_registered_domain'] = 0
            features['brand_in_subdomain'] = 0

        path_query_lower = ((parsed.path or "") + (parsed.query or "")).lower()
        features['brand_in_path_or_query'] = 1 if any(brand in path_query_lower for brand in brands) else 0
        features['brand_mismatch'] = 1 if features['has_brand_names'] and not features['brand_in_registered_domain'] else 0
        features['brand_similarity_registered'] = URLFeatureExtractor._brand_similarity_value(registered_lower, brands)
        features['brand_similarity_subdomain'] = URLFeatureExtractor._brand_similarity_value(subdomain_lower, brands)
        features['brand_similarity_path'] = URLFeatureExtractor._brand_similarity_value(path_query_lower, brands)
        features['brand_homograph'] = 1 if (
            features['brand_similarity_registered'] >= URLFeatureExtractor.HOMOGRAPH_THRESHOLD
            and features['brand_similarity_registered'] < 1.0
        ) else 0
        
        # URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'short.link']
        features['is_shortened'] = 1 if any(shortener in url_lower for shortener in shorteners) else 0
        
        # Suspicious TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'click', 'download', 'stream']
        if extracted:
            features['has_suspicious_tld'] = 1 if extracted.suffix.lower() in suspicious_tlds else 0
        else:
            features['has_suspicious_tld'] = 0
        
        # IP address detection
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        features['has_ip_address'] = 1 if re.search(ip_pattern, url) else 0
        
        return features

    @staticmethod
    def extract_obfuscation_features(url):
        """Extract features capturing URL obfuscation via encoding"""
        if not url:
            return {
                'has_obfuscation': 0,
                'num_obfuscated_chars': 0,
                'obfuscation_ratio': 0.0,
            }

        percent_encoded = re.findall(r'%[0-9a-fA-F]{2}', url)
        hex_encoded = re.findall(r'\\x[0-9a-fA-F]{2}', url)
        unicode_encoded = re.findall(r'\\u[0-9a-fA-F]{4}', url)
        html_entities = re.findall(r'&#x?[0-9a-fA-F]+;?', url)

        total_tokens = (
            len(percent_encoded)
            + len(hex_encoded)
            + len(unicode_encoded)
            + len(html_entities)
        )

        return {
            'has_obfuscation': 1 if total_tokens > 0 else 0,
            'num_obfuscated_chars': total_tokens,
            'obfuscation_ratio': total_tokens / len(url),
        }
    
    @staticmethod
    def extract_statistical_features(url):
        """Extract statistical features from URL"""
        features = {}
        
        if not url:
            return {
                'url_length': 0,
                'digit_ratio': 0,
                'letter_ratio': 0,
                'special_char_ratio': 0,
                'entropy': 0,
                'consonant_ratio': 0,
                'vowel_ratio': 0
            }
        
        # Basic statistics
        features['url_length'] = len(url)
        features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url)
        features['letter_ratio'] = sum(c.isalpha() for c in url) / len(url)
        features['special_char_ratio'] = sum(not c.isalnum() for c in url) / len(url)
        
        # Entropy calculation
        features['entropy'] = URLFeatureExtractor._calculate_entropy(url)
        
        # Vowel/consonant analysis
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        features['vowel_ratio'] = sum(1 for c in url.lower() if c in vowels) / len(url)
        features['consonant_ratio'] = sum(1 for c in url.lower() if c in consonants) / len(url)
        
        return features
    
    @staticmethod
    def _calculate_entropy(text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        text_length = len(text)
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * np.log2(probability)
        
        return entropy

    @staticmethod
    def _brand_similarity_value(text, brands):
        if not text:
            return 0.0
        best_ratio = 0.0
        for brand in brands:
            ratio = SequenceMatcher(None, text, brand).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
        return best_ratio

def extract_all_url_features(url):
    """Extract all URL features using the utility class"""
    extractor = URLFeatureExtractor()
    
    features = {}
    features.update(extractor.extract_domain_features(url))
    features.update(extractor.extract_path_features(url))
    features.update(extractor.extract_query_features(url))
    features.update(extractor.extract_suspicious_patterns(url))
    features.update(extractor.extract_obfuscation_features(url))
    features.update(extractor.extract_statistical_features(url))
    
    return features

if __name__ == "__main__":
    # Test the feature extraction
    test_urls = [
        "https://www.google.com/search?q=python",
        "https://goog1e-security-alert.com/verify-account",
        "https://bit.ly/suspicious-link"
    ]
    
    extractor = URLFeatureExtractor()
    
    for url in test_urls:
        print(f"\nURL: {url}")
        features = extract_all_url_features(url)
        print(f"Features extracted: {len(features)}")
        
        # Show some key features
        key_features = ['domain_length', 'has_suspicious_keywords', 'is_shortened', 'entropy']
        for feature in key_features:
            if feature in features:
                print(f"  {feature}: {features[feature]}")
