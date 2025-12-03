#!/usr/bin/env python3
"""
Phishing URL Detection using Machine Learning
Advanced Feature Engineering for URL Analysis
"""

import os
import re
import urllib.parse
import warnings
from urllib.parse import urlparse, parse_qs

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import requests
import seaborn as sns
import tldextract
from difflib import SequenceMatcher
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings('ignore')

BRAND_KEYWORDS = [
    'google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal',
    'ebay', 'netflix', 'twitter', 'instagram', 'linkedin', 'bank',
    'chase', 'wellsfargo', 'citibank', 'boa', 'netflix', 'outlook',
    'office365', 'icloud', 'gmail'
]
HOMOGRAPH_THRESHOLD = 0.6

class PhishingDetector:
    def __init__(self):
        self.feature_names = []
        self.scaler = StandardScaler()
        self.model = None
        self.tld_extractor = tldextract.TLDExtract(
            # Disable on-disk cache to avoid file lock timeouts
            cache_dir=None,
            suffix_list_urls=None  # use bundled data to avoid network access
        )
        
    def extract_features(self, url):
        """
        Extract comprehensive features from a URL for phishing detection
        """
        features = {}
        
        # Basic URL features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_ampersands'] = url.count('&')
        features['num_percentages'] = url.count('%')
        
        # Parse URL components
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # Domain analysis
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(query)
        
        # TLD analysis
        extracted = self.tld_extractor(url)
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        features['has_subdomain'] = 1 if extracted.subdomain else 0
        features['domain_name_length'] = len(extracted.domain)
        features['tld_length'] = len(extracted.suffix)
        
        # Special character analysis
        features['has_at_symbol'] = 1 if '@' in url else 0
        features['has_port'] = 1 if ':' in domain and domain.split(':')[-1].isdigit() else 0
        features['has_ip'] = self._has_ip_address(url)
        features['has_suspicious_tld'] = self._has_suspicious_tld(extracted.suffix)
        
        # Suspicious patterns
        features['has_shortener'] = self._is_shortened_url(url)
        features['has_suspicious_keywords'] = self._has_suspicious_keywords(url)
        features['has_numbers_in_domain'] = self._has_numbers_in_domain(domain)
        features['has_mixed_case'] = self._has_mixed_case(domain)
        features.update(self._extract_obfuscation_metrics(url))
        
        # Statistical features
        features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url) if url else 0
        features['letter_ratio'] = sum(c.isalpha() for c in url) / len(url) if url else 0
        features['special_char_ratio'] = sum(not c.isalnum() for c in url) / len(url) if url else 0
        
        # Entropy calculation
        features['url_entropy'] = self._calculate_entropy(url)
        features['domain_entropy'] = self._calculate_entropy(domain)
        
        # Path analysis
        features['path_depth'] = path.count('/') if path else 0
        features['has_file_extension'] = 1 if '.' in path.split('/')[-1] and len(path.split('/')[-1]) > 0 else 0
        features['suspicious_file_ext'] = self._has_suspicious_file_extension(path)
        
        # Additional path features
        path_segments = [seg for seg in path.split('/') if seg] if path else []
        features['path_segment_count'] = len(path_segments)
        features['avg_path_segment_length'] = sum(len(seg) for seg in path_segments) / len(path_segments) if path_segments else 0
        features['max_path_segment_length'] = max((len(seg) for seg in path_segments), default=0)
        features['path_entropy'] = self._calculate_entropy(path) if path else 0
        features['path_has_numbers'] = 1 if re.search(r'\d', path) else 0
        features['path_has_special_chars'] = 1 if re.search(r'[^a-zA-Z0-9/._-]', path) else 0
        features['path_digit_ratio'] = sum(c.isdigit() for c in path) / len(path) if path else 0
        features['path_letter_ratio'] = sum(c.isalpha() for c in path) / len(path) if path else 0
        
        # Common legitimate path patterns
        legitimate_paths = ['login', 'home', 'about', 'contact', 'index', 'main', 'page', 
                           'help', 'support', 'faq', 'terms', 'privacy', 'search', 'blog',
                           'news', 'events', 'calendar', 'directory', 'sitemap']
        path_lower = path.lower() if path else ''
        features['has_legitimate_path'] = 1 if any(legit in path_lower for legit in legitimate_paths) else 0
        features['legitimate_path_count'] = sum(1 for legit in legitimate_paths if legit in path_lower)
        
        # Common suspicious path patterns
        suspicious_paths = ['verify', 'confirm', 'update', 'secure', 'account', 'validate',
                          'authenticate', 'signin', 'signup', 'password', 'reset', 'recover']
        features['has_suspicious_path'] = 1 if any(susp in path_lower for susp in suspicious_paths) else 0
        features['suspicious_path_count'] = sum(1 for susp in suspicious_paths if susp in path_lower)
        
        # Path structure patterns
        features['path_starts_with_slash'] = 1 if path and path.startswith('/') else 0
        features['path_ends_with_slash'] = 1 if path and path.endswith('/') else 0
        features['path_has_double_slash'] = 1 if '//' in path else 0
        features['path_has_query_in_path'] = 1 if '?' in path else 0  # Query in path (malformed)
        
        # Query parameter analysis
        features['num_params'] = len(parse_qs(query)) if query else 0
        features['has_suspicious_params'] = self._has_suspicious_params(query)
        
        # Brand impersonation detection
        features.update(self._brand_feature_dict(parsed, extracted))
        
        # URL structure anomalies
        features['double_slash'] = 1 if '//' in url[url.find('://')+3:] else 0
        features['trailing_slash'] = 1 if url.endswith('/') else 0
        
        # HTTPS analysis
        features['uses_https'] = 1 if url.startswith('https://') else 0
        features['uses_http'] = 1 if url.startswith('http://') else 0
        
        return features
    
    def extract_domain_features(self, domain, protocol=''):
        """
        Extract features ONLY from domain component (and protocol).
        All features are domain-specific.
        """
        features = {}
        
        # Parse domain components
        extracted = self.tld_extractor(f"http://{domain}")  # tldextract needs full URL
        
        # Domain length and structure
        features['domain_length'] = len(domain)
        features['domain_name_length'] = len(extracted.domain)
        features['tld_length'] = len(extracted.suffix)
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        features['has_subdomain'] = 1 if extracted.subdomain else 0
        
        # Domain character analysis
        features['domain_num_dots'] = domain.count('.')
        features['domain_num_hyphens'] = domain.count('-')
        features['domain_num_underscores'] = domain.count('_')
        features['domain_has_at_symbol'] = 1 if '@' in domain else 0
        features['domain_has_port'] = 1 if ':' in domain and domain.split(':')[-1].isdigit() else 0
        features['domain_has_ip'] = self._has_ip_address(domain)
        
        # Domain statistical features
        features['domain_digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
        features['domain_letter_ratio'] = sum(c.isalpha() for c in domain) / len(domain) if domain else 0
        features['domain_special_char_ratio'] = sum(not c.isalnum() and c != '.' and c != '-' for c in domain) / len(domain) if domain else 0
        features['domain_entropy'] = self._calculate_entropy(domain)
        
        # Domain patterns
        features['domain_has_numbers'] = self._has_numbers_in_domain(domain)
        features['domain_has_mixed_case'] = self._has_mixed_case(domain)
        features['domain_has_suspicious_tld'] = self._has_suspicious_tld(extracted.suffix)
        features['domain_has_shortener'] = self._is_shortened_url(f"http://{domain}")
        
        # Domain obfuscation
        obfuscation = self._extract_obfuscation_metrics(domain)
        features['domain_has_obfuscation'] = obfuscation.get('has_obfuscation', 0)
        features['domain_num_obfuscated_chars'] = obfuscation.get('num_obfuscated_chars', 0)
        features['domain_obfuscation_ratio'] = obfuscation.get('obfuscation_ratio', 0)
        
        # Domain suspicious keywords (check domain only)
        domain_lower = domain.lower()
        suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'update', 'confirm',
            'validate', 'authenticate', 'bank', 'paypal', 'amazon',
            'facebook', 'google', 'apple', 'microsoft', 'support'
        ]
        features['domain_has_suspicious_keywords'] = 1 if any(keyword in domain_lower for keyword in suspicious_keywords) else 0
        
        # Brand features (domain-specific)
        brand_features = self._brand_feature_dict_domain_only(extracted)
        features.update(brand_features)
        
        # Protocol features (domain-level)
        features['uses_https'] = 1 if protocol.lower() == 'https' else 0
        features['uses_http'] = 1 if protocol.lower() == 'http' else 0
        
        return features
    
    def extract_path_features(self, path, query=''):
        """
        Extract features ONLY from path and query components.
        All features are path/query-specific.
        """
        features = {}
        
        # Path length and structure
        features['path_length'] = len(path)
        features['query_length'] = len(query)
        features['path_depth'] = path.count('/') if path else 0
        features['path_num_slashes'] = path.count('/')
        features['path_num_dots'] = path.count('.')
        features['path_num_hyphens'] = path.count('-')
        features['path_num_underscores'] = path.count('_')
        
        # Query parameter analysis
        features['path_num_question_marks'] = query.count('?') if query else 0
        features['path_num_equals'] = (path + query).count('=')
        features['path_num_ampersands'] = (path + query).count('&')
        features['path_num_percentages'] = (path + query).count('%')
        features['path_num_params'] = len(parse_qs(query)) if query else 0
        features['path_has_suspicious_params'] = self._has_suspicious_params(query)
        
        # Path segments
        path_segments = [seg for seg in path.split('/') if seg] if path else []
        features['path_segment_count'] = len(path_segments)
        features['path_avg_segment_length'] = sum(len(seg) for seg in path_segments) / len(path_segments) if path_segments else 0
        features['path_max_segment_length'] = max((len(seg) for seg in path_segments), default=0)
        
        # Path file extension
        features['path_has_file_extension'] = 1 if '.' in path.split('/')[-1] and len(path.split('/')[-1]) > 0 else 0
        features['path_suspicious_file_ext'] = self._has_suspicious_file_extension(path)
        
        # Path statistical features
        path_query = path + query
        features['path_digit_ratio'] = sum(c.isdigit() for c in path_query) / len(path_query) if path_query else 0
        features['path_letter_ratio'] = sum(c.isalpha() for c in path_query) / len(path_query) if path_query else 0
        features['path_special_char_ratio'] = sum(not c.isalnum() and c != '/' and c != '.' and c != '-' and c != '_' for c in path_query) / len(path_query) if path_query else 0
        features['path_entropy'] = self._calculate_entropy(path_query) if path_query else 0
        
        # Path patterns
        features['path_has_numbers'] = 1 if re.search(r'\d', path) else 0
        features['path_has_special_chars'] = 1 if re.search(r'[^a-zA-Z0-9/._-]', path) else 0
        features['path_starts_with_slash'] = 1 if path and path.startswith('/') else 0
        features['path_ends_with_slash'] = 1 if path and path.endswith('/') else 0
        features['path_has_double_slash'] = 1 if '//' in path else 0
        features['path_has_query_in_path'] = 1 if '?' in path else 0  # Malformed
        
        # Legitimate path patterns
        legitimate_paths = ['login', 'home', 'about', 'contact', 'index', 'main', 'page', 
                           'help', 'support', 'faq', 'terms', 'privacy', 'search', 'blog',
                           'news', 'events', 'calendar', 'directory', 'sitemap']
        path_lower = path.lower() if path else ''
        features['path_has_legitimate_path'] = 1 if any(legit in path_lower for legit in legitimate_paths) else 0
        features['path_legitimate_path_count'] = sum(1 for legit in legitimate_paths if legit in path_lower)
        
        # Suspicious path patterns
        suspicious_paths = ['verify', 'confirm', 'update', 'secure', 'account', 'validate',
                          'authenticate', 'signin', 'signup', 'password', 'reset', 'recover']
        features['path_has_suspicious_path'] = 1 if any(susp in path_lower for susp in suspicious_paths) else 0
        features['path_suspicious_path_count'] = sum(1 for susp in suspicious_paths if susp in path_lower)
        
        # Brand features (path-specific)
        brand_features = self._brand_feature_dict_path_only(path, query)
        features.update(brand_features)
        
        return features
    
    def extract_combined_features(self, domain, path, query, protocol=''):
        """
        Extract features from BOTH domain and path components.
        Combines domain and path features with clear naming.
        """
        features = {}
        
        # Get domain features (with domain_ prefix)
        domain_features = self.extract_domain_features(domain, protocol)
        for key, value in domain_features.items():
            features[key] = value
        
        # Get path features (with path_ prefix where needed)
        path_features = self.extract_path_features(path, query)
        for key, value in path_features.items():
            features[key] = value
        
        # Combined/aggregate features (calculated from both)
        full_url = f"{protocol}://{domain}{path}"
        if query:
            full_url += f"?{query}"
        
        features['combined_url_length'] = len(full_url)
        features['combined_url_entropy'] = self._calculate_entropy(full_url)
        features['combined_digit_ratio'] = sum(c.isdigit() for c in full_url) / len(full_url) if full_url else 0
        features['combined_letter_ratio'] = sum(c.isalpha() for c in full_url) / len(full_url) if full_url else 0
        features['combined_special_char_ratio'] = sum(not c.isalnum() for c in full_url) / len(full_url) if full_url else 0
        
        # Combined brand features
        parsed = urlparse(full_url)
        extracted = self.tld_extractor(full_url)
        brand_features = self._brand_feature_dict(parsed, extracted)
        # Rename to avoid conflicts
        combined_brand = {}
        for key, value in brand_features.items():
            if key.startswith('brand_'):
                combined_brand[f'combined_{key}'] = value
            else:
                combined_brand[key] = value
        features.update(combined_brand)
        
        # Combined structure anomalies
        features['combined_double_slash'] = 1 if '//' in full_url[full_url.find('://')+3:] else 0
        features['combined_trailing_slash'] = 1 if full_url.endswith('/') else 0
        
        return features
    
    def _brand_feature_dict_domain_only(self, extracted):
        """Brand features for domain-only extraction"""
        registered_domain = extracted.registered_domain or extracted.domain or ""
        core_domain = extracted.domain or registered_domain
        registered_lower = registered_domain.lower()
        core_lower = core_domain.lower()
        subdomain_lower = (extracted.subdomain or "").lower()
        
        brand_in_registered = any(brand in registered_lower for brand in BRAND_KEYWORDS)
        brand_in_subdomain = subdomain_lower and any(brand in subdomain_lower for brand in BRAND_KEYWORDS)
        
        registered_similarity = self._brand_similarity(core_lower)
        subdomain_similarity = self._brand_similarity(subdomain_lower)
        
        homograph_flag = 1 if (registered_similarity >= HOMOGRAPH_THRESHOLD and registered_similarity < 1.0) else 0
        
        return {
            'domain_suspicious_brand_usage': 1 if (brand_in_registered or brand_in_subdomain) else 0,
            'domain_brand_in_registered_domain': 1 if brand_in_registered else 0,
            'domain_brand_in_subdomain': 1 if brand_in_subdomain else 0,
            'domain_brand_mismatch': 1 if (brand_in_registered or brand_in_subdomain) and not brand_in_registered else 0,
            'domain_brand_similarity_registered': registered_similarity,
            'domain_brand_similarity_subdomain': subdomain_similarity,
            'domain_brand_homograph': homograph_flag,
        }
    
    def _brand_feature_dict_path_only(self, path, query):
        """Brand features for path-only extraction"""
        path_query = (path or "") + (query or "")
        path_query_lower = path_query.lower()
        
        brand_in_path = any(brand in path_query_lower for brand in BRAND_KEYWORDS)
        path_similarity = self._brand_similarity(path_query_lower)
        
        return {
            'path_suspicious_brand_usage': 1 if brand_in_path else 0,
            'path_brand_in_path_or_query': 1 if brand_in_path else 0,
            'path_brand_similarity_path': path_similarity,
        }
    
    def _has_ip_address(self, url):
        """Check if URL contains an IP address"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return 1 if re.search(ip_pattern, url) else 0
    
    def _has_suspicious_tld(self, tld):
        """Check for suspicious top-level domains"""
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'click', 'download', 'stream']
        return 1 if tld.lower() in suspicious_tlds else 0
    
    def _is_shortened_url(self, url):
        """Check if URL is from a known URL shortener"""
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
        return 1 if any(shortener in url for shortener in shorteners) else 0
    
    def _has_suspicious_keywords(self, url):
        """Check for suspicious keywords in URL"""
        suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'update', 'confirm',
            'validate', 'authenticate', 'bank', 'paypal', 'amazon',
            'facebook', 'google', 'apple', 'microsoft', 'support'
        ]
        url_lower = url.lower()
        return 1 if any(keyword in url_lower for keyword in suspicious_keywords) else 0
    
    def _has_numbers_in_domain(self, domain):
        """Check if domain contains numbers"""
        return 1 if re.search(r'\d', domain) else 0
    
    def _has_mixed_case(self, domain):
        """Check for mixed case in domain (suspicious)"""
        return 1 if domain != domain.lower() and domain != domain.upper() else 0
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        entropy = 0
        for i in range(256):
            freq = float(text.count(chr(i)))
            if freq > 0:
                freq = freq / len(text)
                entropy = entropy - freq * np.log2(freq)
        return entropy
    
    def _has_suspicious_file_extension(self, path):
        """Check for suspicious file extensions"""
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif']
        return 1 if any(ext in path.lower() for ext in suspicious_extensions) else 0
    
    def _has_suspicious_params(self, query):
        """Check for suspicious query parameters"""
        suspicious_params = ['redirect', 'url', 'link', 'goto', 'target']
        params = parse_qs(query)
        return 1 if any(param.lower() in suspicious_params for param in params.keys()) else 0
    
    def _brand_feature_dict(self, parsed, extracted):
        """Generate brand-based impersonation features."""
        url_lower = parsed.geturl().lower()
        registered_domain = extracted.registered_domain or extracted.domain or ""
        core_domain = extracted.domain or registered_domain
        registered_lower = registered_domain.lower()
        core_lower = core_domain.lower()
        subdomain_lower = (extracted.subdomain or "").lower()
        path_query = (parsed.path or "") + (parsed.query or "")
        path_query_lower = path_query.lower()

        brand_in_registered = any(brand in registered_lower for brand in BRAND_KEYWORDS)
        brand_in_subdomain = subdomain_lower and any(brand in subdomain_lower for brand in BRAND_KEYWORDS)
        brand_in_path = any(brand in path_query_lower for brand in BRAND_KEYWORDS)
        brand_anywhere = brand_in_registered or brand_in_subdomain or brand_in_path or any(
            brand in url_lower for brand in BRAND_KEYWORDS
        )

        registered_similarity = self._brand_similarity(core_lower)
        subdomain_similarity = self._brand_similarity(subdomain_lower)
        path_similarity = self._brand_similarity(path_query_lower)

        homograph_flag = 1 if (registered_similarity >= HOMOGRAPH_THRESHOLD and registered_similarity < 1.0) else 0

        return {
            'suspicious_brand_usage': 1 if brand_anywhere else 0,
            'brand_in_registered_domain': 1 if brand_in_registered else 0,
            'brand_in_subdomain': 1 if brand_in_subdomain else 0,
            'brand_in_path_or_query': 1 if brand_in_path else 0,
            'brand_mismatch': 1 if brand_anywhere and not brand_in_registered else 0,
            'brand_similarity_registered': registered_similarity,
            'brand_similarity_subdomain': subdomain_similarity,
            'brand_similarity_path': path_similarity,
            'brand_homograph': homograph_flag,
        }

    def _brand_similarity(self, text):
        """Return the best similarity ratio and matching brand for a given text."""
        if not text:
            return 0.0
        best_ratio = 0.0
        for brand in BRAND_KEYWORDS:
            ratio = SequenceMatcher(None, text, brand).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
        return best_ratio

    def _extract_obfuscation_metrics(self, url):
        """Detect encoded or obfuscated sequences in the URL."""
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
    
    def create_dataset(self, urls, labels):
        """
        Create feature matrix from URLs
        """
        total = len(urls)
        print(f"Extracting features from {total} URLs...")
        features_list = []
        
        for i, url in enumerate(urls):
            # Periodic progress updates so long runs don't look "stuck"
            if i % 100 == 0:
                pct = (i / total * 100) if total else 0
                snippet = url[:80] + ("..." if len(url) > 80 else "")
                print(f"[PhishingDetector.create_dataset] {i}/{total} URLs "
                      f"({pct:5.1f}%) - current URL: {snippet}")
            
            try:
                features = self.extract_features(url)
                features_list.append(features)
            except Exception as e:
                print(f"[PhishingDetector.create_dataset] Error processing URL at index {i}: {url}")
                print(f"   Exception: {e}")
                # Fill with zeros if extraction fails
                features_list.append({key: 0 for key in self.feature_names} if self.feature_names else {})
        
        # Convert to DataFrame
        df = pd.DataFrame(features_list)
        self.feature_names = df.columns.tolist()
        
        print(f"Extracted {len(self.feature_names)} features")
        return df
    
    def train_model(self, X_train, y_train):
        """
        Train the phishing detection model
        """
        print("Training Random Forest model (this may take a while on large datasets)...")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            verbose=1,  # enable internal progress reporting to stdout
        )
        
        self.model.fit(X_train_scaled, y_train)
        print("Model training completed!")
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nTop 10 Most Important Features:")
        print(feature_importance.head(10))
        
        return feature_importance
    
    def evaluate_model(self, X_test, y_test):
        """
        Evaluate the trained model
        """
        print("\nEvaluating model performance...")
        
        # Scale test features
        X_test_scaled = self.scaler.transform(X_test)
        
        # Make predictions
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\nModel Performance:")
        print(f"Accuracy: {accuracy:.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        print("\nConfusion Matrix:")
        print(cm)
        
        return {
            'accuracy': accuracy,
            'predictions': y_pred,
            'probabilities': y_pred_proba,
            'confusion_matrix': cm
        }
    
    def plot_results(self, feature_importance, results):
        """
        Create visualizations of results
        """
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # Feature Importance
        top_features = feature_importance.head(15)
        axes[0, 0].barh(range(len(top_features)), top_features['importance'])
        axes[0, 0].set_yticks(range(len(top_features)))
        axes[0, 0].set_yticklabels(top_features['feature'])
        axes[0, 0].set_xlabel('Feature Importance')
        axes[0, 0].set_title('Top 15 Feature Importances')
        axes[0, 0].invert_yaxis()
        
        # Confusion Matrix Heatmap
        sns.heatmap(results['confusion_matrix'], annot=True, fmt='d', 
                   cmap='Blues', ax=axes[0, 1])
        axes[0, 1].set_title('Confusion Matrix')
        axes[0, 1].set_xlabel('Predicted')
        axes[0, 1].set_ylabel('Actual')
        
        # Prediction Probabilities Distribution
        phishing_probs = results['probabilities'][:, 1]
        axes[1, 0].hist(phishing_probs, bins=50, alpha=0.7, color='red')
        axes[1, 0].set_xlabel('Predicted Probability of Phishing')
        axes[1, 0].set_ylabel('Frequency')
        axes[1, 0].set_title('Distribution of Phishing Probabilities')
        
        # Accuracy by Class
        from sklearn.metrics import precision_recall_fscore_support
        precision, recall, fscore, _ = precision_recall_fscore_support(
            results['predictions'], results['predictions'], average=None
        )
        
        metrics = ['Precision', 'Recall', 'F1-Score']
        legitimate_scores = [precision[0], recall[0], fscore[0]]
        phishing_scores = [precision[1], recall[1], fscore[1]]
        
        x = np.arange(len(metrics))
        width = 0.35
        
        axes[1, 1].bar(x - width/2, legitimate_scores, width, label='Legitimate', alpha=0.8)
        axes[1, 1].bar(x + width/2, phishing_scores, width, label='Phishing', alpha=0.8)
        axes[1, 1].set_xlabel('Metrics')
        axes[1, 1].set_ylabel('Score')
        axes[1, 1].set_title('Performance by Class')
        axes[1, 1].set_xticks(x)
        axes[1, 1].set_xticklabels(metrics)
        axes[1, 1].legend()
        
        plt.tight_layout()
        plt.savefig('phishing_detection_results.png', dpi=300, bbox_inches='tight')
        plt.show()

def main():
    """
    Main function to run the phishing detection system
    """
    print("=== Phishing URL Detection System ===")
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Create synthetic dataset for demonstration
    # In a real scenario, you would load actual phishing and legitimate URLs
    print("\nCreating synthetic dataset for demonstration...")
    
    # Generate sample URLs (legitimate and phishing patterns)
    legitimate_urls = [
        "https://www.google.com/search?q=python",
        "https://github.com/user/repository",
        "https://stackoverflow.com/questions/123456",
        "https://www.amazon.com/product/12345",
        "https://www.wikipedia.org/wiki/Machine_learning",
        "https://www.linkedin.com/in/username",
        "https://www.youtube.com/watch?v=abc123",
        "https://www.reddit.com/r/programming",
        "https://www.medium.com/@author/article",
        "https://www.coursera.org/course/ml"
    ] * 500  # Multiply to create more samples
    
    phishing_urls = [
        "https://goog1e-security-alert.com/verify-account",
        "https://amaz0n-login-verification.tk/update-info",
        "https://paypa1-confirm-account.ml/secure-login",
        "https://faceb00k-security-check.ga/verify-identity",
        "https://app1e-id-verification.cf/confirm-details",
        "https://micros0ft-security-alert.tk/update-security",
        "https://ebay-account-verification.ml/secure-update",
        "https://netflix-security-alert.ga/verify-subscription",
        "https://twitt3r-account-security.tk/confirm-account",
        "https://instagr4m-security-check.ml/verify-login"
    ] * 500  # Multiply to create more samples
    
    # Combine URLs and labels
    all_urls = legitimate_urls + phishing_urls
    all_labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)
    
    print(f"Total URLs: {len(all_urls)}")
    print(f"Legitimate: {len(legitimate_urls)}")
    print(f"Phishing: {len(phishing_urls)}")
    
    # Extract features
    X = detector.create_dataset(all_urls, all_labels)
    y = np.array(all_labels)
    
    # Split data (85% train, 15% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    
    print(f"\nData split:")
    print(f"Training set: {X_train.shape[0]} samples")
    print(f"Testing set: {X_test.shape[0]} samples")
    
    # Train model
    feature_importance = detector.train_model(X_train, y_train)
    
    # Evaluate model
    results = detector.evaluate_model(X_test, y_test)
    
    # Plot results
    detector.plot_results(feature_importance, results)
    
    # Test on some example URLs
    print("\n=== Testing on Example URLs ===")
    test_urls = [
        "https://www.google.com",
        "https://goog1e-security-alert.com/verify",
        "https://github.com/microsoft/vscode",
        "https://paypa1-confirm.tk/login"
    ]
    
    for url in test_urls:
        features = detector.extract_features(url)
        X_test_sample = pd.DataFrame([features])
        X_test_scaled = detector.scaler.transform(X_test_sample)
        prediction = detector.model.predict(X_test_scaled)[0]
        probability = detector.model.predict_proba(X_test_scaled)[0]
        
        result = "PHISHING" if prediction == 1 else "LEGITIMATE"
        confidence = probability[1] if prediction == 1 else probability[0]
        
        print(f"URL: {url}")
        print(f"Prediction: {result} (Confidence: {confidence:.3f})")
        print("-" * 50)

if __name__ == "__main__":
    main()
