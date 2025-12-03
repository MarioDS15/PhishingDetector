#!/usr/bin/env python3
"""
Weighted prediction system that combines domain-only and path-only models
with adjustable weights (default: 75% domain, 25% path)
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.preprocessing import StandardScaler

class WeightedPhishingPredictor:
    """Combines domain and path models with adjustable weights"""
    
    def __init__(self, domain_weight=0.85, path_weight=0.15):
        """
        Initialize weighted predictor
        
        Args:
            domain_weight: Weight for domain model (default: 0.75)
            path_weight: Weight for path model (default: 0.25)
        """
        self.domain_weight = domain_weight
        self.path_weight = path_weight
        
        # Normalize weights
        total = domain_weight + path_weight
        self.domain_weight = domain_weight / total
        self.path_weight = path_weight / total
        
        self.domain_model = None
        self.domain_scaler = None
        self.domain_features = None
        
        self.path_model = None
        self.path_scaler = None
        self.path_features = None
        
    def load_models(self, results_dir=None):
        """Load domain and path models"""
        if results_dir is None:
            results_dir = Path(__file__).resolve().parents[2] / "ML" / "URL" / "URL Results"
        else:
            results_dir = Path(results_dir)
        
        # Load domain model
        domain_file = results_dir / "domain_only_model.joblib"
        if not domain_file.exists():
            raise FileNotFoundError(f"Domain model not found: {domain_file}")
        
        domain_payload = joblib.load(domain_file)
        self.domain_model = domain_payload['model']
        self.domain_scaler = domain_payload['scaler']
        self.domain_features = domain_payload['feature_names']
        
        # Load path model
        path_file = results_dir / "path_only_model.joblib"
        if not path_file.exists():
            raise FileNotFoundError(f"Path model not found: {path_file}")
        
        path_payload = joblib.load(path_file)
        self.path_model = path_payload['model']
        self.path_scaler = path_payload['scaler']
        self.path_features = path_payload['feature_names']
        
        print(f"Loaded models with weights: {self.domain_weight:.1%} domain, {self.path_weight:.1%} path")
    
    def predict(self, url_or_features):
        """
        Make weighted prediction from URL or feature dictionary
        
        Args:
            url_or_features: Either a URL string or dictionary of component features
                           If URL: will extract domain and path features separately
                           If dict: should have 'domain_features' and 'path_features' keys
            
        Returns:
            Dictionary with prediction, confidence, and individual model predictions
        """
        if self.domain_model is None or self.path_model is None:
            raise ValueError("Models not loaded. Call load_models() first.")
        
        # If URL string, extract features using component-specific methods
        if isinstance(url_or_features, str):
            from urllib.parse import urlparse
            import sys
            from pathlib import Path
            project_root = Path(__file__).resolve().parents[2]
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            from ML.phishing_detector import PhishingDetector
            
            detector = PhishingDetector()
            parsed = urlparse(url_or_features)
            domain_features = detector.extract_domain_features(parsed.netloc, parsed.scheme)
            path_features = detector.extract_path_features(parsed.path, parsed.query)
        else:
            # Assume it's a feature dictionary with component-specific features
            features_dict = url_or_features
            domain_features = {k: features_dict.get(k, 0) for k in self.domain_features}
            path_features = {k: features_dict.get(k, 0) for k in self.path_features}
        
        # Extract domain features in correct order
        domain_feat_array = pd.DataFrame([domain_features])[self.domain_features]
        domain_scaled = self.domain_scaler.transform(domain_feat_array)
        domain_proba = self.domain_model.predict_proba(domain_scaled)[0]
        domain_pred = self.domain_model.predict(domain_scaled)[0]
        
        # Extract path features in correct order
        path_feat_array = pd.DataFrame([path_features])[self.path_features]
        path_scaled = self.path_scaler.transform(path_feat_array)
        path_proba = self.path_model.predict_proba(path_scaled)[0]
        path_pred = self.path_model.predict(path_scaled)[0]
        
        # Weighted combination
        # Dataset convention: 0=phishing, 1=legitimate
        # proba[0] = phishing probability, proba[1] = legitimate probability
        weighted_phishing_prob = (
            self.domain_weight * domain_proba[0] + 
            self.path_weight * path_proba[0]
        )
        weighted_legitimate_prob = (
            self.domain_weight * domain_proba[1] + 
            self.path_weight * path_proba[1]
        )
        
        # Final prediction (0=phishing, 1=legitimate)
        final_pred = 0 if weighted_phishing_prob > weighted_legitimate_prob else 1
        
        return {
            'prediction': final_pred,
            'is_phishing': final_pred == 0,
            'phishing_probability': weighted_phishing_prob,
            'legitimate_probability': weighted_legitimate_prob,
            'confidence': max(weighted_phishing_prob, weighted_legitimate_prob),
            'domain_prediction': domain_pred,
            'domain_phishing_prob': domain_proba[0],
            'domain_confidence': max(domain_proba),
            'path_prediction': path_pred,
            'path_phishing_prob': path_proba[0],
            'path_confidence': max(path_proba),
            'weights': {
                'domain': self.domain_weight,
                'path': self.path_weight
            }
        }
    
    def set_weights(self, domain_weight, path_weight):
        """Update weights"""
        total = domain_weight + path_weight
        self.domain_weight = domain_weight / total
        self.path_weight = path_weight / total
        print(f"Updated weights: {self.domain_weight:.1%} domain, {self.path_weight:.1%} path")


def test_weighted_predictor():
    """Test the weighted predictor with example URLs"""
    import sys
    from pathlib import Path
    project_root = Path(__file__).resolve().parents[2]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from ML.phishing_detector import PhishingDetector
    
    predictor = WeightedPhishingPredictor(domain_weight=0.75, path_weight=0.25)
    predictor.load_models()
    
    detector = PhishingDetector()
    
    test_urls = [
        "https://www.google.com/login",
        "https://example.com/file.html",
        "https://suspicious-site.tk/verify-account",
        "https://paypal.com/secure/login",
        "https://goog1e-security.com/update"
    ]
    
    print("\n" + "=" * 70)
    print("Testing Weighted Predictor")
    print("=" * 70)
    
    for url in test_urls:
        result = predictor.predict(url)  # Can now pass URL directly
        
        print(f"\nURL: {url}")
        print(f"  Final: {'PHISHING' if result['is_phishing'] else 'LEGITIMATE'} "
              f"({result['confidence']:.2%} confidence)")
        print(f"  Domain: {'PHISHING' if result['domain_prediction'] == 0 else 'LEGITIMATE'} "
              f"({result['domain_confidence']:.2%})")
        print(f"  Path:   {'PHISHING' if result['path_prediction'] == 0 else 'LEGITIMATE'} "
              f"({result['path_confidence']:.2%})")


if __name__ == "__main__":
    test_weighted_predictor()

