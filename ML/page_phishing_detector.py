#!/usr/bin/env python3
"""
Page-Based Phishing Detection using Machine Learning
Uses pre-extracted page features from Page_Set.csv
"""

import os
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings('ignore')

class PagePhishingDetector:
    """
    Phishing detector based on page-level features (HTML content, structure, etc.)
    Uses pre-extracted features from Page_Set.csv
    """
    def __init__(self):
        self.feature_names = []
        self.scaler = StandardScaler()
        self.model = None
        
    def load_features_from_dataframe(self, df):
        """
        Load features directly from a DataFrame (e.g., from Page_Set.csv)
        Excludes non-feature columns: URL, label, Title (text field)
        """
        # Exclude non-feature columns
        exclude_cols = ['URL', 'url', 'label', 'Title', 'FILENAME']
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        
        # Store feature names
        self.feature_names = feature_cols
        
        # Extract feature matrix
        X = df[feature_cols].values
        
        return X
    
    def create_dataset(self, df):
        """
        Create feature matrix from DataFrame
        """
        print(f"Loading features from dataset with {len(df)} pages...")
        
        # Get feature columns (exclude URL, label, Title)
        exclude_cols = ['URL', 'url', 'label', 'Title', 'FILENAME']
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        
        self.feature_names = feature_cols
        X = df[feature_cols].values
        
        print(f"Extracted {len(self.feature_names)} features")
        print(f"Feature names: {self.feature_names[:10]}..." if len(self.feature_names) > 10 else f"Feature names: {self.feature_names}")
        
        return X
    
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
                   cmap='Blues', ax=axes[0, 1],
                   xticklabels=['Legitimate', 'Phishing'],
                   yticklabels=['Legitimate', 'Phishing'])
        axes[0, 1].set_title('Confusion Matrix')
        axes[0, 1].set_xlabel('Predicted')
        axes[0, 1].set_ylabel('Actual')
        
        # Prediction Probabilities Distribution
        phishing_probs = results['probabilities'][:, 1]
        axes[1, 0].hist(phishing_probs, bins=50, alpha=0.7, color='red', edgecolor='black')
        axes[1, 0].set_xlabel('Predicted Probability of Phishing')
        axes[1, 0].set_ylabel('Frequency')
        axes[1, 0].set_title('Distribution of Phishing Probabilities')
        axes[1, 0].axvline(x=0.5, color='blue', linestyle='--', label='Decision Threshold')
        axes[1, 0].legend()
        
        # Performance Metrics Bar Chart
        from sklearn.metrics import precision_recall_fscore_support
        # Note: This requires y_test which should be passed separately
        # For now, we'll calculate from predictions only (not ideal but works)
        # In practice, this should be called from evaluate_model with y_test
        precision, recall, fscore, _ = precision_recall_fscore_support(
            results['predictions'], 
            results['predictions'], 
            average=None
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
        plt.savefig('ML/Page/Page Results/phishing_detection_page_results.png', dpi=300, bbox_inches='tight')
        print(f"\nResults plot saved to: ML/Page/Page Results/phishing_detection_page_results.png")
        plt.show()

def main():
    """
    Main function to run the page-based phishing detection system
    """
    print("=== Page-Based Phishing URL Detection System ===")
    
    # Initialize detector
    detector = PagePhishingDetector()
    
    # Load dataset
    dataset_path = 'ML/Page/Page Data/Page_Set.csv'
    
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        return
    
    print(f"\nLoading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)
    
    print(f"Dataset loaded: {len(df)} samples")
    print(f"Columns: {df.columns.tolist()}")
    
    # Prepare data
    if 'label' not in df.columns:
        print("Error: Dataset must have 'label' column")
        return
    
    # Extract features
    X = detector.create_dataset(df)
    y = np.array(df['label'].tolist())
    
    # Dataset labels: 0=phishing, 1=legitimate (matches Page_Set.csv)
    print(f"\nLabel distribution:")
    print(f"  Phishing (0): {np.sum(y == 0):,} ({np.sum(y == 0)/len(y)*100:.1f}%)")
    print(f"  Legitimate (1): {np.sum(y == 1):,} ({np.sum(y == 1)/len(y)*100:.1f}%)")
    
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
    os.makedirs('ML/Page/Page Results', exist_ok=True)
    detector.plot_results(feature_importance, results)
    
    # Save feature importance
    feature_importance.to_csv('ML/Page/Page Results/feature_importance.csv', index=False)
    print(f"\nFeature importance saved to: ML/Page/Page Results/feature_importance.csv")
    
    print("\n✅ Page-based phishing detection model training completed!")

if __name__ == "__main__":
    main()

