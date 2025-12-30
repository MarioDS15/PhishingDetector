# Phishing Detection ML System

A machine learning system for detecting phishing URLs using both heuristic and ML-based approaches.

## **Purpose**

This is a research project exploring how machine learning and AI can be applied to phishing detection. The system provides multiple ways to analyze URLs and page content for phishing indicators:

- **URL-Based ML Detection**: Random Forest models analyzing URL structure and features
- **Page Content-Based ML Detection**: Models analyzing rendered webpage structure and content
- **Weighted Ensemble**: Combines domain and path analysis with configurable weights
- **Feature Extraction**: Comprehensive feature engineering for custom implementations

**Note**: This project was created for academic/research purposes to study phishing detection techniques, not as a commercial product.

## **Project Structure**

```
CYSE610Project/
├── main.py                       # Main application for URL phishing detection
├── page_main.py                  # Page-based phishing detection application
├── cli_url_check.py              # Command-line tool for URL checking
├── extension/                    # Chrome browser extension (production-ready)
│   ├── js/                       # Extension JavaScript files
│   │   ├── background.js         # Background service worker
│   │   ├── content.js            # Content script for warnings
│   │   ├── popup.js              # Extension popup UI
│   │   ├── url-features.js       # URL feature extraction
│   │   ├── weighted-model.js     # Weighted ensemble model
│   │   └── ...
│   ├── models/                   # Pre-trained ML models (JSON format)
│   │   ├── domain_model_lite.json
│   │   ├── path_model_lite.json
│   │   ├── page_model_lite.json
│   │   └── ...
│   ├── manifest.json             # Extension manifest
│   └── ...
├── ML/                           # Core ML components and trained models
│   ├── phishing_detector.py      # URL-based phishing detector
│   ├── page_phishing_detector.py # Page content-based detector
│   ├── URL/                      # URL-specific components
│   │   ├── url_features.py       # Feature extraction utilities
│   │   ├── weighted_predictor.py # Weighted ensemble predictor
│   │   ├── URL Data/             # Training datasets
│   │   │   ├── URL_Set.csv
│   │   │   ├── URL_Set_domain_only.csv
│   │   │   ├── URL_Set_path_only.csv
│   │   │   └── ...
│   │   └── URL Results/          # Trained models (.joblib format)
│   │       ├── combined_model.joblib
│   │       ├── domain_only_model.joblib
│   │       ├── path_only_model.joblib
│   │       └── cli_detector.joblib
│   └── Page/                     # Page-based detection components
│       ├── Page Data/            # Page datasets
│       └── Page Results/         # Trained page models
├── Results/                      # Analysis reports and documentation
│   ├── URL_ML_ANALYSIS_REPORT.md
│   ├── PAGE_ML_ANALYSIS_REPORT.md
│   └── ...
├── Setup/
│   └── requirements.txt          # Python dependencies
├── README.md                     # This file
├── QUICK_START.md                # Quick start guide
└── SETUP_README.md               # Setup instructions

Note: Development files (training scripts, export scripts, test files, etc.) have been 
removed from the main branch but are available in the 'dev' branch. The main branch 
contains only the production-ready extension, trained models, and core ML logic needed 
to use the system.
```

## **Quick Start**

### **1. Use the Chrome Extension (Recommended)**
See `QUICK_START.md` and `extension/INSTALL.md` for installation and usage instructions.

### **2. Run the Python Applications**
```bash
# URL-based phishing detection
python3 main.py

# Page content-based phishing detection
python3 page_main.py

# Command-line URL checker
python3 cli_url_check.py <url>
```

### **2. Install Dependencies (if needed)**
```bash
pip install -r requirements.txt
```

## **Testing Results**

- **Basic Detector Accuracy**: 99.61%
- **URL Detector Accuracy**: 99.61%
- **Feature Extraction**: 35+ features per URL
- **Quick Detection**: Heuristic-based (no training required)
- **Implementation Ready**: Yes

## **Usage Examples**

### **Using the Weighted Predictor (Recommended)**
```python
from ML.URL.weighted_predictor import WeightedPhishingPredictor

predictor = WeightedPhishingPredictor(domain_weight=0.85, path_weight=0.15)
predictor.load_models()

result = predictor.predict("https://example.com")
print(f"Phishing: {result['is_phishing']}")
print(f"Confidence: {result['weighted_phishing_prob']:.2%}")
```

### **Feature Extraction**
```python
from ML.URL.url_features import extract_all_url_features

features = extract_all_url_features("https://example.com")
print(f"Extracted {len(features)} features")
```

### **Using Pre-trained Models**
The repository includes pre-trained models in both `.joblib` format (for Python) and JSON format (for the browser extension). You can load and use these directly without retraining.

## **Key Features**

### **URL Analysis Features (39 total)**
- **Basic URL features**: Length, special characters, structure
- **Domain features**: TLD analysis, subdomain count, domain length
- **Suspicious patterns**: Keywords, brand names, shorteners
- **Statistical features**: Entropy, character ratios
- **Path features**: Depth, file extensions, parameters

### **Detection Methods**
1. **Heuristic Detection**: Fast, rule-based (immediate use)
2. **ML Detection**: Random Forest classifier (99.61% accuracy)
3. **Feature Extraction**: Detailed analysis for custom logic

## **System Capabilities**

The system demonstrates several ML approaches to phishing detection:

- **Modular Design**: Core components can be used independently
- **High Accuracy**: 99%+ accuracy on test datasets
- **Multiple Models**: URL-based, page-based, and ensemble approaches
- **Pre-trained Models**: Models are included and ready to use
- **Browser Extension**: Working Chrome extension implementation

## **Performance**

- **Dataset**: 2,557 URLs (legitimate + phishing)
- **Features**: 39 comprehensive URL features
- **Accuracy**: 99.61% on test set
- **Speed**: Heuristic detection is instant, ML detection requires training

## **Sample Results**

### **Legitimate URLs**
- `https://www.google.com` → SAFE (Low risk)
- `https://github.com/microsoft/vscode` → SAFE (Low risk)

### **Phishing URLs**
- `https://goog1e-security-alert.com/verify-account` → PHISHING (High risk)
- `https://paypa1-confirm-account.ml/secure-login` → PHISHING (High risk)

## **Project Status & Note**

**This is a research project**, not a production-ready product. This repository was created as part of an academic study to explore how machine learning and AI techniques can be used for phishing detection.

### **What's Included in This Repository:**
- **Trained ML Models**: Pre-trained Random Forest models for both URL and page content analysis (99%+ accuracy)
- **Chrome Extension**: Fully functional browser extension implementing the detection system
- **Core ML Logic**: Feature extraction, weighted ensemble predictors, and detection algorithms
- **Analysis Reports**: Detailed reports on model performance and feature importance (in `Results/`)

### **What's Not Included (Development Files):**
Development and training files have been moved to the `dev` branch to keep the main branch clean. This includes:
- Training scripts (`train_*.py`, `generate_*.py`)
- Model export scripts (`export_*.py`)
- Test files and datasets used during development
- Visualization outputs and intermediate results

### **Branch Structure:**
- **`main` branch**: Contains production-ready extension, trained models, and core code
- **`dev` branch**: Contains all development files, training scripts, and experimental code

### **Important Disclaimer:**
This system was developed for educational and research purposes. While it demonstrates effective phishing detection capabilities, it should not be relied upon as the sole security measure. The models were trained on specific datasets and may not generalize perfectly to all real-world scenarios.
