# Setup Guide for Phishing Detection ML System

## Quick Setup

### Option 1: Quick Check (Recommended)
```bash
python3 quick_setup.py
```
This will check what's installed and provide specific instructions for what's missing.

### Option 2: Complete Setup
```bash
python3 setup_everything.py
```
This will automatically install everything needed (requires pip3).

## 📋 Manual Setup

### 1. Install Python Dependencies
```bash
pip3 install -r Setup/requirements.txt
```

### 2. Download Datasets
```bash
python3 Setup/enhanced_dataset_collector.py
```

### 3. Create Directories (if needed)
```bash
mkdir -p ML/URL/URL\ Data
mkdir -p ML/URL/URL\ Results
mkdir -p data
mkdir -p logs
```

## Verify Installation

Run the quick check to verify everything is working:
```bash
python3 quick_setup.py
```

## 🚀 Quick Start

Once setup is complete, you can run:

```bash
# Run ML tests
python3 ml_test.py

# Run full application
python3 main.py

# See usage examples
python3 example_usage.py
```

## Project Structure

```
CYSE610Project/
├── main.py                      # Full application
├── cli_url_check.py             # CLI entrypoint
├── ML/                          # Core ML components
│   ├── phishing_detector.py
│   └── URL/
│       ├── __init__.py
│       ├── url_features.py
│       ├── generate_enriched_url_dataset.py
│       ├── URL Data/            # Datasets
│       └── URL Results/         # Model artifacts
├── Setup/
│   └── requirements.txt
└── requirements.txt             # Main requirements file
```

## 🔧 Troubleshooting

### Import Errors
- Make sure `ML/__init__.py` exists
- Check that Python path includes ML directories
- Verify all dependencies are installed

### Dataset Issues
- Ensure `ML/URL/URL Data/URL_Set.csv` exists (regenerate with `generate_enriched_url_dataset.py` if needed)

### Permission Errors
- Use `pip3` instead of `pip`
- Check file permissions in the project directory

## What Gets Installed

- **Python Packages**: pandas, numpy, scikit-learn, matplotlib, seaborn, requests, tldextract, joblib
- **Datasets**: Enhanced phishing dataset (2,557 URLs from multiple sources)
- **Directories**: All necessary folders for data and results
- **ML Modules**: All core ML components for phishing detection

## 🎯 Ready to Use!

Once setup is complete, your phishing detection ML system will be ready for:
- Testing ML models
- Running full applications
- Generating results and graphs
- Integration into other projects
