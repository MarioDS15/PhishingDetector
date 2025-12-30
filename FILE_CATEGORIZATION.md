# File Categorization: Production vs Development

## Production Files (Keep - Needed for End Users)

### Core Extension Files
- `extension/` - Entire directory (Chrome extension code, models, assets)

### Core ML Modules (Used by Extension)
- `ML/phishing_detector.py` - Core phishing detection logic
- `ML/page_phishing_detector.py` - Page-based detection logic
- `ML/URL/url_features.py` - URL feature extraction
- `ML/URL/weighted_predictor.py` - Weighted prediction logic
- `ML/URL/__init__.py` - Package initialization

### Documentation
- `README.md` - Main project documentation
- `QUICK_START.md` - Quick start guide
- `SETUP_README.md` - Setup instructions
- `extension/README.md` - Extension documentation
- `extension/INSTALL.md` - Installation guide
- `Results/` - Analysis reports (optional but useful documentation)

### Setup
- `Setup/requirements.txt` - Python dependencies

### Model Files (Required at Runtime)
- `ML/URL/URL Results/*.joblib` - Trained models
- `ML/Page/Page Results/*.joblib` - Trained models
- `extension/models/*.json` - JavaScript-compatible models

---

## Development-Only Files (Can Be Archived/Removed for Distribution)

### Training & Testing Scripts
- `main.py` - Training/testing script with visualizations
- `page_main.py` - Page model training/testing script
- `cli_url_check.py` - CLI testing tool (useful but not essential for end users)
- `test_extension_model.py` - Extension model testing
- `test_url_features.py` - Feature extraction testing

### Model Export Scripts (Run Once, Already Exported)
- `export_model_to_js.py` - Export URL model to JavaScript
- `export_page_model_to_js.py` - Export page model to JavaScript
- `export_weighted_models_to_js.py` - Export weighted models to JavaScript

### Data Preparation Scripts
- `extractor.py` - Web scraping and feature extraction utilities
- `ML/URL/generate_enriched_url_dataset.py` - Dataset generation
- `ML/URL/generate_component_datasets.py` - Component dataset generation
- `ML/URL/generate_url_results.py` - Result generation script
- `ML/URL/train_separate_models.py` - Model training script
- `ML/URL/train_and_compare.py` - Training comparison script
- `ML/URL/add_legitimate_paths.py` - Dataset modification
- `ML/URL/add_trusted_urls.py` - Dataset modification
- `ML/URL/add_urls_to_datasets.py` - Dataset modification
- `ML/URL/create_separate_datasets.py` - Dataset creation
- `ML/URL/remove_duplicate_urls.py` - Dataset cleaning
- `ML/URL/remove_path_features.py` - Feature removal script
- `ML/URL/regenerate_datasets_with_new_features.py` - Dataset regeneration

### Build/Asset Generation (Run Once)
- `create_extension_icons.py` - Icon generation script

### Test Data
- `test_websites/` - Test HTML files for development testing
- `urls.txt` - Test URLs list
- `phishing_detection_enhanced_results.png` - Visualization output

### Development Documentation
- `EXTENSION_UPDATE_SUMMARY.md` - Development notes
- `ML/URL/RESTRUCTURE_COMPLETE.md` - Development notes
- `ML/URL/DATASET_RESTRUCTURE_ANALYSIS.md` - Development analysis
- `ML/URL/final_improvements_summary.txt` - Development notes
- `ML/URL/path_feature_comparison.txt` - Development notes
- `ML/URL/trusted_domains_list.txt` - Development reference

### Virtual Environment (Should be gitignored)
- `venv/` - Python virtual environment (should not be distributed)

---

## Recommendation

For a production/distribution package, you can safely remove or archive:
1. All training scripts in `ML/URL/` (except `url_features.py`, `weighted_predictor.py`, `__init__.py`)
2. Export scripts (`export_*.py`)
3. Test scripts (`test_*.py`, `test_websites/`)
4. Build scripts (`create_extension_icons.py`)
5. Development documentation (keep user-facing docs only)
6. Visualization outputs (`.png` files in root, but keep `Results/` if it's documentation)
7. Virtual environment (`venv/`)

The minimal production package would be:
- `extension/` (complete)
- `ML/phishing_detector.py`
- `ML/page_phishing_detector.py`
- `ML/URL/url_features.py`
- `ML/URL/weighted_predictor.py`
- `ML/URL/__init__.py`
- `ML/*/Results/*.joblib` (trained models)
- `README.md`, `QUICK_START.md`, `SETUP_README.md`
- `Setup/requirements.txt`

