# URL-Based Phishing Detection Using Machine Learning

## Objective

This section presents the development and evaluation of a machine learning subsystem designed for detecting if a given URL is either a phishing website or legitimate. The approach focuses on analyzing characteristics extracted from the URL itself. Unlike content-based or visual similarity models, this relies solely on URL-level features, enabling faster real-time evaluation. The objective of this component within the entire application is to be the first line of defense, flagging potential phishing attempts before content rendering or user interaction occurs.

## Dataset and Preprocessing

The dataset contains **237,609 URLs** from multiple distinct sources to ensure a diverse and balanced representation of both legitimate and phishing websites. To ensure integrity, all URLs were validated and normalized through the following standardization process:

- Lowercasing all characters
- Removing trailing slashes
- Normalizing URL encodings
- Removing redundant delimiters
- Deduplicating URLs to prevent bias

## URL Feature Engineering

Each URL is transformed into a multi-dimensional numerical representation composed of **50 features** across structural, domain-level, semantic, and statistical indicators. This ensures the model can learn from both explicit patterns (e.g., suspicious tokens) and latent irregularities (e.g., entropy deviations).

| **Category** | **Features** |
|-------------|-------------|
| **Basic URL Structure (12)** | `url_length`, `domain_length`, `domain_name_length`, `tld_length`, `path_length`, `query_length`, `path_depth`, character counts (dots, hyphens, underscores, slashes, question marks, equals, ampersands, percentages), `has_file_extension`, `suspicious_file_ext`, `double_slash`, `trailing_slash`, `uses_http`, `uses_https` |
| **Domain Analysis (8)** | `subdomain_count`, `has_subdomain`, `has_port`, `has_ip`, `has_suspicious_tld`, `has_numbers_in_domain`, `domain_entropy` |
| **Suspicious Patterns & Obfuscation (10)** | `has_at_symbol`, `has_shortener`, `has_suspicious_keywords`, `has_obfuscation`, `num_obfuscated_chars`, `obfuscation_ratio`, `digit_ratio`, `letter_ratio`, `special_char_ratio`, `url_entropy` |
| **Query Parameters (3)** | `num_params`, `has_suspicious_params`, `query_length` |
| **Brand Detection & Homograph (9)** | `suspicious_brand_usage`, `brand_in_registered_domain`, `brand_in_subdomain`, `brand_in_path_or_query`, `brand_mismatch`, `brand_similarity_registered`, `brand_similarity_subdomain`, `brand_similarity_path`, `brand_homograph` |

## Machine Learning Architecture: Hybrid Domain-Path Ensemble

A key innovation in this implementation is the **dual-model weighted ensemble approach** that separates domain analysis from path analysis:

| **Component** | **Description** |
|--------------|-----------------|
| **Domain-Only Model** | Trained on 44 domain-specific features (protocol, TLD, subdomain structure, brand impersonation signals) |
| **Path-Only Model** | Trained on 6 path-specific features (path depth, length, file extensions, query parameters) |
| **Weighted Ensemble** | Combines predictions with configurable weights (default: **85% domain, 15% path**) |

This architecture recognizes that domain characteristics carry stronger phishing signals while path features provide supplementary context. The weighted combination allows fine-tuned detection that leverages both components.

**Random Forest Classifier Parameters:**

| Parameter | Value |
|-----------|-------|
| Number of Trees | 100 |
| Max Depth | 10 |
| Min Samples Split | 5 |
| Min Samples per Leaf | 2 |
| Sampling | Bootstrap |
| Criterion | Gini Impurity |
| Training-Testing Split | 85-15 |

## Evaluation Results

| **Metric** | **Score** |
|-----------|----------|
| Accuracy | 99.33% |
| Precision | 99.45% |
| Recall | 99.38% |
| F1-Score | 99.42% |
| ROC AUC | 99.47% |

**Confusion Matrix (Test Set: 35,570 samples):**

|  | Predicted Legitimate | Predicted Phishing |
|--|---------------------|-------------------|
| **Actual Legitimate** | 14,973 (TN) | 113 (FP) |
| **Actual Phishing** | 126 (FN) | 20,358 (TP) |

- **Specificity (True Negative Rate):** 99.25%
- **Sensitivity (True Positive Rate):** 99.38%

## Feature Importance Analysis

The top contributing features reveal that **protocol and path structure** are the strongest indicators:

| **Rank** | **Feature** | **Importance** |
|---------|-------------|----------------|
| 1 | `uses_https` | 22.38% |
| 2 | `uses_http` | 19.32% |
| 3 | `num_slashes` | 12.48% |
| 4 | `path_depth` | 10.66% |
| 5 | `path_length` | 9.21% |
| 6 | `digit_ratio` | 3.96% |
| 7 | `brand_similarity_subdomain` | 3.93% |
| 8 | `trailing_slash` | 3.37% |
| 9 | `url_length` | 2.04% |
| 10 | `brand_similarity_path` | 1.90% |

**Key Insights:**
- Protocol features (`uses_https`, `uses_http`) account for **41.7%** of model decisions
- Path structure features (`num_slashes`, `path_depth`, `path_length`) contribute **32.35%**
- Brand similarity detection provides critical homograph attack identification
- The top 10 features account for **91.2%** of prediction importance

## Error Analysis

Manual inspection of misclassified URLs revealed that **196 of 239 total errors (82%)**—comprising 102 false positives and 94 false negatives—involved URLs with irregularly long or complex paths. This concentration of errors is attributable to the limited path-specific feature set (only 6 features), which lacks the granularity to distinguish between legitimate complex paths and malicious obfuscation. Specifically, legitimate URLs containing UUIDs, session tokens, or hashed identifiers inflate path length and entropy metrics in ways that mimic phishing characteristics. Additionally, standard path segments such as `/login`, `/verify`, and `/account` trigger false positives despite being common in authentic authentication flows. These findings suggest that future improvements should focus on pattern recognition for legitimate identifiers and context-aware keyword analysis that considers path position rather than treating keywords as universally suspicious.

## Conclusion

The URL-based phishing detection model achieves **99.33% accuracy** with minimal false negatives (126 out of 35,570 test samples), making it highly suitable as a first-line defense mechanism. The hybrid domain-path ensemble architecture provides flexibility in weighting component contributions, and the feature importance analysis confirms that structural URL characteristics—particularly protocol usage and path complexity—are the most discriminative factors in identifying phishing attempts. Error analysis reveals that the majority of misclassifications stem from path complexity edge cases, indicating that enhanced path-specific feature engineering—particularly for UUID recognition and context-aware keyword analysis—represents the primary avenue for further accuracy improvements.

