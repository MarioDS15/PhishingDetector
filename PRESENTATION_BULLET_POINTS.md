# Presentation Bullet Points

## 1. Explaining Random Forest

• **Ensemble Learning Method**: Random Forest combines multiple decision trees (100 trees in our model) to make more accurate predictions than a single tree

• **Voting Mechanism**: Each tree independently classifies a URL as phishing or legitimate, and the final prediction is determined by majority vote across all trees

• **Feature Importance**: The model automatically identifies which features (like URL length, brand similarity, HTTPS usage) are most critical for detection through feature importance scores

• **Handles Non-Linear Relationships**: Unlike simple linear models, Random Forest can capture complex patterns and interactions between features (e.g., detecting that suspicious TLDs combined with brand names indicate phishing)

• **Reduces Overfitting**: By training each tree on a random subset of data (bootstrap sampling) and using random feature subsets, the model generalizes better to new, unseen URLs

• **Scalable and Interpretable**: Can handle large datasets (240,000+ URLs) efficiently and provides feature importance rankings to understand what drives phishing detection

---

## 2. Functions Used in URL Analysis (Advanced Feature Extraction)

• **Homograph Detection**: Uses `SequenceMatcher` algorithm to calculate string similarity between URL components and known brand names, detecting typosquatting attacks (e.g., "paypa1.com" vs "paypal.com") with a similarity threshold of 0.6

• **Brand Impersonation Analysis**: Extracts brand keywords from registered domain, subdomain, and path separately, then calculates similarity scores for each component to detect when brands appear in suspicious locations (e.g., brand in path but not domain)

• **Obfuscation Detection**: Identifies encoded characters in URLs using regex patterns for percent encoding (%XX), hex encoding (\xXX), Unicode encoding (\uXXXX), and HTML entities, calculating obfuscation ratios to detect attempts to hide malicious content

• **Entropy Calculation**: Computes Shannon entropy for both the full URL and domain separately, where high entropy indicates random or obfuscated strings commonly used in phishing URLs to evade detection

• **TLD Extraction and Analysis**: Uses `tldextract` library to parse complex domain structures, separating subdomains, registered domains, and TLDs to detect suspicious patterns like free TLDs (.tk, .ml, .ga) commonly used by phishers

• **Statistical Feature Extraction**: Calculates ratios (digit ratio, letter ratio, special character ratio) and structural metrics (path depth, query parameter count) that aren't directly visible but reveal URL composition patterns indicative of phishing

---

## 3. Issues Encountered

• **Generalization Gap**: Despite 200,000+ training samples, higher false positive rate in real-world browsing than test set

• **Delayed Real-World Testing**: Testing implemented too late, false positives discovered post-deployment

• **Overfitting to Correlated Features**: 40%+ importance assigned to redundant feature pairs (HTTPS/HTTP, path_length/path_depth)

• **HTTP/HTTPS Dominance**: Model flagged all non-HTTPS URLs as phishing, ignoring legitimate HTTP sites

• **Unused Features**: Several features (< 0.001% importance): `has_port`, `obfuscation_ratio`, `has_ip`, `num_percentages`

• **Page Model Limitations**: Struggled with dynamic JavaScript-rendered content and single-page applications

• **Localhost Whitelisting**: Initially blocked local testing; required removal for development

• **Feature Explanation Thresholds**: Had to lower threshold from 10% to 1% to show sufficient explanations

• **Typosquatting in Paths**: Initial detection missed path-based typosquatting; extended to analyze paths

• **Retraining Complexity**: Adding URLs required regenerating features for 240,000+ samples

• **Explanation Format Inconsistency**: URL and page explanations returned different formats; unified to strings

