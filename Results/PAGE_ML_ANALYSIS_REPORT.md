# Page Content-Based Phishing Detection Using Machine Learning

## Objective

This section presents the development and evaluation of a secondary machine learning subsystem designed to analyze rendered webpage content for phishing indicators. Unlike the URL-based model which operates on URL structure alone, this component performs DOM inspection and content analysis after page load, serving as a deeper verification layer that examines the actual webpage structure, resources, and behavioral signals.

## Dataset and Preprocessing

The dataset contains **235,795 webpages** with pre-extracted HTML and DOM features. Each page was scraped and analyzed to extract structural and content-based indicators, with labels indicating legitimate (1) or phishing (0) classification.

## Page Feature Engineering

Each webpage is transformed into a **28-feature** numerical representation spanning content structure, trust signals, form behavior, and resource analysis:

| **Category** | **Features** | **Description** |
|-------------|-------------|-----------------|
| **Content Structure (3)** | `LineOfCode`, `LargestLineLength`, `HasTitle` | HTML complexity and basic structure indicators |
| **Title Matching (2)** | `DomainTitleMatchScore`, `URLTitleMatchScore` | Consistency between page title and URL/domain |
| **Trust Signals (4)** | `HasFavicon`, `Robots`, `IsResponsive`, `HasCopyrightInfo` | Indicators of legitimate site development practices |
| **Redirect Analysis (2)** | `NoOfURLRedirect`, `NoOfSelfRedirect` | Detection of suspicious redirect chains |
| **Metadata (1)** | `HasDescription` | Presence of meta description tags |
| **DOM Structure (2)** | `NoOfPopup`, `NoOfiFrame` | Popup scripts and iframe embedding counts |
| **Form Analysis (4)** | `HasExternalFormSubmit`, `HasSubmitButton`, `HasHiddenFields`, `HasPasswordField` | Credential harvesting indicators |
| **Social Presence (1)** | `HasSocialNet` | Links to legitimate social media platforms |
| **Keyword Detection (3)** | `Bank`, `Pay`, `Crypto` | Financial and cryptocurrency terminology presence |
| **Resource Counts (3)** | `NoOfImage`, `NoOfCSS`, `NoOfJS` | External resource loading patterns |
| **Link Analysis (3)** | `NoOfSelfRef`, `NoOfEmptyRef`, `NoOfExternalRef` | Internal vs external link distribution |

## Machine Learning Architecture

The page-based model uses a **Random Forest Classifier** with the same hyperparameters as the URL model for consistency:

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
| Accuracy | 99.70% |
| Precision | 99.70% |
| Recall | 99.70% |
| F1-Score | 99.70% |
| ROC AUC | 100.00% |

**Confusion Matrix (Test Set: 35,369 samples):**

|  | Predicted Legitimate | Predicted Phishing |
|--|---------------------|-------------------|
| **Actual Legitimate** | 15,056 (TN) | 86 (FP) |
| **Actual Phishing** | 20 (FN) | 20,207 (TP) |

## Feature Importance Analysis

The top contributing features reveal that **external reference patterns and resource counts** are the strongest indicators:

| **Rank** | **Feature** | **Importance** |
|---------|-------------|----------------|
| 1 | `NoOfExternalRef` | 24.67% |
| 2 | `NoOfSelfRef` | 14.91% |
| 3 | `NoOfImage` | 13.15% |
| 4 | `LineOfCode` | 12.22% |
| 5 | `NoOfJS` | 8.44% |
| 6 | `NoOfCSS` | 6.22% |
| 7 | `HasSocialNet` | 5.86% |
| 8 | `HasCopyrightInfo` | 4.51% |
| 9 | `HasDescription` | 3.14% |
| 10 | `DomainTitleMatchScore` | 2.28% |

## Key Findings

**1. Link Structure as Primary Discriminator**

Link analysis features (`NoOfExternalRef`, `NoOfSelfRef`) account for **39.58%** of model decisions. Phishing pages exhibit distinct linking patterns: they typically lack comprehensive internal navigation structures that legitimate sites develop over time, and often contain excessive external references to load resources from third-party hosting services. Legitimate websites maintain consistent internal link ecosystems pointing to other pages within the same domain, while phishing clones frequently omit these interconnections to minimize development effort.

**2. Resource Complexity Reflects Development Investment**

Resource-related features (`NoOfImage`, `LineOfCode`, `NoOfJS`, `NoOfCSS`) contribute **40.03%** of predictive power. Phishing pages are typically simplified clones that replicate only the visual appearance necessary to deceive users, resulting in significantly fewer images, shorter codebases, and minimal JavaScript/CSS complexity. Legitimate commercial websites invest in rich media, interactive features, and responsive design frameworks that inflate these metrics beyond what attackers typically replicate.

**3. Trust Signal Absence**

Professional indicators (`HasSocialNet`, `HasCopyrightInfo`, `HasDescription`) provide **13.51%** importance. Legitimate organizations consistently include social media links, copyright notices, and meta descriptions for SEO purposes. Phishing pages frequently omit these elements as they serve no functional purpose for credential harvesting and require additional effort to implement convincingly.

**4. Form Features as Secondary Validators**

While form-related features (`HasPasswordField`, `HasHiddenFields`, `HasExternalFormSubmit`) show lower individual importance scores, they remain critical for detecting credential harvesting attempts. The model learns that the *combination* of password fields with other suspicious indicators (low resource counts, missing trust signals) strongly correlates with phishing behavior.

## Issues and Limitations

**1. Dynamic Content and JavaScript Rendering**

A significant limitation encountered was the inability to fully analyze dynamically-rendered content. Modern phishing kits increasingly use JavaScript frameworks to render login forms client-side, meaning the initial HTML source may appear benign while malicious elements are injected post-load. The current feature extraction captures the DOM state at a single point, potentially missing delayed content injection.

**2. Redirect Chain Analysis**

The `NoOfURLRedirect` and `NoOfSelfRedirect` features showed near-zero importance (0.05% and 0.002% respectively) because accurate redirect counting requires server-side request tracing rather than client-side DOM inspection. This represents a blind spot where multi-hop redirect attacks may evade detection.

**3. Robots.txt Verification**

The `Robots` feature consistently returned 0 across the dataset because verifying robots.txt existence requires an additional HTTP request that was not performed during feature extraction. This trust signal, while theoretically valuable, provided no discriminative power in practice.

**4. Keyword Feature Limitations**

Binary keyword features (`Bank`, `Pay`, `Crypto`) showed minimal importance (< 0.1% combined) because both legitimate financial services and phishing pages targeting them contain these terms. The presence of financial keywords alone is not discriminative; context matters more than vocabulary.

**5. Single-Page Analysis Scope**

The model analyzes individual pages in isolation without considering site-wide patterns. Legitimate websites exhibit consistent design language, navigation structures, and branding across multiple pages, while phishing sites typically consist of a single credential-harvesting page. Multi-page behavioral analysis could improve detection accuracy.

## Conclusion

The page content-based model provides a complementary detection layer that analyzes actual webpage structure rather than URL patterns alone. The feature importance analysis confirms that phishing pages exhibit characteristic deficiencies in link structure, resource complexity, and professional trust signals—patterns that persist even when attackers successfully mimic legitimate URL structures. This two-layer approach (URL + Page) enables defense-in-depth detection where each model compensates for the other's blind spots.

