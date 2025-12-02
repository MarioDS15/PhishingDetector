/**
 * Page-Based ML Model Inference Engine for Phishing Detection
 * Implements Random Forest prediction in JavaScript for page/DOM features
 */

class PagePhishingModel {
    constructor() {
        this.modelData = null;
        this.isLoaded = false;
    }

    /**
     * Load the page model from JSON file
     * @param {string} modelPath - Path to the model JSON file
     */
    async loadModel(modelPath = '/models/page_model_lite.json') {
        try {
            // Support both Chrome extension and regular fetch
            const url = typeof chrome !== 'undefined' && chrome.runtime
                ? chrome.runtime.getURL(modelPath)
                : modelPath;

            const response = await fetch(url);
            this.modelData = await response.json();
            this.isLoaded = true;

            console.log(`Page model loaded successfully:`);
            console.log(`  - Trees: ${this.modelData.n_estimators}`);
            console.log(`  - Features: ${this.modelData.n_features}`);
            console.log(`  - Detection type: ${this.modelData.detection_type}`);

            return true;
        } catch (error) {
            console.error('Error loading page model:', error);
            return false;
        }
    }

    /**
     * Predict if a page is phishing based on DOM features
     * @param {Object} features - Feature object with 28 numeric values
     * @returns {Object} Prediction result with confidence and details
     */
    predict(features) {
        if (!this.isLoaded) {
            throw new Error('Page model not loaded! Call loadModel() first.');
        }

        // Validate features
        if (!features || typeof features !== 'object') {
            throw new Error('Invalid features: must be an object');
        }

        // Ensure all required features are present
        const missingFeatures = this.modelData.feature_names.filter(
            name => !(name in features)
        );

        if (missingFeatures.length > 0) {
            console.warn('Missing features:', missingFeatures);
            // Fill missing features with 0
            missingFeatures.forEach(name => {
                features[name] = 0;
            });
        }

        // Scale features
        const scaledFeatures = this.scaleFeatures(features);

        // Get predictions from all trees
        const treePredictions = [];
        const treeConfidences = [];

        for (const tree of this.modelData.trees) {
            const result = this.predictTree(tree, scaledFeatures);
            treePredictions.push(result.class);
            treeConfidences.push(result.confidence);
        }

        // Aggregate predictions (majority vote)
        // Dataset convention: 0 = phishing, 1 = legitimate
        const phishingVotes = treePredictions.filter(p => p === 0).length;
        const legitimateVotes = treePredictions.filter(p => p === 1).length;
        const totalVotes = treePredictions.length;

        const isPhishing = phishingVotes > legitimateVotes;
        const confidence = isPhishing
            ? phishingVotes / totalVotes
            : legitimateVotes / totalVotes;

        // Calculate average tree confidence
        const avgTreeConfidence = treeConfidences.reduce((a, b) => a + b, 0) / treeConfidences.length;

        // Get feature importance insights
        const topFeatures = this.getTopFeatures(features);

        return {
            isPhishing: isPhishing,
            confidence: confidence,
            confidencePercent: Math.round(confidence * 100),
            phishingProbability: phishingVotes / totalVotes,
            legitimateProbability: legitimateVotes / totalVotes,
            phishingVotes: phishingVotes,
            legitimateVotes: legitimateVotes,
            totalVotes: totalVotes,
            avgTreeConfidence: avgTreeConfidence,
            features: features,
            topFeatures: topFeatures,
            riskLevel: this.getRiskLevel(confidence, isPhishing),
            detectionType: 'page'
        };
    }

    /**
     * Predict using a single decision tree
     * @param {Object} node - Current tree node
     * @param {Object} features - Scaled feature values
     * @returns {Object} Prediction with class and confidence
     */
    predictTree(node, features) {
        // If leaf node, return the prediction
        if (node.leaf) {
            return {
                class: node.class,
                confidence: node.confidence
            };
        }

        // Get feature value
        const featureValue = features[node.feature];

        // Handle missing feature
        if (featureValue === undefined || featureValue === null) {
            console.warn(`Missing feature in tree traversal: ${node.feature}`);
            // Default to left branch
            return this.predictTree(node.left, features);
        }

        // Traverse tree based on threshold
        if (featureValue <= node.threshold) {
            return this.predictTree(node.left, features);
        } else {
            return this.predictTree(node.right, features);
        }
    }

    /**
     * Scale features using the model's StandardScaler
     * @param {Object} features - Raw feature values
     * @returns {Object} Scaled feature values
     */
    scaleFeatures(features) {
        const scaled = {};

        for (let i = 0; i < this.modelData.feature_names.length; i++) {
            const featureName = this.modelData.feature_names[i];
            const value = features[featureName] !== undefined ? features[featureName] : 0;
            const mean = this.modelData.scaler.mean[i];
            const scale = this.modelData.scaler.scale[i];

            // StandardScaler formula: (x - mean) / scale
            scaled[featureName] = (value - mean) / scale;
        }

        return scaled;
    }

    /**
     * Get top contributing features (features with unusual values)
     * @param {Object} features - Raw feature values
     * @returns {Array} Top features with their values
     */
    getTopFeatures(features) {
        const featureScores = [];

        for (let i = 0; i < this.modelData.feature_names.length; i++) {
            const featureName = this.modelData.feature_names[i];
            const value = features[featureName] || 0;
            const mean = this.modelData.scaler.mean[i];
            const scale = this.modelData.scaler.scale[i];

            // Calculate how many standard deviations from mean
            const zScore = Math.abs((value - mean) / scale);

            featureScores.push({
                name: featureName,
                value: value,
                zScore: zScore,
                deviation: value - mean
            });
        }

        // Sort by z-score (most unusual features first)
        featureScores.sort((a, b) => b.zScore - a.zScore);

        // Return top 5 features
        return featureScores.slice(0, 5);
    }

    /**
     * Determine risk level based on confidence
     * @param {number} confidence - Prediction confidence (0-1)
     * @param {boolean} isPhishing - Whether predicted as phishing
     * @returns {string} Risk level: safe, low, medium, high
     */
    getRiskLevel(confidence, isPhishing) {
        if (!isPhishing) {
            return 'safe';
        }

        if (confidence >= 0.8) {
            return 'high';      // 80%+ confidence in phishing
        } else if (confidence >= 0.6) {
            return 'medium';    // 60-79% confidence
        } else {
            return 'low';       // 50-59% confidence
        }
    }

    /**
     * Get model information
     * @returns {Object} Model metadata
     */
    getModelInfo() {
        if (!this.isLoaded) {
            return null;
        }

        return {
            modelType: this.modelData.model_type,
            detectionType: this.modelData.detection_type,
            numTrees: this.modelData.n_estimators,
            numFeatures: this.modelData.n_features,
            featureNames: this.modelData.feature_names,
            classes: this.modelData.class_names
        };
    }

    /**
     * Get explanation for the prediction
     * @param {Object} result - Prediction result
     * @returns {Array} Human-readable explanations
     */
    getExplanations(result) {
        const explanations = [];

        if (!result.isPhishing) {
            explanations.push({
                icon: '✅',
                text: 'Page appears legitimate',
                severity: 'safe'
            });
            return explanations;
        }

        // Analyze top features for phishing indicators
        if (result.topFeatures && result.topFeatures.length > 0) {
            for (const feature of result.topFeatures.slice(0, 3)) {
                const explanation = this.getFeatureExplanation(feature);
                if (explanation) {
                    explanations.push(explanation);
                }
            }
        }

        return explanations;
    }

    /**
     * Get human-readable explanation for a feature
     * @param {Object} feature - Feature with name and value
     * @returns {Object} Explanation object
     */
    getFeatureExplanation(feature) {
        const featureExplanations = {
            'NoOfExternalRef': {
                icon: '🔗',
                text: `Unusual number of external links (${feature.value})`,
                severity: 'warning'
            },
            'NoOfiFrame': {
                icon: '🖼️',
                text: `Contains ${feature.value} iframes (often used in phishing)`,
                severity: 'warning'
            },
            'HasPasswordField': {
                icon: '🔑',
                text: 'Contains password field',
                severity: 'info'
            },
            'HasExternalFormSubmit': {
                icon: '📤',
                text: 'Form submits to external domain',
                severity: 'danger'
            },
            'HasSocialNet': {
                icon: '📱',
                text: feature.value === 0 ? 'No social media links' : 'Has social media links',
                severity: feature.value === 0 ? 'warning' : 'safe'
            },
            'HasCopyrightInfo': {
                icon: '©️',
                text: feature.value === 0 ? 'No copyright information' : 'Has copyright info',
                severity: feature.value === 0 ? 'warning' : 'safe'
            },
            'HasFavicon': {
                icon: '🎨',
                text: feature.value === 0 ? 'No favicon' : 'Has favicon',
                severity: feature.value === 0 ? 'warning' : 'safe'
            },
            'DomainTitleMatchScore': {
                icon: '🏷️',
                text: feature.value < 0.5 ? 'Domain doesn\'t match page title' : 'Domain matches title',
                severity: feature.value < 0.5 ? 'warning' : 'safe'
            }
        };

        return featureExplanations[feature.name] || null;
    }
}

/**
 * Singleton instance for the page model
 */
let pageModelInstance = null;

/**
 * Get or create the page model instance
 * @returns {Promise<PagePhishingModel>} Model instance
 */
async function getPageModel() {
    if (!pageModelInstance) {
        pageModelInstance = new PagePhishingModel();
        await pageModelInstance.loadModel('/models/page_model_lite.json');
    }
    return pageModelInstance;
}

/**
 * Quick prediction function for page features
 * @param {Object} features - Page feature object
 * @returns {Promise<Object>} Prediction result
 */
async function predictPage(features) {
    const model = await getPageModel();
    return model.predict(features);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { PagePhishingModel, getPageModel, predictPage };
}
