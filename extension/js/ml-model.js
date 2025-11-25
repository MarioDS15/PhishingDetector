/**
 * ML Model Inference Engine for Phishing Detection
 * Implements Random Forest prediction in JavaScript
 */

class RandomForestModel {
    constructor() {
        this.modelData = null;
        this.featureExtractor = new URLFeatureExtractor();
        this.isLoaded = false;
    }

    /**
     * Load the model from JSON file
     */
    async loadModel(modelPath = '/models/model_lite.json') {
        try {
            const response = await fetch(chrome.runtime.getURL(modelPath));
            this.modelData = await response.json();
            this.isLoaded = true;
            console.log(`Model loaded: ${this.modelData.n_estimators} trees, ${this.modelData.n_features} features`);
            return true;
        } catch (error) {
            console.error('Error loading model:', error);
            return false;
        }
    }

    /**
     * Predict if a URL is phishing
     */
    predict(url) {
        if (!this.isLoaded) {
            throw new Error('Model not loaded! Call loadModel() first.');
        }

        // Check whitelist first
        if (this.featureExtractor.isWhitelisted(url)) {
            return {
                isPhishing: false,
                confidence: 1.0,
                confidencePercent: 100,
                phishingVotes: 0,
                legitimateVotes: this.modelData.n_estimators,
                totalVotes: this.modelData.n_estimators,
                features: {},
                explanations: [],
                riskLevel: 'safe',
                whitelisted: true
            };
        }

        // Extract features
        const features = this.featureExtractor.extractAllFeatures(url);

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
        // Align with dataset: 0 = phishing, 1 = legitimate
        const phishingVotes = treePredictions.filter(p => p === 0).length;      // Class 0 = phishing
        const legitimateVotes = treePredictions.filter(p => p === 1).length;    // Class 1 = legitimate
        const totalVotes = treePredictions.length;

        const isPhishing = phishingVotes > legitimateVotes;
        const confidence = isPhishing
            ? phishingVotes / totalVotes
            : legitimateVotes / totalVotes;

        // Get feature explanations
        const explanations = this.featureExtractor.getFeatureExplanations(features);

        return {
            isPhishing: isPhishing,
            confidence: confidence,
            confidencePercent: Math.round(confidence * 100),
            phishingVotes: phishingVotes,
            legitimateVotes: legitimateVotes,
            totalVotes: totalVotes,
            features: features,
            explanations: explanations,
            riskLevel: this.getRiskLevel(confidence, isPhishing)
        };
    }

    /**
     * Predict using a single decision tree
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

        // Traverse tree
        if (featureValue <= node.threshold) {
            return this.predictTree(node.left, features);
        } else {
            return this.predictTree(node.right, features);
        }
    }

    /**
     * Scale features using the model's scaler
     */
    scaleFeatures(features) {
        const scaled = {};

        for (let i = 0; i < this.modelData.feature_names.length; i++) {
            const featureName = this.modelData.feature_names[i];
            const value = features[featureName] || 0;
            const mean = this.modelData.scaler.mean[i];
            const scale = this.modelData.scaler.scale[i];

            scaled[featureName] = (value - mean) / scale;
        }

        return scaled;
    }

    /**
     * Determine risk level based on confidence
     */
    getRiskLevel(confidence, isPhishing) {
        if (!isPhishing) {
            return 'safe';
        }

        if (confidence >= 0.8) {
            return 'high';
        } else if (confidence >= 0.6) {
            return 'medium';
        } else {
            return 'low';
        }
    }

    /**
     * Get model information
     */
    getModelInfo() {
        if (!this.isLoaded) {
            return null;
        }

        return {
            modelType: this.modelData.model_type,
            numTrees: this.modelData.n_estimators,
            numFeatures: this.modelData.n_features,
            featureNames: this.modelData.feature_names
        };
    }
}

/**
 * Singleton instance for the model
 */
let modelInstance = null;

async function getModel() {
    if (!modelInstance) {
        modelInstance = new RandomForestModel();
        await modelInstance.loadModel('/models/model_lite.json');
    }
    return modelInstance;
}

/**
 * Quick prediction function
 */
async function predictURL(url) {
    const model = await getModel();
    return model.predict(url);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { RandomForestModel, getModel, predictURL };
}
