/**
 * Weighted Phishing Detection Model
 * Combines domain-only and path-only models with adjustable weights
 * Default: 85% domain, 15% path
 */

class WeightedPhishingModel {
    constructor(domainWeight = 0.85, pathWeight = 0.15) {
        this.domainModel = null;
        this.pathModel = null;
        this.featureExtractor = new URLFeatureExtractor();
        this.isLoaded = false;
        this.domainWeight = domainWeight;
        this.pathWeight = pathWeight;
        
        // Normalize weights
        const total = domainWeight + pathWeight;
        this.domainWeight = domainWeight / total;
        this.pathWeight = pathWeight / total;
    }

    /**
     * Load both domain and path models
     */
    async loadModels(domainModelPath = '/models/domain_model_lite.json', 
                     pathModelPath = '/models/path_model_lite.json') {
        try {
            // Load domain model
            const domainResponse = await fetch(chrome.runtime.getURL(domainModelPath));
            this.domainModel = await domainResponse.json();
            
            // Load path model
            const pathResponse = await fetch(chrome.runtime.getURL(pathModelPath));
            this.pathModel = await pathResponse.json();
            
            this.isLoaded = true;
            console.log(`Weighted model loaded: ${this.domainModel.n_estimators} domain trees, ${this.pathModel.n_estimators} path trees`);
            console.log(`Weights: ${(this.domainWeight * 100).toFixed(0)}% domain, ${(this.pathWeight * 100).toFixed(0)}% path`);
            return true;
        } catch (error) {
            console.error('Error loading weighted models:', error);
            return false;
        }
    }

    /**
     * Predict if a URL is phishing using weighted domain+path models
     */
    predict(url) {
        if (!this.isLoaded) {
            throw new Error('Models not loaded! Call loadModels() first.');
        }

        // Check whitelist first
        if (this.featureExtractor.isWhitelisted(url)) {
            return {
                isPhishing: false,
                confidence: 1.0,
                confidencePercent: 100,
                phishingPercent: 0,
                domainPhishingPercent: 0,
                pathPhishingPercent: 0,
                domainVotes: { phishing: 0, legitimate: this.domainModel.n_estimators },
                pathVotes: { phishing: 0, legitimate: this.pathModel.n_estimators },
                features: {},
                explanations: [],
                riskLevel: 'safe',
                whitelisted: true
            };
        }

        // Parse URL
        let parsedUrl;
        try {
            parsedUrl = new URL(url);
        } catch (e) {
            console.error('Invalid URL:', url);
            return {
                isPhishing: false,
                confidence: 0,
                confidencePercent: 0,
                error: 'Invalid URL'
            };
        }

        // Extract component-specific features
        const domain = parsedUrl.hostname;
        const path = parsedUrl.pathname;
        const query = parsedUrl.search.substring(1);
        const protocol = parsedUrl.protocol.replace(':', '');

        const domainFeatures = this.featureExtractor.extractDomainFeatures(domain, protocol);
        const pathFeatures = this.featureExtractor.extractPathFeatures(path, query);

        // Scale features
        const scaledDomainFeatures = this.scaleFeatures(domainFeatures, this.domainModel);
        const scaledPathFeatures = this.scaleFeatures(pathFeatures, this.pathModel);

        // Get predictions from domain model
        const domainResult = this.predictModel(scaledDomainFeatures, this.domainModel, 'domain');
        
        // Get predictions from path model
        const pathResult = this.predictModel(scaledPathFeatures, this.pathModel, 'path');

        // Weighted combination
        const weightedPhishingProb = (
            this.domainWeight * domainResult.phishingProb +
            this.pathWeight * pathResult.phishingProb
        );
        const weightedLegitimateProb = (
            this.domainWeight * domainResult.legitimateProb +
            this.pathWeight * pathResult.legitimateProb
        );

        const isPhishing = weightedPhishingProb > weightedLegitimateProb;
        const confidence = isPhishing ? weightedPhishingProb : weightedLegitimateProb;

        // Combine explanations (prioritize domain, then path)
        const explanations = [];
        if (domainResult.explanations && domainResult.explanations.length > 0) {
            explanations.push(...domainResult.explanations.slice(0, 3)); // Top 3 domain
        }
        if (pathResult.explanations && pathResult.explanations.length > 0 && explanations.length < 4) {
            explanations.push(...pathResult.explanations.slice(0, 4 - explanations.length)); // Fill remaining
        }

        return {
            isPhishing: isPhishing,
            confidence: confidence,
            confidencePercent: Math.round(confidence * 100),
            phishingPercent: Math.round(weightedPhishingProb * 100),
            domainPhishingPercent: Math.round(domainResult.phishingProb * 100),
            pathPhishingPercent: Math.round(pathResult.phishingProb * 100),
            domainVotes: domainResult.votes,
            pathVotes: pathResult.votes,
            domainFeatures: domainFeatures,
            pathFeatures: pathFeatures,
            explanations: explanations,
            riskLevel: this.getRiskLevel(confidence, isPhishing),
            weights: {
                domain: this.domainWeight,
                path: this.pathWeight
            }
        };
    }

    /**
     * Predict using a single model (domain or path)
     */
    predictModel(scaledFeatures, modelData, modelType) {
        const treePredictions = [];
        const featureUsage = {};
        const allFeatureUsage = {};

        for (const tree of modelData.trees) {
            const usedFeatures = new Set();
            const result = this.predictTreeWithTracking(tree, scaledFeatures, usedFeatures);
            treePredictions.push(result.class);
            
            // Track feature usage
            usedFeatures.forEach(featureName => {
                allFeatureUsage[featureName] = (allFeatureUsage[featureName] || 0) + 1;
                if (result.class === 0) { // Phishing vote
                    featureUsage[featureName] = (featureUsage[featureName] || 0) + 1;
                }
            });
        }

        const phishingVotes = treePredictions.filter(p => p === 0).length;
        const legitimateVotes = treePredictions.filter(p => p === 1).length;
        const totalVotes = treePredictions.length;

        const isPhishing = phishingVotes > legitimateVotes;
        const phishingProb = phishingVotes / totalVotes;
        const legitimateProb = legitimateVotes / totalVotes;

        // Get explanations
        const features = modelType === 'domain' 
            ? this.featureExtractor.getDomainFeaturesForExplanations(scaledFeatures, modelData.feature_names)
            : this.featureExtractor.getPathFeaturesForExplanations(scaledFeatures, modelData.feature_names);
        
        const explanations = this.featureExtractor.getFeatureExplanations(
            features, 
            featureUsage, 
            phishingVotes,
            modelType
        );

        return {
            isPhishing: isPhishing,
            phishingProb: phishingProb,
            legitimateProb: legitimateProb,
            votes: { phishing: phishingVotes, legitimate: legitimateVotes },
            explanations: explanations
        };
    }

    /**
     * Predict using a single decision tree with feature tracking
     */
    predictTreeWithTracking(node, features, usedFeatures) {
        if (node.leaf) {
            return {
                class: node.class,
                confidence: node.confidence
            };
        }

        usedFeatures.add(node.feature);
        const featureValue = features[node.feature];

        if (featureValue <= node.threshold) {
            return this.predictTreeWithTracking(node.left, features, usedFeatures);
        } else {
            return this.predictTreeWithTracking(node.right, features, usedFeatures);
        }
    }

    /**
     * Scale features using model's scaler
     */
    scaleFeatures(features, modelData) {
        const scaled = {};

        for (let i = 0; i < modelData.feature_names.length; i++) {
            const featureName = modelData.feature_names[i];
            const value = features[featureName] || 0;
            const mean = modelData.scaler.mean[i];
            const scale = modelData.scaler.scale[i];

            scaled[featureName] = (value - mean) / scale;
        }

        return scaled;
    }

    /**
     * Determine risk level
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
}

