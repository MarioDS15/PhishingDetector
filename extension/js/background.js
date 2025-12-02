/**
 * Background Service Worker for Phishing Detection
 * Monitors URL changes and triggers phishing detection
 */

// Import scripts (Manifest V3 style)
importScripts('url-features.js', 'ml-model.js', 'page-features.js', 'page-model.js');

// Model instances
let urlModel = null;
let pageModel = null;

// Cache for predictions to avoid redundant checks
const predictionCache = new Map();
const CACHE_EXPIRY = 1000 * 60 * 10; // 10 minutes

// Store predictions for each tab (URL + Page)
const tabPredictions = new Map();

// Combination weights and threshold
const URL_WEIGHT = 0.8;  // 80% weight for URL prediction
const PAGE_WEIGHT = 0.2;  // 20% weight for Page prediction
const WARNING_THRESHOLD = 0.7;  // 70% combined confidence triggers warning

/**
 * Initialize both URL and Page models when extension loads
 */
async function initializeModels() {
    try {
        console.log('Initializing phishing detection models...');

        // Load URL model
        urlModel = new RandomForestModel();
        await urlModel.loadModel('/models/model_lite.json');
        console.log('✓ URL model loaded successfully!');

        // Load Page model
        pageModel = new PagePhishingModel();
        await pageModel.loadModel('/models/page_model_lite.json');
        console.log('✓ Page model loaded successfully!');

        console.log('All models initialized!');
        return true;
    } catch (error) {
        console.error('Failed to load models:', error);
        return false;
    }
}

/**
 * Check if URL is in cache and still valid
 */
function getCachedPrediction(url) {
    const cached = predictionCache.get(url);
    if (cached && Date.now() - cached.timestamp < CACHE_EXPIRY) {
        return cached.result;
    }
    return null;
}

/**
 * Store prediction in cache
 */
function cachePrediction(url, result) {
    predictionCache.set(url, {
        result: result,
        timestamp: Date.now()
    });

    // Limit cache size to 100 entries
    if (predictionCache.size > 100) {
        const firstKey = predictionCache.keys().next().value;
        predictionCache.delete(firstKey);
    }
}

/**
 * Check if URL should be skipped (whitelisted for testing)
 */
function shouldSkipURL(url) {
    if (!url) return true;

    // Skip file:// URLs for testing
    if (url.startsWith('file://')) {
        return true;
    }

    return false;
}

/**
 * Analyze URL for phishing (URL-based detection only)
 */
async function analyzeURL(url, tabId) {
    try {
        // Skip whitelisted URLs
        if (shouldSkipURL(url)) {
            console.log('Skipping whitelisted URL:', url);
            return {
                isPhishing: false,
                confidence: 0,
                confidencePercent: 0,
                detectionType: 'skipped',
                message: 'Localhost/file URLs are whitelisted for testing'
            };
        }

        // Check cache first
        const cached = getCachedPrediction(url);
        if (cached) {
            console.log('Using cached URL prediction for:', url);
            return cached;
        }

        // Ensure models are loaded
        if (!urlModel || !urlModel.isLoaded) {
            await initializeModels();
        }

        // Predict using URL model
        console.log('Analyzing URL:', url);
        const result = urlModel.predict(url);
        result.detectionType = 'url';

        // Cache the URL prediction
        cachePrediction(url, result);

        console.log('URL analysis result:', result);

        // Store URL prediction for this tab
        if (tabId) {
            if (!tabPredictions.has(tabId)) {
                tabPredictions.set(tabId, {});
            }
            tabPredictions.get(tabId).url = result;
            tabPredictions.get(tabId).tabUrl = url;
        }

        return result;
    } catch (error) {
        console.error('Error analyzing URL:', error);
        return {
            error: true,
            message: error.message,
            detectionType: 'url'
        };
    }
}

/**
 * Combine URL and Page predictions
 */
function combinePredictions(urlResult, pageResult) {
    // If URL was skipped (localhost/file), use page result only
    if (urlResult.detectionType === 'skipped') {
        console.log('URL was skipped, using page prediction only');
        return { ...pageResult, detectionType: 'page_only' };
    }

    // If either prediction has an error, use the other one
    if (urlResult.error && pageResult.error) {
        return { error: true, message: 'Both predictions failed' };
    }
    if (urlResult.error) {
        return { ...pageResult, detectionType: 'page_only' };
    }
    if (pageResult.error) {
        return { ...urlResult, detectionType: 'url_only' };
    }

    // Calculate weighted combined confidence
    // For phishing: use the phishing probability from each model
    const urlPhishingProb = urlResult.isPhishing ? urlResult.confidence : (1 - urlResult.confidence);
    const pagePhishingProb = pageResult.isPhishing ? pageResult.confidence : (1 - pageResult.confidence);

    const combinedPhishingProb = (URL_WEIGHT * urlPhishingProb) + (PAGE_WEIGHT * pagePhishingProb);
    const isPhishing = combinedPhishingProb >= 0.5;
    const confidence = isPhishing ? combinedPhishingProb : (1 - combinedPhishingProb);

    // Combine explanations from both models
    const explanations = [
        ...(urlResult.explanations || []),
        ...(pageResult.explanations || [])
    ];

    // Get top features from page model
    const topFeatures = pageResult.topFeatures || [];

    // Calculate phishing confidence percentages for display
    const urlPhishingPercent = Math.round(urlPhishingProb * 100);
    const pagePhishingPercent = Math.round(pagePhishingProb * 100);

    return {
        isPhishing: isPhishing,
        confidence: confidence,
        confidencePercent: Math.round(confidence * 100),
        combinedPhishingProb: combinedPhishingProb,
        urlPrediction: {
            isPhishing: urlResult.isPhishing,
            confidence: urlResult.confidence,
            confidencePercent: urlResult.confidencePercent,
            phishingPercent: urlPhishingPercent  // Phishing probability for display
        },
        pagePrediction: {
            isPhishing: pageResult.isPhishing,
            confidence: pageResult.confidence,
            confidencePercent: pageResult.confidencePercent,
            phishingPercent: pagePhishingPercent  // Phishing probability for display
        },
        explanations: explanations,
        topFeatures: topFeatures,
        detectionType: 'combined',
        weights: {
            url: URL_WEIGHT,
            page: PAGE_WEIGHT
        }
    };
}

/**
 * Run page prediction using the page model
 */
function runPagePrediction(tabId, features) {
    try {
        const startTime = performance.now();

        // Run prediction
        const result = pageModel.predict(features);
        result.detectionType = 'page';

        const predictionTime = performance.now() - startTime;
        console.log(`Page prediction completed in ${predictionTime.toFixed(2)}ms`);
        console.log('Page prediction result:', result);

        // Store page prediction
        if (!tabPredictions.has(tabId)) {
            tabPredictions.set(tabId, {});
        }
        tabPredictions.get(tabId).page = result;

        // Check and combine predictions
        checkAndNotifyPhishing(tabId);
    } catch (error) {
        console.error('Error running page prediction:', error);
    }
}

/**
 * Check if we should trigger a warning based on combined prediction
 */
async function checkAndNotifyPhishing(tabId) {
    const predictions = tabPredictions.get(tabId);
    if (!predictions) {
        return;
    }

    const { url: urlResult, page: pageResult } = predictions;

    // Need both predictions to combine
    if (!urlResult || !pageResult) {
        // If we only have URL prediction and it's high confidence, notify
        if (urlResult && urlResult.isPhishing && urlResult.confidence >= WARNING_THRESHOLD) {
            try {
                await chrome.tabs.sendMessage(tabId, {
                    type: 'PHISHING_DETECTED',
                    data: { ...urlResult, detectionType: 'url_only' }
                });
            } catch (error) {
                console.log('Could not send message to tab:', error.message);
            }
        }
        return;
    }

    // Combine predictions
    const combinedResult = combinePredictions(urlResult, pageResult);
    console.log('Combined prediction:', combinedResult);

    // Always send combined result to update badge
    try {
        await chrome.tabs.sendMessage(tabId, {
            type: 'COMBINED_RESULT',
            data: combinedResult
        });
    } catch (error) {
        console.log('Could not send combined result to tab:', error.message);
    }

    // Notify if phishing detected with sufficient confidence
    if (combinedResult.isPhishing && combinedResult.confidence >= WARNING_THRESHOLD) {
        try {
            await chrome.tabs.sendMessage(tabId, {
                type: 'PHISHING_DETECTED',
                data: combinedResult
            });
        } catch (error) {
            console.log('Could not send phishing warning to tab:', error.message);
        }
    }

    // Store combined result in cache
    if (predictions.tabUrl) {
        cachePrediction(predictions.tabUrl, combinedResult);
    }
}

/**
 * Listen for tab updates (navigation)
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only check when page finishes loading and has a URL
    if (changeInfo.status === 'loading' && tab.url && !tab.url.startsWith('chrome://')) {
        analyzeURL(tab.url, tabId);
    }
});

/**
 * Listen for tab activation (switching tabs)
 */
chrome.tabs.onActivated.addListener(async (activeInfo) => {
    try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        if (tab.url && !tab.url.startsWith('chrome://')) {
            analyzeURL(tab.url, activeInfo.tabId);
        }
    } catch (error) {
        console.error('Error handling tab activation:', error);
    }
});

/**
 * Listen for messages from popup and content scripts
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'ANALYZE_URL') {
        // Analyze the requested URL
        analyzeURL(request.url, sender.tab?.id || null)
            .then(result => sendResponse(result))
            .catch(error => sendResponse({ error: true, message: error.message }));
        return true; // Keep channel open for async response
    }

    if (request.type === 'PAGE_FEATURES') {
        // Receive page features from content script and run prediction
        const tabId = sender.tab?.id;
        if (tabId) {
            console.log('Received page features from tab:', tabId);

            // Ensure page model is loaded
            if (!pageModel || !pageModel.isLoaded) {
                initializeModels().then(() => {
                    runPagePrediction(tabId, request.features);
                });
            } else {
                runPagePrediction(tabId, request.features);
            }

            sendResponse({ success: true });
        } else {
            sendResponse({ error: true, message: 'No tab ID' });
        }
        return false;
    }

    if (request.type === 'PAGE_PREDICTION') {
        // Receive page prediction from content script
        const tabId = sender.tab?.id;
        if (tabId) {
            console.log('Received page prediction from tab:', tabId);

            // Store page prediction
            if (!tabPredictions.has(tabId)) {
                tabPredictions.set(tabId, {});
            }
            tabPredictions.get(tabId).page = request.data;

            // Check and combine predictions
            checkAndNotifyPhishing(tabId);

            sendResponse({ success: true });
        } else {
            sendResponse({ error: true, message: 'No tab ID' });
        }
        return false;
    }

    if (request.type === 'GET_CURRENT_ANALYSIS') {
        const tabId = sender.tab?.id;
        if (tabId && tabPredictions.has(tabId)) {
            const predictions = tabPredictions.get(tabId);
            if (predictions.url && predictions.page) {
                // Return combined prediction
                const combined = combinePredictions(predictions.url, predictions.page);
                sendResponse(combined);
            } else if (predictions.url) {
                sendResponse(predictions.url);
            } else {
                sendResponse({ error: true, message: 'No analysis available' });
            }
        } else {
            // Try cache
            const cached = getCachedPrediction(request.url);
            sendResponse(cached || { error: true, message: 'No analysis available' });
        }
        return false;
    }

    if (request.type === 'CLEAR_CACHE') {
        predictionCache.clear();
        tabPredictions.clear();
        sendResponse({ success: true });
        return false;
    }

    if (request.type === 'GET_MODEL_INFO') {
        const info = {
            urlModel: urlModel && urlModel.isLoaded ? urlModel.getModelInfo() : null,
            pageModel: pageModel && pageModel.isLoaded ? pageModel.getModelInfo() : null,
            weights: { url: URL_WEIGHT, page: PAGE_WEIGHT },
            threshold: WARNING_THRESHOLD
        };
        sendResponse(info);
        return false;
    }
});

/**
 * Initialize on extension install/update
 */
chrome.runtime.onInstalled.addListener(async (details) => {
    console.log('Extension installed/updated:', details.reason);
    await initializeModels();

    // Set default settings
    await chrome.storage.sync.set({
        autoDetection: true,
        showWarnings: true,
        confidenceThreshold: WARNING_THRESHOLD
    });
});

/**
 * Initialize on startup
 */
chrome.runtime.onStartup.addListener(() => {
    console.log('Browser started, initializing models...');
    initializeModels();
});

// Initialize models immediately
initializeModels();

console.log('Phishing Detection Extension: Background script loaded');
