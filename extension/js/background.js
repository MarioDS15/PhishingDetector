/**
 * Background Service Worker for Phishing Detection
 * Monitors URL changes and triggers phishing detection
 */

// Import scripts (Manifest V3 style)
importScripts('url-features.js', 'ml-model.js');

// Model instance
let model = null;

// Cache for predictions to avoid redundant checks
const predictionCache = new Map();
const CACHE_EXPIRY = 1000 * 60 * 10; // 10 minutes

/**
 * Initialize the model when extension loads
 */
async function initializeModel() {
    try {
        console.log('Initializing phishing detection model...');
        model = new RandomForestModel();
        await model.loadModel('/models/model_lite.json');
        console.log('Model loaded successfully!');
        return true;
    } catch (error) {
        console.error('Failed to load model:', error);
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
 * Analyze URL for phishing
 */
async function analyzeURL(url, tabId) {
    try {
        // Check cache first
        const cached = getCachedPrediction(url);
        if (cached) {
            console.log('Using cached prediction for:', url);
            return cached;
        }

        // Ensure model is loaded
        if (!model || !model.isLoaded) {
            await initializeModel();
        }

        // Predict
        console.log('Analyzing URL:', url);
        const result = model.predict(url);

        // Cache the result
        cachePrediction(url, result);

        console.log('Analysis result:', result);

        // If phishing detected, notify content script
        if (result.isPhishing && result.confidence >= 0.85) {
            try {
                await chrome.tabs.sendMessage(tabId, {
                    type: 'PHISHING_DETECTED',
                    data: result
                });
            } catch (error) {
                console.log('Could not send message to tab:', error.message);
            }
        }

        return result;
    } catch (error) {
        console.error('Error analyzing URL:', error);
        return {
            error: true,
            message: error.message
        };
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

    if (request.type === 'GET_CURRENT_ANALYSIS') {
        // Return cached result if available
        const cached = getCachedPrediction(request.url);
        sendResponse(cached || { error: true, message: 'No analysis available' });
        return false;
    }

    if (request.type === 'CLEAR_CACHE') {
        predictionCache.clear();
        sendResponse({ success: true });
        return false;
    }

    if (request.type === 'GET_MODEL_INFO') {
        if (model && model.isLoaded) {
            sendResponse(model.getModelInfo());
        } else {
            sendResponse({ error: true, message: 'Model not loaded' });
        }
        return false;
    }
});

/**
 * Initialize on extension install/update
 */
chrome.runtime.onInstalled.addListener(async (details) => {
    console.log('Extension installed/updated:', details.reason);
    await initializeModel();

    // Set default settings
    await chrome.storage.sync.set({
        autoDetection: true,
        showWarnings: true,
        confidenceThreshold: 0.85
    });
});

/**
 * Initialize on startup
 */
chrome.runtime.onStartup.addListener(() => {
    console.log('Browser started, initializing model...');
    initializeModel();
});

// Initialize model immediately
initializeModel();

console.log('Phishing Detection Extension: Background script loaded');
