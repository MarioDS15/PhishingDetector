/**
 * Popup Script for Phishing Detection Extension
 * Handles the extension popup UI
 */

// DOM elements
let loadingDiv, resultDiv, statusIcon, statusText, currentUrlText;
let confidenceValue, confidenceFill, featuresList, featuresSection, safeSection;
let recheckBtn, detailsBtn;

/**
 * Initialize popup
 */
document.addEventListener('DOMContentLoaded', async () => {
    // Get DOM elements
    loadingDiv = document.getElementById('loading');
    resultDiv = document.getElementById('result');
    statusIcon = document.getElementById('status-icon');
    statusText = document.getElementById('status-text');
    currentUrlText = document.getElementById('current-url');
    confidenceValue = document.getElementById('confidence-value');
    confidenceFill = document.getElementById('confidence-fill');
    featuresList = document.getElementById('feature-list');
    featuresSection = document.getElementById('features-section');
    safeSection = document.getElementById('safe-section');
    recheckBtn = document.getElementById('recheck-btn');
    detailsBtn = document.getElementById('details-btn');

    // Add event listeners
    recheckBtn.addEventListener('click', recheckCurrentPage);
    detailsBtn.addEventListener('click', showDetails);

    // Analyze current tab
    await analyzeCurrentTab();
});

/**
 * Get current active tab
 */
async function getCurrentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab;
}

/**
 * Analyze current tab
 */
async function analyzeCurrentTab() {
    try {
        showLoading();

        const tab = await getCurrentTab();

        // Check if it's a valid URL
        if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
            showError('Cannot analyze this page (browser internal page)');
            return;
        }

        // Update URL display
        currentUrlText.textContent = tab.url;

        // Request analysis from background script
        chrome.runtime.sendMessage({
            type: 'ANALYZE_URL',
            url: tab.url
        }, (response) => {
            if (response && !response.error) {
                showResult(response);
            } else {
                showError(response?.message || 'Failed to analyze URL');
            }
        });
    } catch (error) {
        console.error('Error analyzing tab:', error);
        showError(error.message);
    }
}

/**
 * Show loading state
 */
function showLoading() {
    loadingDiv.style.display = 'block';
    resultDiv.style.display = 'none';
}

/**
 * Show analysis result
 */
function showResult(data) {
    loadingDiv.style.display = 'none';
    resultDiv.style.display = 'block';

    // Update status
    if (data.isPhishing) {
        statusIcon.className = 'status-icon danger';
        statusText.textContent = '⚠️ Phishing Detected!';
        statusText.className = 'status-text danger';
    } else {
        statusIcon.className = 'status-icon safe';
        statusText.textContent = '✅ Safe Website';
        statusText.className = 'status-text safe';
    }

    // Update confidence
    confidenceValue.textContent = `${data.confidencePercent}%`;
    confidenceFill.style.width = `${data.confidencePercent}%`;

    // Set confidence bar color
    if (data.confidencePercent >= 80) {
        confidenceFill.className = 'confidence-fill high';
    } else if (data.confidencePercent >= 60) {
        confidenceFill.className = 'confidence-fill medium';
    } else {
        confidenceFill.className = 'confidence-fill low';
    }

    // Show features/explanations
    if (data.isPhishing) {
        // Phishing detected
        if (data.explanations && data.explanations.length > 0) {
            // Show explanations if available
            featuresSection.style.display = 'block';
            featuresList.innerHTML = '';
            data.explanations.forEach(explanation => {
                const li = document.createElement('li');
                li.textContent = explanation;
                featuresList.appendChild(li);
            });
        } else {
            // No specific explanations, but still phishing
            featuresSection.style.display = 'block';
            featuresList.innerHTML = '<li>Detected by machine learning model</li>';
        }
        safeSection.style.display = 'none';
    } else {
        // Legitimate URL
        featuresSection.style.display = 'none';
        safeSection.style.display = 'block';
    }

    // Store data for details view
    window.currentAnalysis = data;
}

/**
 * Show error message
 */
function showError(message) {
    loadingDiv.style.display = 'none';
    resultDiv.style.display = 'block';

    statusIcon.className = 'status-icon warning';
    statusText.textContent = 'Error';
    statusText.className = 'status-text warning';

    currentUrlText.textContent = message;
    confidenceValue.textContent = 'N/A';
    confidenceFill.style.width = '0%';

    featuresSection.style.display = 'none';
    safeSection.style.display = 'none';
}

/**
 * Recheck current page
 */
async function recheckCurrentPage() {
    // Clear cache first
    chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' }, () => {
        analyzeCurrentTab();
    });
}

/**
 * Show detailed analysis
 */
function showDetails() {
    if (!window.currentAnalysis) {
        return;
    }

    const data = window.currentAnalysis;

    // Create details popup
    const detailsHtml = `
        <div style="padding: 20px; font-family: monospace; font-size: 12px;">
            <h3>Detailed Analysis</h3>

            <div style="margin: 15px 0;">
                <strong>Prediction:</strong> ${data.isPhishing ? 'PHISHING' : 'LEGITIMATE'}<br>
                <strong>Confidence:</strong> ${data.confidencePercent}%<br>
                <strong>Risk Level:</strong> ${data.riskLevel.toUpperCase()}<br>
                <strong>Voting:</strong> ${data.phishingVotes} phishing / ${data.legitimateVotes} legitimate (${data.totalVotes} trees)
            </div>

            <div style="margin: 15px 0;">
                <strong>Feature Values:</strong>
                <div style="max-height: 200px; overflow-y: auto; margin-top: 10px;">
                    ${Object.entries(data.features)
                        .map(([key, value]) => `<div>${key}: ${typeof value === 'number' ? value.toFixed(4) : value}</div>`)
                        .join('')}
                </div>
            </div>

            ${data.explanations && data.explanations.length > 0 ? `
                <div style="margin: 15px 0;">
                    <strong>Detection Reasons:</strong>
                    <ul style="margin-top: 10px;">
                        ${data.explanations.map(exp => `<li>${exp}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
    `;

    // Open in new window
    const detailsWindow = window.open('', 'Analysis Details', 'width=600,height=800');
    detailsWindow.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Phishing Detection - Detailed Analysis</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    padding: 20px;
                    background: #f8f9fa;
                }
                h3 {
                    color: #667eea;
                    margin-bottom: 20px;
                }
                strong {
                    color: #495057;
                }
                div {
                    line-height: 1.6;
                }
            </style>
        </head>
        <body>
            ${detailsHtml}
        </body>
        </html>
    `);
    detailsWindow.document.close();
}

console.log('Phishing Detection Extension: Popup script loaded');
