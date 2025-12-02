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
        alert('No analysis data available');
        return;
    }

    const data = window.currentAnalysis;

    // Build detection type info
    let detectionInfo = '';
    if (data.detectionType === 'combined') {
        detectionInfo = `
            <div style="background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 15px 0;">
                <strong>🔗 Combined Detection (80% URL + 20% Page)</strong><br>
                <div style="margin-top: 10px;">
                    <strong>URL Analysis:</strong> ${data.urlPrediction.isPhishing ? 'Phishing' : 'Legitimate'} (${data.urlPrediction.confidencePercent}%)<br>
                    <strong>Page Analysis:</strong> ${data.pagePrediction.isPhishing ? 'Phishing' : 'Legitimate'} (${data.pagePrediction.confidencePercent}%)<br>
                    <strong>Combined Result:</strong> ${data.isPhishing ? 'Phishing' : 'Legitimate'} (${data.confidencePercent}%)
                </div>
            </div>
        `;
    } else if (data.detectionType === 'page_only') {
        detectionInfo = `
            <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 15px 0;">
                <strong>📄 Page Analysis Only</strong><br>
                <div style="margin-top: 10px;">
                    URL analysis was skipped (localhost/file URL)
                </div>
            </div>
        `;
    } else if (data.detectionType === 'url_only') {
        detectionInfo = `
            <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 15px 0;">
                <strong>🔗 URL Analysis Only</strong><br>
                <div style="margin-top: 10px;">
                    Page analysis not available
                </div>
            </div>
        `;
    }

    // Create details popup
    const detailsHtml = `
        <div style="padding: 20px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
            <h2 style="color: #667eea; margin-bottom: 20px;">🛡️ Detailed Analysis</h2>

            ${detectionInfo}

            <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
                <strong>Overall Result</strong><br>
                <div style="margin-top: 10px;">
                    <strong>Prediction:</strong> <span style="color: ${data.isPhishing ? '#dc3545' : '#28a745'}; font-weight: bold;">${data.isPhishing ? '⚠️ PHISHING' : '✅ LEGITIMATE'}</span><br>
                    <strong>Confidence:</strong> ${data.confidencePercent}%<br>
                    ${data.riskLevel ? `<strong>Risk Level:</strong> ${data.riskLevel.toUpperCase()}<br>` : ''}
                    ${data.totalVotes ? `<strong>Model Votes:</strong> ${data.phishingVotes || 0} phishing / ${data.legitimateVotes || 0} legitimate (${data.totalVotes} trees)` : ''}
                </div>
            </div>

            ${data.explanations && data.explanations.length > 0 ? `
                <div style="margin: 15px 0;">
                    <strong>🔍 Detection Reasons:</strong>
                    <ul style="margin-top: 10px; line-height: 1.8;">
                        ${data.explanations.map(exp => `<li>${exp}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}

            ${data.features && Object.keys(data.features).length > 0 ? `
                <div style="margin: 15px 0;">
                    <details>
                        <summary style="cursor: pointer; font-weight: bold; margin-bottom: 10px;">📊 Feature Values (${Object.keys(data.features).length} features)</summary>
                        <div style="max-height: 300px; overflow-y: auto; margin-top: 10px; font-family: monospace; font-size: 12px; background: white; padding: 10px; border-radius: 5px;">
                            ${Object.entries(data.features)
                                .map(([key, value]) => `<div style="padding: 3px 0;">${key}: ${typeof value === 'number' ? value.toFixed(4) : value}</div>`)
                                .join('')}
                        </div>
                    </details>
                </div>
            ` : ''}

            ${data.topFeatures && data.topFeatures.length > 0 ? `
                <div style="margin: 15px 0;">
                    <strong>🎯 Top Contributing Features:</strong>
                    <ul style="margin-top: 10px; line-height: 1.8;">
                        ${data.topFeatures.slice(0, 5).map(f =>
                            `<li>${f.name}: ${f.value} (z-score: ${f.zScore.toFixed(2)})</li>`
                        ).join('')}
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
