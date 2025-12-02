/**
 * Page Feature Extraction for Phishing Detection
 * Extracts 28 DOM/webpage features for the page-based ML model
 */

class PageFeatureExtractor {
    constructor() {
        this.features = {};
    }

    /**
     * Extract all 28 page features from the current document
     * @returns {Object} Feature object with 28 numeric values
     */
    extractAll() {
        try {
            const html = document.documentElement.outerHTML;
            const soup = document; // Use document as our BeautifulSoup equivalent
            const url = window.location.href;
            const domain = window.location.hostname;
            const title = this.getTitle();

            this.features = {
                // Content features
                'LineOfCode': this.getLineOfCode(html),
                'LargestLineLength': this.getLargestLineLength(html),
                'HasTitle': this.hasTitle(),

                // Title matching features
                'DomainTitleMatchScore': this.domainTitleMatchScore(url, title),
                'URLTitleMatchScore': this.urlTitleMatchScore(url, title),

                // Trust signals
                'HasFavicon': this.hasFavicon(),
                'Robots': this.hasRobotsTxt(),
                'IsResponsive': this.isResponsive(),

                // Redirect features
                'NoOfURLRedirect': 0, // Cannot determine in browser (would need backend)
                'NoOfSelfRedirect': 0, // Cannot determine in browser (would need backend)

                // Description
                'HasDescription': this.hasDescription(),

                // Structure features
                'NoOfPopup': this.countPopups(html),
                'NoOfiFrame': this.countIframes(),

                // Form features
                'HasExternalFormSubmit': this.hasExternalFormSubmit(domain),
                'HasSocialNet': this.hasSocialLinks(),
                'HasSubmitButton': this.hasSubmitButton(),
                'HasHiddenFields': this.hasHiddenFields(),
                'HasPasswordField': this.hasPasswordField(),

                // Keyword features
                'Bank': this.hasKeyword(['bank', 'online banking', 'account', 'login']),
                'Pay': this.hasKeyword(['pay', 'payment', 'checkout', 'billing']),
                'Crypto': this.hasKeyword(['bitcoin', 'crypto', 'ethereum', 'wallet', 'btc', 'eth']),

                // Other trust signals
                'HasCopyrightInfo': this.hasCopyright(),

                // Resource counts
                'NoOfImage': this.countImages(),
                'NoOfCSS': this.countCSS(),
                'NoOfJS': this.countJS(),

                // Link analysis
                'NoOfSelfRef': this.countLinkTypes(domain).self,
                'NoOfEmptyRef': this.countLinkTypes(domain).empty,
                'NoOfExternalRef': this.countLinkTypes(domain).external
            };

            return this.features;
        } catch (error) {
            console.error('Error extracting page features:', error);
            return this.getDefaultFeatures();
        }
    }

    /**
     * Get default features (all zeros) in case of error
     */
    getDefaultFeatures() {
        return {
            'LineOfCode': 0, 'LargestLineLength': 0, 'HasTitle': 0,
            'DomainTitleMatchScore': 0, 'URLTitleMatchScore': 0,
            'HasFavicon': 0, 'Robots': 0, 'IsResponsive': 0,
            'NoOfURLRedirect': 0, 'NoOfSelfRedirect': 0,
            'HasDescription': 0, 'NoOfPopup': 0, 'NoOfiFrame': 0,
            'HasExternalFormSubmit': 0, 'HasSocialNet': 0,
            'HasSubmitButton': 0, 'HasHiddenFields': 0, 'HasPasswordField': 0,
            'Bank': 0, 'Pay': 0, 'Crypto': 0,
            'HasCopyrightInfo': 0, 'NoOfImage': 0, 'NoOfCSS': 0, 'NoOfJS': 0,
            'NoOfSelfRef': 0, 'NoOfEmptyRef': 0, 'NoOfExternalRef': 0
        };
    }

    // ========================================
    // FEATURE EXTRACTION METHODS
    // ========================================

    getLineOfCode(html) {
        return html ? html.split('\n').length : 0;
    }

    getLargestLineLength(html) {
        if (!html) return 0;
        const lines = html.split('\n');
        return Math.max(...lines.map(line => line.length));
    }

    hasTitle() {
        return document.title && document.title.trim().length > 0 ? 1 : 0;
    }

    getTitle() {
        return document.title ? document.title.trim() : '';
    }

    domainTitleMatchScore(url, title) {
        if (!title) return 0;

        try {
            // Extract domain name (without TLD)
            const hostname = new URL(url).hostname;
            const parts = hostname.split('.');
            // Get the main domain (second-to-last part for most domains)
            const domain = parts.length > 1 ? parts[parts.length - 2] : parts[0];

            const titleLower = title.toLowerCase();
            const domainLower = domain.toLowerCase();

            if (titleLower.includes(domainLower)) {
                return 1;
            } else if (domainLower.length >= 3 && titleLower.includes(domainLower.substring(0, 3))) {
                return 0.5;
            }
            return 0;
        } catch {
            return 0;
        }
    }

    urlTitleMatchScore(url, title) {
        if (!title) return 0;

        try {
            const path = new URL(url).pathname.toLowerCase();
            const words = title.toLowerCase().split(/\s+/).filter(w => w.length > 0);

            if (words.length === 0) return 0;

            const matches = words.filter(word => path.includes(word)).length;
            return matches / words.length;
        } catch {
            return 0;
        }
    }

    hasFavicon() {
        const links = document.querySelectorAll('link[rel*="icon"]');
        return links.length > 0 ? 1 : 0;
    }

    hasRobotsTxt() {
        // Cannot synchronously check robots.txt in browser
        // Would require async fetch which complicates feature extraction
        // Return 0 as default (can be enhanced later)
        return 0;
    }

    isResponsive() {
        const viewport = document.querySelector('meta[name="viewport"]');
        return viewport ? 1 : 0;
    }

    hasDescription() {
        const metaDesc = document.querySelector('meta[name="description"]');
        const ogDesc = document.querySelector('meta[property="og:description"]');

        if (metaDesc && metaDesc.content && metaDesc.content.trim().length > 0) return 1;
        if (ogDesc && ogDesc.content && ogDesc.content.trim().length > 0) return 1;

        return 0;
    }

    countPopups(html) {
        if (!html) return 0;
        const popupPatterns = ['alert(', 'prompt(', 'confirm('];
        let count = 0;
        for (const pattern of popupPatterns) {
            const matches = html.match(new RegExp(pattern.replace('(', '\\('), 'g'));
            count += matches ? matches.length : 0;
        }
        return count;
    }

    countIframes() {
        return document.querySelectorAll('iframe').length;
    }

    hasExternalFormSubmit(domain) {
        const forms = document.querySelectorAll('form');
        for (const form of forms) {
            const action = form.getAttribute('action');
            if (action && action.startsWith('http')) {
                try {
                    const actionDomain = new URL(action).hostname;
                    if (actionDomain && actionDomain !== domain) {
                        return 1;
                    }
                } catch {
                    // Invalid URL, skip
                }
            }
        }
        return 0;
    }

    hasSocialLinks() {
        const socialDomains = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'youtube.com'];
        const links = document.querySelectorAll('a[href]');

        for (const link of links) {
            const href = link.getAttribute('href') || '';
            for (const social of socialDomains) {
                if (href.includes(social)) {
                    return 1;
                }
            }
        }
        return 0;
    }

    hasSubmitButton() {
        const submitInputs = document.querySelectorAll('input[type="submit"]');
        const buttons = document.querySelectorAll('button');
        return (submitInputs.length > 0 || buttons.length > 0) ? 1 : 0;
    }

    hasHiddenFields() {
        const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
        return hiddenInputs.length > 0 ? 1 : 0;
    }

    hasPasswordField() {
        const passwordInputs = document.querySelectorAll('input[type="password"]');
        return passwordInputs.length > 0 ? 1 : 0;
    }

    hasKeyword(keywords) {
        const title = this.getTitle().toLowerCase();
        const description = this.getDescriptionText().toLowerCase();
        const bodyText = document.body ? (document.body.innerText || document.body.textContent || '').toLowerCase() : '';

        for (const keyword of keywords) {
            if (title.includes(keyword) || description.includes(keyword) || bodyText.includes(keyword)) {
                return 1;
            }
        }
        return 0;
    }

    getDescriptionText() {
        const metaDesc = document.querySelector('meta[name="description"]');
        const ogDesc = document.querySelector('meta[property="og:description"]');

        if (metaDesc && metaDesc.content) return metaDesc.content;
        if (ogDesc && ogDesc.content) return ogDesc.content;

        return '';
    }

    hasCopyright() {
        const bodyText = document.body ? (document.body.innerText || document.body.textContent || '').toLowerCase() : '';
        const html = document.documentElement.outerHTML.toLowerCase();
        const keywords = ['©', 'copyright', 'all rights reserved'];

        for (const keyword of keywords) {
            if (bodyText.includes(keyword) || html.includes(keyword)) {
                return 1;
            }
        }
        return 0;
    }

    countImages() {
        return document.querySelectorAll('img').length;
    }

    countCSS() {
        const links = document.querySelectorAll('link');
        let count = 0;

        for (const link of links) {
            const rel = link.getAttribute('rel') || '';
            const type = link.getAttribute('type') || '';
            if (rel.toLowerCase().includes('stylesheet') || type.toLowerCase().includes('text/css')) {
                count++;
            }
        }
        return count;
    }

    countJS() {
        const scripts = document.querySelectorAll('script[src]');
        return scripts.length;
    }

    countLinkTypes(domain) {
        const links = document.querySelectorAll('a');
        let selfRef = 0, emptyRef = 0, externalRef = 0;

        for (const link of links) {
            const href = link.getAttribute('href') || '';

            // Empty or hash links
            if (!href || href === '#' || href.toLowerCase().startsWith('javascript:')) {
                emptyRef++;
                continue;
            }

            try {
                // Try to parse as URL
                if (href.startsWith('http')) {
                    const linkDomain = new URL(href).hostname;
                    if (linkDomain === domain || linkDomain === '') {
                        selfRef++;
                    } else {
                        externalRef++;
                    }
                } else {
                    // Relative URL = self reference
                    selfRef++;
                }
            } catch {
                // If URL parsing fails, treat as self reference
                selfRef++;
            }
        }

        return { self: selfRef, empty: emptyRef, external: externalRef };
    }

    /**
     * Get features as an array in the correct order for the model
     * @returns {Array} Array of 28 numeric values
     */
    getFeaturesArray() {
        const featureNames = [
            'LineOfCode', 'LargestLineLength', 'HasTitle',
            'DomainTitleMatchScore', 'URLTitleMatchScore',
            'HasFavicon', 'Robots', 'IsResponsive',
            'NoOfURLRedirect', 'NoOfSelfRedirect',
            'HasDescription', 'NoOfPopup', 'NoOfiFrame',
            'HasExternalFormSubmit', 'HasSocialNet',
            'HasSubmitButton', 'HasHiddenFields', 'HasPasswordField',
            'Bank', 'Pay', 'Crypto',
            'HasCopyrightInfo', 'NoOfImage', 'NoOfCSS', 'NoOfJS',
            'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfExternalRef'
        ];

        return featureNames.map(name => this.features[name] || 0);
    }

    /**
     * Print features for debugging
     */
    printFeatures() {
        console.log('=== Page Features ===');
        for (const [key, value] of Object.entries(this.features)) {
            console.log(`${key}: ${value}`);
        }
        console.log('===================');
    }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PageFeatureExtractor;
}
