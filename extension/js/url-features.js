/**
 * URL Feature Extraction for Phishing Detection
 * Port of Python URLFeatureExtractor to JavaScript
 */

class URLFeatureExtractor {
    constructor() {
        // Whitelist of known legitimate domains
        this.whitelistedDomains = [
            'google.com', 'youtube.com', 'gmail.com', 'maps.google.com',
            'facebook.com', 'instagram.com', 'whatsapp.com', 'messenger.com',
            'amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de',
            'apple.com', 'icloud.com', 'microsoft.com', 'live.com',
            'outlook.com', 'office.com', 'linkedin.com', 'twitter.com',
            'x.com', 'reddit.com', 'wikipedia.org', 'github.com',
            'stackoverflow.com', 'paypal.com', 'ebay.com', 'netflix.com',
            'spotify.com', 'dropbox.com', 'zoom.us', 'slack.com',
            'adobe.com', 'salesforce.com', 'yahoo.com', 'bing.com',
            'cloudflare.com', 'wordpress.com', 'tumblr.com'
        ];

        // Suspicious keywords and patterns
        this.suspiciousKeywords = [
            'login', 'verify', 'secure', 'account', 'update', 'confirm',
            'validate', 'authenticate', 'bank', 'support',
            'password', 'signin', 'signup', 'register'
        ];

        // Brand keywords for impersonation detection
        this.brandKeywords = [
            'google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal',
            'ebay', 'netflix', 'twitter', 'instagram', 'linkedin', 'bank',
            'chase', 'wellsfargo', 'citibank', 'boa', 'outlook',
            'office365', 'icloud', 'gmail'
        ];

        this.suspiciousTLDs = [
            'tk', 'ml', 'ga', 'cf', 'click', 'download', 'stream',
            'gq', 'top', 'zip', 'review'
        ];

        this.urlShorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'short.link', 'buff.ly'
        ];

        this.suspiciousExtensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs'
        ];

        // Homograph detection threshold
        this.HOMOGRAPH_THRESHOLD = 0.6;
    }

    /**
     * Check if domain is whitelisted
     */
    isWhitelisted(url) {
        try {
            const parsedUrl = new URL(url);
            const hostname = parsedUrl.hostname.toLowerCase();

            // Check exact match or if hostname ends with whitelisted domain
            return this.whitelistedDomains.some(domain => {
                return hostname === domain || hostname.endsWith('.' + domain);
            });
        } catch (e) {
            return false;
        }
    }

    /**
     * Extract all features from a URL
     */
    extractAllFeatures(url) {
        const features = {};

        // Parse URL
        let parsedUrl;
        try {
            parsedUrl = new URL(url);
        } catch (e) {
            console.error('Invalid URL:', url);
            return this.getDefaultFeatures();
        }

        // Basic URL features
        features['url_length'] = url.length;
        features['num_dots'] = (url.match(/\./g) || []).length;
        features['num_hyphens'] = (url.match(/-/g) || []).length;
        features['num_underscores'] = (url.match(/_/g) || []).length;
        features['num_slashes'] = (url.match(/\//g) || []).length;
        features['num_question_marks'] = (url.match(/\?/g) || []).length;
        features['num_equals'] = (url.match(/=/g) || []).length;
        features['num_ampersands'] = (url.match(/&/g) || []).length;
        features['num_percentages'] = (url.match(/%/g) || []).length;

        // Domain analysis
        const domain = parsedUrl.hostname;
        const path = parsedUrl.pathname;
        const query = parsedUrl.search.substring(1);

        features['domain_length'] = domain.length;
        features['path_length'] = path.length;
        features['query_length'] = query.length;

        // Enhanced TLD analysis
        const tldInfo = this.extractEnhancedTLD(domain);
        features['subdomain_count'] = tldInfo.subdomainCount;
        features['has_subdomain'] = tldInfo.hasSubdomain ? 1 : 0;
        features['domain_name_length'] = tldInfo.domainLength;
        features['tld_length'] = tldInfo.tldLength;

        // Special character analysis
        features['has_at_symbol'] = url.includes('@') ? 1 : 0;
        features['has_port'] = parsedUrl.port !== '' ? 1 : 0;
        features['has_ip'] = this.hasIPAddress(url);
        features['has_suspicious_tld'] = this.hasSuspiciousTLD(tldInfo.tld);

        // Suspicious patterns
        features['has_shortener'] = this.isShortenerURL(url);
        features['has_suspicious_keywords'] = this.hasSuspiciousKeywords(url);
        features['has_numbers_in_domain'] = /\d/.test(domain) ? 1 : 0;
        features['has_mixed_case'] = this.hasMixedCase(domain);

        // Obfuscation features (NEW)
        const obfuscationFeatures = this.extractObfuscationFeatures(url);
        features['has_obfuscation'] = obfuscationFeatures.has_obfuscation;
        features['num_obfuscated_chars'] = obfuscationFeatures.num_obfuscated_chars;
        features['obfuscation_ratio'] = obfuscationFeatures.obfuscation_ratio;

        // Statistical features
        features['digit_ratio'] = this.calculateDigitRatio(url);
        features['letter_ratio'] = this.calculateLetterRatio(url);
        features['special_char_ratio'] = this.calculateSpecialCharRatio(url);

        // Entropy calculation
        features['url_entropy'] = this.calculateEntropy(url);
        features['domain_entropy'] = this.calculateEntropy(domain);

        // Path analysis
        features['path_depth'] = (path.match(/\//g) || []).length;
        features['has_file_extension'] = this.hasFileExtension(path);
        features['suspicious_file_ext'] = this.hasSuspiciousFileExtension(path);

        // Query parameter analysis
        const params = new URLSearchParams(query);
        features['num_params'] = params.size;
        features['has_suspicious_params'] = this.hasSuspiciousParams(query);

        // Brand impersonation features (NEW)
        const brandFeatures = this.extractBrandFeatures(parsedUrl, tldInfo);
        features['suspicious_brand_usage'] = brandFeatures.suspicious_brand_usage;
        features['brand_in_registered_domain'] = brandFeatures.brand_in_registered_domain;
        features['brand_in_subdomain'] = brandFeatures.brand_in_subdomain;
        features['brand_in_path_or_query'] = brandFeatures.brand_in_path_or_query;
        features['brand_mismatch'] = brandFeatures.brand_mismatch;
        features['brand_similarity_registered'] = brandFeatures.brand_similarity_registered;
        features['brand_similarity_subdomain'] = brandFeatures.brand_similarity_subdomain;
        features['brand_similarity_path'] = brandFeatures.brand_similarity_path;
        features['brand_homograph'] = brandFeatures.brand_homograph;

        // URL structure anomalies
        features['double_slash'] = (url.indexOf('//') !== url.lastIndexOf('//')) ? 1 : 0;
        features['trailing_slash'] = url.endsWith('/') ? 1 : 0;

        // HTTPS analysis
        features['uses_https'] = url.startsWith('https://') ? 1 : 0;
        features['uses_http'] = url.startsWith('http://') ? 1 : 0;

        return features;
    }

    /**
     * Extract TLD information from domain
     */
    extractTLD(domain) {
        const parts = domain.split('.');
        const tld = parts.length > 1 ? parts[parts.length - 1] : '';
        const domainName = parts.length > 1 ? parts[parts.length - 2] : parts[0];
        const subdomain = parts.length > 2 ? parts.slice(0, -2).join('.') : '';

        return {
            tld: tld,
            domain: domainName,
            subdomain: subdomain,
            tldLength: tld.length,
            domainLength: domainName.length,
            subdomainCount: subdomain ? subdomain.split('.').length : 0,
            hasSubdomain: subdomain !== ''
        };
    }

    /**
     * Check if URL contains an IP address
     */
    hasIPAddress(url) {
        const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
        return ipPattern.test(url) ? 1 : 0;
    }

    /**
     * Check for suspicious TLD
     */
    hasSuspiciousTLD(tld) {
        return this.suspiciousTLDs.includes(tld.toLowerCase()) ? 1 : 0;
    }

    /**
     * Check if URL is from a shortener service
     */
    isShortenerURL(url) {
        const urlLower = url.toLowerCase();
        return this.urlShorteners.some(shortener => urlLower.includes(shortener)) ? 1 : 0;
    }

    /**
     * Check for suspicious keywords
     */
    hasSuspiciousKeywords(url) {
        const urlLower = url.toLowerCase();
        return this.suspiciousKeywords.some(keyword => urlLower.includes(keyword)) ? 1 : 0;
    }

    /**
     * Check for mixed case in domain
     */
    hasMixedCase(domain) {
        const hasUpper = /[A-Z]/.test(domain);
        const hasLower = /[a-z]/.test(domain);
        return (hasUpper && hasLower) ? 1 : 0;
    }

    /**
     * Calculate digit ratio
     */
    calculateDigitRatio(text) {
        const digitCount = (text.match(/\d/g) || []).length;
        return text.length > 0 ? digitCount / text.length : 0;
    }

    /**
     * Calculate letter ratio
     */
    calculateLetterRatio(text) {
        const letterCount = (text.match(/[a-zA-Z]/g) || []).length;
        return text.length > 0 ? letterCount / text.length : 0;
    }

    /**
     * Calculate special character ratio
     */
    calculateSpecialCharRatio(text) {
        const specialCount = (text.match(/[^a-zA-Z0-9]/g) || []).length;
        return text.length > 0 ? specialCount / text.length : 0;
    }

    /**
     * Calculate Shannon entropy
     */
    calculateEntropy(text) {
        if (!text || text.length === 0) return 0;

        const charCounts = {};
        for (let char of text) {
            charCounts[char] = (charCounts[char] || 0) + 1;
        }

        let entropy = 0;
        const textLength = text.length;

        for (let count of Object.values(charCounts)) {
            const probability = count / textLength;
            entropy -= probability * Math.log2(probability);
        }

        return entropy;
    }

    /**
     * Check if path has file extension
     */
    hasFileExtension(path) {
        const pathParts = path.split('/');
        const lastPart = pathParts[pathParts.length - 1];
        return (lastPart.includes('.') && lastPart.length > 0) ? 1 : 0;
    }

    /**
     * Check for suspicious file extensions
     */
    hasSuspiciousFileExtension(path) {
        const pathLower = path.toLowerCase();
        return this.suspiciousExtensions.some(ext => pathLower.includes(ext)) ? 1 : 0;
    }

    /**
     * Check for suspicious query parameters
     */
    hasSuspiciousParams(query) {
        const suspiciousParams = ['redirect', 'url', 'link', 'goto', 'target', 'ref'];
        const queryLower = query.toLowerCase();
        return suspiciousParams.some(param => queryLower.includes(param)) ? 1 : 0;
    }

    /**
     * Calculate string similarity (Levenshtein distance-based)
     * Similar to Python's SequenceMatcher
     */
    stringSimilarity(str1, str2) {
        if (!str1 || !str2) return 0;
        if (str1 === str2) return 1.0;

        const longer = str1.length > str2.length ? str1 : str2;
        const shorter = str1.length > str2.length ? str2 : str1;

        if (longer.length === 0) return 1.0;

        // Calculate Levenshtein distance
        const editDistance = this.levenshteinDistance(str1, str2);
        return (longer.length - editDistance) / longer.length;
    }

    /**
     * Calculate Levenshtein distance between two strings
     */
    levenshteinDistance(str1, str2) {
        const matrix = [];

        for (let i = 0; i <= str2.length; i++) {
            matrix[i] = [i];
        }

        for (let j = 0; j <= str1.length; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }

        return matrix[str2.length][str1.length];
    }

    /**
     * Calculate best brand similarity score for a given text
     */
    calculateBrandSimilarity(text) {
        if (!text) return 0.0;

        let bestRatio = 0.0;
        for (const brand of this.brandKeywords) {
            const ratio = this.stringSimilarity(text.toLowerCase(), brand);
            if (ratio > bestRatio) {
                bestRatio = ratio;
            }
        }
        return bestRatio;
    }

    /**
     * Extract enhanced TLD information
     */
    extractEnhancedTLD(domain) {
        const parts = domain.split('.');

        // Handle different TLD scenarios
        let tld = '';
        let domainName = '';
        let subdomain = '';
        let registeredDomain = '';

        if (parts.length === 1) {
            domainName = parts[0];
        } else if (parts.length === 2) {
            domainName = parts[0];
            tld = parts[1];
            registeredDomain = domain;
        } else {
            // 3+ parts: subdomain.domain.tld or subdomain.domain.co.uk etc
            tld = parts[parts.length - 1];
            domainName = parts[parts.length - 2];
            subdomain = parts.slice(0, -2).join('.');
            registeredDomain = parts.slice(-2).join('.');
        }

        return {
            tld: tld,
            domain: domainName,
            subdomain: subdomain,
            registeredDomain: registeredDomain,
            tldLength: tld.length,
            domainLength: domainName.length,
            subdomainCount: subdomain ? subdomain.split('.').length : 0,
            hasSubdomain: subdomain !== ''
        };
    }

    /**
     * Extract obfuscation features
     */
    extractObfuscationFeatures(url) {
        if (!url) {
            return {
                has_obfuscation: 0,
                num_obfuscated_chars: 0,
                obfuscation_ratio: 0.0
            };
        }

        // Detect various encoding schemes
        const percentEncoded = (url.match(/%[0-9a-fA-F]{2}/g) || []).length;
        const hexEncoded = (url.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
        const unicodeEncoded = (url.match(/\\u[0-9a-fA-F]{4}/g) || []).length;
        const htmlEntities = (url.match(/&#x?[0-9a-fA-F]+;?/g) || []).length;

        const totalTokens = percentEncoded + hexEncoded + unicodeEncoded + htmlEntities;

        return {
            has_obfuscation: totalTokens > 0 ? 1 : 0,
            num_obfuscated_chars: totalTokens,
            obfuscation_ratio: url.length > 0 ? totalTokens / url.length : 0.0
        };
    }

    /**
     * Extract brand impersonation features
     */
    extractBrandFeatures(parsedUrl, tldInfo) {
        const urlLower = parsedUrl.href.toLowerCase();
        const registeredDomainLower = (tldInfo.registeredDomain || tldInfo.domain || '').toLowerCase();
        const coreDomainLower = (tldInfo.domain || '').toLowerCase();
        const subdomainLower = (tldInfo.subdomain || '').toLowerCase();
        const pathQueryLower = ((parsedUrl.pathname || '') + (parsedUrl.search || '')).toLowerCase();

        // Check if brand appears in different parts
        const brandInRegistered = this.brandKeywords.some(brand => registeredDomainLower.includes(brand));
        const brandInSubdomain = subdomainLower && this.brandKeywords.some(brand => subdomainLower.includes(brand));
        const brandInPath = this.brandKeywords.some(brand => pathQueryLower.includes(brand));
        const brandAnywhere = this.brandKeywords.some(brand => urlLower.includes(brand));

        // Calculate similarity scores
        const registeredSimilarity = this.calculateBrandSimilarity(coreDomainLower);
        const subdomainSimilarity = this.calculateBrandSimilarity(subdomainLower);
        const pathSimilarity = this.calculateBrandSimilarity(pathQueryLower);

        // Detect homograph attacks
        const homographFlag = (registeredSimilarity >= this.HOMOGRAPH_THRESHOLD && registeredSimilarity < 1.0) ? 1 : 0;

        return {
            suspicious_brand_usage: brandAnywhere ? 1 : 0,
            brand_in_registered_domain: brandInRegistered ? 1 : 0,
            brand_in_subdomain: brandInSubdomain ? 1 : 0,
            brand_in_path_or_query: brandInPath ? 1 : 0,
            brand_mismatch: (brandAnywhere && !brandInRegistered) ? 1 : 0,
            brand_similarity_registered: registeredSimilarity,
            brand_similarity_subdomain: subdomainSimilarity,
            brand_similarity_path: pathSimilarity,
            brand_homograph: homographFlag
        };
    }

    /**
     * Get default features for invalid URLs
     */
    getDefaultFeatures() {
        const defaultFeatures = {};
        const featureNames = [
            'url_length', 'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
            'num_question_marks', 'num_equals', 'num_ampersands', 'num_percentages',
            'domain_length', 'path_length', 'query_length', 'subdomain_count',
            'has_subdomain', 'domain_name_length', 'tld_length', 'has_at_symbol',
            'has_port', 'has_ip', 'has_suspicious_tld', 'has_shortener',
            'has_suspicious_keywords', 'has_numbers_in_domain', 'has_mixed_case',
            'has_obfuscation', 'num_obfuscated_chars', 'obfuscation_ratio',
            'digit_ratio', 'letter_ratio', 'special_char_ratio', 'url_entropy',
            'domain_entropy', 'path_depth', 'has_file_extension', 'suspicious_file_ext',
            'num_params', 'has_suspicious_params', 'suspicious_brand_usage',
            'brand_in_registered_domain', 'brand_in_subdomain', 'brand_in_path_or_query',
            'brand_mismatch', 'brand_similarity_registered', 'brand_similarity_subdomain',
            'brand_similarity_path', 'brand_homograph',
            'double_slash', 'trailing_slash', 'uses_https', 'uses_http'
        ];

        featureNames.forEach(name => {
            defaultFeatures[name] = 0;
        });

        return defaultFeatures;
    }

    /**
     * Get feature explanations for detected phishing indicators
     * @param {Object} features - Extracted features
     * @param {Object} featureUsage - Map of feature names to usage count in phishing-voting trees
     * @param {number} phishingVotes - Number of trees that voted for phishing
     * @returns {Array} Explanations for features that actually contributed to the prediction
     */
    getFeatureExplanations(features, featureUsage = {}, phishingVotes = 0) {
        const explanations = [];
        
        // If no feature usage data, fall back to rule-based (for backwards compatibility)
        const useDynamicExplanations = featureUsage && Object.keys(featureUsage).length > 0 && phishingVotes > 0;
        
        // Calculate minimum usage threshold (feature must be used in at least 10% of phishing-voting trees)
        const minUsageThreshold = Math.max(1, Math.floor(phishingVotes * 0.1));
        
        // Helper function to check if a feature should be explained
        const shouldExplain = (featureName) => {
            if (!useDynamicExplanations) {
                // Fall back to rule-based if no usage data
                return true;
            }
            // Only explain if feature was used in enough phishing-voting trees
            return (featureUsage[featureName] || 0) >= minUsageThreshold;
        };

        if (features['has_ip'] && shouldExplain('has_ip')) {
            explanations.push('URL contains an IP address instead of a domain name');
        }

        if (features['has_suspicious_tld'] && shouldExplain('has_suspicious_tld')) {
            explanations.push('Uses a suspicious top-level domain (TLD) commonly used in phishing');
        }

        if (features['has_suspicious_keywords'] && shouldExplain('has_suspicious_keywords')) {
            explanations.push('Contains suspicious keywords like "login", "verify", "secure", etc.');
        }

        if (features['has_shortener'] && shouldExplain('has_shortener')) {
            explanations.push('Uses a URL shortening service (hides actual destination)');
        }

        if (features['url_length'] > 150 && shouldExplain('url_length')) {
            explanations.push(`Unusually long URL (${features['url_length']} characters)`);
        }

        // Top features from model that need explanations
        if (features['num_slashes'] > 5 && shouldExplain('num_slashes')) {
            explanations.push(`Many slashes in URL (${features['num_slashes']}) - unusual structure`);
        }

        if (features['path_depth'] > 3 && shouldExplain('path_depth')) {
            explanations.push(`Deep URL path structure (${features['path_depth']} levels) - common in phishing`);
        }

        if (features['path_length'] > 50 && shouldExplain('path_length')) {
            explanations.push(`Long path component (${features['path_length']} characters) - suspicious`);
        }

        if (features['has_port'] && shouldExplain('has_port')) {
            explanations.push('URL contains port number (unusual for standard websites)');
        }

        if (features['has_numbers_in_domain'] && shouldExplain('has_numbers_in_domain')) {
            explanations.push('Domain contains numbers (e.g., "goog1e" instead of "google")');
        }

        if (features['subdomain_count'] > 2 && shouldExplain('subdomain_count')) {
            explanations.push(`Multiple subdomains detected (${features['subdomain_count']})`);
        }

        if (features['has_at_symbol'] && shouldExplain('has_at_symbol')) {
            explanations.push('Contains @ symbol (can be used to obscure real domain)');
        }

        if (features['suspicious_file_ext'] && shouldExplain('suspicious_file_ext')) {
            explanations.push('Contains suspicious file extension (.exe, .bat, etc.)');
        }

        if (features['has_suspicious_params'] && shouldExplain('has_suspicious_params')) {
            explanations.push('Has suspicious query parameters (redirect, url, etc.)');
        }

        if (!features['uses_https'] && shouldExplain('uses_https')) {
            explanations.push('Does not use HTTPS encryption');
        }

        if (features['url_entropy'] > 5.5 && shouldExplain('url_entropy')) {
            explanations.push('High URL randomness/entropy (characteristic of generated phishing URLs)');
        }

        if (features['has_obfuscation'] && shouldExplain('has_obfuscation')) {
            explanations.push('URL contains obfuscated/encoded characters');
        }

        if (features['brand_mismatch'] && shouldExplain('brand_mismatch')) {
            explanations.push('Brand name appears in URL but not in actual domain (impersonation attempt)');
        }

        if (features['brand_homograph'] && shouldExplain('brand_homograph')) {
            explanations.push('Domain name is suspiciously similar to a known brand (homograph attack)');
        }

        if (features['brand_similarity_registered'] > 0.7 && features['brand_similarity_registered'] < 1.0 && shouldExplain('brand_similarity_registered')) {
            explanations.push('Domain closely resembles a known brand name');
        }

        // Additional important features from model
        if (features['brand_similarity_subdomain'] > 0.5 && shouldExplain('brand_similarity_subdomain')) {
            explanations.push('Subdomain closely resembles a known brand (potential impersonation)');
        }

        if (features['digit_ratio'] > 0.3 && shouldExplain('digit_ratio')) {
            explanations.push(`High ratio of digits in URL (${(features['digit_ratio'] * 100).toFixed(1)}%) - unusual`);
        }

        if (features['domain_entropy'] > 4.0 && shouldExplain('domain_entropy')) {
            explanations.push('High domain name randomness (characteristic of generated domains)');
        }

        if (features['has_subdomain'] && features['subdomain_count'] === 0) {
            // This shouldn't happen, but just in case
        }

        return explanations;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = URLFeatureExtractor;
}
