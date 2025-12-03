/**
 * URL Feature Extraction for Phishing Detection
 * Port of Python URLFeatureExtractor to JavaScript
 */

class URLFeatureExtractor {
    constructor() {
        // Whitelist of known legitimate domains (from trusted URLs training data)
        this.whitelistedDomains = [
            'abcnews.co',
            'abcnews.com',
            'abcnews.io',
            'abcnews.org',
            'adobe.co',
            'adobe.com',
            'adobe.net',
            'adobe.org',
            'airbnb.com',
            'airbnb.io',
            'airbnb.net',
            'airbnb.org',
            'alibaba.co',
            'alibaba.io',
            'alibaba.net',
            'alibaba.org',
            'aliexpress.co',
            'aliexpress.com',
            'aliexpress.org',
            'amazon.co',
            'amazon.com',
            'amazon.io',
            'amazon.net',
            'amd.com',
            'amd.io',
            'amd.net',
            'amd.org',
            'american.com',
            'american.io',
            'american.net',
            'american.org',
            'americanexpress.co',
            'americanexpress.com',
            'americanexpress.net',
            'americanexpress.org',
            'ap.co',
            'ap.io',
            'ap.net',
            'ap.org',
            'apple.co',
            'apple.com',
            'apple.io',
            'apple.org',
            'artstation.co',
            'artstation.com',
            'artstation.net',
            'artstation.org',
            'asana.co',
            'asana.com',
            'asana.org',
            'atlassian.co',
            'atlassian.com',
            'atlassian.io',
            'atlassian.org',
            'bankofamerica.co',
            'bankofamerica.com',
            'bankofamerica.io',
            'bankofamerica.net',
            'bankofamerica.org',
            'basecamp.co',
            'basecamp.com',
            'basecamp.net',
            'basecamp.org',
            'bbc.co',
            'bbc.net',
            'bbc.org',
            'behance.io',
            'behance.net',
            'berkeley.co',
            'berkeley.io',
            'berkeley.net',
            'berkeley.org',
            'bestbuy.co',
            'bestbuy.com',
            'bestbuy.io',
            'bestbuy.net',
            'bestbuy.org',
            'bing.co',
            'bing.com',
            'bing.io',
            'bing.net',
            'bing.org',
            'blackrock.co',
            'blackrock.com',
            'blackrock.io',
            'blackrock.net',
            'blackrock.org',
            'blog.com',
            'blog.org',
            'blogger.co',
            'blogger.com',
            'blogger.io',
            'blogger.net',
            'blogger.org',
            'bloomberg.co',
            'bloomberg.com',
            'bloomberg.net',
            'bloomberg.org',
            'booking.co',
            'booking.com',
            'booking.io',
            'booking.net',
            'booking.org',
            'brave.co',
            'brave.com',
            'brave.io',
            'brave.net',
            'brave.org',
            'brown.edu',
            'brown.net',
            'brown.org',
            'canva.co',
            'canva.io',
            'canva.net',
            'canva.org',
            'capitalone.co',
            'capitalone.com',
            'capitalone.io',
            'capitalone.net',
            'caviar.co',
            'caviar.com',
            'caviar.io',
            'caviar.net',
            'cbsnews.co',
            'cbsnews.io',
            'cdc.gov',
            'cdc.io',
            'cdc.net',
            'cdc.org',
            'chase.co',
            'chase.com',
            'chase.io',
            'chase.net',
            'chase.org',
            'cia.co',
            'cia.gov',
            'cia.io',
            'cia.net',
            'cia.org',
            'cisco.co',
            'cisco.com',
            'cisco.org',
            'citibank.co',
            'citibank.com',
            'citibank.io',
            'citibank.net',
            'citibank.org',
            'cnn.com',
            'cnn.io',
            'cnn.net',
            'cnn.org',
            'codecademy.co',
            'codecademy.io',
            'codecademy.net',
            'codecademy.org',
            'coinbase.co',
            'coinbase.com',
            'coinbase.net',
            'columbia.co',
            'columbia.edu',
            'columbia.io',
            'columbia.net',
            'columbia.org',
            'confluence.com',
            'cornell.co',
            'cornell.io',
            'cornell.net',
            'cornell.org',
            'costco.co',
            'costco.com',
            'costco.io',
            'costco.net',
            'costco.org',
            'coursera.co',
            'coursera.io',
            'coursera.net',
            'coursera.org',
            'dartmouth.co',
            'dartmouth.edu',
            'dartmouth.io',
            'dartmouth.org',
            'deliveroo.co',
            'deliveroo.com',
            'deliveroo.io',
            'deliveroo.net',
            'deliveroo.org',
            'dell.co',
            'dell.net',
            'dell.org',
            'delta.co',
            'delta.io',
            'delta.org',
            'deviantart.co',
            'deviantart.com',
            'deviantart.io',
            'deviantart.net',
            'deviantart.org',
            'dhs.co',
            'dhs.io',
            'dhs.net',
            'dhs.org',
            'discord.co',
            'discord.net',
            'discord.org',
            'discover.co',
            'discover.com',
            'discover.net',
            'dmv.co',
            'dmv.gov',
            'dmv.io',
            'dmv.net',
            'dmv.org',
            'docker.com',
            'doordash.com',
            'doordash.io',
            'doordash.net',
            'doordash.org',
            'dribbble.co',
            'dribbble.com',
            'dribbble.io',
            'dribbble.org',
            'dropbox.com',
            'dropbox.io',
            'dropbox.net',
            'drugs.co',
            'drugs.com',
            'drugs.io',
            'drugs.net',
            'drugs.org',
            'duckduckgo.co',
            'duckduckgo.com',
            'duckduckgo.io',
            'duckduckgo.net',
            'duckduckgo.org',
            'ebay.co',
            'ebay.io',
            'ebay.org',
            'economist.co',
            'economist.com',
            'economist.io',
            'economist.org',
            'edx.co',
            'edx.io',
            'edx.net',
            'edx.org',
            'epa.co',
            'epa.gov',
            'epa.io',
            'epa.net',
            'epa.org',
            'etrade.co',
            'etrade.net',
            'etrade.org',
            'etsy.co',
            'etsy.com',
            'etsy.io',
            'etsy.net',
            'etsy.org',
            'example.co',
            'example.com',
            'example.io',
            'example.net',
            'expedia.co',
            'expedia.com',
            'expedia.io',
            'expedia.org',
            'facebook.co',
            'facebook.com',
            'facebook.io',
            'facebook.net',
            'facebook.org',
            'fbi.co',
            'fbi.gov',
            'fbi.io',
            'fbi.net',
            'fbi.org',
            'fda.co',
            'fda.io',
            'fda.org',
            'fidelity.co',
            'fidelity.io',
            'fidelity.net',
            'fidelity.org',
            'figma.co',
            'figma.com',
            'figma.io',
            'figma.org',
            'flickr.co',
            'flickr.com',
            'flickr.io',
            'flickr.org',
            'forbes.co',
            'forbes.com',
            'forbes.io',
            'forbes.net',
            'forbes.org',
            'forum.com',
            'forum.net',
            'forum.org',
            'foxnews.co',
            'foxnews.io',
            'foxnews.net',
            'foxnews.org',
            'freecodecamp.io',
            'freecodecamp.net',
            'freecodecamp.org',
            'gemini.co',
            'gemini.com',
            'gemini.net',
            'gemini.org',
            'github.co',
            'github.com',
            'github.io',
            'github.net',
            'github.org',
            'gitlab.com',
            'gmail.co',
            'gmail.com',
            'gmail.io',
            'gmail.net',
            'gmail.org',
            'gmu.edu',
            'goldmansachs.co',
            'goldmansachs.net',
            'goldmansachs.org',
            'google.com',
            'google.io',
            'google.net',
            'google.org',
            'groupon.co',
            'groupon.com',
            'groupon.net',
            'groupon.org',
            'grubhub.co',
            'grubhub.com',
            'grubhub.io',
            'grubhub.net',
            'grubhub.org',
            'harvard.co',
            'harvard.io',
            'harvard.net',
            'harvard.org',
            'healthgrades.com',
            'healthgrades.net',
            'healthline.co',
            'healthline.com',
            'healthline.io',
            'healthline.net',
            'healthline.org',
            'hilton.com',
            'hilton.io',
            'hilton.net',
            'hilton.org',
            'homedepot.co',
            'homedepot.net',
            'homedepot.org',
            'hotels.co',
            'hotels.com',
            'hotels.io',
            'hotels.net',
            'hotels.org',
            'houzz.co',
            'houzz.com',
            'houzz.io',
            'houzz.net',
            'houzz.org',
            'hp.co',
            'hp.com',
            'hp.io',
            'hp.org',
            'ibm.com',
            'ibm.io',
            'ibm.org',
            'icloud.co',
            'icloud.com',
            'icloud.io',
            'icloud.net',
            'icloud.org',
            'imgur.co',
            'imgur.com',
            'imgur.io',
            'imgur.net',
            'imgur.org',
            'instacart.co',
            'instacart.io',
            'instacart.net',
            'instacart.org',
            'instagram.co',
            'instagram.com',
            'instagram.io',
            'intel.com',
            'intel.io',
            'intel.net',
            'intel.org',
            'irs.gov',
            'irs.net',
            'irs.org',
            'jetblue.co',
            'jetblue.com',
            'jetblue.io',
            'jetblue.net',
            'jetblue.org',
            'jira.com',
            'jpmorgan.co',
            'jpmorgan.com',
            'jpmorgan.io',
            'jpmorgan.org',
            'justeat.co',
            'justeat.io',
            'justeat.net',
            'kayak.co',
            'kayak.com',
            'kayak.io',
            'kayak.net',
            'kayak.org',
            'khanacademy.io',
            'khanacademy.net',
            'khanacademy.org',
            'kraken.co',
            'kraken.io',
            'kraken.net',
            'kraken.org',
            'kubernetes.io',
            'lenovo.co',
            'lenovo.com',
            'lenovo.io',
            'lenovo.net',
            'lenovo.org',
            'linkedin.co',
            'linkedin.com',
            'linkedin.io',
            'linkedin.org',
            'livejournal.co',
            'livejournal.com',
            'livejournal.io',
            'livejournal.net',
            'livejournal.org',
            'livingsocial.co',
            'livingsocial.com',
            'livingsocial.io',
            'livingsocial.net',
            'livingsocial.org',
            'lowes.co',
            'lowes.io',
            'lowes.net',
            'lowes.org',
            'lynda.co',
            'lynda.com',
            'lynda.io',
            'lynda.net',
            'macys.co',
            'macys.io',
            'macys.net',
            'macys.org',
            'mail.com',
            'mail.net',
            'mail.org',
            'marriott.co',
            'marriott.com',
            'marriott.net',
            'mastercard.co',
            'mastercard.com',
            'mastercard.io',
            'mastercard.net',
            'mastercard.org',
            'mayoclinic.co',
            'mayoclinic.io',
            'mayoclinic.net',
            'mayoclinic.org',
            'medium.com',
            'medium.io',
            'medium.net',
            'medium.org',
            'medlineplus.co',
            'medlineplus.io',
            'medlineplus.net',
            'medlineplus.org',
            'microsoft.co',
            'microsoft.com',
            'microsoft.io',
            'microsoft.net',
            'microsoft.org',
            'mit.co',
            'mit.edu',
            'mit.org',
            'morganstanley.com',
            'morganstanley.io',
            'morganstanley.net',
            'morganstanley.org',
            'mozilla.co',
            'mozilla.io',
            'mozilla.net',
            'mozilla.org',
            'msnbc.co',
            'msnbc.com',
            'msnbc.net',
            'msnbc.org',
            'nasa.co',
            'nasa.gov',
            'nasa.io',
            'nasa.net',
            'nasa.org',
            'nbcnews.com',
            'nbcnews.io',
            'nbcnews.org',
            'netflix.co',
            'netflix.com',
            'netflix.io',
            'netflix.org',
            'news.com',
            'news.org',
            'newsweek.co',
            'newsweek.com',
            'newsweek.io',
            'newsweek.net',
            'newsweek.org',
            'nih.co',
            'nih.gov',
            'nih.io',
            'nih.net',
            'nih.org',
            'noaa.co',
            'noaa.gov',
            'noaa.io',
            'noaa.org',
            'nordstrom.com',
            'nordstrom.io',
            'nordstrom.org',
            'notion.co',
            'notion.io',
            'notion.net',
            'notion.org',
            'notion.so',
            'npmjs.com',
            'npr.co',
            'npr.io',
            'npr.net',
            'nsa.gov',
            'nsa.io',
            'nvidia.co',
            'nvidia.com',
            'nvidia.io',
            'nvidia.net',
            'nvidia.org',
            'nytimes.com',
            'nytimes.io',
            'nytimes.org',
            'onedrive.co',
            'onedrive.com',
            'onedrive.io',
            'onedrive.net',
            'onedrive.org',
            'opera.co',
            'opera.com',
            'opera.io',
            'opera.net',
            'opera.org',
            'oracle.co',
            'oracle.com',
            'oracle.io',
            'oracle.net',
            'oracle.org',
            'orbitz.co',
            'orbitz.io',
            'outlook.co',
            'outlook.com',
            'outlook.io',
            'outlook.net',
            'outlook.org',
            'overstock.co',
            'overstock.com',
            'overstock.io',
            'overstock.net',
            'overstock.org',
            'paypal.co',
            'paypal.com',
            'paypal.io',
            'paypal.net',
            'paypal.org',
            'pinterest.co',
            'pinterest.com',
            'pinterest.io',
            'pinterest.org',
            'pluralsight.co',
            'pluralsight.net',
            'postmates.co',
            'postmates.com',
            'postmates.io',
            'postmates.net',
            'postmates.org',
            'priceline.co',
            'priceline.net',
            'priceline.org',
            'princeton.co',
            'princeton.io',
            'princeton.net',
            'qualcomm.com',
            'qualcomm.io',
            'qualcomm.net',
            'qualcomm.org',
            'reddit.co',
            'reddit.com',
            'reddit.io',
            'reddit.net',
            'reddit.org',
            'reuters.co',
            'reuters.io',
            'robinhood.co',
            'robinhood.com',
            'robinhood.io',
            'robinhood.net',
            'robinhood.org',
            'salesforce.co',
            'salesforce.net',
            'salesforce.org',
            'schwab.co',
            'schwab.com',
            'schwab.net',
            'seamless.com',
            'seamless.net',
            'seamless.org',
            'shop.com',
            'shop.net',
            'shop.org',
            'shopify.co',
            'shopify.io',
            'shopify.net',
            'skype.co',
            'skype.com',
            'skype.io',
            'skype.net',
            'skype.org',
            'slack.com',
            'slack.io',
            'slack.net',
            'slack.org',
            'snapchat.com',
            'snapchat.io',
            'snapchat.net',
            'snapchat.org',
            'sourceforge.net',
            'southwest.co',
            'southwest.com',
            'southwest.io',
            'southwest.net',
            'southwest.org',
            'spotify.co',
            'spotify.com',
            'spotify.io',
            'spotify.net',
            'spotify.org',
            'ssa.co',
            'ssa.gov',
            'ssa.io',
            'ssa.net',
            'ssa.org',
            'stackoverflow.com',
            'stackoverflow.io',
            'stackoverflow.net',
            'stackoverflow.org',
            'stanford.co',
            'stanford.edu',
            'stanford.io',
            'stanford.net',
            'stanford.org',
            'store.com',
            'store.net',
            'target.co',
            'target.com',
            'target.io',
            'target.org',
            'tdameritrade.co',
            'tdameritrade.com',
            'tdameritrade.io',
            'tdameritrade.net',
            'teams.co',
            'teams.io',
            'teams.microsoft.com',
            'teams.net',
            'teams.org',
            'tenor.co',
            'tenor.com',
            'tenor.io',
            'tenor.net',
            'tenor.org',
            'terraform.io',
            'theguardian.co',
            'theguardian.io',
            'theguardian.net',
            'theguardian.org',
            'tiktok.co',
            'tiktok.com',
            'tiktok.io',
            'tiktok.net',
            'tiktok.org',
            'time.com',
            'time.io',
            'trello.co',
            'trello.com',
            'trello.io',
            'trello.net',
            'tripadvisor.co',
            'tripadvisor.com',
            'tripadvisor.io',
            'tripadvisor.net',
            'tripadvisor.org',
            'tryhackme.co',
            'tryhackme.com',
            'tryhackme.io',
            'tryhackme.net',
            'tryhackme.org',
            'tumblr.co',
            'tumblr.com',
            'tumblr.io',
            'tumblr.org',
            'twitter.co',
            'twitter.com',
            'twitter.io',
            'twitter.net',
            'twitter.org',
            'ubereats.co',
            'ubereats.com',
            'ubereats.io',
            'ubereats.net',
            'ubereats.org',
            'udacity.co',
            'udacity.com',
            'udacity.org',
            'udemy.co',
            'udemy.com',
            'udemy.net',
            'united.co',
            'united.com',
            'united.io',
            'united.net',
            'upenn.co',
            'upenn.edu',
            'upenn.io',
            'upenn.net',
            'upenn.org',
            'usa.gov',
            'usa.io',
            'usa.net',
            'usatoday.co',
            'usatoday.com',
            'usatoday.io',
            'usatoday.net',
            'usatoday.org',
            'usbank.com',
            'usbank.io',
            'usbank.net',
            'usps.co',
            'usps.io',
            'usps.net',
            'usps.org',
            'vanguard.co',
            'vanguard.com',
            'vanguard.io',
            'vanguard.net',
            'vanguard.org',
            'visa.co',
            'visa.com',
            'visa.net',
            'visa.org',
            'walmart.co',
            'walmart.com',
            'walmart.io',
            'walmart.net',
            'walmart.org',
            'washingtonpost.co',
            'washingtonpost.com',
            'washingtonpost.io',
            'washingtonpost.net',
            'washingtonpost.org',
            'wayfair.co',
            'wayfair.net',
            'wayfair.org',
            'web.net',
            'web.org',
            'webmd.co',
            'webmd.com',
            'webmd.net',
            'webmd.org',
            'wellsfargo.com',
            'wellsfargo.net',
            'wellsfargo.org',
            'who.co',
            'who.int',
            'who.io',
            'who.net',
            'who.org',
            'wikipedia.co',
            'wikipedia.io',
            'wikipedia.net',
            'wikipedia.org',
            'wish.io',
            'wish.net',
            'wordpress.co',
            'wordpress.com',
            'wordpress.net',
            'wordpress.org',
            'wsj.co',
            'wsj.com',
            'wsj.io',
            'wsj.org',
            'x.co',
            'x.com',
            'x.io',
            'x.net',
            'x.org',
            'yahoo.co',
            'yahoo.com',
            'yahoo.io',
            'yahoo.net',
            'yale.co',
            'yale.edu',
            'yale.net',
            'yale.org',
            'youtube.co',
            'youtube.com',
            'youtube.net',
            'zappos.co',
            'zappos.io',
            'zappos.net',
            'zappos.org',
            'zocdoc.co',
            'zocdoc.io',
            'zocdoc.net',
            'zoom.co',
            'zoom.io',
            'zoom.net',
            'zoom.org',
            'zoom.us'
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

        // Detect homograph attacks (in domain or path)
        const domainHomograph = (registeredSimilarity >= this.HOMOGRAPH_THRESHOLD && registeredSimilarity < 1.0) ? 1 : 0;
        const pathHomograph = (pathSimilarity >= this.HOMOGRAPH_THRESHOLD && pathSimilarity < 1.0 && brandInPath) ? 1 : 0;
        const homographFlag = domainHomograph || pathHomograph;

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
        const explanationEntries = []; // Store explanations with their impact scores
        
        // If no feature usage data, fall back to rule-based (for backwards compatibility)
        const useDynamicExplanations = featureUsage && Object.keys(featureUsage).length > 0 && phishingVotes > 0;
        
        // Calculate minimum usage threshold (feature must be used in at least 1% of phishing-voting trees, or at least 1 tree)
        const minUsageThreshold = Math.max(1, Math.floor(phishingVotes * 0.01));
        
        // Debug logging
        if (useDynamicExplanations && Object.keys(featureUsage).length > 0) {
            console.log('Features used in phishing trees:', featureUsage);
            console.log('Threshold:', minUsageThreshold);
            // Debug brand features
            if (features['brand_mismatch'] || features['brand_in_path_or_query'] || features['brand_similarity_path'] > 0) {
                console.log('Brand features:', {
                    brand_mismatch: features['brand_mismatch'],
                    brand_in_path_or_query: features['brand_in_path_or_query'],
                    brand_similarity_path: features['brand_similarity_path'],
                    brand_similarity_registered: features['brand_similarity_registered']
                });
            }
        }
        
        // Helper function to get impact score for a feature
        const getImpactScore = (featureName) => {
            if (!useDynamicExplanations) {
                return 1; // Default score if no usage data
            }
            return featureUsage[featureName] || 0;
        };
        
        // Helper function to add explanation with impact score
        const addExplanation = (featureName, explanationText) => {
            const impactScore = getImpactScore(featureName);
            if (impactScore > 0 || !useDynamicExplanations) {
                explanationEntries.push({
                    text: explanationText,
                    impact: impactScore,
                    feature: featureName
                });
            }
        };
        
        // Get top features by usage (for prioritizing)
        const topFeaturesByUsage = useDynamicExplanations 
            ? Object.entries(featureUsage)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 4)
                .map(([name]) => name)
            : [];
        
        // Helper function to check if a feature should be explained
        const shouldExplain = (featureName) => {
            if (!useDynamicExplanations) {
                // Fall back to rule-based if no usage data
                return true;
            }
            // Always explain if it's in top 4 by usage
            if (topFeaturesByUsage.includes(featureName)) {
                return true;
            }
            // Otherwise, only explain if feature was used in at least 1 tree that voted for phishing
            const usageCount = featureUsage[featureName] || 0;
            const shouldShow = usageCount >= minUsageThreshold;
            if (usageCount > 0 && !shouldShow) {
                console.log(`Feature ${featureName} used ${usageCount} times but below threshold ${minUsageThreshold}`);
            }
            return shouldShow;
        };

        if (features['has_ip'] && shouldExplain('has_ip')) {
            addExplanation('has_ip', 'URL contains an IP address instead of a domain name');
        }

        if (features['has_suspicious_tld'] && shouldExplain('has_suspicious_tld')) {
            addExplanation('has_suspicious_tld', 'Uses a suspicious top-level domain (TLD) commonly used in phishing');
        }

        if (features['has_suspicious_keywords'] && shouldExplain('has_suspicious_keywords')) {
            addExplanation('has_suspicious_keywords', 'Contains suspicious keywords like "login", "verify", "secure", etc.');
        }

        if (features['has_shortener'] && shouldExplain('has_shortener')) {
            addExplanation('has_shortener', 'Uses a URL shortening service (hides actual destination)');
        }

        if (features['url_length'] > 150 && shouldExplain('url_length')) {
            addExplanation('url_length', `Unusually long URL (${features['url_length']} characters)`);
        }

        // Top features from model that need explanations
        if (features['num_slashes'] > 5 && shouldExplain('num_slashes')) {
            addExplanation('num_slashes', `Many slashes in URL (${features['num_slashes']}) - unusual structure`);
        }

        // Path depth - adjust threshold for top features
        const pathDepthThreshold = topFeaturesByUsage.includes('path_depth') ? 0 : 3;
        if (features['path_depth'] > pathDepthThreshold && shouldExplain('path_depth')) {
            if (features['path_depth'] > 3) {
                addExplanation('path_depth', `Deep URL path structure (${features['path_depth']} levels) - common in phishing`);
            } else {
                addExplanation('path_depth', `URL path structure (${features['path_depth']} level${features['path_depth'] !== 1 ? 's' : ''})`);
            }
        }

        // Path length - adjust threshold for top features
        const pathLengthThreshold = topFeaturesByUsage.includes('path_length') ? 0 : 50;
        if (features['path_length'] > pathLengthThreshold && shouldExplain('path_length')) {
            if (features['path_length'] > 50) {
                addExplanation('path_length', `Long path component (${features['path_length']} characters) - suspicious`);
            } else {
                addExplanation('path_length', `Path component length (${features['path_length']} characters)`);
            }
        }

        if (features['has_port'] && shouldExplain('has_port')) {
            addExplanation('has_port', 'URL contains port number (unusual for standard websites)');
        }

        if (features['has_numbers_in_domain'] && shouldExplain('has_numbers_in_domain')) {
            addExplanation('has_numbers_in_domain', 'Domain contains numbers (e.g., "goog1e" instead of "google")');
        }

        if (features['subdomain_count'] > 2 && shouldExplain('subdomain_count')) {
            addExplanation('subdomain_count', `Multiple subdomains detected (${features['subdomain_count']})`);
        }

        if (features['has_at_symbol'] && shouldExplain('has_at_symbol')) {
            addExplanation('has_at_symbol', 'Contains @ symbol (can be used to obscure real domain)');
        }

        if (features['suspicious_file_ext'] && shouldExplain('suspicious_file_ext')) {
            addExplanation('suspicious_file_ext', 'Contains suspicious file extension (.exe, .bat, etc.)');
        }

        if (features['has_suspicious_params'] && shouldExplain('has_suspicious_params')) {
            addExplanation('has_suspicious_params', 'Has suspicious query parameters (redirect, url, etc.)');
        }

        if (!features['uses_https'] && shouldExplain('uses_https')) {
            addExplanation('uses_https', 'Does not use HTTPS encryption');
        }

        // URL entropy - adjust threshold for top features
        const urlEntropyThreshold = topFeaturesByUsage.includes('url_entropy') ? 0 : 5.5;
        if (features['url_entropy'] > urlEntropyThreshold && shouldExplain('url_entropy')) {
            if (features['url_entropy'] > 5.5) {
                addExplanation('url_entropy', 'High URL randomness/entropy (characteristic of generated phishing URLs)');
            } else {
                addExplanation('url_entropy', `URL has moderate randomness/entropy (${features['url_entropy'].toFixed(2)})`);
            }
        }

        if (features['has_obfuscation'] && shouldExplain('has_obfuscation')) {
            addExplanation('has_obfuscation', 'URL contains obfuscated/encoded characters');
        }

        if (features['brand_mismatch'] && shouldExplain('brand_mismatch')) {
            // Check if brand is in path for more specific typosquatting message
            if (features['brand_in_path_or_query']) {
                addExplanation('brand_mismatch', 'Brand name in URL path but not in domain (typosquatting/impersonation attempt)');
            } else {
                addExplanation('brand_mismatch', 'Brand name appears in URL but not in actual domain (impersonation attempt)');
            }
        } else if (features['brand_in_path_or_query'] && shouldExplain('brand_in_path_or_query')) {
            // Only show this if brand_mismatch didn't already show
            addExplanation('brand_in_path_or_query', 'Brand name detected in URL path (potential impersonation)');
        }

        if (features['brand_homograph'] && shouldExplain('brand_homograph')) {
            addExplanation('brand_homograph', 'Domain name is suspiciously similar to a known brand (homograph attack)');
        }

        if (features['brand_similarity_registered'] > 0.7 && features['brand_similarity_registered'] < 1.0 && shouldExplain('brand_similarity_registered')) {
            addExplanation('brand_similarity_registered', 'Domain closely resembles a known brand name');
        }

        // Additional important features from model
        if (features['brand_similarity_subdomain'] > 0.5 && shouldExplain('brand_similarity_subdomain')) {
            addExplanation('brand_similarity_subdomain', 'Subdomain closely resembles a known brand (potential impersonation)');
        }

        // Lower threshold for path similarity to catch cases like "fake_paypal" 
        if (features['brand_similarity_path'] > 0.3 && shouldExplain('brand_similarity_path')) {
            addExplanation('brand_similarity_path', 'URL path closely resembles a known brand name (typosquatting)');
        }

        if (features['digit_ratio'] > 0.3 && shouldExplain('digit_ratio')) {
            addExplanation('digit_ratio', `High ratio of digits in URL (${(features['digit_ratio'] * 100).toFixed(1)}%) - unusual`);
        }

        if (features['domain_entropy'] > 4.0 && shouldExplain('domain_entropy')) {
            addExplanation('domain_entropy', 'High domain name randomness (characteristic of generated domains)');
        }

        if (features['has_subdomain'] && features['subdomain_count'] === 0) {
            // This shouldn't happen, but just in case
        }

        // Sort by impact score (highest first) and return top 4
        explanationEntries.sort((a, b) => b.impact - a.impact);
        const topExplanations = explanationEntries.slice(0, 4).map(entry => entry.text);
        
        console.log(`Top 4 most impactful factors:`, explanationEntries.slice(0, 4).map(e => `${e.feature} (${e.impact})`));
        
        return topExplanations;
    }

    /**
     * Extract domain-only features (component-specific)
     */
    extractDomainFeatures(domain, protocol = '') {
        const features = {};

        // Enhanced TLD analysis
        const tldInfo = this.extractEnhancedTLD(domain);

        // Domain length and structure
        features['domain_length'] = domain.length;
        features['domain_name_length'] = tldInfo.domainLength;
        features['tld_length'] = tldInfo.tldLength;
        features['subdomain_count'] = tldInfo.subdomainCount;
        features['has_subdomain'] = tldInfo.hasSubdomain ? 1 : 0;

        // Domain character analysis
        features['domain_num_dots'] = (domain.match(/\./g) || []).length;
        features['domain_num_hyphens'] = (domain.match(/-/g) || []).length;
        features['domain_num_underscores'] = (domain.match(/_/g) || []).length;
        features['domain_has_at_symbol'] = domain.includes('@') ? 1 : 0;
        features['domain_has_port'] = domain.includes(':') && /:\d+$/.test(domain) ? 1 : 0;
        features['domain_has_ip'] = this.hasIPAddress(domain) ? 1 : 0;

        // Domain statistical features
        features['domain_digit_ratio'] = domain.length > 0 ? (domain.match(/\d/g) || []).length / domain.length : 0;
        features['domain_letter_ratio'] = domain.length > 0 ? (domain.match(/[a-zA-Z]/g) || []).length / domain.length : 0;
        const specialChars = domain.replace(/[a-zA-Z0-9.-]/g, '').length;
        features['domain_special_char_ratio'] = domain.length > 0 ? specialChars / domain.length : 0;
        features['domain_entropy'] = this.calculateEntropy(domain);

        // Domain patterns
        features['domain_has_numbers'] = /\d/.test(domain) ? 1 : 0;
        features['domain_has_mixed_case'] = domain !== domain.toLowerCase() && domain !== domain.toUpperCase() ? 1 : 0;
        features['domain_has_suspicious_tld'] = this.hasSuspiciousTLD(tldInfo.tld) ? 1 : 0;
        features['domain_has_shortener'] = this.isShortenedURL(`http://${domain}`) ? 1 : 0;

        // Domain obfuscation
        const obfuscation = this.extractObfuscationMetrics(domain);
        features['domain_has_obfuscation'] = obfuscation.has_obfuscation;
        features['domain_num_obfuscated_chars'] = obfuscation.num_obfuscated_chars;
        features['domain_obfuscation_ratio'] = obfuscation.obfuscation_ratio;

        // Domain suspicious keywords
        const domainLower = domain.toLowerCase();
        const suspiciousKeywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm',
            'validate', 'authenticate', 'bank', 'paypal', 'amazon',
            'facebook', 'google', 'apple', 'microsoft', 'support'];
        features['domain_has_suspicious_keywords'] = suspiciousKeywords.some(kw => domainLower.includes(kw)) ? 1 : 0;

        // Brand features (domain-specific)
        const brandFeatures = this.getBrandFeaturesDomainOnly(domain, tldInfo);
        Object.assign(features, brandFeatures);

        // Protocol features
        features['uses_https'] = protocol.toLowerCase() === 'https' ? 1 : 0;
        features['uses_http'] = protocol.toLowerCase() === 'http' ? 1 : 0;

        return features;
    }

    /**
     * Extract path-only features (component-specific)
     */
    extractPathFeatures(path, query = '') {
        const features = {};

        // Path length and structure
        features['path_length'] = path.length;
        features['query_length'] = query.length;
        features['path_depth'] = (path.match(/\//g) || []).length;
        features['path_num_slashes'] = (path.match(/\//g) || []).length;
        features['path_num_dots'] = (path.match(/\./g) || []).length;
        features['path_num_hyphens'] = (path.match(/-/g) || []).length;
        features['path_num_underscores'] = (path.match(/_/g) || []).length;

        // Query parameter analysis
        features['path_num_question_marks'] = query.includes('?') ? 1 : 0;
        const pathQuery = path + query;
        features['path_num_equals'] = (pathQuery.match(/=/g) || []).length;
        features['path_num_ampersands'] = (pathQuery.match(/&/g) || []).length;
        features['path_num_percentages'] = (pathQuery.match(/%/g) || []).length;
        
        const params = new URLSearchParams(query);
        features['path_num_params'] = Array.from(params.keys()).length;
        features['path_has_suspicious_params'] = this.hasSuspiciousParams(query) ? 1 : 0;

        // Path segments
        const segments = path.split('/').filter(s => s.length > 0);
        features['path_segment_count'] = segments.length;
        features['path_avg_segment_length'] = segments.length > 0 
            ? segments.reduce((sum, s) => sum + s.length, 0) / segments.length 
            : 0;
        features['path_max_segment_length'] = segments.length > 0 
            ? Math.max(...segments.map(s => s.length)) 
            : 0;

        // Path file extension
        const lastSegment = segments[segments.length - 1] || '';
        features['path_has_file_extension'] = lastSegment.includes('.') && lastSegment.split('.').length > 1 ? 1 : 0;
        features['path_suspicious_file_ext'] = this.hasSuspiciousFileExtension(path) ? 1 : 0;

        // Path statistical features
        features['path_digit_ratio'] = pathQuery.length > 0 ? (pathQuery.match(/\d/g) || []).length / pathQuery.length : 0;
        features['path_letter_ratio'] = pathQuery.length > 0 ? (pathQuery.match(/[a-zA-Z]/g) || []).length / pathQuery.length : 0;
        const pathSpecialChars = pathQuery.replace(/[a-zA-Z0-9/._-]/g, '').length;
        features['path_special_char_ratio'] = pathQuery.length > 0 ? pathSpecialChars / pathQuery.length : 0;
        features['path_entropy'] = this.calculateEntropy(pathQuery);

        // Path patterns
        features['path_has_numbers'] = /\d/.test(path) ? 1 : 0;
        features['path_has_special_chars'] = /[^a-zA-Z0-9/._-]/.test(path) ? 1 : 0;
        features['path_starts_with_slash'] = path.startsWith('/') ? 1 : 0;
        features['path_ends_with_slash'] = path.endsWith('/') ? 1 : 0;
        features['path_has_double_slash'] = path.includes('//') ? 1 : 0;
        features['path_has_query_in_path'] = path.includes('?') ? 1 : 0;

        // Legitimate path patterns
        const legitimatePaths = ['login', 'home', 'about', 'contact', 'index', 'main', 'page',
            'help', 'support', 'faq', 'terms', 'privacy', 'search', 'blog',
            'news', 'events', 'calendar', 'directory', 'sitemap'];
        const pathLower = path.toLowerCase();
        features['path_has_legitimate_path'] = legitimatePaths.some(lp => pathLower.includes(lp)) ? 1 : 0;
        features['path_legitimate_path_count'] = legitimatePaths.filter(lp => pathLower.includes(lp)).length;

        // Suspicious path patterns
        const suspiciousPaths = ['verify', 'confirm', 'update', 'secure', 'account', 'validate',
            'authenticate', 'signin', 'signup', 'password', 'reset', 'recover'];
        features['path_has_suspicious_path'] = suspiciousPaths.some(sp => pathLower.includes(sp)) ? 1 : 0;
        features['path_suspicious_path_count'] = suspiciousPaths.filter(sp => pathLower.includes(sp)).length;

        // Brand features (path-specific)
        const brandFeatures = this.getBrandFeaturesPathOnly(path, query);
        Object.assign(features, brandFeatures);

        return features;
    }

    /**
     * Get brand features for domain-only extraction
     */
    getBrandFeaturesDomainOnly(domain, tldInfo) {
        // Simplified brand detection for domain
        const domainLower = domain.toLowerCase();
        const registeredDomain = tldInfo.domain || domain;
        const registeredLower = registeredDomain.toLowerCase();
        const subdomainLower = tldInfo.subdomain ? tldInfo.subdomain.toLowerCase() : '';

        const BRAND_KEYWORDS = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal',
            'ebay', 'netflix', 'twitter', 'instagram', 'linkedin', 'bank',
            'chase', 'wellsfargo', 'citibank', 'boa', 'netflix', 'outlook',
            'office365', 'icloud', 'gmail'];

        const brandInRegistered = BRAND_KEYWORDS.some(brand => registeredLower.includes(brand));
        const brandInSubdomain = subdomainLower && BRAND_KEYWORDS.some(brand => subdomainLower.includes(brand));

        const registeredSimilarity = this.brandSimilarity(registeredLower);
        const subdomainSimilarity = this.brandSimilarity(subdomainLower);
        const homographFlag = (registeredSimilarity >= 0.6 && registeredSimilarity < 1.0) ? 1 : 0;

        return {
            'domain_suspicious_brand_usage': (brandInRegistered || brandInSubdomain) ? 1 : 0,
            'domain_brand_in_registered_domain': brandInRegistered ? 1 : 0,
            'domain_brand_in_subdomain': brandInSubdomain ? 1 : 0,
            'domain_brand_mismatch': ((brandInRegistered || brandInSubdomain) && !brandInRegistered) ? 1 : 0,
            'domain_brand_similarity_registered': registeredSimilarity,
            'domain_brand_similarity_subdomain': subdomainSimilarity,
            'domain_brand_homograph': homographFlag
        };
    }

    /**
     * Get brand features for path-only extraction
     */
    getBrandFeaturesPathOnly(path, query) {
        const pathQuery = (path || '') + (query || '');
        const pathQueryLower = pathQuery.toLowerCase();

        const BRAND_KEYWORDS = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal',
            'ebay', 'netflix', 'twitter', 'instagram', 'linkedin', 'bank',
            'chase', 'wellsfargo', 'citibank', 'boa', 'netflix', 'outlook',
            'office365', 'icloud', 'gmail'];

        const brandInPath = BRAND_KEYWORDS.some(brand => pathQueryLower.includes(brand));
        const pathSimilarity = this.brandSimilarity(pathQueryLower);

        return {
            'path_suspicious_brand_usage': brandInPath ? 1 : 0,
            'path_brand_in_path_or_query': brandInPath ? 1 : 0,
            'path_brand_similarity_path': pathSimilarity
        };
    }

    /**
     * Helper methods for feature extraction
     */
    hasIPAddress(text) {
        const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
        return ipPattern.test(text);
    }

    hasSuspiciousTLD(tld) {
        const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'click', 'download', 'stream'];
        return suspiciousTLDs.includes(tld.toLowerCase());
    }

    isShortenedURL(url) {
        const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd'];
        return shorteners.some(shortener => url.includes(shortener));
    }

    hasSuspiciousParams(query) {
        const suspiciousParams = ['redirect', 'url', 'link', 'goto', 'target'];
        const params = new URLSearchParams(query);
        return Array.from(params.keys()).some(key => suspiciousParams.includes(key.toLowerCase()));
    }

    hasSuspiciousFileExtension(path) {
        const suspiciousExtensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif'];
        return suspiciousExtensions.some(ext => path.toLowerCase().includes(ext));
    }

    extractObfuscationMetrics(text) {
        if (!text) {
            return { has_obfuscation: 0, num_obfuscated_chars: 0, obfuscation_ratio: 0.0 };
        }

        const percentEncoded = (text.match(/%[0-9a-fA-F]{2}/g) || []).length;
        const hexEncoded = (text.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
        const unicodeEncoded = (text.match(/\\u[0-9a-fA-F]{4}/g) || []).length;
        const htmlEntities = (text.match(/&#x?[0-9a-fA-F]+;?/g) || []).length;

        const totalTokens = percentEncoded + hexEncoded + unicodeEncoded + htmlEntities;

        return {
            has_obfuscation: totalTokens > 0 ? 1 : 0,
            num_obfuscated_chars: totalTokens,
            obfuscation_ratio: totalTokens / text.length
        };
    }

    brandSimilarity(text) {
        if (!text) return 0.0;
        const BRAND_KEYWORDS = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal',
            'ebay', 'netflix', 'twitter', 'instagram', 'linkedin', 'bank',
            'chase', 'wellsfargo', 'citibank', 'boa', 'netflix', 'outlook',
            'office365', 'icloud', 'gmail'];
        
        let bestRatio = 0.0;
        for (const brand of BRAND_KEYWORDS) {
            const ratio = this.stringSimilarity(text, brand);
            if (ratio > bestRatio) {
                bestRatio = ratio;
            }
        }
        return bestRatio;
    }

    stringSimilarity(str1, str2) {
        const longer = str1.length > str2.length ? str1 : str2;
        const shorter = str1.length > str2.length ? str2 : str1;
        if (longer.length === 0) return 1.0;
        const distance = this.levenshteinDistance(longer, shorter);
        return (longer.length - distance) / longer.length;
    }

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

    calculateEntropy(text) {
        if (!text || text.length === 0) return 0;
        const freq = {};
        for (let i = 0; i < text.length; i++) {
            const char = text.charAt(i);
            freq[char] = (freq[char] || 0) + 1;
        }
        let entropy = 0;
        for (const char in freq) {
            const p = freq[char] / text.length;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    /**
     * Helper methods for explanations
     */
    getDomainFeaturesForExplanations(scaledFeatures, featureNames) {
        const features = {};
        for (let i = 0; i < featureNames.length; i++) {
            const name = featureNames[i];
            // Reverse scale to get original value (approximate)
            const mean = 0; // We'd need the actual mean, but for explanations we can use scaled
            const scale = 1;
            features[name] = scaledFeatures[name] || 0;
        }
        return features;
    }

    getPathFeaturesForExplanations(scaledFeatures, featureNames) {
        return this.getDomainFeaturesForExplanations(scaledFeatures, featureNames);
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = URLFeatureExtractor;
}
