(() => {
    "use strict";

    // Import necessary scripts for functionality.
    importScripts(
        // Util
        "util/UrlHelpers.js",
        "util/CacheManager.js",
        "util/Storage.js",
        "util/Settings.js",

        // Telemetry
        "util/telemetry/Telemetry.js",
        "util/telemetry/MessageType.js",

        // Hashing
        "util/hashing/MD5.js",
        "util/hashing/RC4.js",

        // Other
        "util/other/SmartScreenUtil.js",
        "util/other/EmsisoftUtil.js",

        // Protection
        "protection/ProtectionResult.js",
        "protection/BrowserProtection.js"
    );

    // Start a new telemetry session.
    Telemetry.startNewSession();

    // List of valid protocols (e.g., HTTP, HTTPS).
    const validProtocols = ['http:', 'https:'];

    // Function to handle navigation checks.
    const handleNavigation = (navigationDetails) => {
        Settings.get((settings) => {
            // Retrieve settings to check if protection is enabled.
            if (!settings.smartScreenEnabled
                && !settings.comodoEnabled
                && !settings.emsisoftEnabled
                && !settings.bitdefenderEnabled
                && !settings.nortonEnabled
                && !settings.totalEnabled
                && !settings.gDataEnabled) {
                console.warn("Protection is disabled; bailing out early.");
                return;
            }

            let {tabId, frameId, url: currentUrl} = navigationDetails;

            // Remove query parameters from the URL.
            currentUrl = currentUrl.replace(/\?.*$/, '');

            // Remove trailing slashes from the URL.
            currentUrl = currentUrl.replace(/\/+$/, '');

            // Remove www. from the start of the URL.
            currentUrl = currentUrl.replace(/https?:\/\/www\./, 'https://');

            // Check if the frame ID is not the main frame.
            if (frameId !== 0) {
                console.warn(`Ignoring frame navigation: ${currentUrl}; bailing out.`);
                return;
            }

            // Check if the URL is missing or incomplete.
            if (!currentUrl || !currentUrl.includes('://')) {
                console.debug(`Incomplete or missing URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Sanitize and encode the URL to handle spaces and special characters.
            try {
                currentUrl = encodeURI(currentUrl);
            } catch (error) {
                console.warn(`Failed to encode URL: ${currentUrl}; bailing out: ` + error);
                return;
            }

            // Parse the URL object.
            let urlObject;
            try {
                urlObject = new URL(currentUrl);
            } catch (error) {
                console.warn(`Invalid URL format: ${currentUrl}; bailing out: ` + error);
                return;
            }

            // Check for valid protocols.
            if (!validProtocols.includes(urlObject.protocol)) {
                console.warn(`Invalid protocol: ${urlObject.protocol}; bailing out.`);
                return;
            }

            // Check for missing hostname.
            if (!urlObject.hostname) {
                console.warn(`Missing hostname in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Check for incomplete URLs missing the scheme.
            if (!urlObject.protocol || currentUrl.startsWith('//')) {
                console.warn(`URL is missing a scheme: ${currentUrl}; bailing out.`);
                return;
            }

            // Check for obfuscated characters, encoding issues, or malicious patterns.
            const decodedUrl = decodeURIComponent(currentUrl);
            if (decodedUrl.includes('..') || /%2E/i.test(currentUrl)) {
                console.warn(`Suspicious encoding in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Check for long subdomain chains or overly nested subdomains.
            const subdomains = urlObject.hostname.split('.');
            if (subdomains.length > 4) {
                console.warn(`Suspiciously long subdomain chain in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Check if the hostname ends with a valid TLD.
            const tldRegex = /(\.[a-z]{2,63})$/i; // Matches any valid TLD (e.g., .com, .org, .co.uk, .io, etc.)
            if (!tldRegex.test(urlObject.hostname)) {
                console.warn(`Invalid or missing TLD in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Check for data URIs embedded in query parameters.
            if (currentUrl.includes('data:')) {
                console.warn(`Data URI found in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Exclude internal network addresses, loopback, or reserved domains.
            if (['localhost', '127.0.0.1'].includes(urlObject.hostname)
                || urlObject.hostname.endsWith('.local')
                || /^192\.168\.\d{1,3}\.\d{1,3}$/.test(urlObject.hostname)
                || /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(urlObject.hostname)
                || /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(urlObject.hostname)) {
                console.warn(`Local/internal network URL detected: ${currentUrl}; bailing out.`);
                return;
            }

            // Ensure no fragment-only URL.
            if (urlObject.href === urlObject.origin + urlObject.pathname && currentUrl.includes('#')) {
                console.warn(`Fragment-only URL detected: ${currentUrl}; bailing out.`);
                return;
            }

            // Skip URLs with unusual ports.
            const port = urlObject.port || (urlObject.protocol === 'https:' ? '443' : '80');
            if (!['80', '443'].includes(port)) {
                console.warn(`Non-standard port detected: ${port} in ${currentUrl}; bailing out.`);
                return;
            }

            // Ensure domain names are not obfuscated or invalid.
            if (urlObject.hostname.includes('xn--')) {
                console.warn(`IDN domain detected (Punycode): ${urlObject.hostname}; converting to ASCII.`);

                try {
                    urlObject.hostname = urlObject.hostname.toASCII(); // Convert IDN to ASCII
                } catch (error) {
                    console.warn(`Failed to convert IDN: ${currentUrl}; bailing out.`);
                    return;
                }
            }

            // Abandon any pending requests.
            BrowserProtection.abandonPendingRequests("Closed connection due to new navigation: " + navigationDetails.url);

            let malicious = false;
            console.log(`Checking URL: ${currentUrl}`);

            // Check if the URL is malicious.
            BrowserProtection.checkIfUrlIsMalicious(currentUrl, (result) => {
                const systemName = ProtectionResult.ResultOriginNames[result.origin];

                if (malicious) {
                    BrowserProtection.abandonPendingRequests("Malicious navigation already detected.");
                    return;
                }

                console.log(`[${systemName}] Result for ${currentUrl}: ${result.result}`);

                if (result.result !== ProtectionResult.ResultType.FAILED
                    && result.result !== ProtectionResult.ResultType.KNOWN_SAFE
                    && result.result !== ProtectionResult.ResultType.ALLOWED) {
                    malicious = true;

                    chrome.tabs.get(tabId, (tab) => {
                        if (!tab) {
                            console.log(`chrome.tabs.get(${tabId}) failed '${chrome.runtime.lastError?.message}'; bailing out.`);
                            return;
                        }

                        const pendingUrl = tab.pendingUrl || tab.url;

                        if (pendingUrl.startsWith("chrome-extension:")) {
                            console.log(`[${systemName}] The tab is at an extension page; bailing out.`);
                            return;
                        }

                        const targetUrl = frameId === 0 ? currentUrl : pendingUrl;

                        if (targetUrl) {
                            Telemetry.getInstanceID((instanceId) => {
                                const blockPageUrl = UrlHelpers.getBlockPageUrl(pendingUrl, result, instanceId, Telemetry.getSessionID());
                                console.log(`[${systemName}] Navigating to block page: ${blockPageUrl}.`);
                                chrome.tabs.update(tab.id, {url: blockPageUrl});
                            });
                        } else {
                            console.warn(`chrome.tab '${tabId}' failed to supply a top-level URL; bailing out.`);
                        }
                    });
                }
            });
        });
    };

    // Listener for before navigating events.
    chrome.webNavigation.onBeforeNavigate.addListener((navigationDetails) => {
        handleNavigation(navigationDetails);
    });

    // Listener for committed navigation events.
    chrome.webNavigation.onCommitted.addListener((navigationDetails) => {
        if (navigationDetails.transitionQualifiers.includes("server_redirect")) {
            handleNavigation(navigationDetails);
        }
    });

    // Listener for incoming messages.
    chrome.runtime.onMessage.addListener((message, sender) => {
        if (message && message.messageType) {
            switch (message.messageType) {
                case Messages.MessageType.CONTINUE_TO_SITE:
                    Telemetry.logWarningPageInteraction(message);

                    if (!message.continueUrl) {
                        console.warn(`No continue URL was found!`);
                        return;
                    }

                    if (!message.origin) {
                        console.warn(`No origin was found!`);
                        return;
                    }

                    let continueUrlObject = new URL(message.continueUrl);

                    // Redirects to the new tab page if the continue URL is not a valid HTTP(S) URL.
                    if (!validProtocols.includes(continueUrlObject.protocol)) {
                        chrome.tabs.update(sender.tab.id, {url: "about:newtab"});
                        return;
                    }

                    switch (message.origin) {
                        case "1":
                            console.warn(`Added SmartScreen URL to cache: ` + message.maliciousUrl);
                            BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "smartScreen");
                            break;

                        case "2":
                            console.warn(`Added Comodo URL to cache: ` + message.maliciousUrl);
                            BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "comodo");
                            break;

                        case "3":
                            console.warn(`Added Emsisoft URL to cache: ` + message.maliciousUrl);
                            BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "emsisoft");
                            break;

                        case "4":
                            console.warn(`Added Bitdefender URL to cache: ` + message.maliciousUrl);
                            BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "bitdefender");
                            break;

                        case "5":
                            console.warn(`Added Norton URL to cache: ` + message.maliciousUrl);
                            BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "norton");
                            break;

                        case "6":
                            console.warn(`Added TOTAL URL to cache: ` + message.maliciousUrl);
                            BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "total");
                            break;

                        case "7":
                            console.warn(`Added G Data URL to cache: ` + message.maliciousUrl);
                            BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "gData");
                            break;

                        default:
                            console.warn(`Unknown origin: ${message.origin}`);
                            break;
                    }

                    chrome.tabs.update(sender.tab.id, {url: message.continueUrl});
                    break;

                case Messages.MessageType.CONTINUE_TO_SAFETY:
                    Telemetry.logWarningPageInteraction(message);

                    setTimeout(() => {
                        chrome.tabs.update(sender.tab.id, {url: "about:newtab"});
                    }, 200);
                    break;

                case Messages.MessageType.SMARTSCREEN_TOGGLED:
                case Messages.MessageType.COMODO_TOGGLED:
                case Messages.MessageType.EMSISOFT_TOGGLED:
                case Messages.MessageType.BITDEFENDER_TOGGLED:
                case Messages.MessageType.NORTON_TOGGLED:
                case Messages.MessageType.TOTAL_TOGGLED:
                case Messages.MessageType.G_DATA_TOGGLED:
                    Telemetry.logSettingsChanged(message);
                    break;

                case Messages.MessageType.POPUP_LAUNCHED:
                    Telemetry.logPopupInteraction(message);
                    break;

                default:
                    console.warn(`Received unknown message type: ${message.messageType}`);
                    break;
            }
        }
    });
})();
