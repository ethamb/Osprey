"use strict";

// Main object for managing browser protection functionality
const BrowserProtection = function () {

    let tabAbortControllers = new Map();

    /**
     * Closes all open connections for a specific tab.
     */
    const closeOpenConnections = function (tabId, reason) {
        if (tabAbortControllers.has(tabId)) {
            tabAbortControllers.get(tabId).abort(reason); // Abort all pending requests for the tab
            tabAbortControllers.set(tabId, new AbortController()); // Create a new controller for future requests
        }
    };

    /**
     * Cleans up controllers for tabs that no longer exist.
     */
    const cleanupTabControllers = function () {
        // Browser API compatibility between Chrome and Firefox
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;

        // Remove controllers for tabs that no longer exist
        browserAPI.tabs.query({}, tabs => {
            const activeTabIds = new Set(tabs.map(tab => tab.id));

            for (const tabId of tabAbortControllers.keys()) {
                if (!activeTabIds.has(tabId)) {
                    tabAbortControllers.delete(tabId);
                    console.debug("Removed controller for tab ID: " + tabId);
                }
            }
        });
    };

    return {
        /**
         * Abandons all pending requests for a specific tab.
         */
        abandonPendingRequests: function (tabId, reason) {
            closeOpenConnections(tabId, reason);
        },

        /**
         * Checks if a URL is malicious or trusted.
         *
         * @param {number} tabId - The ID of the tab that initiated the request.
         * @param {string} url - The URL to check.
         * @param {function} callback - The callback function to handle the result.
         */
        checkIfUrlIsMalicious: function (tabId, url, callback) {
            // Return early if any of the parameters are missing
            if (!tabId || !url || !callback) {
                return;
            }

            // Capture the current time for response measurement
            const startTime = (new Date()).getTime();

            // Parse the URL to extract the hostname and pathname
            const urlObject = new URL(url);
            const urlHostname = urlObject.hostname;
            const urlPathname = urlObject.pathname;

            // The non-filtering URL used for DNS lookups
            const nonFilteringURL = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(urlHostname)}`;

            // Ensure there is an AbortController for the tab
            if (!tabAbortControllers.has(tabId)) {
                tabAbortControllers.set(tabId, new AbortController());
            }

            // Get the signal from the current AbortController
            const signal = tabAbortControllers.get(tabId).signal;

            /**
             * Checks the URL with PrecisionSec's API.
             */
            const checkUrlWithPrecisionSec = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.precisionSecEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "precisionSec")) {
                    console.debug(`[PrecisionSec] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "precisionSec")) {
                    console.debug(`[PrecisionSec] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "precisionSec", tabId);

                const apiUrl = `https://api.precisionsec.com/check_url/${encodeURIComponent(url)}`;

                try {
                    const response = await fetch(apiUrl, {
                        method: "GET",
                        headers: {
                            "Content-Type": "application/json",
                            "API-Key": "0b5b7628-382b-11f0-a59c-b3b5227b1076",
                        },
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[PrecisionSec] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.json();
                    const {result} = data;

                    // Malicious
                    if (result === "Malicious") {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Safe/Trusted
                    if (result === "No result") {
                        console.debug(`[PrecisionSec] Added URL to allowed cache: ` + url);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "precisionSec");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Unexpected result
                    console.warn(`[PrecisionSec] Returned an unexpected result for URL ${url}: ${data}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[PrecisionSec] Failed to check URL: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Bitdefender's API.
             */
            const checkUrlWithBitdefender = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.bitdefenderEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "bitdefender")) {
                    console.debug(`[Bitdefender] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "bitdefender")) {
                    console.debug(`[Bitdefender] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "bitdefender", tabId);

                const apiUrl = "https://nimbus.bitdefender.net/url/status";
                const payload = {url};

                try {
                    const response = await fetch(apiUrl, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "X-Nimbus-Client-Id": "a4c35c82-b0b5-46c3-b641-41ed04075269",
                        },
                        body: JSON.stringify(payload),
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[Bitdefender] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.json();
                    const {status_message} = data;

                    // Phishing
                    if (status_message.includes("phishing")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Malware
                    if (status_message.includes("malware")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Fraud
                    if (status_message.includes("fraud")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FRAUD, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Potentially Unwanted Applications
                    if (status_message.includes("pua")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.PUA, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Cryptojacking
                    if (status_message.includes("miner")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.CRYPTOJACKING, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Malvertising
                    if (status_message.includes("malvertising")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.MALVERTISING, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Untrusted
                    if (status_message.includes("untrusted")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.UNTRUSTED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Command & Control
                    if (status_message.includes("c&c")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.COMPROMISED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Safe/Trusted
                    if (status_message.includes("not found")) {
                        console.debug(`[Bitdefender] Added URL to allowed cache: ` + url);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "bitdefender");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Unexpected result
                    console.warn(`[Bitdefender] Returned an unexpected result for URL ${url}: ${JSON.stringify(data)}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Bitdefender] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with G DATA's API.
             */
            const checkUrlWithGDATA = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.gDataEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "gData")) {
                    console.debug(`[G DATA] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "gData")) {
                    console.debug(`[G DATA] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "gData", tabId);

                const apiUrl = "https://dlarray-bp-europ-secsrv069.gdatasecurity.de/url/v3";

                const payload = {
                    "REVOKEID": 0,
                    "CLIENT": "EXED",
                    "CLV": "1.14.0 25.5.17.335 129.0.0.0",
                    "URLS": [url]
                };

                try {
                    const response = await fetch(apiUrl, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json"
                        },
                        body: JSON.stringify(payload),
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[G DATA] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.text();

                    // Phishing
                    if (data.includes("\"PHISHING\"")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Malicious
                    if (data.includes("\"MALWARE\"")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Safe/Allowed
                    if (data.includes("\"TRUSTED\"")
                        || data.includes("\"WHITELIST\"")
                        || data.includes("\"URLS\":[{}]}")) {
                        console.debug(`[G DATA] Added URL to allowed cache: ` + url);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "gData");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Unexpected result
                    console.warn(`[G DATA] Returned an unexpected result for URL ${url}: ${data}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[G DATA] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with SmartScreen's API.
             */
            const checkUrlWithSmartScreen = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.smartScreenEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "smartScreen")) {
                    console.debug(`[SmartScreen] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "smartScreen")) {
                    console.debug(`[SmartScreen] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "smartScreen", tabId);

                // Prepare request data
                const requestData = JSON.stringify({
                    destination: {
                        uri: UrlHelpers.normalizeHostname(urlHostname + urlPathname)
                    }
                });

                // Generate the hash and authorization header
                const {hash, key} = SmartScreenUtil.hash(requestData);
                const authHeader = `SmartScreenHash ${btoa(JSON.stringify({
                    authId: "381ddd1e-e600-42de-94ed-8c34bf73f16d",
                    hash,
                    key
                }))}`;

                try {
                    const response = await fetch("https://bf.smartscreen.microsoft.com/api/browser/Navigate/1", {
                        method: "POST",
                        credentials: "omit",
                        headers: {
                            "Content-Type": "application/json; charset=utf-8",
                            Authorization: authHeader
                        },
                        body: requestData,
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[SmartScreen] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.json();
                    const {responseCategory} = data;

                    switch (responseCategory) {
                        case "Phishing":
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                            break;

                        case "Malicious":
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                            break;

                        case "Untrusted":
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.UNTRUSTED, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                            break;

                        case "Allowed":
                            console.debug(`[SmartScreen] Added URL to allowed cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "smartScreen");
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                            break;

                        default:
                            console.warn(`[SmartScreen] Returned an unexpected result for URL ${url}: ${JSON.stringify(data)}`);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                            break;
                    }
                } catch (error) {
                    console.debug(`[SmartScreen] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Norton's API.
             */
            const checkUrlWithNorton = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.nortonEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "norton")) {
                    console.debug(`[Norton] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "norton")) {
                    console.debug(`[Norton] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "norton", tabId);

                const apiUrl = `https://ratings-wrs.norton.com/brief?url=${encodeURIComponent(url)}`;

                try {
                    const response = await fetch(apiUrl, {
                        method: "GET",
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[Norton] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.text();

                    // Malicious
                    if (data.includes('r="b"')) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Safe/Trusted
                    if (data.includes('r="g"')
                        || data.includes('r="r"')
                        || data.includes('r="w"')
                        || data.includes('r="u"')) {
                        console.debug(`[Norton] Added URL to allowed cache: ` + url);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "norton");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Unexpected result
                    console.warn(`[Norton] Returned an unexpected result for URL ${url}: ${data}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Norton] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with AdGuard's Security DNS API.
             */
            const checkUrlWithAdGuardSecurity = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.adGuardSecurityEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "adGuardSecurity")) {
                    console.debug(`[AdGuard Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "adGuardSecurity")) {
                    console.debug(`[AdGuard Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "adGuardSecurity", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://dns.adguard-dns.com/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[AdGuard Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // AdGuard's way of blocking the domain.
                        if (filteringDataString.includes("0,0,1,0,1,192,12,0,1,0,1,0,0,14,16,0,4,94,140,14,3")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[AdGuard Security] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "adGuardSecurity");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[AdGuard Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with AdGuard's Family DNS API.
             */
            const checkUrlWithAdGuardFamily = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.adGuardFamilyEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "adGuardFamily")) {
                    console.debug(`[AdGuard Family] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "adGuardFamily")) {
                    console.debug(`[AdGuard Family] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "adGuardFamily", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://family.adguard-dns.com/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[AdGuard Family] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        console.debug(`[AdGuard Family] Filtering data: ${filteringDataString}`);

                        // AdGuard's way of blocking the domain.
                        if (filteringDataString.includes("0,0,1,0,1,192,12,0,1,0,1,0,0,14,16,0,4,94,140,14,3")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.RESTRICTED, ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[AdGuard Family] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "adGuardFamily");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[AdGuard Family] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with CERT-EE's DNS API.
             */
            const checkUrlWithCERTEE = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.certEEEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "certEE")) {
                    console.debug(`[CERT-EE] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "certEE")) {
                    console.debug(`[CERT-EE] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "certEE", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://dns.cert.ee/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[CERT-EE] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // CERT-EE's way of blocking the domain.
                        if (filteringDataString.endsWith("180,0,0,9,58,128")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[CERT-EE] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "certEE");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[CERT-EE] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with CIRA's Security DNS API.
             */
            const checkUrlWithCIRASecurity = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.ciraSecurityEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "ciraSecurity")) {
                    console.debug(`[CIRA Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CIRA_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "ciraSecurity")) {
                    console.debug(`[CIRA Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CIRA_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "ciraSecurity", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://protected.canadianshield.cira.ca/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[CIRA Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CIRA_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // CIRA's way of blocking the domain.
                        if (filteringDataString.includes("0,1,0,1,0,0,0,0,0,4")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CIRA_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[CIRA Security] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "ciraSecurity");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CIRA_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[CIRA Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CIRA_SECURITY), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with CIRA's Family DNS API.
             */
            const checkUrlWithCIRAFamily = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.ciraFamilyEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "ciraFamily")) {
                    console.debug(`[CIRA Family] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CIRA_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "ciraFamily")) {
                    console.debug(`[CIRA Family] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CIRA_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "ciraFamily", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://family.canadianshield.cira.ca/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[CIRA Family] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CIRA_FAMILY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // CIRA's way of blocking the domain.
                        if (filteringDataString.includes("0,1,0,1,0,0,0,0,0,4")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.RESTRICTED, ProtectionResult.ResultOrigin.CIRA_FAMILY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[CIRA Family] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "ciraFamily");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CIRA_FAMILY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[CIRA Family] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CIRA_FAMILY), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with CleanBrowsing's Security DNS API.
             */
            const checkUrlWithCleanBrowsingSecurity = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.cleanBrowsingSecurityEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "cleanBrowsingSecurity")) {
                    console.debug(`[CleanBrowsing Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "cleanBrowsingSecurity")) {
                    console.debug(`[CleanBrowsing Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "cleanBrowsingSecurity", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://doh.cleanbrowsing.org/doh/security-filter/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[CleanBrowsing Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // CleanBrowsing's way of blocking the domain.
                        if (filteringData[3] === 131) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[CleanBrowsing Security] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "cleanBrowsingSecurity");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[CleanBrowsing Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with CleanBrowsing's Family DNS API.
             */
            const checkUrlWithCleanBrowsingFamily = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.cleanBrowsingFamilyEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "cleanBrowsingFamily")) {
                    console.debug(`[CleanBrowsing Family] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "cleanBrowsingFamily")) {
                    console.debug(`[CleanBrowsing Family] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "cleanBrowsingFamily", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://doh.cleanbrowsing.org/doh/family-filter/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[CleanBrowsing Family] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // CleanBrowsing's way of blocking the domain.
                        if (filteringData[3] === 131) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.RESTRICTED, ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[CleanBrowsing Family] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "cleanBrowsingFamily");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[CleanBrowsing Family] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with CleanBrowsing's Adult DNS API.
             */
            const checkUrlWithCleanBrowsingAdult = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.cleanBrowsingAdultEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "cleanBrowsingAdult")) {
                    console.debug(`[CleanBrowsing Adult] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLEANBROWSING_ADULT), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "cleanBrowsingAdult")) {
                    console.debug(`[CleanBrowsing Adult] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CLEANBROWSING_ADULT), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "cleanBrowsingAdult", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://doh.cleanbrowsing.org/doh/adult-filter/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[CleanBrowsing Adult] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING_ADULT), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // CleanBrowsing's way of blocking the domain.
                        if (filteringData[3] === 131) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.RESTRICTED, ProtectionResult.ResultOrigin.CLEANBROWSING_ADULT), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[CleanBrowsing Adult] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "cleanBrowsingAdult");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLEANBROWSING_ADULT), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[CleanBrowsing Adult] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING_ADULT), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Cloudflare's Security DNS APIs.
             */
            const checkUrlWithCloudflareSecurity = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.cloudflareSecurityEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "cloudflareSecurity")) {
                    console.debug(`[Cloudflare Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "cloudflareSecurity")) {
                    console.debug(`[Cloudflare Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "cloudflareSecurity", tabId);

                const filteringURL = `https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(urlHostname)}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[Cloudflare Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = await filteringResponse.json();
                    const filteringDataString = JSON.stringify(filteringData);
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // Cloudflare's way of blocking the domain.
                        if (filteringDataString.includes("EDE(16): Censored")
                            || filteringDataString.includes("\"TTL\":60,\"data\":\"0.0.0.0\"")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Cloudflare Security] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "cloudflareSecurity");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Cloudflare Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Cloudflare's Family DNS APIs.
             */
            const checkUrlWithCloudflareFamily = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.cloudflareFamilyEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "cloudflareFamily")) {
                    console.debug(`[Cloudflare Family] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "cloudflareFamily")) {
                    console.debug(`[Cloudflare Family] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "cloudflareFamily", tabId);

                const filteringURL = `https://family.cloudflare-dns.com/dns-query?name=${encodeURIComponent(urlHostname)}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[Cloudflare Family] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = await filteringResponse.json();
                    const filteringDataString = JSON.stringify(filteringData);
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // Cloudflare's way of blocking the domain.
                        if (filteringDataString.includes("EDE(16): Censored")
                            || filteringDataString.includes("\"TTL\":60,\"data\":\"0.0.0.0\"")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.RESTRICTED, ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Cloudflare Family] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "cloudflareFamily");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Cloudflare Family] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Control D's DNS API.
             */
            const checkUrlWithControlDSecurity = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.controlDSecurityEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "controlDSecurity")) {
                    console.debug(`[Control D Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "controlDSecurity")) {
                    console.debug(`[Control D Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "controlDSecurity", tabId);

                const filteringURL = `https://freedns.controld.com/p1?name=${encodeURIComponent(urlHostname)}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[Control D Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // ControlD's way of blocking the domain.
                        if (filteringDataString.endsWith("0,4,0,0,0,0")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Control D Security] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "controlDSecurity");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Control D Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Control D's Family DNS API.
             */
            const checkUrlWithControlDFamily = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.controlDFamilyEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "controlDFamily")) {
                    console.debug(`[Control D Family] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "controlDFamily")) {
                    console.debug(`[Control D Family] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "controlDFamily", tabId);

                const filteringURL = `https://freedns.controld.com/family?name=${encodeURIComponent(urlHostname)}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[Control D Family] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // ControlD's way of blocking the domain.
                        if (filteringDataString.endsWith("0,4,0,0,0,0")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Control D Family] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "controlDFamily");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Control D Family] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with DNS0's Security DNS API.
             */
            const checkUrlWithDNS0Security = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.dns0SecurityEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "dns0Security")) {
                    console.debug(`[DNS0 Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "dns0Security")) {
                    console.debug(`[DNS0 Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "dns0Security", tabId);

                const filteringURL = `https://zero.dns0.eu/dns-query?name=${encodeURIComponent(urlHostname)}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[DNS0 Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = await filteringResponse.json();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // DNS0's way of blocking the domain.
                        if (filteringData.Status === 3) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[DNS0 Security] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "dns0Security");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[DNS0 Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with DNS0's Kids DNS API.
             */
            const checkUrlWithDNS0Kids = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.dns0KidsEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "dns0Kids")) {
                    console.debug(`[DNS0 Kids] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.DNS0_KIDS), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "dns0Kids")) {
                    console.debug(`[DNS0 Kids] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.DNS0_KIDS), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "dns0Kids", tabId);

                const filteringURL = `https://kids.dns0.eu/dns-query?name=${encodeURIComponent(urlHostname)}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[DNS0 Kids] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS0_KIDS), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = await filteringResponse.json();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // DNS0's way of blocking the domain.
                        if (filteringData.Status === 3) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.RESTRICTED, ProtectionResult.ResultOrigin.DNS0_KIDS), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[DNS0 Kids] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "dns0Kids");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.DNS0_KIDS), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[DNS0 Kids] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS0_KIDS), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with OpenDNS's Security DNS API.
             */
            const checkUrlWithOpenDNSSecurity = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.openDNSSecurityEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "openDNSSecurity")) {
                    console.debug(`[OpenDNS Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.OPENDNS_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "openDNSSecurity")) {
                    console.debug(`[OpenDNS Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.OPENDNS_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "openDNSSecurity", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://doh.opendns.com/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[OpenDNS Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.OPENDNS_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // OpenDNS's way of blocking the domain.
                        if (filteringDataString.includes("0,1,0,1,0,0,0,0,0,4")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.OPENDNS_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[OpenDNS Security] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "openDNSSecurity");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.OPENDNS_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[OpenDNS Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.OPENDNS_SECURITY), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with OpenDNS's Family Shield DNS API.
             */
            const checkUrlWithOpenDNSFamilyShield = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.openDNSFamilyShieldEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "openDNSFamilyShield")) {
                    console.debug(`[OpenDNS Family Shield] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.OPENDNS_FAMILY_SHIELD), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "openDNSFamilyShield")) {
                    console.debug(`[OpenDNS Family Shield] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.OPENDNS_FAMILY_SHIELD), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "openDNSFamilyShield", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://doh.familyshield.opendns.com/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[OpenDNS Family Shield] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.OPENDNS_FAMILY_SHIELD), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // OpenDNS's way of blocking the domain.
                        if (filteringDataString.includes("0,1,0,1,0,0,0,0,0,4")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.RESTRICTED, ProtectionResult.ResultOrigin.OPENDNS_FAMILY_SHIELD), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[OpenDNS Family Shield] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "openDNSFamilyShield");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.OPENDNS_FAMILY_SHIELD), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[OpenDNS Family Shield] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.OPENDNS_FAMILY_SHIELD), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Quad9's DNS API.
             */
            const checkUrlWithQuad9 = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.quad9Enabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "quad9")) {
                    console.debug(`[Quad9] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "quad9")) {
                    console.debug(`[Quad9] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "quad9", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://dns.quad9.net/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[Quad9] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // Quad9's way of blocking the domain.
                        if (filteringData[3] === 3) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Quad9] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "quad9");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Quad9] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Switch.ch's DNS API.
             */
            const checkUrlWithSwitchCH = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.switchCHEnabled) {
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "switchCH")) {
                    console.debug(`[Switch.ch] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.SWITCH_CH), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "switchCH")) {
                    console.debug(`[Switch.ch] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.SWITCH_CH), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "switchCH", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://dns.switch.ch/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Return early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[Switch.ch] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.SWITCH_CH), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    const maliciousResultSURBL = "0,0,0,180,0,0,0,180,0,9,58,128,0,0,0,10";
                    const maliciousResultRPZ = "0,0,2,88,0,0,1,44,0,9,58,128,0,0,1,44";

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // Switch.ch's way of blocking the domain.
                        if (filteringDataString.endsWith(maliciousResultSURBL)
                            || filteringDataString.endsWith(maliciousResultRPZ)) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.SWITCH_CH), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Switch.ch] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "switchCH");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.SWITCH_CH), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Switch.ch] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.SWITCH_CH), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Encodes a DNS query for the given domain and type.
             *
             * @param {string} domain - The domain to encode.
             * @param {number} type - The type of DNS record (default is 1 for A record).
             */
            function encodeDnsQuery(domain, type = 1) {
                // Create DNS query components
                const header = new Uint8Array([
                    0x00, 0x00, // ID (0)
                    0x01, 0x00, // Flags: standard query
                    0x00, 0x01, // QDCOUNT: 1 question
                    0x00, 0x00, // ANCOUNT: 0 answers
                    0x00, 0x00, // NSCOUNT: 0 authority records
                    0x00, 0x00  // ARCOUNT: 0 additional records
                ]);

                // Encode domain parts
                const domainParts = domain.split('.');
                let domainBuffer = [];

                for (const part of domainParts) {
                    domainBuffer.push(part.length);

                    for (let i = 0; i < part.length; i++) {
                        domainBuffer.push(part.charCodeAt(i));
                    }
                }

                // Add terminating zero
                domainBuffer.push(0);

                // Add QTYPE and QCLASS
                domainBuffer.push(0x00, type); // QTYPE (1 = A record)
                domainBuffer.push(0x00, 0x01); // QCLASS (1 = IN)

                // Combine header and domain parts
                const dnsPacket = new Uint8Array([...header, ...domainBuffer]);

                // Base64url encode
                return btoa(String.fromCharCode(...dnsPacket))
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=+$/, '');
            }

            /**
             * Checks if the URL is in the allowed caches.
             *
             * @param urlObject - The URL object.
             * @param hostname - The hostname of the URL.
             * @param provider - The provider to check the allowed cache against.
             * @returns {boolean} - True if the URL is in the allowed cache, false otherwise.
             */
            const isUrlInAllowedCache = function (urlObject, hostname, provider) {
                return BrowserProtection.cacheManager.isUrlInAllowedCache(urlObject, provider)
                    || BrowserProtection.cacheManager.isStringInAllowedCache(hostname + " (allowed)", provider);
            };

            /**
             * Checks if the URL is in the allowed caches.
             *
             * @param urlObject - The URL object.
             * @param hostname - The hostname of the URL.
             * @param provider - The provider to check the allowed cache against.
             * @returns {boolean} - True if the URL is in the allowed cache, false otherwise.
             */
            const isUrlInProcessingCache = function (urlObject, hostname, provider) {
                return BrowserProtection.cacheManager.isUrlInProcessingCache(urlObject, provider)
                    || BrowserProtection.cacheManager.isStringInProcessingCache(hostname, provider);
            };

            // Call all the check functions asynchronously
            Settings.get(settings => {
                // Page 1
                checkUrlWithPrecisionSec(settings);
                checkUrlWithBitdefender(settings);
                checkUrlWithGDATA(settings);
                checkUrlWithSmartScreen(settings);
                checkUrlWithNorton(settings);
                checkUrlWithAdGuardSecurity(settings);
                checkUrlWithAdGuardFamily(settings);

                // Page 2
                checkUrlWithCERTEE(settings);
                checkUrlWithCIRASecurity(settings);
                checkUrlWithCIRAFamily(settings);
                checkUrlWithCleanBrowsingSecurity(settings);
                checkUrlWithCleanBrowsingFamily(settings);
                checkUrlWithCleanBrowsingAdult(settings);
                checkUrlWithCloudflareSecurity(settings);

                // Page 3
                checkUrlWithCloudflareFamily(settings);
                checkUrlWithControlDSecurity(settings);
                checkUrlWithControlDFamily(settings);
                checkUrlWithDNS0Security(settings);
                checkUrlWithDNS0Kids(settings);
                checkUrlWithOpenDNSSecurity(settings);
                checkUrlWithOpenDNSFamilyShield(settings);

                // Page 4
                checkUrlWithQuad9(settings);
                checkUrlWithSwitchCH(settings);
            });

            // Clean up controllers for tabs that no longer exist
            cleanupTabControllers();
        }
    };
}();

// Initialize the cache manager
BrowserProtection.cacheManager = new CacheManager();
