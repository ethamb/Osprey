"use strict";

// Main object for managing browser protection functionality
const BrowserProtection = function () {

    let tabAbortControllers = new Map();

    // Create a unique UUID for the MalwareURL API.
    const malwareURLUUID = UUIDUtil.createUUID();

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
             * Checks the URL with the SmartScreen API.
             */
            const checkUrlWithSmartScreen = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.smartScreenEnabled) {
                    console.debug(`[SmartScreen] Protection is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "smartScreen")) {
                    console.debug(`[SmartScreen] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "smartScreen")) {
                    console.debug(`[SmartScreen] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "smartScreen");

                // Prepare request data
                const requestData = JSON.stringify({
                    destination: {
                        uri: UrlHelpers.normalizeHostname(urlHostname + urlPathname)
                    }
                });

                // Generate the hash and authorization header
                const {hash, key} = SmartScreenUtil.hash(requestData);
                const authHeader = `SmartScreenHash ${btoa(JSON.stringify({
                    // Working Auth IDs (a.k.a. prodGuid):
                    // - 6d2e7d9c-1334-4fc2-a549-5ec504f0e8f1 (default)
                    // - 381ddd1e-e600-42de-94ed-8c34bf73f16d
                    // - be432eec-9895-4194-963C-d24f4a15bfaa
                    // - 41a438bc-1249-43d3-a26d-69cd62c08317
                    authId: "6d2e7d9c-1334-4fc2-a549-5ec504f0e8f1",
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
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.json();
                    const {responseCategory} = data;

                    switch (responseCategory) {
                        case "Phishing":
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                            break;

                        case "Malicious":
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                            break;

                        case "Untrusted":
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.UNTRUSTED, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                            break;

                        case "Allowed":
                            console.debug(`[SmartScreen] Added URL to allowed cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "smartScreen");
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                            break;

                        default:
                            console.warn(`[SmartScreen] Returned an unexpected result for URL ${url}: ${JSON.stringify(data)}`);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                            break;
                    }
                } catch (error) {
                    console.debug(`[SmartScreen] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with the Symantec API.
             */
            const checkUrlWithSymantec = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.symantecEnabled) {
                    console.debug(`[Symantec] Protection is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "symantec")) {
                    console.debug(`[Symantec] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "symantec")) {
                    console.debug(`[Symantec] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "symantec");

                // Replaces the http:// and https:// with nothing
                const trimmedUrl = url.replace(/^(http|https):\/\//, "");

                // Adds "/80/" after the first "/" character it sees
                // Example: malware.wicar.org/data/ms14_064_ole_xp.html becomes malware.wicar.org/80/data/ms14_064_ole_xp.html
                const trimmedUrlWithPort = trimmedUrl.replace(/\//, "/80/");

                // Checks if the URL has "/80/" in it. If it doesn't, it adds it to the end
                // Example: wicar.org becomes wicar.org/80/
                const trimmedUrlWithPortAndSlash = trimmedUrlWithPort.includes("/80/") ? trimmedUrlWithPort : trimmedUrlWithPort + "/80/";

                const apiUrl = `https://ent-shasta-rrs.symantec.com/webpulse/2/R/CA45FE7076BBCE1812A859E0AB82B49F/BRDSBPNWA1/-/GET/https/${trimmedUrlWithPortAndSlash}`;

                try {
                    const response = await fetch(apiUrl, {
                        method: "GET",
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[Symantec] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.text();

                    // Compromised Sites
                    if (data.includes("<DomC>7C") || data.includes("7C</DomC>")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.COMPROMISED, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Malicious Sources
                    if (data.includes("<DirC>2B") || data.includes("2B</DirC>")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Malicious Outbound Data
                    if (data.includes("<DirC>2C") || data.includes("2C</DirC>")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.UNTRUSTED, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Phishing
                    if (data.includes("<FileC>6C") || data.includes("6C</FileC>")
                        || data.includes("<DomC>12") || data.includes("12</DomC>")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Potentially Unwanted Applications
                    if (data.includes("<DomC>66") || data.includes("66</DomC>")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.PUA, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Scam/Questionable Legality
                    if (data.includes("<DirC>09") || data.includes("09</DirC>")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FRAUD, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Spam
                    if (data.includes("<DomC>65") || data.includes("65</DomC>")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.SPAM, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Safe/Trusted
                    console.debug(`[Symantec] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "symantec");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Symantec] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with the Emsisoft API.
             */
            const checkUrlWithEmsisoft = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.emsisoftEnabled) {
                    console.debug(`[Emsisoft] Protection is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "emsisoft")) {
                    console.debug(`[Emsisoft] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "emsisoft")) {
                    console.debug(`[Emsisoft] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "emsisoft");

                const hostnameArray = EmsisoftUtil.createHostnameArray(urlHostname);
                const stringOfHashes = EmsisoftUtil.getStringOfHashes(hostnameArray);
                const apiUrl = `https://alomar.emsisoft.com/api/v1/url/get/${stringOfHashes}`;

                try {
                    const response = await fetch(apiUrl, {
                        method: "GET",
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[Emsisoft] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.json();

                    // Allow if the hostname is in the bypass list
                    if (urlHostname.match(/alomar\.emsisoft\.com$/)) {
                        console.warn(`(This shouldn't happen) Added Emsisoft's own URL to allowed cache: ` + url);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "emsisoft");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Check if the URL should be blocked
                    for (const match of data.matches) {
                        const decoded = atob(match.regex);
                        const perUrlSalt = decoded.slice(0, 8);
                        const encryptedRegex = decoded.slice(8);
                        const subdomain = EmsisoftUtil.findSubdomainByHash(urlHostname, match.hash);
                        const key = MD5("Kd3fIjAq" + perUrlSalt + subdomain, null, true);
                        const result = RC4(key, encryptedRegex);

                        // Malicious
                        if (result.split("\t").some(value => value
                            && EmsisoftUtil.newRegExp(value, true)?.test(url))) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Safe/Trusted
                    console.debug(`[Emsisoft] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "emsisoft");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Emsisoft] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with the Bitdefender API.
             */
            const checkUrlWithBitdefender = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.bitdefenderEnabled) {
                    console.debug(`[Bitdefender] Protection is disabled; bailing out early.`);
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
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "bitdefender");

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
             * Checks the URL with the Norton API.
             */
            const checkUrlWithNorton = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.nortonEnabled) {
                    console.debug(`[Norton] Protection is disabled; bailing out early.`);
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
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "norton");

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
             * Checks the URL with the G DATA API.
             */
            const checkUrlWithGDATA = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.gDataEnabled) {
                    console.debug(`[G DATA] Protection is disabled; bailing out early.`);
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
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "gData");

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
             * Checks the URL with the MalwareURL API.
             */
            const checkUrlWithMalwareURL = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.malwareURLEnabled) {
                    console.debug(`[MalwareURL] Protection is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "malwareURL")) {
                    console.debug(`[MalwareURL] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.MALWAREURL), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "malwareURL")) {
                    console.debug(`[MalwareURL] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.MALWAREURL), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "malwareURL");

                const apiUrl = `https://www.malwareurl.com/api/?api_key=a2xo64&api_domain=${urlHostname}&browse=action&URL=${encodeURIComponent(urlObject.href)}&version=2.3&uuid=${malwareURLUUID}`;

                try {
                    const response = await fetch(apiUrl, {
                        method: "GET",
                        mode: "cors",
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[MalwareURL] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.MALWAREURL), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.text();

                    // Malicious
                    if (data === "1") {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.MALWAREURL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Safe/Trusted
                    if (data === "0") {
                        console.debug(`[MalwareURL] URL to allowed cache: ` + url);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "malwareURL");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.MALWAREURL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // UUID is Expired
                    if (data === "2") {
                        console.warn(`[MalwareURL] UUID is expired: ${data}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.MALWAREURL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Unexpected result
                    console.warn(`[MalwareURL] Returned an unexpected result for URL ${url}: ${data}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.MALWAREURL), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[MalwareURL] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.MALWAREURL), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Cloudflare's DNS APIs.
             */
            const checkUrlWithCloudflare = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.cloudflareEnabled) {
                    console.debug(`[Cloudflare] Protection is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "cloudflare")) {
                    console.debug(`[Cloudflare] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLOUDFLARE), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "cloudflare")) {
                    console.debug(`[Cloudflare] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CLOUDFLARE), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "cloudflare");

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
                        console.warn(`[Cloudflare] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLOUDFLARE), (new Date()).getTime() - startTime);
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
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CLOUDFLARE), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Cloudflare] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "cloudflare");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLOUDFLARE), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Cloudflare] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLOUDFLARE), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Quad9's DNS API.
             */
            const checkUrlWithQuad9 = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.quad9Enabled) {
                    console.debug(`[Quad9] Protection is disabled; bailing out early.`);
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
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "quad9");

                const filteringURL = `https://dns.quad9.net:5053/dns-query?name=${encodeURIComponent(urlHostname)}`;

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
                        console.warn(`[Quad9] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = await filteringResponse.json();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // Quad9's way of blocking the domain.
                        if (filteringData.Status === 3) {
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
             * Checks the URL with DNS0's DNS API.
             */
            const checkUrlWithDNS0 = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.dns0Enabled) {
                    console.debug(`[DNS0] Protection is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "dns0")) {
                    console.debug(`[DNS0] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.DNS0), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "dns0")) {
                    console.debug(`[DNS0] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.DNS0), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "dns0");

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
                        console.warn(`[DNS0] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS0), (new Date()).getTime() - startTime);
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
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.DNS0), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[DNS0] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "dns0");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.DNS0), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[DNS0] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS0), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with CleanBrowsing's DNS API.
             */
            const checkUrlWithCleanBrowsing = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.cleanBrowsingEnabled) {
                    console.debug(`[CleanBrowsing] Protection is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "cleanBrowsing")) {
                    console.debug(`[CleanBrowsing] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLEANBROWSING), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "cleanBrowsing")) {
                    console.debug(`[CleanBrowsing] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CLEANBROWSING), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "cleanBrowsing");

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
                        console.warn(`[CleanBrowsing] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING), (new Date()).getTime() - startTime);
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
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CLEANBROWSING), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[CleanBrowsing] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "cleanBrowsing");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLEANBROWSING), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[CleanBrowsing] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with CIRA's DNS API.
             */
            const checkUrlWithCIRA = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.ciraEnabled) {
                    console.debug(`[CIRA] Protection is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "cira")) {
                    console.debug(`[CIRA] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CIRA), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "cira")) {
                    console.debug(`[CIRA] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CIRA), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "cira");

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
                        console.warn(`[CIRA] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CIRA), (new Date()).getTime() - startTime);
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
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CIRA), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[CIRA] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "cira");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CIRA), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[CIRA] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CIRA), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with AdGuard's DNS API.
             */
            const checkUrlWithAdGuard = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.adGuardEnabled) {
                    console.debug(`[AdGuard] Protection is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "adGuard")) {
                    console.debug(`[AdGuard] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.ADGUARD), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "adGuard")) {
                    console.debug(`[AdGuard] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.ADGUARD), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "adGuard");

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
                        console.warn(`[AdGuard] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ADGUARD), (new Date()).getTime() - startTime);
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
                        if (filteringDataString.endsWith("0,0,1,0,1,192,12,0,1,0,1,0,0,14,16,0,4,94,140,14,33")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.ADGUARD), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[AdGuard] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "adGuard");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.ADGUARD), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[AdGuard] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ADGUARD), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Switch.ch's DNS API.
             */
            const checkUrlWithSwitchCH = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.switchCHEnabled) {
                    console.debug(`[Switch.ch] Protection is disabled; bailing out early.`);
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
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "switchCH");

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
             * Checks the URL with Switch.ch's DNS API.
             */
            const checkUrlWithCERTEE = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.certEEEnabled) {
                    console.debug(`[CERT-EE] Protection is disabled; bailing out early.`);
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
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "certEE");

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
             * Checks the URL with Control D's DNS API.
             */
            const checkUrlWithControlD = async function (settings) {
                // Check if the provider is enabled.
                if (!settings.controlDEnabled) {
                    console.debug(`[Control D] Protection is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the allowed cache.
                if (isUrlInAllowedCache(urlObject, urlHostname, "controlD")) {
                    console.debug(`[Control D] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CONTROL_D), (new Date()).getTime() - startTime);
                    return;
                }

                // Check if the URL is in the processing cache.
                if (isUrlInProcessingCache(urlObject, urlHostname, "controlD")) {
                    console.debug(`[Control D] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CONTROL_D), (new Date()).getTime() - startTime);
                    return;
                }

                // Add the URL to the processing cache to prevent duplicate requests.
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "controlD");

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
                        console.warn(`[Control D] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CONTROL_D), (new Date()).getTime() - startTime);
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
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CONTROL_D), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Control D] Added URL to allowed cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "controlD");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CONTROL_D), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Control D] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CONTROL_D), (new Date()).getTime() - startTime);
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
                // HTTP APIs
                checkUrlWithSymantec(settings);
                checkUrlWithBitdefender(settings);
                checkUrlWithSmartScreen(settings);
                checkUrlWithNorton(settings);
                checkUrlWithGDATA(settings);
                checkUrlWithEmsisoft(settings);
                checkUrlWithMalwareURL(settings);

                // DNS APIs
                checkUrlWithCloudflare(settings);
                checkUrlWithQuad9(settings);
                checkUrlWithDNS0(settings);
                checkUrlWithCleanBrowsing(settings);
                checkUrlWithCIRA(settings);
                checkUrlWithAdGuard(settings);
                checkUrlWithSwitchCH(settings);
                checkUrlWithCERTEE(settings);
                checkUrlWithControlD(settings);
            });

            // Clean up controllers for tabs that no longer exist
            cleanupTabControllers();
        }
    };
}();

// Initialize the cache manager
BrowserProtection.cacheManager = new CacheManager();
