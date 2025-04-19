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
        browserAPI.tabs.query({}, (tabs) => {
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

            // Browser API compatibility between Chrome and Firefox
            const browserAPI = typeof browser === 'undefined' ? chrome : browser;

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
                // Check if SmartScreen is enabled
                if (!settings.smartScreenEnabled) {
                    console.debug(`SmartScreen is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "smartScreen")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                    return;
                }

                const userLocale = navigator.languages ? navigator.languages[0] : navigator.language;

                // Prepare request data
                const requestData = JSON.stringify({
                    correlationId: Telemetry.generateGuid(),

                    destination: {
                        uri: UrlHelpers.normalizeHostname(urlHostname + urlPathname)
                    },

                    identity: {
                        client: {version: browserAPI.runtime.getManifest().version.replace(/\./g, "")},
                        device: {id: settings.instanceID},
                        user: {locale: userLocale}
                    }
                });

                // Generate the hash and authorization header
                const {hash, key} = SmartScreenUtil.hash(requestData);
                const authHeader = `SmartScreenHash ${btoa(JSON.stringify({
                    authId: "6D2E7D9C-1334-4FC2-A549-5EC504F0E8F1",
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
                        console.warn(`SmartScreen returned early: ${response.status}`);
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
                            console.debug(`Added SmartScreen URL to cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToCache(urlObject, "smartScreen");
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                            break;

                        default:
                            console.warn(`SmartScreen returned an unexpected result for URL ${url}: ${JSON.stringify(data)}`);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                            break;
                    }
                } catch (error) {
                    console.debug(`Failed to check URL with SmartScreen: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with the Symantec API.
             */
            const checkUrlWithSymantec = async function (settings) {
                // Check if Symantec is enabled
                if (!settings.symantecEnabled) {
                    console.debug(`Symantec is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "symantec")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                    return;
                }

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
                        console.warn(`Symantec returned early: ${response.status}`);
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
                    console.debug(`Added Symantec URL to cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToCache(urlObject, "symantec");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with Symantec: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.SYMANTEC), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with the Emsisoft API.
             */
            const checkUrlWithEmsisoft = async function (settings) {
                // Check if Emsisoft is enabled
                if (!settings.emsisoftEnabled) {
                    console.debug(`Emsisoft is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "emsisoft")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                    return;
                }

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
                        console.warn(`Emsisoft returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.json();

                    // Allow if the hostname is in the bypass list
                    if (urlHostname.match(/alomar\.emsisoft\.com$/)) {
                        console.info(`(This shouldn't happen) Added Emsisoft's own URL to cache: ` + url);
                        BrowserProtection.cacheManager.addUrlToCache(urlObject, "emsisoft");
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
                    console.debug(`Added Emsisoft URL to cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToCache(urlObject, "emsisoft");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with Emsisoft: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with the Bitdefender API.
             */
            const checkUrlWithBitdefender = async function (settings) {
                // Check if Bitdefender is enabled
                if (!settings.bitdefenderEnabled) {
                    console.debug(`Bitdefender is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "bitdefender")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                    return;
                }

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
                        console.warn(`Bitdefender returned early: ${response.status}`);
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
                        console.debug(`Added Bitdefender URL to cache: ` + url);
                        BrowserProtection.cacheManager.addUrlToCache(urlObject, "bitdefender");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Unexpected result
                    console.warn(`Bitdefender returned an unexpected result for URL ${url}: ` + JSON.stringify(data));
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with Bitdefender: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with the Norton API.
             */
            const checkUrlWithNorton = async function (settings) {
                // Check if Norton is enabled
                if (!settings.nortonEnabled) {
                    console.debug(`Norton is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "norton")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                    return;
                }

                const apiUrl = `https://ratings-wrs.norton.com/brief?url=${encodeURIComponent(url)}`;

                try {
                    const response = await fetch(apiUrl, {
                        method: "GET",
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`Norton returned early: ${response.status}`);
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
                        console.debug(`Added Norton URL to cache: ` + url);
                        BrowserProtection.cacheManager.addUrlToCache(urlObject, "norton");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Unexpected result
                    console.warn(`Norton returned an unexpected result for URL ${url}: ${data}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with Norton: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with the TOTAL API.
             */
            const checkUrlWithTOTAL = async function (settings) {
                // Check if TOTAL is enabled
                if (!settings.totalEnabled) {
                    console.debug(`TOTAL is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "total")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                    return;
                }

                const apiUrl = "https://api.webshield.protected.net/e3/gsb/url";
                const payload = {url};

                try {
                    const response = await fetch(apiUrl, {
                        method: "POST",
                        headers: {
                            "Content-Type": "multipart/form-data",
                        },
                        body: JSON.stringify(payload),
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`TOTAL returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.text();

                    // Phishing
                    if (data.includes('phishing')) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Malicious
                    if (data.includes('malware')) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Cryptojacking
                    if (data.includes('crypto')) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.CRYPTOJACKING, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Potentially Unwanted Applications
                    if (data.includes('pua')) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.PUA, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Call Centers
                    if (data.includes('call_center')) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FRAUD, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Adware
                    if (data.includes('adware')) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ADWARE, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Spam
                    if (data.includes('spam')) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.SPAM, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Compromised
                    if (data.includes('compromised')) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.COMPROMISED, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Fleeceware
                    if (data.includes('fleeceware')) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FLEECEWARE, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Untrusted
                    if (data.includes('low_trust') || data.includes('lowtrust')) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.UNTRUSTED, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Safe/Trusted
                    if (data === "") {
                        console.debug(`Added TOTAL URL to cache: ` + url);
                        BrowserProtection.cacheManager.addUrlToCache(urlObject, "total");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Unexpected result
                    console.warn(`TOTAL returned an unexpected result for URL ${url}: ${data}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with TOTAL: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with the G DATA API.
             */
            const checkUrlWithGDATA = async function (settings) {
                // Check if G DATA is enabled
                if (!settings.gDataEnabled) {
                    console.debug(`G DATA is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "gData")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                    return;
                }

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
                        console.warn(`G DATA returned early: ${response.status}`);
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
                        console.debug(`Added G DATA URL to cache: ` + url);
                        BrowserProtection.cacheManager.addUrlToCache(urlObject, "gData");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Unexpected result
                    console.warn(`G DATA returned an unexpected result for URL ${url}: ${data}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with G DATA: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Cloudflare's DNS APIs.
             */
            const checkUrlWithCloudflare = async function (settings) {
                // Check if Cloudflare is enabled
                if (!settings.cloudflareEnabled) {
                    console.debug(`Cloudflare is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "cloudflare")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLOUDFLARE), (new Date()).getTime() - startTime);
                    return;
                }

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
                        console.warn(`Cloudflare returned early: ${filteringResponse.status}`);
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
                    console.debug(`Added Cloudflare URL to cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToCache(urlObject, "cloudflare");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLOUDFLARE), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with Cloudflare: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLOUDFLARE), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Quad9's DNS API.
             */
            const checkUrlWithQuad9 = async function (settings) {
                // Check if Quad9 is enabled
                if (!settings.quad9Enabled) {
                    console.debug(`Quad9 is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "quad9")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                    return;
                }

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
                        console.warn(`Quad9 returned early: ${filteringResponse.status}`);
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
                    console.debug(`Added Quad9 URL to cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToCache(urlObject, "quad9");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with Quad9: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with DNS0's DNS API.
             */
            const checkUrlWithDNS0 = async function (settings) {
                // Check if DNS0 is enabled
                if (!settings.dns0Enabled) {
                    console.debug(`DNS0 is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "dns0")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.DNS0), (new Date()).getTime() - startTime);
                    return;
                }

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
                        console.warn(`DNS0 returned early: ${filteringResponse.status}`);
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
                    console.debug(`Added DNS0 URL to cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToCache(urlObject, "dns0");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.DNS0), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with DNS0: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS0), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Control D's DNS API.
             */
            const checkUrlWithControlD = async function (settings) {
                // Check if ControlD is enabled
                if (!settings.controlDEnabled) {
                    console.debug(`Control D is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "controlD")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CONTROL_D), (new Date()).getTime() - startTime);
                    return;
                }

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
                        console.warn(`Control D returned early: ${filteringResponse.status}`);
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
                        if (filteringDataString.endsWith("60,0,4,0,0,0,0")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CONTROL_D), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`Added Control D URL to cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToCache(urlObject, "controlD");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CONTROL_D), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with Control D: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CONTROL_D), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with CleanBrowsing's DNS API.
             */
            const checkUrlWithCleanBrowsing = async function (settings) {
                // Check if CleanBrowsing is enabled
                if (!settings.cleanBrowsingEnabled) {
                    console.debug(`CleanBrowsing is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "cleanBrowsing")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLEANBROWSING), (new Date()).getTime() - startTime);
                    return;
                }

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
                        console.warn(`CleanBrowsing returned early: ${filteringResponse.status}`);
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
                    console.debug(`Added CleanBrowsing URL to cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToCache(urlObject, "cleanBrowsing");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLEANBROWSING), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with CleanBrowsing: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with Mullvad's DNS API.
             */
            const checkUrlWithMullvad = async function (settings) {
                // Check if Mullvad is enabled
                if (!settings.mullvadEnabled) {
                    console.debug(`Mullvad is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "mullvad")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.MULLVAD), (new Date()).getTime() - startTime);
                    return;
                }

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://base.dns.mullvad.net/dns-query?dns=${encodedQuery}`;

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
                        console.warn(`Mullvad returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.MULLVAD), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0
                        && nonFilteringData.Answer
                        && nonFilteringData.Answer.length > 0) {

                        // Mullvad's way of blocking the domain.
                        if (filteringData[3] === 131) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.MULLVAD), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`Added Mullvad URL to cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToCache(urlObject, "mullvad");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.MULLVAD), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with Mullvad: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.MULLVAD), (new Date()).getTime() - startTime);
                }
            };

            /**
             * Checks the URL with AdGuard's DNS API.
             */
            const checkUrlWithAdGuard = async function (settings) {
                // Check if AdGuard is enabled
                if (!settings.adGuardEnabled) {
                    console.debug(`AdGuard is disabled; bailing out early.`);
                    return;
                }

                // Check if the URL is in the cache
                if (isUrlInAnyCache(urlObject, urlHostname, "adGuard")) {
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.ADGUARD), (new Date()).getTime() - startTime);
                    return;
                }

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
                        console.warn(`AdGuard returned early: ${filteringResponse.status}`);
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
                    console.debug(`Added AdGuard URL to cache: ` + url);
                    BrowserProtection.cacheManager.addUrlToCache(urlObject, "adGuard");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.ADGUARD), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`Failed to check URL with AdGuard: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ADGUARD), (new Date()).getTime() - startTime);
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
             * Checks if the URL is in any cache.
             *
             * @param urlObject - The URL object.
             * @param hostname - The hostname of the URL.
             * @param provider - The provider to check the cache against.
             * @returns {boolean} - True if the URL is in the cache, false otherwise.
             */
            const isUrlInAnyCache = function (urlObject, hostname, provider) {
                return BrowserProtection.cacheManager.isUrlInCache(urlObject, provider)
                    || BrowserProtection.cacheManager.isStringInCache(hostname + " (allowed)", provider);
            };

            // Call all the check functions asynchronously
            Settings.get((settings) => {
                // HTTP APIs
                checkUrlWithSymantec(settings);
                checkUrlWithBitdefender(settings);
                checkUrlWithSmartScreen(settings);
                checkUrlWithNorton(settings);
                checkUrlWithTOTAL(settings);
                checkUrlWithGDATA(settings);
                checkUrlWithEmsisoft(settings);

                // DNS APIs
                checkUrlWithCloudflare(settings);
                checkUrlWithQuad9(settings);
                checkUrlWithDNS0(settings);
                checkUrlWithControlD(settings);
                checkUrlWithCleanBrowsing(settings);
                checkUrlWithMullvad(settings);
                checkUrlWithAdGuard(settings);
            });

            // Clean up controllers for tabs that no longer exist
            cleanupTabControllers();
        }
    };
}();

// Initialize the cache manager
BrowserProtection.cacheManager = new CacheManager();
