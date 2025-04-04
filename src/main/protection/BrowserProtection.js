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
            // Return early if URL or callback is not provided
            if (!url || !callback) {
                return;
            }

            const startTime = (new Date()).getTime(); // Capture the current time for response measurement
            const urlObject = new URL(url); // Parse the URL

            // Ensure there is an AbortController for the tab
            if (!tabAbortControllers.has(tabId)) {
                tabAbortControllers.set(tabId, new AbortController());
            }

            const signal = tabAbortControllers.get(tabId).signal; // Get the signal from the current AbortController

            /**
             * Checks the URL with the SmartScreen API.
             */
            const checkUrlWithSmartScreen = async function () {
                Settings.get(async (settings) => {
                    if (!settings.smartScreenEnabled) {
                        console.debug(`SmartScreen is disabled; bailing out early.`);
                        return;
                    }

                    // Check if the URL is in the cache
                    if (BrowserProtection.cacheManager.isUrlInCache(urlObject, "smartScreen")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                        return;
                    }

                    const userLocale = navigator.languages ? navigator.languages[0] : navigator.language;

                    // Prepare request data
                    const requestData = JSON.stringify({
                        correlationId: Telemetry.generateGuid(),
                        destination: {uri: UrlHelpers.normalizeHostname(urlObject.hostname + urlObject.pathname)},
                        identity: {
                            client: {version: chrome.runtime.getManifest().version.replace(/\./g, "")},
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

                        // Check if we need to allow the URL
                        if (!response.ok) {
                            console.warn(`SmartScreen returned early: ${response.status}`);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                            return;
                        }

                        const data = await response.json();
                        console.debug(`SmartScreen response: ` + JSON.stringify(data));

                        switch (data.responseCategory) {
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
                                if (url !== null) {
                                    console.debug(`Added SmartScreen URL to cache: ` + url);
                                    BrowserProtection.cacheManager.addUrlToCache(urlObject, "smartScreen");
                                }

                                callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                                break;

                            default:
                                console.warn(`SmartScreen returned an unexpected result for URL ${url}: ${data.responseCategory}`);
                                callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                                break;
                        }
                    } catch (error) {
                        console.warn(`Failed to check URL with SmartScreen: ${error}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.MICROSOFT), (new Date()).getTime() - startTime);
                    }
                });
            };

            /**
             * Checks the URL with the Comodo API.
             */
            const checkUrlWithComodo = async function () {
                Settings.get(async (settings) => {
                    if (!settings.comodoEnabled) {
                        console.debug(`Comodo is disabled; bailing out early.`);
                        return;
                    }

                    // Check if the URL is in the cache
                    if (BrowserProtection.cacheManager.isUrlInCache(urlObject, "comodo")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.COMODO), (new Date()).getTime() - startTime);
                        return;
                    }

                    const apiUrl = `https://verdict.valkyrie.comodo.com/api/v1/url/query?url=${encodeURIComponent(url)}`;

                    try {
                        const response = await fetch(apiUrl, {
                            method: "POST",
                            headers: {
                                "X-Api-Key": await ComodoUtil.getXApiKey()
                            },
                            body: JSON.stringify({url}),
                            signal
                        });

                        // Return early if the response is not OK
                        if (!response.ok) {
                            console.warn(`Comodo returned early: ${response.status}`);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.COMODO), (new Date()).getTime() - startTime);
                            return;
                        }

                        const data = await response.json();
                        const {url_result_text} = data;
                        console.debug(`Comodo response: ` + JSON.stringify(data));

                        // Check the response for malicious categories
                        if (url_result_text === "Phishing") {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.COMODO), (new Date()).getTime() - startTime);
                        } else if (url_result_text === "Malware") {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.COMODO), (new Date()).getTime() - startTime);
                        } else if (url_result_text === "Safe" || url_result_text === "Unknown") {
                            if (url !== null) {
                                console.debug(`Added Comodo URL to cache: ` + url);
                                BrowserProtection.cacheManager.addUrlToCache(urlObject, "comodo");
                            }

                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.COMODO), (new Date()).getTime() - startTime);
                        } else {
                            console.warn(`Comodo returned an unexpected result for URL ${url}: ${url_result_text}`);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.COMODO), (new Date()).getTime() - startTime);
                        }
                    } catch (error) {
                        console.warn(`Failed to check URL with Comodo: ${error}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.COMODO), (new Date()).getTime() - startTime);
                    }
                });
            };

            /**
             * Checks the URL with the Emsisoft API.
             */
            const checkUrlWithEmsisoft = async function () {
                Settings.get(async (settings) => {
                    if (!settings.emsisoftEnabled) {
                        console.debug(`Emsisoft is disabled; bailing out early.`);
                        return;
                    }

                    // Check if the URL is in the cache
                    if (BrowserProtection.cacheManager.isUrlInCache(urlObject, "emsisoft")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                        return;
                    }

                    const hostname = new URL(url).hostname;
                    const hostnameArray = EmsisoftUtil.createHostnameArray(hostname);
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

                        // Allow if the hostname is in the bypass list
                        if (hostname.match(/alomar\.emsisoft\.com$/)) {
                            if (url !== null) {
                                console.debug(`Added Emsisoft URL to cache: ` + url);
                                BrowserProtection.cacheManager.addUrlToCache(urlObject, "emsisoft");
                            }

                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                            return;
                        }

                        const data = await response.json();
                        console.debug(`Emsisoft response: ` + JSON.stringify(data));

                        // Check if the URL should be blocked
                        for (const match of data.matches) {
                            const decoded = atob(match.regex);
                            const perUrlSalt = decoded.slice(0, 8);
                            const encryptedRegex = decoded.slice(8);
                            const subdomain = EmsisoftUtil.findSubdomainByHash(hostname, match.hash);
                            const key = MD5("Kd3fIjAq" + perUrlSalt + subdomain, null, true);
                            const result = RC4(key, encryptedRegex);

                            // If the URL matches the regex, block it
                            if (result.split("\t").some(value => value
                                && EmsisoftUtil.newRegExp(value, true)?.test(url))) {
                                // Check if the hostname is in the cache
                                if (BrowserProtection.cacheManager.isHostnameInCache(urlObject, "emsisoft")) {
                                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                                    return;
                                }

                                callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                                return;
                            }
                        }

                        // If the URL is not blocked, allow it
                        if (url !== null) {
                            console.debug(`Added Emsisoft URL to cache: ` + url);
                            BrowserProtection.cacheManager.addUrlToCache(urlObject, "emsisoft");
                        }

                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                    } catch (error) {
                        console.warn(`Failed to check URL with Emsisoft: ${error}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.EMSISOFT), (new Date()).getTime() - startTime);
                    }
                });
            };

            /**
             * Checks the URL with the Bitdefender API.
             */
            const checkUrlWithBitdefender = async function () {
                Settings.get(async (settings) => {
                    if (!settings.bitdefenderEnabled) {
                        console.debug(`Bitdefender is disabled; bailing out early.`);
                        return;
                    }

                    // Check if the URL is in the cache
                    if (BrowserProtection.cacheManager.isUrlInCache(urlObject, "bitdefender")) {
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
                        console.debug(`Bitdefender response: ` + JSON.stringify(data));

                        // Check if the hostname is in the cache
                        if (status_message.includes("phishing")
                            || status_message.includes("malware")
                            || status_message.includes("fraud")
                            || status_message.includes("pua")
                            || status_message.includes("miner")
                            || status_message.includes("malvertising")
                            || status_message.includes("untrusted")) {
                            if (BrowserProtection.cacheManager.isHostnameInCache(urlObject, "bitdefender")) {
                                callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                                return;
                            }
                        }

                        // Check the response for malicious categories
                        if (status_message.includes("phishing")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        } else if (status_message.includes("malware")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        } else if (status_message.includes("fraud")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.FRAUD, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        } else if (status_message.includes("pua")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.PUA, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        } else if (status_message.includes("miner")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.CRYPTOJACKING, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        } else if (status_message.includes("malvertising")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALVERTISING, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        } else if (status_message.includes("untrusted")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.UNTRUSTED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        } else if (status_message.includes("not found")) {
                            if (url !== null) {
                                console.debug(`Added Bitdefender URL to cache: ` + url);
                                BrowserProtection.cacheManager.addUrlToCache(urlObject, "bitdefender");
                            }

                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        } else {
                            console.warn(`Bitdefender returned an unexpected result for URL ${url}: ${status_message}`);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                        }
                    } catch (error) {
                        console.warn(`Failed to check URL with Bitdefender: ${error}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.BITDEFENDER), (new Date()).getTime() - startTime);
                    }
                });
            };

            /**
             * Checks the URL with the Norton API.
             */
            const checkUrlWithNorton = async function () {
                Settings.get(async (settings) => {
                    if (!settings.nortonEnabled) {
                        console.debug(`Norton is disabled; bailing out early.`);
                        return;
                    }

                    // Check if the URL is in the cache
                    if (BrowserProtection.cacheManager.isUrlInCache(urlObject, "norton")) {
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                        return;
                    }

                    const apiUrl = `https://ratings-wrs.norton.com/brief?url=${encodeURIComponent(url)}`;

                    try {
                        const response = await fetch(apiUrl, {
                            method: "GET",
                            headers: {
                                "Accept": "application/xml",
                                "x-nlok-country": "US",
                                "x-symc-user-agent": "xBP/SafeWeb"
                            },
                            signal
                        });

                        // Return early if the response is not OK
                        if (!response.ok) {
                            console.warn(`Norton returned early: ${response.status}`);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                            return;
                        }

                        const data = await response.text();
                        console.debug(`Norton response: ` + data);

                        // Check the response for malicious categories
                        if (data.includes('r="b"')) {
                            // Check if the hostname is in the cache
                            if (BrowserProtection.cacheManager.isHostnameInCache(urlObject, "norton")) {
                                callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                                return;
                            }

                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                        } else if (data.includes('r="g"')
                            || data.includes('r="r"')
                            || data.includes('r="w"')
                            || data.includes('r="u"')) {
                            if (url !== null) {
                                console.debug(`Added Norton URL to cache: ` + url);
                                BrowserProtection.cacheManager.addUrlToCache(urlObject, "norton");
                            }

                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                        } else {
                            console.warn(`Norton returned an unexpected result for URL ${url}: ${data}`);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                        }
                    } catch (error) {
                        console.warn(`Failed to check URL with Norton: ${error}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                    }
                });
            };

            /**
             * Checks the URL with the TOTAL API.
             */
            const checkUrlWithTOTAL = async function () {
                Settings.get(async (settings) => {
                    if (!settings.totalEnabled) {
                        console.debug(`TOTAL is disabled; bailing out early.`);
                        return;
                    }

                    // Check if the URL is in the cache
                    if (BrowserProtection.cacheManager.isUrlInCache(urlObject, "total")) {
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
                                "X-Categories": "adware,adware,call_center,compromised,crypto,fleeceware,low_trust,lowtrust,malware,phishing,pua,spam",
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
                        console.debug(`TOTAL response: ` + data);

                        // Check if the hostname is in the cache
                        if (data.includes('phishing')
                            || data.includes('malware')
                            || data.includes('crypto')
                            || data.includes('pua')
                            || data.includes('call_center')
                            || data.includes('adware')
                            || data.includes('spam')
                            || data.includes('compromised')
                            || data.includes('fleeceware')) {
                            if (BrowserProtection.cacheManager.isHostnameInCache(urlObject, "total")) {
                                callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                                return;
                            }
                        }

                        // Check the response for malicious categories
                        if (data.includes('phishing')) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        } else if (data.includes('malware')) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        } else if (data.includes('crypto')) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.CRYPTOJACKING, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        } else if (data.includes('pua')) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.PUA, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        } else if (data.includes('call_center')) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.FRAUD, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        } else if (data.includes('adware')) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ADWARE, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        } else if (data.includes('spam')) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.SPAM, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        } else if (data.includes('compromised')) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.COMPROMISED, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        } else if (data.includes('fleeceware')) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.FLEECEWARE, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        } else {
                            if (url !== null) {
                                console.debug(`Added TOTAL URL to cache: ` + url);
                                BrowserProtection.cacheManager.addUrlToCache(urlObject, "total");
                            }

                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                        }
                    } catch (error) {
                        console.warn(`Failed to check URL with TOTAL: ${error}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.TOTAL), (new Date()).getTime() - startTime);
                    }
                });
            };

            /**
             * Checks the URL with the G DATA API.
             */
            const checkUrlWithGDATA = async function () {
                Settings.get(async (settings) => {
                    if (!settings.gDataEnabled) {
                        console.debug(`G DATA is disabled; bailing out early.`);
                        return;
                    }

                    // Check if the URL is in the cache
                    if (BrowserProtection.cacheManager.isUrlInCache(urlObject, "gData")) {
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
                        console.debug(`G DATA response: ` + data);

                        // Check if the hostname is in the cache
                        if (data.includes("\"PHISHING\"")
                            || data.includes("\"MALWARE\"")) {
                            if (BrowserProtection.cacheManager.isHostnameInCache(urlObject, "gData")) {
                                callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                                return;
                            }
                        }

                        // Check the response for malicious categories
                        if (data.includes("\"PHISHING\"")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        } else if (data.includes("\"MALWARE\"")) {
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        } else if (data.includes("\"TRUSTED\"")
                            || data.includes("\"WHITELIST\"")
                            || data.includes("\"URLS\":[{}]}")) {
                            if (url !== null) {
                                console.debug(`Added G DATA URL to cache: ` + url);
                                BrowserProtection.cacheManager.addUrlToCache(urlObject, "gData");
                            }

                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        } else {
                            console.warn(`G DATA returned an unexpected result for URL ${url}: ${data}`);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        }
                    } catch (error) {
                        console.warn(`Failed to check URL with G DATA: ${error}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                    }
                });
            };

            Settings.get(checkUrlWithSmartScreen);
            checkUrlWithComodo();
            checkUrlWithEmsisoft();
            checkUrlWithBitdefender();
            checkUrlWithNorton();
            checkUrlWithTOTAL();
            checkUrlWithGDATA();
        }
    };
}();

BrowserProtection.cacheManager = new CacheManager();
