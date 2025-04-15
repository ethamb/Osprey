(() => {
    "use strict";

    // Browser API compatibility between Chrome and Firefox
    const browserAPI = chrome || browser;

    // Import necessary scripts for functionality (only on Chrome)
    if (browserAPI === chrome) {
        importScripts(
            // Util
            "util/Settings.js",
            "util/UrlHelpers.js",
            "util/CacheManager.js",
            "util/Storage.js",

            // Other
            "util/other/SmartScreenUtil.js",
            "util/other/EmsisoftUtil.js",

            // Telemetry
            "util/telemetry/Telemetry.js",
            "util/telemetry/MessageType.js",

            // Hashing
            "util/hashing/MD5.js",
            "util/hashing/RC4.js",

            // Protection
            "protection/ProtectionResult.js",
            "protection/BrowserProtection.js"
        );
    }

    // Start a new telemetry session.
    Telemetry.startNewSession();

    // List of valid protocols (e.g., HTTP, HTTPS).
    const validProtocols = ['http:', 'https:'];

    // Function to handle navigation checks.
    const handleNavigation = (navigationDetails) => {
        Settings.get((settings) => {
            // Retrieve settings to check if protection is enabled.
            if (!settings.smartScreenEnabled
                && !settings.symantecEnabled
                && !settings.emsisoftEnabled
                && !settings.bitdefenderEnabled
                && !settings.nortonEnabled
                && !settings.totalEnabled
                && !settings.gDataEnabled) {
                console.warn("Protection is disabled; bailing out early.");
                return;
            }

            let {tabId, frameId, url: currentUrl} = navigationDetails;

            // Check if the frame ID is not the main frame.
            if (frameId !== 0) {
                console.debug(`Ignoring frame navigation: ${currentUrl} #${frameId}; bailing out.`);
                return;
            }

            // Check if the URL is missing or incomplete.
            if (!currentUrl || !currentUrl.includes('://')) {
                console.debug(`Incomplete or missing URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Remove query parameters from the URL.
            currentUrl = currentUrl.replace(/\?.*$/, '');

            // Remove trailing slashes from the URL.
            currentUrl = currentUrl.replace(/\/+$/, '');

            // Remove www. from the start of the URL.
            currentUrl = currentUrl.replace(/https?:\/\/www\./, 'https://');

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

            const protocol = urlObject.protocol;
            let hostname = urlObject.hostname;
            const pathname = urlObject.pathname;
            const href = urlObject.href;
            const origin = urlObject.origin;

            // Check for incomplete URLs missing the scheme.
            if (!protocol || currentUrl.startsWith('//')) {
                console.warn(`URL is missing a scheme: ${currentUrl}; bailing out.`);
                return;
            }

            // Check for valid protocols.
            if (!validProtocols.includes(protocol)) {
                console.debug(`Invalid protocol: ${protocol}; bailing out.`);
                return;
            }

            // Check for missing hostname.
            if (!hostname) {
                console.warn(`Missing hostname in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Check for obfuscated characters, encoding issues, or malicious patterns.
            const decodedUrl = decodeURIComponent(currentUrl);
            if (decodedUrl.includes('..') || /%2E/i.test(currentUrl)) {
                console.warn(`Suspicious encoding in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Check for long subdomain chains or overly nested subdomains.
            const subdomains = hostname.split('.');
            if (subdomains.length > 4) {
                console.warn(`Suspiciously long subdomain chain in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Check if the hostname ends with a valid TLD.
            const tldRegex = /(\.[a-z]{2,63})$/i; // Matches any valid TLD (e.g., .com, .org, .co.uk, .io, etc.)
            if (!tldRegex.test(hostname)) {
                console.debug(`Invalid or missing TLD in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Check for data URIs embedded in query parameters.
            if (currentUrl.includes('data:')) {
                console.warn(`Data URI found in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Exclude internal network addresses, loopback, or reserved domains.
            if (['localhost', '127.0.0.1'].includes(hostname)
                || hostname.endsWith('.local')
                || /^192\.168\.\d{1,3}\.\d{1,3}$/.test(hostname)
                || /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)
                || /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
                console.warn(`Local/internal network URL detected: ${currentUrl}; bailing out.`);
                return;
            }

            // Ensure no fragment-only URL.
            if (href === origin + pathname && currentUrl.includes('#')) {
                console.warn(`Fragment-only URL detected: ${currentUrl}; bailing out.`);
                return;
            }

            // Skip URLs with unusual ports.
            const port = urlObject.port || (protocol === 'https:' ? '443' : '80');
            if (!['80', '443'].includes(port)) {
                console.warn(`Non-standard port detected: ${port} in ${currentUrl}; bailing out.`);
                return;
            }

            // Ensure domain names are not obfuscated or invalid.
            if (hostname.includes('xn--')) {
                console.warn(`IDN domain detected (Punycode): ${hostname}; converting to ASCII.`);

                try {
                    hostname = hostname.toASCII(); // Convert IDN to ASCII
                } catch (ignored) {
                    console.warn(`Failed to convert IDN: ${currentUrl}; bailing out.`);
                    return;
                }
            }

            // Set the hostname back to the URL object.
            urlObject.hostname = hostname;

            // Abandon any pending requests.
            BrowserProtection.abandonPendingRequests(tabId, "New navigation event detected.");

            let malicious = false;
            console.info(`Checking URL: ${currentUrl}`);

            // Check if the URL is malicious.
            BrowserProtection.checkIfUrlIsMalicious(tabId, currentUrl, (result, duration) => {
                const systemName = ProtectionResult.ResultOriginNames[result.origin];
                const resultType = result.result;

                if (malicious) {
                    BrowserProtection.abandonPendingRequests(tabId, "Malicious navigation already detected.");
                    return;
                }

                console.info(`[${systemName}] Result for ${currentUrl}: ${resultType} (${duration}ms)`);

                if (resultType !== ProtectionResult.ResultType.FAILED
                    && resultType !== ProtectionResult.ResultType.KNOWN_SAFE
                    && resultType !== ProtectionResult.ResultType.ALLOWED) {
                    malicious = true;

                    browserAPI.tabs.get(tabId, (tab) => {
                        if (!tab) {
                            console.debug(`tabs.get(${tabId}) failed '${browserAPI.runtime.lastError?.message}'; bailing out.`);
                            return;
                        }

                        const pendingUrl = tab.pendingUrl || tab.url;

                        if (pendingUrl.startsWith("chrome-extension:")
                            || pendingUrl.startsWith("moz-extension:")
                            || pendingUrl.startsWith("extension:")) {
                            console.debug(`[${systemName}] The tab is at an extension page; bailing out.`);
                            return;
                        }

                        const targetUrl = frameId === 0 ? currentUrl : pendingUrl;

                        if (targetUrl) {
                            Telemetry.getInstanceID((instanceId) => {
                                // Navigate to the block page
                                const blockPageUrl = UrlHelpers.getBlockPageUrl(pendingUrl, result, instanceId, Telemetry.getSessionID());
                                console.debug(`[${systemName}] Navigating to block page: ${blockPageUrl}.`);
                                browserAPI.tabs.update(tab.id, {url: blockPageUrl});

                                // Build the warning notification options
                                const notificationOptions = {
                                    type: "basic",
                                    iconUrl: "assets/icons/icon128.png",
                                    title: "Unsafe Website Blocked",
                                    message: `URL: ${currentUrl}\nReason: ${resultType}`,
                                    contextMessage: `Reported by: ${systemName}`,
                                    priority: 2,
                                };

                                // Create a unique notification ID based on a random number
                                const randomNumber = Math.floor(Math.random() * 100000000);
                                const notificationId = `warning-` + randomNumber;

                                // Display the warning notification
                                browserAPI.notifications.create(notificationId, notificationOptions, (notificationId) => {
                                    console.debug(`Notification created with ID: ${notificationId}`);
                                });
                            });
                        } else {
                            console.debug(`Tab '${tabId}' failed to supply a top-level URL; bailing out.`);
                        }
                    });
                }
            });
        });
    };

    // Listener for onBeforeNavigate events.
    browserAPI.webNavigation.onBeforeNavigate.addListener((navigationDetails) => {
        console.debug(`[onBeforeNavigate] ${navigationDetails.url}`);
        handleNavigation(navigationDetails);
    });

    // Listener for onCommitted events.
    browserAPI.webNavigation.onCommitted.addListener((navigationDetails) => {
        if (navigationDetails.transitionQualifiers.includes("server_redirect")) {
            console.debug(`[server_redirect] ${navigationDetails.url}`);
            handleNavigation(navigationDetails);
        } else if (navigationDetails.transitionQualifiers.includes("client_redirect")) {
            console.debug(`[client_redirect] ${navigationDetails.url}`);
            handleNavigation(navigationDetails);
        }
    });

    // Listener for onCreatedNavigationTarget events.
    browserAPI.webNavigation.onCreatedNavigationTarget.addListener((navigationDetails) => {
        console.debug(`[onCreatedNavigationTarget] ${navigationDetails.url}`);
        handleNavigation(navigationDetails);
    });

    // Listener for onHistoryStateUpdated events.
    browserAPI.webNavigation.onHistoryStateUpdated.addListener((navigationDetails) => {
        console.debug(`[onHistoryStateUpdated] ${navigationDetails.url}`);
        handleNavigation(navigationDetails);
    });

    // Listener for onReferenceFragmentUpdated events.
    browserAPI.webNavigation.onReferenceFragmentUpdated.addListener((navigationDetails) => {
        console.debug(`[onReferenceFragmentUpdated] ${navigationDetails.url}`);
        handleNavigation(navigationDetails);
    });

    // Listener for onTabReplaced events.
    browserAPI.webNavigation.onTabReplaced.addListener((navigationDetails) => {
        console.debug(`[onTabReplaced] ${navigationDetails.url}`);
        handleNavigation(navigationDetails);
    });

    // Listener for incoming messages.
    browserAPI.runtime.onMessage.addListener((message, sender) => {
        // Check if the message is valid and has a message type.
        if (!(message && message.messageType)) {
            return;
        }

        switch (message.messageType) {
            case Messages.MessageType.CONTINUE_TO_SITE: {
                if (!message.continueUrl) {
                    console.debug(`No continue URL was found; sending to new tab page.`);
                    browserAPI.tabs.update(sender.tab.id, {url: "about:newtab"});
                    return;
                }

                if (!message.origin) {
                    console.debug(`No origin was found; sending to new tab page.`);
                    browserAPI.tabs.update(sender.tab.id, {url: "about:newtab"});
                    return;
                }

                let continueUrlObject = new URL(message.continueUrl);

                // Redirects to the new tab page if the continue URL is not a valid HTTP(S) URL.
                if (!validProtocols.includes(continueUrlObject.protocol)) {
                    console.debug(`Invalid protocol in continue URL: ${message.continueUrl}; sending to new tab page.`);
                    browserAPI.tabs.update(sender.tab.id, {url: "about:newtab"});
                    return;
                }

                switch (message.origin) {
                    case "1":
                        console.debug(`Added SmartScreen URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "smartScreen");
                        break;

                    case "2":
                        console.debug(`Added Symantec URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "symantec");
                        break;

                    case "3":
                        console.debug(`Added Emsisoft URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "emsisoft");
                        break;

                    case "4":
                        console.debug(`Added Bitdefender URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "bitdefender");
                        break;

                    case "5":
                        console.debug(`Added Norton URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "norton");
                        break;

                    case "6":
                        console.debug(`Added TOTAL URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "total");
                        break;

                    case "7":
                        console.debug(`Added G DATA URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "gData");
                        break;

                    default:
                        console.warn(`Unknown origin: ${message.origin}`);
                        break;
                }

                browserAPI.tabs.update(sender.tab.id, {url: message.continueUrl});
                break;
            }

            case Messages.MessageType.CONTINUE_TO_SAFETY: {
                setTimeout(() => {
                    browserAPI.tabs.update(sender.tab.id, {url: "about:newtab"});
                }, 200);
                break;
            }

            case Messages.MessageType.REPORT_SITE: {
                // Ignores blank URLs.
                if (message.reportUrl === null || message.reportUrl === "") {
                    console.debug(`Report URL is blank.`);
                    break;
                }

                if (!message.origin) {
                    console.debug(`No origin was found; sending to new tab page.`);
                    browserAPI.tabs.create({url: "about:newtab"});
                    break;
                }

                let reportUrlObject = new URL(message.reportUrl);

                if (validProtocols.includes(reportUrlObject.protocol)) {
                    console.debug(`Navigating to report URL: ${message.reportUrl}`);
                    browserAPI.tabs.create({url: message.reportUrl});
                } else {
                    // Ignore the mailto: protocol.
                    if (reportUrlObject.protocol === "mailto:") {
                        browserAPI.tabs.create({url: message.reportUrl});
                    } else {
                        console.warn(`Invalid protocol in report URL: ${message.reportUrl}; sending to new tab page.`);
                        browserAPI.tabs.create({url: "about:newtab"});
                    }
                }
                break;
            }

            case Messages.MessageType.ALLOW_HOSTNAME: {
                // Ignores blank URLs.
                if (message.maliciousUrl === null || message.maliciousUrl === "") {
                    console.debug(`Malicious URL is blank.`);
                    break;
                }

                if (!message.continueUrl) {
                    console.debug(`No continue URL was found; sending to new tab page.`);
                    browserAPI.tabs.update(sender.tab.id, {url: "about:newtab"});
                    return;
                }

                if (!message.origin) {
                    console.debug(`No origin was found; sending to new tab page.`);
                    browserAPI.tabs.create({url: "about:newtab"});
                    break;
                }

                let continueUrlObject = new URL(message.continueUrl);
                let hostnameUrlObject = new URL(message.maliciousUrl);
                const hostnameString = hostnameUrlObject.hostname + " (allowed)";

                // Adds the hostname to the cache.
                console.debug("Adding hostname to cache: " + hostnameString);

                switch (message.origin) {
                    case "1":
                        console.debug(`Added SmartScreen hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "smartScreen");
                        break;

                    case "2":
                        console.debug(`Added Symantec hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "symantec");
                        break;

                    case "3":
                        console.debug(`Added Emsisoft hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "emsisoft");
                        break;

                    case "4":
                        console.debug(`Added Bitdefender hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "bitdefender");
                        break;

                    case "5":
                        console.debug(`Added Norton hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "norton");
                        break;

                    case "6":
                        console.debug(`Added TOTAL hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "total");
                        break;

                    case "7":
                        console.debug(`Added G DATA hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "gData");
                        break;

                    default:
                        console.warn(`Unknown origin: ${message.origin}`);
                        break;
                }

                // Redirects to the new tab page if the continue URL is not a valid HTTP(S) URL.
                if (!validProtocols.includes(continueUrlObject.protocol)) {
                    console.debug(`Invalid protocol in continue URL: ${message.continueUrl}; sending to new tab page.`);
                    browserAPI.tabs.update(sender.tab.id, {url: "about:newtab"});
                    return;
                }

                browserAPI.tabs.update(sender.tab.id, {url: message.continueUrl});
                break;
            }

            case Messages.MessageType.POPUP_LAUNCHED:
                console.debug("Popup has been launched.");
                break;

            case Messages.MessageType.POPUP_CLOSED:
                console.debug("Popup has been closed.");
                break;

            case Messages.MessageType.SMARTSCREEN_TOGGLED:
                console.debug(`SmartScreen protection toggled: ${message.toggleState}`);
                break;

            case Messages.MessageType.SYMANTEC_TOGGLED:
                console.debug(`Symantec protection toggled: ${message.toggleState}`);
                break;

            case Messages.MessageType.EMSISOFT_TOGGLED:
                console.debug(`Emsisoft protection toggled: ${message.toggleState}`);
                break;

            case Messages.MessageType.BITDEFENDER_TOGGLED:
                console.debug(`Bitdefender protection toggled: ${message.toggleState}`);
                break;

            case Messages.MessageType.NORTON_TOGGLED:
                console.debug(`Norton protection toggled: ${message.toggleState}`);
                break;

            case Messages.MessageType.TOTAL_TOGGLED:
                console.debug(`TOTAL protection toggled: ${message.toggleState}`);
                break;

            case Messages.MessageType.G_DATA_TOGGLED:
                console.debug(`G DATA protection toggled: ${message.toggleState}`);
                break;

            default:
                console.warn(`Received unknown message type: ${message.messageType}`);
                console.debug(`Message: ${JSON.stringify(message)}`);
                break;
        }
    });
})();
