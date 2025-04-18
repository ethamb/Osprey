(() => {
    "use strict";

    // Browser API compatibility between Chrome and Firefox
    const browserAPI = typeof browser === 'undefined' ? chrome : browser;

    // Check if we're running in Firefox
    const isFirefox = typeof browser !== 'undefined';

    // Import necessary scripts for functionality
    try {
        // This will work in Chrome service workers but throw in Firefox
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
    } catch (error) {
        // In Firefox, importScripts is not available, but scripts are loaded via background.html
        console.log("Running in Firefox or another environment without importScripts");
        console.debug("Error: " + error);
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
                && !settings.gDataEnabled
                && !settings.cloudflareEnabled
                && !settings.quad9Enabled
                && !settings.dns0Enabled
                && !settings.controlDEnabled
                && !settings.cleanBrowsingEnabled
                && !settings.openDNSEnabled) {
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
                                if (settings.notificationsEnabled) {
                                    const notificationOptions = {
                                        type: "basic",
                                        iconUrl: "assets/icons/icon128.png",
                                        title: "Unsafe Website Blocked",
                                        message: `URL: ${currentUrl}\nReason: ${resultType}\nReported by: ${systemName}`,
                                        priority: 2,
                                    };

                                    // Create a unique notification ID based on a random number
                                    const randomNumber = Math.floor(Math.random() * 100000000);
                                    const notificationId = `warning-` + randomNumber;

                                    // Display the warning notification
                                    browserAPI.notifications.create(notificationId, notificationOptions, (notificationId) => {
                                        console.debug(`Notification created with ID: ${notificationId}`);
                                    });
                                }
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

    // // Listener for onCreatedNavigationTarget events.
    // browserAPI.webNavigation.onCreatedNavigationTarget.addListener((navigationDetails) => {
    //     console.debug(`[onCreatedNavigationTarget] ${navigationDetails.url}`);
    //     handleNavigation(navigationDetails);
    // });

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
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                if (!message.origin) {
                    console.debug(`No origin was found; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                let continueUrlObject = new URL(message.continueUrl);

                // Redirects to the blocked URL if the continue URL is 'about:blank'.
                // This fixes a strange bug in Firefox.
                if (continueUrlObject.href === "about:blank") {
                    console.debug(`Continue URL is 'about:blank'; sending to the blocked URL.`);
                    browserAPI.tabs.update(sender.tab.id, {url: message.maliciousUrl});
                    return;
                }

                // Redirects to the new tab page if the continue URL is not a valid HTTP(S) URL.
                if (!validProtocols.includes(continueUrlObject.protocol)) {
                    console.debug(`Invalid protocol in continue URL: ${message.continueUrl}; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
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

                    case "8":
                        console.debug(`Added Cloudflare URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "cloudflare");
                        break;

                    case "9":
                        console.debug(`Added Quad9 URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "quad9");
                        break;

                    case "10":
                        console.debug(`Added DNS0 URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "dns0");
                        break;

                    case "11":
                        console.debug(`Added Control D URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "controlD");
                        break;

                    case "12":
                        console.debug(`Added CleanBrowsing URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "cleanBrowsing");
                        break;

                    case "13":
                        console.debug(`Added OpenDNS URL to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.maliciousUrl, "openDNS");
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
                    sendToNewTabPage(sender.tab.id);
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
                    console.debug(`No origin was found; doing nothing.`);
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
                        console.warn(`Invalid protocol in report URL: ${message.reportUrl}; doing nothing.`);
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
                    console.debug(`No continue URL was found; sending to the blocked URL.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                if (!message.origin) {
                    console.debug(`No origin was found; sending to the blocked URL.`);
                    sendToNewTabPage(sender.tab.id);
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

                    case "8":
                        console.debug(`Added Cloudflare hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "cloudflare");
                        break;

                    case "9":
                        console.debug(`Added Quad9 hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "quad9");
                        break;

                    case "10":
                        console.debug(`Added DNS0 hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "dns0");
                        break;

                    case "11":
                        console.debug(`Added Control D hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "controlD");
                        break;

                    case "12":
                        console.debug(`Added CleanBrowsing hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "cleanBrowsing");
                        break;

                    case "13":
                        console.debug(`Added OpenDNS hostname to cache: ` + message.maliciousUrl);
                        BrowserProtection.cacheManager.addStringToCache(hostnameString, "openDNS");
                        break;

                    default:
                        console.warn(`Unknown origin: ${message.origin}`);
                        break;
                }

                // Redirects to the blocked URL if the continue URL is 'about:blank'.
                // This fixes a strange bug in Firefox.
                if (continueUrlObject.href === "about:blank") {
                    console.debug(`Continue URL is 'about:blank'; sending to the blocked URL.`);
                    browserAPI.tabs.update(sender.tab.id, {url: message.maliciousUrl});
                    return;
                }

                // Redirects to the new tab page if the continue URL is not a valid HTTP(S) URL.
                if (!validProtocols.includes(continueUrlObject.protocol)) {
                    console.debug(`Invalid protocol in continue URL: ${message.continueUrl}; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
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
            case Messages.MessageType.SYMANTEC_TOGGLED:
            case Messages.MessageType.EMSISOFT_TOGGLED:
            case Messages.MessageType.BITDEFENDER_TOGGLED:
            case Messages.MessageType.NORTON_TOGGLED:
            case Messages.MessageType.TOTAL_TOGGLED:
            case Messages.MessageType.G_DATA_TOGGLED:
            case Messages.MessageType.CLOUDFLARE_TOGGLED:
            case Messages.MessageType.QUAD9_TOGGLED:
            case Messages.MessageType.DNS0_TOGGLED:
            case Messages.MessageType.CONTROL_D_TOGGLED:
            case Messages.MessageType.CLEAN_BROWSING_TOGGLED:
            case Messages.MessageType.OPEN_DNS_TOGGLED:
                console.debug(`${message.title} has been ${message.toggleState ? "disabled" : "enabled"}.`);
                break;

            default:
                console.warn(`Received unknown message type: ${message.messageType}`);
                console.debug(`Message: ${JSON.stringify(message)}`);
                break;
        }
    });

    // Create the context menu when the extension is installed or updated
    browserAPI.runtime.onInstalled.addListener(() => {
        createContextMenu();
    });

    // Listen for clicks on the context menu item
    browserAPI.contextMenus.onClicked.addListener((info) => {
        if (info.menuItemId === "toggleNotifications") {
            Settings.set({notificationsEnabled: info.checked});
            console.debug("Notifications enabled: " + info.checked);
        }
    });

    // Create the context menu with the current state
    function createContextMenu() {
        Settings.get((settings) => {
            // First remove existing menu items to avoid duplicates
            browserAPI.contextMenus.removeAll(() => {
                // Create the context menu item with a checkbox
                browserAPI.contextMenus.create({
                    id: "toggleNotifications",
                    title: "Enable notifications",
                    type: "checkbox",
                    checked: settings.notificationsEnabled,
                    contexts: ["action"],
                });
            });
        });
    }

    // Function to send the user to the new tab page.
    function sendToNewTabPage(tabId) {
        if (isFirefox) {
            browserAPI.tabs.remove(tabId);
            browserAPI.tabs.create({});
        } else {
            browserAPI.tabs.update(tabId, {url: "about:newtab"});
        }
    }
})();
