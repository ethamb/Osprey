(() => {
    "use strict";

    // Browser API compatibility between Chrome and Firefox
    const isFirefox = typeof browser !== 'undefined';
    const browserAPI = isFirefox ? browser : chrome;
    const contextMenuAPI = isFirefox ? browserAPI.menus : browserAPI.contextMenus;
    let supportsManagedPolicies = true;

    // Import necessary scripts for functionality
    try {
        // This will work in Chrome service workers but throw in Firefox
        importScripts(
            // Util
            "util/Settings.js",
            "util/UrlHelpers.js",
            "util/CacheManager.js",
            "util/Storage.js",
            "util/MessageType.js",

            // Other
            "util/other/SmartScreenUtil.js",
            "util/other/EmsisoftUtil.js",
            "util/other/UUIDUtil.js",

            // Hashing
            "util/hashing/MD5.js",
            "util/hashing/RC4.js",

            // Protection
            "protection/ProtectionResult.js",
            "protection/BrowserProtection.js"
        );
    } catch (error) {
        // In Firefox, importScripts is not available, but scripts are loaded via background.html
        console.debug("Running in Firefox or another environment without importScripts");
        console.debug("Error: " + error);
    }

    // List of valid protocols (e.g., HTTP, HTTPS).
    const validProtocols = ['http:', 'https:'];

    // Function to handle navigation checks.
    const handleNavigation = navigationDetails => {
        Settings.get(settings => {
            // Retrieve settings to check if protection is enabled.
            if (!settings.smartScreenEnabled
                && !settings.symantecEnabled
                && !settings.emsisoftEnabled
                && !settings.bitdefenderEnabled
                && !settings.nortonEnabled
                && !settings.gDataEnabled
                && !settings.malwareURLEnabled
                && !settings.cloudflareEnabled
                && !settings.quad9Enabled
                && !settings.dns0Enabled
                && !settings.cleanBrowsingEnabled
                && !settings.ciraEnabled
                && !settings.adGuardEnabled
                && !settings.switchCHEnabled
                && !settings.certEEEnabled
                && !settings.controlDEnabled
            ) {
                console.debug("Protection is disabled; bailing out early.");
                return;
            }

            let {tabId, frameId, url: currentUrl} = navigationDetails;

            // Check if the frame ID is not the main frame.
            if (settings.ignoreFrameNavigation && frameId !== 0) {
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

                // Returns early if the result is already known as malicious.
                if (malicious) {
                    BrowserProtection.abandonPendingRequests(tabId, "Malicious navigation already detected.");
                    return;
                }

                console.info(`[${systemName}] Result for ${currentUrl}: ${resultType} (${duration}ms)`);

                if (resultType !== ProtectionResult.ResultType.FAILED
                    && resultType !== ProtectionResult.ResultType.KNOWN_SAFE
                    && resultType !== ProtectionResult.ResultType.ALLOWED) {
                    malicious = true;

                    browserAPI.tabs.get(tabId, tab => {
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
                            // Navigate to the block page
                            const blockPageUrl = UrlHelpers.getBlockPageUrl(result);
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
                                browserAPI.notifications.create(notificationId, notificationOptions, notificationId => {
                                    console.debug(`Notification created with ID: ${notificationId}`);
                                });
                            }
                        } else {
                            console.debug(`Tab '${tabId}' failed to supply a top-level URL; bailing out.`);
                        }
                    });
                }
            });
        });
    };

    // Gather all policy keys needed for managed policies
    const policyKeys = [
        'DisableContextMenu',
        'DisableNotifications',
        'HideContinueButtons',
        'HideReportButton',
        'IgnoreFrameNavigation',
        'CacheExpirationSeconds',
        'LockProtectionOptions',
        'SmartScreenEnabled',
        'SymantecEnabled',
        'EmsisoftEnabled',
        'BitdefenderEnabled',
        'NortonEnabled',
        'GDATAEnabled',
        'MalwareURLEnabled',
        'CloudflareEnabled',
        'Quad9Enabled',
        'DNS0Enabled',
        'CleanBrowsingEnabled',
        'CIRAEnabled',
        'AdGuardEnabled',
        'SwitchCHEnabled',
        'CERTEEEnabled',
        'ControlDEnabled'
    ];

    // Creates the context menu and sets managed policies
    browserAPI.storage.managed.get(policyKeys, policies => {
        if (typeof policies === 'undefined') {
            supportsManagedPolicies = false;
            console.debug("Managed policies are not supported or setup correctly in this browser.");
        } else {
            supportsManagedPolicies = true;
            console.debug("Managed policies are supported in this browser.");

            let settings = {};

            // If the context menu is disabled by policy,
            // apply the related policy settings (do not create the menu).
            if (policies.DisableContextMenu !== undefined && policies.DisableContextMenu) {
                console.debug("Context menu is disabled by policy.");

                // Update the notifications settings using the policy
                if (policies.DisableNotifications !== undefined) {
                    settings.notificationsEnabled = !policies.DisableNotifications;
                    console.debug("Notifications are managed by system policy.");
                }

                // Update the ignore frame navigation settings using the policy
                if (policies.IgnoreFrameNavigation !== undefined) {
                    settings.ignoreFrameNavigation = policies.IgnoreFrameNavigation;
                    console.debug("Ignoring frame navigation is managed by system policy.");
                }
            }

            // Check and set the cache expiration time using the policy.
            if (policies.CacheExpirationSeconds !== undefined) {
                if (typeof policies.CacheExpirationSeconds !== "number" || policies.CacheExpirationSeconds < 60) {
                    console.debug("Cache expiration time is invalid; using default value.");
                    settings.cacheExpirationSeconds = 86400;
                } else {
                    settings.cacheExpirationSeconds = policies.CacheExpirationSeconds;
                    console.debug("Cache expiration time set to: " + policies.CacheExpirationSeconds);
                }
            }

            // Check and set the continue buttons settings using the policy.
            if (policies.HideContinueButtons !== undefined) {
                settings.hideContinueButtons = policies.HideContinueButtons;
                console.debug("Continue buttons are managed by system policy.");
            }

            // Check and set the report button settings using the policy.
            if (policies.HideReportButton !== undefined) {
                settings.hideReportButton = policies.HideReportButton;
                console.debug("Report button is managed by system policy.");
            }

            // Check and set the lock protection options using the policy.
            if (policies.LockProtectionOptions !== undefined) {
                settings.lockProtectionOptions = policies.LockProtectionOptions;
                console.debug("Protection options are managed by system policy.");
            }

            // Check and set the SmartScreen settings using the policy.
            if (policies.SmartScreenEnabled !== undefined) {
                settings.smartScreenEnabled = policies.SmartScreenEnabled;
                console.debug("SmartScreen is managed by system policy.");
            }

            // Check and set the Symantec settings using the policy.
            if (policies.SymantecEnabled !== undefined) {
                settings.symantecEnabled = policies.SymantecEnabled;
                console.debug("Symantec is managed by system policy.");
            }

            // Check and set the Emsisoft settings using the policy.
            if (policies.EmsisoftEnabled !== undefined) {
                settings.emsisoftEnabled = policies.EmsisoftEnabled;
                console.debug("Emsisoft is managed by system policy.");
            }

            // Check and set the Bitdefender settings using the policy.
            if (policies.BitdefenderEnabled !== undefined) {
                settings.bitdefenderEnabled = policies.BitdefenderEnabled;
                console.debug("Bitdefender is managed by system policy.");
            }

            // Check and set the Norton settings using the policy.
            if (policies.NortonEnabled !== undefined) {
                settings.nortonEnabled = policies.NortonEnabled;
                console.debug("Norton is managed by system policy.");
            }

            // Check and set the G DATA settings using the policy.
            if (policies.GDATAEnabled !== undefined) {
                settings.gDataEnabled = policies.GDATAEnabled;
                console.debug("G DATA is managed by system policy.");
            }

            // Check and set the MalwareURL settings using the policy.
            if (policies.MalwareURLEnabled !== undefined) {
                settings.malwareURLEnabled = policies.MalwareURLEnabled;
                console.debug("MalwareURL is managed by system policy.");
            }

            // Check and set the Cloudflare settings using the policy.
            if (policies.CloudflareEnabled !== undefined) {
                settings.cloudflareEnabled = policies.CloudflareEnabled;
                console.debug("Cloudflare is managed by system policy.");
            }

            // Check and set the Quad9 settings using the policy.
            if (policies.Quad9Enabled !== undefined) {
                settings.quad9Enabled = policies.Quad9Enabled;
                console.debug("Quad9 is managed by system policy.");
            }

            // Check and set the DNS0 settings using the policy.
            if (policies.DNS0Enabled !== undefined) {
                settings.dns0Enabled = policies.DNS0Enabled;
                console.debug("DNS0 is managed by system policy.");
            }

            // Check and set the CleanBrowsing settings using the policy.
            if (policies.CleanBrowsingEnabled !== undefined) {
                settings.cleanBrowsingEnabled = policies.CleanBrowsingEnabled;
                console.debug("CleanBrowsing is managed by system policy.");
            }

            // Check and set the CIRA settings using the policy.
            if (policies.CIRAEnabled !== undefined) {
                settings.ciraEnabled = policies.CIRAEnabled;
                console.debug("CIRA is managed by system policy.");
            }

            // Check and set the AdGuard settings using the policy.
            if (policies.AdGuardEnabled !== undefined) {
                settings.adGuardEnabled = policies.AdGuardEnabled;
                console.debug("AdGuard is managed by system policy.");
            }

            // Check and set the Switch.ch settings using the policy.
            if (policies.SwitchCHEnabled !== undefined) {
                settings.switchCHEnabled = policies.SwitchCHEnabled;
                console.debug("Switch.ch is managed by system policy.");
            }

            // Check and set the CERT-EE settings using the policy.
            if (policies.CERTEEEnabled !== undefined) {
                settings.certEEEnabled = policies.CERTEEEnabled;
                console.debug("CERT-EE is managed by system policy.");
            }

            // Check and set the Control D settings using the policy.
            if (policies.ControlDEnabled !== undefined) {
                settings.controlDEnabled = policies.ControlDEnabled;
                console.debug("Control D is managed by system policy.");
            }

            // Finally, if there are any updates, update the stored settings in one go.
            if (Object.keys(settings).length > 0) {
                Settings.set(settings, () => {
                    console.debug("Updated settings on install: ", settings);
                });
            }
        }

        // Create the context menu.
        console.debug("Creating context menu...");
        createContextMenu();
    });

    // Listener for onBeforeNavigate events.
    browserAPI.webNavigation.onBeforeNavigate.addListener(navigationDetails => {
        console.debug(`[onBeforeNavigate] ${navigationDetails.url}`);
        handleNavigation(navigationDetails);
    });

    // Listener for onCommitted events.
    browserAPI.webNavigation.onCommitted.addListener(navigationDetails => {
        if (navigationDetails.transitionQualifiers.includes("server_redirect")) {
            console.debug(`[server_redirect] ${navigationDetails.url}`);
            handleNavigation(navigationDetails);
        } else if (navigationDetails.transitionQualifiers.includes("client_redirect")) {
            console.debug(`[client_redirect] ${navigationDetails.url}`);
            handleNavigation(navigationDetails);
        }
    });

    // // Listener for onCreatedNavigationTarget events.
    // browserAPI.webNavigation.onCreatedNavigationTarget.addListener(navigationDetails => {
    //     console.debug(`[onCreatedNavigationTarget] ${navigationDetails.url}`);
    //     handleNavigation(navigationDetails);
    // });

    // Listener for onHistoryStateUpdated events.
    browserAPI.webNavigation.onHistoryStateUpdated.addListener(navigationDetails => {
        console.debug(`[onHistoryStateUpdated] ${navigationDetails.url}`);
        handleNavigation(navigationDetails);
    });

    // Listener for onReferenceFragmentUpdated events.
    browserAPI.webNavigation.onReferenceFragmentUpdated.addListener(navigationDetails => {
        console.debug(`[onReferenceFragmentUpdated] ${navigationDetails.url}`);
        handleNavigation(navigationDetails);
    });

    // Listener for onTabReplaced events.
    browserAPI.webNavigation.onTabReplaced.addListener(navigationDetails => {
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
                if (!message.blockedUrl) {
                    console.debug(`No blocked URL was found; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                if (!message.origin) {
                    console.debug(`No origin was found; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                let blockedUrlObject = new URL(message.blockedUrl);

                // Redirects to the new tab page if the blocked URL is not a valid HTTP(S) URL.
                if (!validProtocols.includes(blockedUrlObject.protocol)) {
                    console.debug(`Invalid protocol in blocked URL: ${message.blockedUrl}; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                switch (message.origin) {
                    case "1":
                        console.debug(`Added SmartScreen URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "smartScreen");
                        break;

                    case "2":
                        console.debug(`Added Symantec URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "symantec");
                        break;

                    case "3":
                        console.debug(`Added Emsisoft URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "emsisoft");
                        break;

                    case "4":
                        console.debug(`Added Bitdefender URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "bitdefender");
                        break;

                    case "5":
                        console.debug(`Added Norton URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "norton");
                        break;

                    case "6":
                        console.debug(`Added G DATA URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "gData");
                        break;

                    case "7":
                        console.debug(`Added MalwareURL URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "malwareURL");
                        break;

                    case "8":
                        console.debug(`Added Cloudflare URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "cloudflare");
                        break;

                    case "9":
                        console.debug(`Added Quad9 URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "quad9");
                        break;

                    case "10":
                        console.debug(`Added DNS0 URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "dns0");
                        break;

                    case "11":
                        console.debug(`Added CleanBrowsing URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "cleanBrowsing");
                        break;

                    case "12":
                        console.debug(`Added CIRA URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "cira");
                        break;

                    case "13":
                        console.debug(`Added AdGuard URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "adGuard");
                        break;

                    case "14":
                        console.debug(`Added Switch.ch URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "switchCH");
                        break;

                    case "15":
                        console.debug(`Added CERT-EE URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "certEE");
                        break;

                    case "16":
                        console.debug(`Added Control D URL to cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToCache(message.blockedUrl, "controlD");
                        break;

                    default:
                        console.warn(`Unknown origin: ${message.origin}`);
                        break;
                }

                browserAPI.tabs.update(sender.tab.id, {url: message.blockedUrl});
                break;
            }

            case Messages.MessageType.CONTINUE_TO_SAFETY: {
                setTimeout(() => {
                    sendToNewTabPage(sender.tab.id);
                }, 200);
                break;
            }

            case Messages.MessageType.REPORT_SITE: {
                // Ignores blank report URLs.
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

            case Messages.MessageType.ALLOW_SITE: {
                // Ignores blank blocked URLs.
                if (message.blockedUrl === null || message.blockedUrl === "") {
                    console.debug(`Blocked URL is blank.`);
                    break;
                }

                if (!message.origin) {
                    console.debug(`No origin was found; sending to the new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    break;
                }

                let blockedUrl = new URL(message.blockedUrl);
                const hostnameString = blockedUrl.hostname + " (allowed)";

                // Adds the hostname to the every cache.
                console.debug("Adding hostname to every cache: " + hostnameString);
                BrowserProtection.cacheManager.addStringToCache(hostnameString, "all");

                // Redirects to the new tab page if the blocked URL is not a valid HTTP(S) URL.
                if (!validProtocols.includes(blockedUrl.protocol)) {
                    console.debug(`Invalid protocol in blocked URL: ${message.blockedUrl}; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                browserAPI.tabs.update(sender.tab.id, {url: message.blockedUrl});
                break;
            }

            case Messages.MessageType.SMARTSCREEN_TOGGLED:
            case Messages.MessageType.SYMANTEC_TOGGLED:
            case Messages.MessageType.EMSISOFT_TOGGLED:
            case Messages.MessageType.BITDEFENDER_TOGGLED:
            case Messages.MessageType.NORTON_TOGGLED:
            case Messages.MessageType.G_DATA_TOGGLED:
            case Messages.MessageType.MALWAREURL_TOGGLED:
            case Messages.MessageType.CLOUDFLARE_TOGGLED:
            case Messages.MessageType.QUAD9_TOGGLED:
            case Messages.MessageType.DNS0_TOGGLED:
            case Messages.MessageType.CLEAN_BROWSING_TOGGLED:
            case Messages.MessageType.CIRA_TOGGLED:
            case Messages.MessageType.ADGUARD_TOGGLED:
            case Messages.MessageType.SWITCH_CH_TOGGLED:
            case Messages.MessageType.CERT_EE_TOGGLED:
            case Messages.MessageType.CONTROL_D_TOGGLED:
                console.debug(`${message.title} has been ${message.toggleState ? "enabled" : "disabled"}.`);
                break;

            default:
                console.warn(`Received unknown message type: ${message.messageType}`);
                console.debug(`Message: ${JSON.stringify(message)}`);
                break;
        }
    });

    // Listener for context menu creation.
    contextMenuAPI.onClicked.addListener(info => {
        switch (info.menuItemId) {
            case "toggleNotifications":
                Settings.set({notificationsEnabled: info.checked});
                console.debug("Notifications: " + info.checked);
                break;

            case "toggleFrameNavigation":
                Settings.set({ignoreFrameNavigation: info.checked});
                console.debug("Ignoring frame navigation: " + info.checked);
                break;

            case "clearAllowedSites":
                BrowserProtection.cacheManager.clearAllCaches();
                console.debug("Cleared all allowed site caches.");

                // Create a notification to inform the user.
                const notificationOptions = {
                    type: "basic",
                    iconUrl: "assets/icons/icon128.png",
                    title: "Allowed Sites Cleared",
                    message: "All allowed sites have been cleared.",
                    priority: 2,
                };

                const randomNumber = Math.floor(Math.random() * 100000000);
                const notificationId = `cache-cleared-${randomNumber}`;

                browserAPI.notifications.create(notificationId, notificationOptions, id => {
                    console.debug(`Notification created with ID: ${id}`);
                });
                break;

            default:
                break;
        }
    });

    // Create the context menu with the current state.
    function createContextMenu() {
        Settings.get(settings => {
            // First remove existing menu items to avoid duplicates.
            console.debug("Removing all context menu items...");
            contextMenuAPI.removeAll();

            // Create the toggle notifications menu item
            console.debug("Creating toggleNotifications with value: " + settings.notificationsEnabled);
            contextMenuAPI.create({
                id: "toggleNotifications",
                title: "Enable notifications",
                type: "checkbox",
                checked: settings.notificationsEnabled,
                contexts: ["action"],
            });

            // Create the toggle frame navigation menu item
            console.debug("Creating ignoreFrameNavigation with value: " + settings.ignoreFrameNavigation);
            contextMenuAPI.create({
                id: "toggleFrameNavigation",
                title: "Ignore frame navigation",
                type: "checkbox",
                checked: settings.ignoreFrameNavigation,
                contexts: ["action"],
            });

            // Create the clear allowed sites menu item
            console.debug("Creating clearAllowedSites with value: none");
            contextMenuAPI.create({
                id: "clearAllowedSites",
                title: "Clear list of allowed sites",
                contexts: ["action"],
            });

            // Returns early if managed policies are not supported.
            if (!supportsManagedPolicies) {
                return;
            }

            // Gather the policy values for updating the context menu.
            const policyKeys = [
                "DisableNotifications",
                "DisableClearAllowedSites",
                "IgnoreFrameNavigation"
            ];

            browserAPI.storage.managed.get(policyKeys, policies => {
                let updatedSettings = {};

                // Check if the enable notifications button should be disabled.
                if (policies.DisableNotifications !== undefined) {
                    contextMenuAPI.update("toggleNotifications", {
                        enabled: false,
                        checked: !policies.DisableNotifications,
                    });

                    updatedSettings.notificationsEnabled = !policies.DisableNotifications;
                    console.debug("Notifications are managed by system policy.");
                }

                // Check if the ignore frame navigation button should be disabled.
                if (policies.IgnoreFrameNavigation !== undefined) {
                    contextMenuAPI.update("toggleFrameNavigation", {
                        enabled: false,
                        checked: policies.IgnoreFrameNavigation,
                    });

                    updatedSettings.ignoreFrameNavigation = policies.IgnoreFrameNavigation;
                    console.debug("Ignoring frame navigation is managed by system policy.");
                }

                // Check if the clear allowed sites button should be disabled.
                if (policies.DisableClearAllowedSites !== undefined && policies.DisableClearAllowedSites) {
                    contextMenuAPI.update("clearAllowedSites", {
                        enabled: false,
                    });

                    console.debug("Clear allowed sites button is managed by system policy.");
                }

                // Update settings cumulatively if any policy-based changes were made.
                if (Object.keys(updatedSettings).length > 0) {
                    Settings.set(updatedSettings, () => {
                        console.debug("Updated settings from context menu creation:", updatedSettings);
                    });
                }
            });
        });
    }

    /**
     * Function to send the user to the new tab page.
     *
     * @param {number} tabId - The ID of the tab to be closed. (Firefox only)
     */
    function sendToNewTabPage(tabId) {
        if (isFirefox) {
            browserAPI.tabs.remove(tabId);
            browserAPI.tabs.create({});
        } else {
            browserAPI.tabs.update(tabId, {url: "about:newtab"});
        }
    }
})();
