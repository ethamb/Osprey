"use strict";

// Use a global singleton pattern to ensure we don't duplicate resources
window.WarningSingleton = window.WarningSingleton || (function () {
    // Browser API compatibility between Chrome and Firefox
    const browserAPI = typeof browser === 'undefined' ? chrome : browser;

    /**
     * Initialize the popup or refresh if already initialized
     */
    const initialize = function () {
        // Extract the threat code from the current page URL
        const pageUrl = window.document.URL;
        const result = UrlHelpers.extractResult(pageUrl);

        // Set the reason text based on the result
        if (!result) {
            console.warn("No result found in the URL.");
            return;
        }

        // Cache for DOM elements
        const domElements = Object.fromEntries(
            ["reason", "url", "reportedBy", "reportSite", "allowSite", "homepageButton", "continueButton"]
                .map(id => [id, document.getElementById(id)])
        );

        domElements.reason.innerText = result;

        // Extract the blocked URL from the current page URL
        const blockedUrl = UrlHelpers.extractBlockedUrl(pageUrl);

        // Encode the URLs for safe use in other contexts
        const encodedBlockedUrl = encodeURIComponent(blockedUrl);
        const encodedResult = encodeURIComponent(result);

        // Set the URL text to the current page URL
        domElements.url.innerText = blockedUrl;

        // Get origin information
        const origin = UrlHelpers.extractOrigin(pageUrl);
        const originInt = parseInt(origin);
        const systemName = ProtectionResult.ResultOriginNames[originInt];

        // Set reported by text
        domElements.reportedBy.innerText = systemName || "Unknown";

        // Create a function to get the report URL lazily when needed
        const getReportUrl = () => {
            switch (originInt) {
                case ProtectionResult.ResultOrigin.PRECISIONSEC:
                    // Verified working as of: 05/28/2025
                    // Response time: 1-2 days
                    return new URL("mailto:info@precisionsec.com?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20PrecisionSec%20Web%20Protection"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.BITDEFENDER:
                    return new URL("https://www.bitdefender.com/consumer/support/answer/29358/#scroll-to-heading-2");

                case ProtectionResult.ResultOrigin.G_DATA:
                    // Old URL: "https://submit.gdatasoftware.com/privacy"
                    // TODO: Needs verification of response from support team.
                    return new URL("mailto:support-us@gdata-software.com?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20G%20DATA%20WebProtection"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.SMARTSCREEN:
                    return new URL("https://feedback.smartscreen.microsoft.com/feedback.aspx?t=16&url=" + blockedUrl);

                case ProtectionResult.ResultOrigin.NORTON:
                    return new URL("https://safeweb.norton.com/report?url=" + encodedBlockedUrl);

                case ProtectionResult.ResultOrigin.ADGUARD_SECURITY:
                    // Verified working as of: 05/25/2025
                    // Response time: 1-2 days
                    return new URL("mailto:support@adguard.com?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20AdGuard%20DNS"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.ADGUARD_FAMILY:
                    // Verified working as of: 05/25/2025
                    // Response time: 1-2 days
                    return new URL("mailto:support@adguard.com?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20AdGuard%20Family%20DNS"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.CERT_EE:
                    // Verified working as of: 05/06/2025
                    // Response time: 2-3 days
                    return new URL("mailto:ria@ria.ee?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20CERT-EE%20DNS"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.CIRA_SECURITY:
                case ProtectionResult.ResultOrigin.CIRA_FAMILY:
                    return new URL("https://www.cira.ca/en/canadian-shield/suppor");

                case ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY:
                    // Verified working as of: 05/12/2025
                    // Response time: 1-2 days
                    return new URL("mailto:support@cleanbrowsing.org?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20CleanBrowsing%20Security%20Filter"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY:
                    // Verified working as of: 05/12/2025
                    // Response time: 1-2 days
                    return new URL("mailto:support@cleanbrowsing.org?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20CleanBrowsing%20Family%20Filter"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.CLEANBROWSING_ADULT:
                    // Verified working as of: 05/12/2025
                    // Response time: 1-2 days
                    return new URL("mailto:support@cleanbrowsing.org?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20CleanBrowsing%20Adult%20Filter"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY:
                case ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY:
                    return new URL("https://radar.cloudflare.com/domains/feedback/" + encodedBlockedUrl);

                case ProtectionResult.ResultOrigin.CONTROL_D_SECURITY:
                    // TODO: Needs verification of response from support team.
                    return new URL("mailto:help@controld.com?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20Control%20D%20P1%20DNS"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.CONTROL_D_FAMILY:
                    // TODO: Needs verification of response from support team.
                    return new URL("mailto:help@controld.com?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20Control%20D%20Family%20DNS"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.DNS0_SECURITY:
                case ProtectionResult.ResultOrigin.DNS0_KIDS:
                    return new URL("https://www.dns0.eu/report");

                case ProtectionResult.ResultOrigin.OPENDNS_SECURITY:
                    // TODO: Needs verification of response from support team.
                    return new URL("mailto:support@opendns.com?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20OpenDNS%20Home%20DNS"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.OPENDNS_FAMILY_SHIELD:
                    // TODO: Needs verification of response from support team.
                    return new URL("mailto:support@opendns.com?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20OpenDNS%20Family%20Shield%20DNS"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.QUAD9:
                    // Old URL: "https://quad9.net/support/contact"
                    // TODO: Needs verification of response from support team.
                    return new URL("mailto:support@quad9.net?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20Quad9%20DNS"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                case ProtectionResult.ResultOrigin.SWITCH_CH:
                    // TODO: Needs verification of response from support team.
                    return new URL("mailto:info@switch.ch?subject=False%20Positive&body=Hello%2C"
                        + "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive."
                        + "%0A%0AProduct%3A%20Switch.ch%20DNS"
                        + "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29"
                        + "%0ADetected%20as%3A%20" + encodedResult
                        + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

                default:
                    return null;
            }
        };

        // Unified message sending function with error handling
        const sendMessage = async (messageType, additionalData = {}) => {
            try {
                // Convert URL objects to strings before sending
                const message = {
                    messageType,
                    blockedUrl: blockedUrl instanceof URL ? blockedUrl.toString() : blockedUrl,
                    origin: origin instanceof URL ? origin.toString() : origin,
                    ...additionalData
                };

                // Also check any properties in additionalData that might be URL objects
                for (const key in message) {
                    if (message[key] instanceof URL) {
                        message[key] = message[key].toString();
                    }
                }

                await browserAPI.runtime.sendMessage(message);
            } catch (error) {
                console.error(`Error sending message ${messageType}:`, error);
            }
        };

        // Add event listener to "Report this website as safe" button
        Settings.get(settings => {
            domElements.reportSite.addEventListener("click", async () => {
                if (!settings.hideReportButton) {
                    await sendMessage(Messages.MessageType.REPORT_SITE, {
                        reportUrl: getReportUrl()
                    });
                }
            });

            // Add event listener to "Temporarily allow this website" button
            domElements.allowSite.addEventListener("click", async () => {
                if (!settings.hideContinueButtons) {
                    await sendMessage(Messages.MessageType.ALLOW_SITE, {
                        blockedUrl: blockedUrl
                    });
                }
            });

            // Add event listener to "Back to safety" button
            domElements.homepageButton.addEventListener("click", async () => {
                await sendMessage(Messages.MessageType.CONTINUE_TO_SAFETY, {
                    blockedUrl: blockedUrl
                });
            });

            // Add event listener to "Continue anyway" button
            domElements.continueButton.addEventListener("click", async () => {
                if (!settings.hideContinueButtons) {
                    await sendMessage(Messages.MessageType.CONTINUE_TO_SITE, {
                        blockedUrl: blockedUrl
                    });
                }
            });

            // Checks for overrides to any HTML elements from settings
            if (!settings.hideContinueButtons) {
                document.getElementById("allowSite").style.display = "";
                document.getElementById("continueButton").style.display = "";
            }

            if (!settings.hideReportButton) {
                document.getElementById("reportSite").style.display = "";
                document.getElementById("reportBreakpoint").style.display = "";
            }
        });
    };

    // Public API
    return {
        initialize
    };
})();

document.addEventListener("DOMContentLoaded", () => {
    // Initialize the singleton instance
    window.WarningSingleton.initialize();
});
