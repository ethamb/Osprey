"use strict";

// Event listener for page load
window.addEventListener("load", () => {
    // Extract the threat code from the current page URL
    const pageUrl = window.document.URL;
    const result = UrlHelpers.extractResult(pageUrl);

    // Set the reason text based on the result
    if (!result) {
        console.warn("No result found in the URL.");
        return;
    }

    // Browser API compatibility between Chrome and Firefox
    const browserAPI = chrome || browser;

    // Cache for DOM elements
    const domElements = Object.fromEntries(
        ["reason", "url", "reportedBy", "reportSafe", "allowHostname", "homepageButton", "continueButton"]
            .map(id => [id, document.getElementById(id)])
    );

    domElements.reason.innerText = result;

    // Extract the malicious & continue-to-site URLs from the current page URL
    const maliciousUrl = UrlHelpers.extractMaliciousUrl(pageUrl);
    const continueUrl = UrlHelpers.extractContinueUrl(pageUrl);

    // Encode the URLs for safe use in other contexts
    const encodedMaliciousUrl = encodeURIComponent(maliciousUrl);
    const encodedResult = encodeURIComponent(result);

    // Set the URL text to the current page URL
    domElements.url.innerText = maliciousUrl;

    // Get origin information
    const origin = UrlHelpers.extractOrigin(pageUrl);
    const originInt = parseInt(origin);
    const systemName = ProtectionResult.ResultOriginNames[originInt];

    // Set reported by text
    domElements.reportedBy.innerText = systemName || "Unknown";

    // Create a function to get the report URL lazily when needed
    const getReportUrl = () => {
        switch (originInt) {
            case ProtectionResult.ResultOrigin.MICROSOFT:
                return new URL("https://feedback.smartscreen.microsoft.com/feedback.aspx?t=16&url=" + maliciousUrl);

            case ProtectionResult.ResultOrigin.SYMANTEC:
                return new URL("https://sitereview.symantec.com/sitereview.jsp?referrer=sedsbp&url=" + encodedMaliciousUrl);

            case ProtectionResult.ResultOrigin.EMSISOFT:
                return new URL("mailto:fp@emsisoft.com?subject=False%20Positive&body=Hello%2C%0A%0AI%20would%20like%20"
                    + "to%20report%20a%20false%20positive.%0A%0AProduct%3A%20Emsisoft%20Browser%20Security%0AURL%3A%20"
                    + encodedMaliciousUrl + "%0ADetected%20as%3A%20" + encodedResult
                    + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");

            case ProtectionResult.ResultOrigin.BITDEFENDER:
                return new URL("https://bitdefender.com/consumer/support/answer/29358/#scroll-to-heading-2");

            case ProtectionResult.ResultOrigin.NORTON:
                return new URL("https://safeweb.norton.com/report?url=" + encodedMaliciousUrl);

            case ProtectionResult.ResultOrigin.TOTAL:
                return new URL("https://totalwebshield.com/submit-file#false-positive-website");

            case ProtectionResult.ResultOrigin.G_DATA:
                return new URL("https://submit.gdatasoftware.com/url?key=NWNjNWIzY2RlMGE0ZDA5YzkyNzJmMTA3MTRmZTYwMjBi"
                    + "NmZmOWNjZDQ1MTQ1NjQ3F9FNhTj0IOo0u_jyw7nqx5c7jZxGFVmoR7X_4r7__CZJnGtqJsIzn-tN&lang=en");

            default:
                return null;
        }
    };

    // Unified message sending function with error handling
    const sendMessage = async (messageType, additionalData = {}) => {
        try {
            const message = {
                messageType,
                maliciousUrl,
                origin,
                ...additionalData
            };

            await browserAPI.runtime.sendMessage(message);
        } catch (error) {
            console.error(`Error sending message ${messageType}:`, error);
        }
    };

    // Add event listener to "Report this site" button
    domElements.reportSafe.addEventListener("click", async () => {
        await sendMessage(Messages.MessageType.REPORT_SITE, {
            reportUrl: getReportUrl()
        });
    });

    // Add event listener to "Add hostname to allowlist" button
    domElements.allowHostname.addEventListener("click", async () => {
        await sendMessage(Messages.MessageType.ALLOW_HOSTNAME, {
            continueUrl
        });
    });

    // Add event listener to "Back to safety" button
    domElements.homepageButton.addEventListener("click", async () => {
        await sendMessage(Messages.MessageType.CONTINUE_TO_SAFETY, {
            hostUrl: continueUrl
        });
    });

    // Add event listener to "Continue anyway" button
    domElements.continueButton.addEventListener("click", async () => {
        await sendMessage(Messages.MessageType.CONTINUE_TO_SITE, {
            continueUrl
        });
    });
}, {once: true});
