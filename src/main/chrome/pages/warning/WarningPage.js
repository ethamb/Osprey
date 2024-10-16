"use strict";

// Event listener for page load
window.addEventListener("load", () => {
    // Extract the threat code from the current page URL
    const result = UrlHelpers.extractResult(window.document.URL);

    if (result) {
        // Set the reason text based on the detected threat
        let reasonText;
        switch (result) {
            case ProtectionResult.ResultType.PHISHING:
                reasonText = "Phishing";
                break;

            case ProtectionResult.ResultType.MALICIOUS:
                reasonText = "Malware";
                break;

            case ProtectionResult.ResultType.FRAUD:
                reasonText = "Fraud";
                break;

            case ProtectionResult.ResultType.PUA:
                reasonText = "Potentially Unwanted Applications";
                break;

            case ProtectionResult.ResultType.CRYPTOJACKING:
                reasonText = "Cryptojacking";
                break;

            case ProtectionResult.ResultType.MALVERTISING:
                reasonText = "Malvertising";
                break;

            case ProtectionResult.ResultType.SPAM:
                reasonText = "Spam";
                break;

            case ProtectionResult.ResultType.ADWARE:
                reasonText = "Adware";
                break;

            case ProtectionResult.ResultType.COMPROMISED:
                reasonText = "Compromised";
                break;

            case ProtectionResult.ResultType.FLEECEWARE:
                reasonText = "Fleeceware";
                break;

            case ProtectionResult.ResultType.UNTRUSTED:
                reasonText = "Untrusted";
                break;

            default:
                reasonText = "Unknown";
                break;
        }

        document.getElementById("reason").innerText = reasonText;
    } else {
        return;
    }

    // Extract the malicious & continue-to-site URLs from the current page URL
    const maliciousUrl = UrlHelpers.extractMaliciousUrl(window.document.URL);
    const continueUrl = UrlHelpers.extractContinueUrl(window.document.URL);

    // Modify the "Reported by" text based on the origin of the protection result
    const origin = UrlHelpers.extractOrigin(window.document.URL);
    const systemName = ProtectionResult.ResultOriginNames[parseInt(origin)];

    switch (origin) {
        case ProtectionResult.ResultOrigin.MICROSOFT.valueOf().toString():
        case ProtectionResult.ResultOrigin.COMODO.valueOf().toString():
        case ProtectionResult.ResultOrigin.EMSISOFT.valueOf().toString():
        case ProtectionResult.ResultOrigin.BITDEFENDER.valueOf().toString():
        case ProtectionResult.ResultOrigin.NORTON.valueOf().toString():
        case ProtectionResult.ResultOrigin.TOTAL.valueOf().toString():
        case ProtectionResult.ResultOrigin.G_DATA.valueOf().toString():
            document.getElementById("reportedBy").innerText = systemName;
            break;

        default:
            document.getElementById("reportedBy").innerText = "Unknown";
            break;
    }

    // Add event listener to "Back to safety" button
    document.getElementById("homepageButton").addEventListener("click", async () => {
        await chrome.runtime.sendMessage({
            messageType: Messages.MessageType.CONTINUE_TO_SAFETY,
            maliciousUrl: maliciousUrl,
            hostUrl: continueUrl
        });
    });

    // Add event listener to "Continue anyway" button
    document.getElementById("continueButton").addEventListener("click", async () => {
        await chrome.runtime.sendMessage({
            messageType: Messages.MessageType.CONTINUE_TO_SITE,
            maliciousUrl: maliciousUrl,
            continueUrl: continueUrl,
            origin: origin
        });
    });
}, {once: true});
