"use strict";

// Event listener for page load
window.addEventListener("load", () => {
    // Extract the threat code from the current page URL
    const result = UrlHelpers.extractResult(window.document.URL);

    // Set the reason text based on the detected threat
    let reasonText;

    if (result) {
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

    // Set the URL text to the current page URL
    document.getElementById("url").innerText = maliciousUrl;

    // Modify the "Reported by" text based on the origin of the protection result
    const origin = UrlHelpers.extractOrigin(window.document.URL);
    const systemName = ProtectionResult.ResultOriginNames[parseInt(origin)];

    let reportUrl;

    switch (origin) {
        case ProtectionResult.ResultOrigin.MICROSOFT.valueOf().toString():
            reportUrl = new URL("https://feedback.smartscreen.microsoft.com/feedback.aspx?t=16&url=" + maliciousUrl);
            document.getElementById("reportedBy").innerText = systemName;
            break;

        case ProtectionResult.ResultOrigin.COMODO.valueOf().toString():
            reportUrl = new URL("https://comodo.com/home/internet-security/submit.php?url=" + maliciousUrl + "&submissionType=2");
            document.getElementById("reportedBy").innerText = systemName;
            break;

        case ProtectionResult.ResultOrigin.EMSISOFT.valueOf().toString():
            reportUrl = new URL("mailto:fp@emsisoft.com?subject=False%20Positive&body=Hello%2C%0A%0AI%20would%20like%20"
                + "to%20report%20a%20false%20positive.%0A%0AProduct%3A%20Emsisoft%20Browser%20Security%0AURL%3A%20"
                + encodeURIComponent(maliciousUrl) + "%0ADetected%20as%3A%20" + encodeURIComponent(reasonText)
                + "%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0AThanks.");
            document.getElementById("reportedBy").innerText = systemName;
            break;

        case ProtectionResult.ResultOrigin.BITDEFENDER.valueOf().toString():
            reportUrl = new URL("https://bitdefender.com/consumer/support/answer/29358/#scroll-to-heading-2");
            document.getElementById("reportedBy").innerText = systemName;
            break;

        case ProtectionResult.ResultOrigin.NORTON.valueOf().toString():
            reportUrl = new URL("https://safeweb.norton.com/report?url=" + encodeURIComponent(maliciousUrl));
            document.getElementById("reportedBy").innerText = systemName;
            break;

        case ProtectionResult.ResultOrigin.TOTAL.valueOf().toString():
            reportUrl = new URL("https://totalwebshield.com/submit-file#false-positive-website");
            document.getElementById("reportedBy").innerText = systemName;
            break;

        case ProtectionResult.ResultOrigin.G_DATA.valueOf().toString():
            reportUrl = new URL("https://submit.gdatasoftware.com/url?key=NWNjNWIzY2RlMGE0ZDA5YzkyNzJmMTA3MTRmZTYwMjBi"
                + "NmZmOWNjZDQ1MTQ1NjQ3F9FNhTj0IOo0u_jyw7nqx5c7jZxGFVmoR7X_4r7__CZJnGtqJsIzn-tN&lang=en");
            document.getElementById("reportedBy").innerText = systemName;
            break;

        default:
            document.getElementById("reportedBy").innerText = "Unknown";
            break;
    }

    // Add event listener to "Report this site" button
    document.getElementById("reportSafe").addEventListener("click", async () => {
        await chrome.runtime.sendMessage({
            messageType: Messages.MessageType.REPORT_SITE,
            reportUrl: reportUrl,
            origin: origin
        });
    });

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
