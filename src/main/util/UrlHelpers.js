"use strict";

// Object containing helper functions for working with URLs.
const UrlHelpers = {

    /**
     * Extracts the result (e.g., phishing, malware) from the query parameters of a URL.
     *
     * @param {string} url - The URL containing the result.
     * @returns {string|null} - The result from the URL, or null if not found.
     */
    extractResult: url => new URL(url).searchParams.get("rs"),

    /**
     * Extracts the malicious URL (the site being reported as malicious) from the query parameters of a URL.
     * @param {string} url - The URL containing the malicious site information.
     * @returns {string|null} - The malicious URL, or null if not found.
     */
    extractMaliciousUrl: url => new URL(url).searchParams.get("u"),

    /**
     * Extracts the continue-to-site URL from the query parameters of a URL.
     * @param {string} url - The URL containing the continue URL.
     * @returns {string|null} - The continue-to-site URL, or null if not found.
     */
    extractContinueUrl: url => new URL(url).searchParams.get("cu"),

    /**
     * Extracts the origin of the protection result from the query parameters of a URL.
     * @param url - The URL containing the origin information
     * @returns {string} - The origin of the protection result
     */
    extractOrigin: url => new URL(url).searchParams.get("origin"),

    /**
     * Constructs the URL for the browser's block page, which shows a warning when a site is blocked.
     * @param {string} continueUrl - The URL to continue to the blocked site.
     * @param {object} protectionResult - The result object containing details about the threat.
     * @param {string} instanceId - A unique identifier for the block event.
     * @param {string} sessionId - A unique session identifier.
     * @returns {string} - The full URL for the block page.
     */
    getBlockPageUrl: (continueUrl, protectionResult, instanceId, sessionId) => {
        // Base URL for the block page
        const blockPageBaseUrl = chrome.runtime.getURL("pages/warning/WarningPage.html");

        // Determine the result from the protection result object
        const result = protectionResult.result;

        // Construct a new URL object for the block page
        let blockPageUrl = new URL(blockPageBaseUrl);

        // Set the search parameters for the block page URL
        blockPageUrl.search = new URLSearchParams([
            ["u", protectionResult.url],         // The URL of the malicious or blocked site
            ["rs", result],                      // The result
            ["cu", continueUrl],                 // Continue-to-site URL
            ["origin", protectionResult.origin], // The origin of the protection result
            ["iid", instanceId || ""],           // Unique instance ID for the block event
            ["sid", sessionId || ""]             // Unique session ID
        ]).toString();

        // Return the constructed block page URL as a string
        return blockPageUrl.toString();
    },

    /**
     * Normalizes a hostname by removing "www." if it exists.
     * @param {string} hostname - The hostname to normalize.
     * @returns {string} - The normalized hostname.
     */
    normalizeHostname: hostname => {
        // Ensure the hostname is a string before proceeding
        if (typeof hostname !== 'string') {
            return '';
        }

        // Remove "www." prefix if it exists in the hostname
        if (hostname.toLowerCase().startsWith("www.")) {
            hostname = hostname.substring(4);
        }
        return hostname;
    }
};
