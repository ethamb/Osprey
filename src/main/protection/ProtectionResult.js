"use strict";

class ProtectionResult {
    /**
     * Constructor function for creating a browser protection result object.
     * @param {string} urlChecked - The URL that was checked.
     * @param {string} resultType - The result type of the protection check (e.g., "allowed", "malicious").
     * @param {number} resultOrigin - The origin of the result (e.g., from endpoint or known top site).
     */
    constructor(urlChecked, resultType, resultOrigin) {
        this.url = urlChecked;
        this.result = resultType;
        this.origin = resultOrigin;
    }
}

ProtectionResult.ResultType = {
    KNOWN_SAFE: "Known Safe",
    FAILED: "Failed",
    ALLOWED: "Allowed",
    PHISHING: "Phishing",
    MALICIOUS: "Malicious",
    FRAUD: "Fraud",
    PUA: "Potentially Unwanted Applications",
    CRYPTOJACKING: "Cryptojacking",
    MALVERTISING: "Malvertising",
    SPAM: "Spam",
    COMPROMISED: "Compromised",
    UNTRUSTED: "Untrusted"
};

ProtectionResult.ResultOrigin = {
    UNKNOWN: 0, // The result was determined via an unknown origin
    MICROSOFT: 1, // The result was determined via Microsoft SmartScreen
    SYMANTEC: 2, // The result was determined via Symantec
    EMSISOFT: 3, // The result was determined via Emsisoft
    BITDEFENDER: 4, // The result was determined via Bitdefender
    NORTON: 5, // The result was determined via Norton
    G_DATA: 6, // The result was determined via G DATA
    CLOUDFLARE: 7, // The result was determined via Cloudflare
    QUAD9: 8, // The result was determined via Quad9
    DNS0: 9, // The result was determined via DNS0
    CLEANBROWSING: 10, // The result was determined via CleanBrowsing
    CIRA: 11, // The result was determined via CIRA
    ADGUARD: 12, // The result was determined via AdGuard
    SWITCH_CH: 13, // The result was determined via Switch.ch
    CERT_EE: 14, // The result was determined via CERT-EE
};

ProtectionResult.ResultOriginNames = {
    0: "Unknown",
    1: "Microsoft SmartScreen",
    2: "Symantec Browser Protection",
    3: "Emsisoft Web Protection",
    4: "Bitdefender TrafficLight",
    5: "Norton SafeWeb",
    6: "G DATA WebProtection",
    7: "Cloudflare Security DNS",
    8: "Quad9 Security DNS",
    9: "DNS0.eu Security DNS",
    10: "CleanBrowsing Security DNS",
    11: "CIRA Canadian Shield DNS",
    12: "AdGuard Security DNS",
    13: "Switch.ch Security DNS",
    14: "CERT-EE Security DNS"
};
