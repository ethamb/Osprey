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
    ADWARE: "Adware",
    COMPROMISED: "Compromised",
    FLEECEWARE: "Fleeceware",
    UNTRUSTED: "Untrusted"
};

ProtectionResult.ResultOrigin = {
    UNKNOWN: 0, // The result was determined via an unknown origin
    MICROSOFT: 1, // The result was determined via Microsoft SmartScreen
    SYMANTEC: 2, // The result was determined via Symantec
    EMSISOFT: 3, // The result was determined via Emsisoft
    BITDEFENDER: 4, // The result was determined via Bitdefender
    NORTON: 5, // The result was determined via Norton
    TOTAL: 6, // The total was determined via TOTAL WebShield
    G_DATA: 7, // The result was determined via G DATA
};

ProtectionResult.ResultOriginNames = {
    0: "Unknown",
    1: "Microsoft SmartScreen",
    2: "Symantec Browser Protection",
    3: "Emsisoft Web Protection",
    4: "Bitdefender TrafficLight",
    5: "Norton SafeWeb",
    6: "TOTAL WebShield",
    7: "G DATA WebProtection",
};
