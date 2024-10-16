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
    KNOWN_SAFE: "knownsafe",
    FAILED: "failed",
    ALLOWED: "allowed",
    PHISHING: "phishing",
    MALICIOUS: "malicious",
    FRAUD: "fraud",
    PUA: "pua",
    CRYPTOJACKING: "cryptojacking",
    MALVERTISING: "malvertising",
    SPAM: "spam",
    ADWARE: "adware",
    COMPROMISED: "compromised",
    FLEECEWARE: "fleeceware",
    UNTRUSTED: "untrusted"
};

ProtectionResult.ResultOrigin = {
    MICROSOFT: 1, // The result was determined via Microsoft SmartScreen
    COMODO: 2, // The result was determined via Comodo Valkyrie
    EMSISOFT: 3, // The result was determined via Emsisoft
    BITDEFENDER: 4, // The result was determined via Bitdefender
    NORTON: 5, // The result was determined via Norton
    TOTAL: 6, // The total was determined via TOTAL WebShield
    G_DATA: 7 // The result was determined via G Data
};

ProtectionResult.ResultOriginNames = {
    1: "Microsoft SmartScreen",
    2: "Comodo Valkyrie",
    3: "Emsisoft Web Protection",
    4: "Bitdefender TrafficLight",
    5: "Norton SafeWeb",
    6: "TOTAL WebShield",
    7: "G Data WebProtection"
};
