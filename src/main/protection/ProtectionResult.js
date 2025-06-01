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
    WAITING: "Waiting",
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
    PRECISIONSEC: 1, // The result was determined via PrecisionSec
    SMARTSCREEN: 2, // The result was determined via SmartScreen
    SYMANTEC: 3, // The result was determined via Symantec
    EMSISOFT: 4, // The result was determined via Emsisoft
    BITDEFENDER: 5, // The result was determined via Bitdefender
    NORTON: 6, // The result was determined via Norton
    G_DATA: 7, // The result was determined via G DATA
    CLOUDFLARE: 8, // The result was determined via Cloudflare
    QUAD9: 9, // The result was determined via Quad9
    DNS0: 10, // The result was determined via DNS0
    CLEANBROWSING: 11, // The result was determined via CleanBrowsing
    CIRA: 12, // The result was determined via CIRA
    ADGUARD: 13, // The result was determined via AdGuard
    SWITCH_CH: 14, // The result was determined via Switch.ch
    CERT_EE: 15, // The result was determined via CERT-EE
    CONTROL_D: 16, // The result was determined via Control D
};

ProtectionResult.ResultOriginNames = {
    0: "Unknown",
    1: "PrecisionSec Web Protection",
    2: "Microsoft SmartScreen",
    3: "Symantec Browser Protection",
    4: "Emsisoft Web Protection",
    5: "Bitdefender TrafficLight",
    6: "Norton SafeWeb",
    7: "G DATA WebProtection",
    8: "Cloudflare Security DNS",
    9: "Quad9 Security DNS",
    10: "DNS0.eu Security DNS",
    11: "CleanBrowsing Security DNS",
    12: "CIRA Canadian Shield DNS",
    13: "AdGuard Security DNS",
    14: "Switch.ch Security DNS",
    15: "CERT-EE Security DNS",
    16: "Control D Security DNS"
};

ProtectionResult.ShortOriginNames = {
    0: "Unknown",
    1: "PrecisionSec",
    2: "SmartScreen",
    3: "Symantec",
    4: "Emsisoft",
    5: "Bitdefender",
    6: "Norton",
    7: "G DATA",
    8: "Cloudflare",
    9: "Quad9",
    10: "DNS0",
    11: "CleanBrowsing",
    12: "CIRA",
    13: "AdGuard",
    14: "Switch.ch",
    15: "CERT-EE",
    16: "Control D"
};

ProtectionResult.CacheOriginNames = {
    0: "unknown",
    1: "precisionSec",
    2: "smartScreen",
    3: "symantec",
    4: "emsisoft",
    5: "bitdefender",
    6: "norton",
    7: "gData",
    8: "cloudflare",
    9: "quad9",
    10: "dns0",
    11: "cleanBrowsing",
    12: "cira",
    13: "adGuard",
    14: "switchCH",
    15: "certEE",
    16: "controlD"
};
