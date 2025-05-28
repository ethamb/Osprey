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
    MICROSOFT: 1, // The result was determined via Microsoft SmartScreen
    SYMANTEC: 2, // The result was determined via Symantec
    EMSISOFT: 3, // The result was determined via Emsisoft
    BITDEFENDER: 4, // The result was determined via Bitdefender
    NORTON: 5, // The result was determined via Norton
    G_DATA: 6, // The result was determined via G DATA
    MALWAREURL: 7, // The result was determined via MalwareURL
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
    1: "Microsoft SmartScreen",
    2: "Symantec Browser Protection",
    3: "Emsisoft Web Protection",
    4: "Bitdefender TrafficLight",
    5: "Norton SafeWeb",
    6: "G DATA WebProtection",
    7: "MalwareURL Protection",
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
    1: "SmartScreen",
    2: "Symantec",
    3: "Emsisoft",
    4: "Bitdefender",
    5: "Norton",
    6: "G DATA",
    7: "MalwareURL",
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
    1: "smartScreen",
    2: "symantec",
    3: "emsisoft",
    4: "bitdefender",
    5: "norton",
    6: "gData",
    7: "malwareURL",
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
