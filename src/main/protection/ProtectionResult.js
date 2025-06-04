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
    COMPROMISED: "Compromised",
    UNTRUSTED: "Untrusted",
    RESTRICTED: "Restricted",
};

ProtectionResult.ResultOrigin = {
    UNKNOWN: 0,

    // Page 1
    PRECISIONSEC: 1,
    BITDEFENDER: 2,
    EMSISOFT: 3,
    G_DATA: 4,
    SMARTSCREEN: 5,
    NORTON: 6,

    // Page 2
    ADGUARD_SECURITY: 7,
    ADGUARD_FAMILY: 8,
    CERT_EE: 9,
    CIRA_SECURITY: 10,
    CIRA_FAMILY: 11,
    CLEANBROWSING_SECURITY: 12,
    CLEANBROWSING_FAMILY: 13,

    // Page 3
    CLEANBROWSING_ADULT: 14,
    CLOUDFLARE_SECURITY: 15,
    CLOUDFLARE_FAMILY: 16,
    CONTROL_D_SECURITY: 17,
    CONTROL_D_FAMILY: 18,
    DNS0_SECURITY: 19,
    DNS0_KIDS: 20,

    // Page 4
    OPENDNS_SECURITY: 21,
    OPENDNS_FAMILY_SHIELD: 22,
    QUAD9: 23,
    SWITCH_CH: 24,
};

ProtectionResult.ResultOriginNames = {
    0: "Unknown",

    // Page 1
    1: "PrecisionSec Web Protection",
    2: "Bitdefender TrafficLight",
    3: "Emsisoft Web Protection",
    4: "G DATA WebProtection",
    5: "Microsoft SmartScreen",
    6: "Norton SafeWeb",
    7: "AdGuard Security DNS",

    // Page 2
    8: "AdGuard Family DNS",
    9: "CERT-EE Security DNS",
    10: "CIRA Security DNS",
    11: "CIRA Family DNS",
    12: "CleanBrowsing Security DNS",
    13: "CleanBrowsing Family DNS",
    14: "CleanBrowsing Adult DNS",

    // Page 3
    15: "Cloudflare Security DNS",
    16: "Cloudflare Family DNS",
    17: "Control D Security DNS",
    18: "Control D Family DNS",
    29: "DNS0 Security DNS",
    20: "DNS0 Kids DNS",
    21: "OpenDNS Security DNS",

    // Page 4
    22: "OpenDNS Family Shield DNS",
    23: "Quad9 Security DNS",
    24: "Switch.ch Security DNS"
};

ProtectionResult.ShortOriginNames = {
    0: "Unknown",

    // Page 1
    1: "PrecisionSec",
    2: "Bitdefender",
    3: "Emsisoft",
    4: "G DATA",
    5: "SmartScreen",
    6: "Norton",
    7: "AdGuard Security",

    // Page 2
    8: "AdGuard Family",
    9: "CERT-EE",
    10: "CIRA Security",
    11: "CIRA Family",
    12: "CleanBrowsing Security",
    13: "CleanBrowsing Family",
    14: "CleanBrowsing Adult",

    // Page 3
    15: "Cloudflare Security",
    16: "Cloudflare Family",
    17: "Control D Security",
    18: "Control D Family",
    19: "DNS0 Security",
    20: "DNS0 Kids",
    21: "OpenDNS Security",

    // Page 4
    22: "OpenDNS Family Shield",
    23: "Quad9",
    24: "Switch.ch"
};

ProtectionResult.CacheOriginNames = {
    0: "unknown",

    // Page 1
    1: "precisionSec",
    2: "bitdefender",
    3: "emsisoft",
    4: "gData",
    5: "smartScreen",
    6: "norton",
    7: "adGuardSecurity",

    // Page 2
    8: "adGuardFamily",
    9: "certEE",
    10: "ciraSecurity",
    11: "ciraFamily",
    12: "cleanBrowsingSecurity",
    13: "cleanBrowsingFamily",
    14: "cleanBrowsingAdult",

    // Page 3
    15: "cloudflareSecurity",
    16: "cloudflareFamily",
    17: "controlDSecurity",
    18: "controlDFamily",
    19: "dns0Security",
    20: "dns0Kids",
    21: "openDNSSecurity",

    // Page 4
    22: "openDNSFamilyShield",
    23: "quad9",
    24: "switchCH"
};
