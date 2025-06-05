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
    G_DATA: 3,
    SMARTSCREEN: 4,
    NORTON: 5,
    ADGUARD_SECURITY: 6,
    ADGUARD_FAMILY: 7,

    // Page 2
    CERT_EE: 8,
    CIRA_SECURITY: 9,
    CIRA_FAMILY: 10,
    CLEANBROWSING_SECURITY: 11,
    CLEANBROWSING_FAMILY: 12,
    CLEANBROWSING_ADULT: 13,
    CLOUDFLARE_SECURITY: 14,

    // Page 3
    CLOUDFLARE_FAMILY: 15,
    CONTROL_D_SECURITY: 16,
    CONTROL_D_FAMILY: 17,
    DNS0_SECURITY: 18,
    DNS0_KIDS: 19,
    OPENDNS_SECURITY: 20,
    OPENDNS_FAMILY_SHIELD: 21,

    // Page 4
    QUAD9: 23,
    SWITCH_CH: 24,
};

ProtectionResult.ResultOriginNames = {
    0: "Unknown",

    // Page 1
    1: "PrecisionSec Web Protection",
    2: "Bitdefender TrafficLight",
    3: "G DATA WebProtection",
    4: "Microsoft SmartScreen",
    5: "Norton SafeWeb",
    6: "AdGuard Security DNS",
    7: "AdGuard Family DNS",

    // Page 2
    8: "CERT-EE Security DNS",
    9: "CIRA Security DNS",
    10: "CIRA Family DNS",
    11: "CleanBrowsing Security DNS",
    12: "CleanBrowsing Family DNS",
    13: "CleanBrowsing Adult DNS",
    14: "Cloudflare Security DNS",

    // Page 3
    15: "Cloudflare Family DNS",
    16: "Control D Security DNS",
    17: "Control D Family DNS",
    18: "DNS0 Security DNS",
    19: "DNS0 Kids DNS",
    20: "OpenDNS Security DNS",
    21: "OpenDNS Family Shield DNS",

    // Page 4
    22: "Quad9 Security DNS",
    23: "Switch.ch Security DNS"
};

ProtectionResult.ShortOriginNames = {
    0: "Unknown",

    // Page 1
    1: "PrecisionSec",
    2: "Bitdefender",
    3: "G DATA",
    4: "SmartScreen",
    5: "Norton",
    6: "AdGuard Security",
    7: "AdGuard Family",

    // Page 2
    8: "CERT-EE",
    9: "CIRA Security",
    10: "CIRA Family",
    11: "CleanBrowsing Security",
    12: "CleanBrowsing Family",
    13: "CleanBrowsing Adult",
    14: "Cloudflare Security",

    // Page 3
    15: "Cloudflare Family",
    16: "Control D Security",
    17: "Control D Family",
    18: "DNS0 Security",
    19: "DNS0 Kids",
    20: "OpenDNS Security",
    21: "OpenDNS Family Shield",

    // Page 4
    23: "Quad9",
    24: "Switch.ch"
};

ProtectionResult.CacheOriginNames = {
    0: "unknown",

    // Page 1
    1: "precisionSec",
    2: "bitdefender",
    3: "gData",
    4: "smartScreen",
    5: "norton",
    6: "adGuardSecurity",
    7: "adGuardFamily",

    // Page 2
    8: "certEE",
    9: "ciraSecurity",
    10: "ciraFamily",
    11: "cleanBrowsingSecurity",
    12: "cleanBrowsingFamily",
    13: "cleanBrowsingAdult",
    14: "cloudflareSecurity",

    // Page 3
    15: "cloudflareFamily",
    16: "controlDSecurity",
    17: "controlDFamily",
    18: "dns0Security",
    19: "dns0Kids",
    20: "openDNSSecurity",
    21: "openDNSFamilyShield",

    // Page 4
    23: "quad9",
    24: "switchCH"
};
