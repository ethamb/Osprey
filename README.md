# Osprey: Browser Protection

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![CodeQL](https://github.com/Foulest/Osprey/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Foulest/Osprey/actions/workflows/github-code-scanning/codeql)

**Osprey** is a browser extension that protects you from malicious websites.

![Osprey Banner](https://i.imgur.com/K8m11GN.png)

## Protections

When you visit a website, **Osprey** checks the URL with:

- [Microsoft SmartScreen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen)
- [Comodo Valkyrie](https://valkyrie.comodo.com)
- [Emsisoft Web Protection](https://emsisoft.com/en/help/1636/web-protection)
- [Bitdefender TrafficLight](https://bitdefender.com/en-us/consumer/trafficlight)
- [Norton SafeWeb](https://safeweb.norton.com)
- [TOTAL WebShield](https://dashboard.totalwebshield.com/products/totalwebshield)
- [G DATA WebProtection](https://gdata.de/help/en/consumer/FAQ/webProtectionWinFAQ)

## Settings

You can configure the extension's protection options in the settings:

![Osprey Settings](https://i.imgur.com/lHZHTas.png)

## Detections

**Osprey** blocks websites that are classified as:

- [Malware](https://us.norton.com/blog/malware/what-are-malicious-websites)
- [Phishing](https://f-secure.com/us-en/articles/what-is-phishing)
- [Fraud](https://usa.kaspersky.com/resource-center/preemptive-safety/scam-websites)
- [PUAs](https://us.norton.com/blog/malware/what-are-puas-potentially-unwanted-applications)
- [Cryptojacking](https://kaspersky.com/resource-center/definitions/what-is-cryptojacking)
- [Malvertising](https://malwarebytes.com/malvertising)
- [Spam](https://developers.google.com/search/docs/essentials/spam-policies)
- [Adware](https://us.norton.com/blog/malware/adware)
- [Compromised](https://malwarebytes.com/glossary/compromised)
- [Fleeceware](https://blog.avast.com/how-to-spot-fleeceware)
- [Untrusted](https://mcafee.com/blogs/internet-security/how-to-tell-whether-a-website-is-safe-or-unsafe)

## Warning

If the website is malicious, **Osprey** will block the page and display a warning:

![Osprey Warning](https://i.imgur.com/Avbwce5.png)

## Installation

You can install **Osprey** from the [Chrome Web Store]().

If that doesn't work, you can install the extension manually:

1. Download the latest release from the [Releases section](https://github.com/Foulest/Osprey/releases).
2. If you want a newer build, download the latest artifact from
   the [Actions section](https://github.com/Foulest/Osprey/actions/workflows).
3. Navigate to `chrome://extensions` or `edge://extensions` in your browser.
4. Enable `Developer mode` and click `Load unpacked`.
5. Select the downloaded ZIP file and click `Select Folder`.

**Osprey** should now be installed in your browser.

You can test the extension by visiting the [WICAR](https://wicar.org) website.

## Getting Help

For support or queries, please open an issue in the [Issues section](https://github.com/Foulest/Osprey/issues).
