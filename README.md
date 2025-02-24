# Osprey: Browser Protection

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![CodeQL](https://github.com/Foulest/Osprey/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Foulest/Osprey/actions/workflows/github-code-scanning/codeql)
![Chrome Stats](https://img.shields.io/chrome-web-store/users/jmnpibhfpmpfjhhkmpadlbgjnbhpjgnd?label=Chrome%20Installs&color=00CC00)
![Edge Stats](https://img.shields.io/badge/dynamic/json?label=Edge%20Installs&color=00CC00&query=%24.activeInstallCount&url=https%3A%2F%2Fmicrosoftedge.microsoft.com%2Faddons%2Fgetproductdetailsbycrxid%2Fnopglhplnghfhpniofkcopmhbjdonlgn)

**Osprey** is a browser extension that protects you from malicious websites.

[Chrome Web Store](https://chromewebstore.google.com/detail/osprey-browser-protection/jmnpibhfpmpfjhhkmpadlbgjnbhpjgnd)
• [Microsoft Edge Addons](https://microsoftedge.microsoft.com/addons/detail/osprey-browser-protectio/nopglhplnghfhpniofkcopmhbjdonlgn)
• [Privacy Policy](https://github.com/Foulest/Osprey/blob/main/.github/PRIVACY.md)

![Osprey Banner](https://i.imgur.com/K8m11GN.png)

## Protections

By default, when you visit a website, **Osprey** checks the URL with:

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

![Osprey Warning](https://i.imgur.com/FpPtbJh.png)

## Installation

You can install **Osprey** from the web stores listed at the top.

For other installations, you can install the extension manually:

1. Navigate to the [Actions section](https://github.com/Foulest/Osprey/actions/workflows) and click `Compile for Chrome` or `Compile for Edge`.
2. Scroll down to the `Artifacts` section and download the artifact file.
3. Extract the artifact's ZIP file to a folder on your computer.
4. Navigate to `about://extensions` in your browser.
5. Enable `Developer mode` and click `Load unpacked`.
6. Select the downloaded ZIP file and click `Select Folder`.

**Osprey** should now be installed in your browser.

## Getting Help

For support or queries, please open an issue in the [Issues section](https://github.com/Foulest/Osprey/issues).
