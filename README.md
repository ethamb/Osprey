# Osprey: Browser Protection

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![CodeQL](https://github.com/Foulest/Osprey/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Foulest/Osprey/actions/workflows/github-code-scanning/codeql)
![Chrome Stats](https://img.shields.io/chrome-web-store/users/jmnpibhfpmpfjhhkmpadlbgjnbhpjgnd?label=Chrome%20Installs&color=00CC00)
![Edge Stats](https://img.shields.io/badge/dynamic/json?label=Edge%20Installs&color=00CC00&query=%24.activeInstallCount&url=https%3A%2F%2Fmicrosoftedge.microsoft.com%2Faddons%2Fgetproductdetailsbycrxid%2Fnopglhplnghfhpniofkcopmhbjdonlgn)

**Osprey** is a browser extension that protects you from malicious websites.

[Google Chrome](https://chromewebstore.google.com/detail/osprey-browser-protection/jmnpibhfpmpfjhhkmpadlbgjnbhpjgnd)
• [Microsoft Edge](https://microsoftedge.microsoft.com/addons/detail/osprey-browser-protectio/nopglhplnghfhpniofkcopmhbjdonlgn)
• Firefox (TBD)

[Privacy Policy](https://github.com/Foulest/Osprey/blob/main/.github/PRIVACY.md)
• [Wiki (FAQs)](https://github.com/Foulest/Osprey/wiki)
• [Discord Server](https://discord.gg/ujYcBCgkSr)

![Osprey Banner](https://i.imgur.com/K8m11GN.png)

## Protections

By default, when you visit a website, **Osprey** checks the URL with:

- [Microsoft SmartScreen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen)
- [Symantec Browser Protection](https://chromewebstore.google.com/detail/symantec-browser-protecti/hielpjjagjimpgppnopiibaefhfpbpfn)
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

- [Malicious](https://us.norton.com/blog/malware/what-are-malicious-websites)
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

## Privacy

**Osprey** strips down each URL of tracking parameters before sending it to any APIs.

For example:
1. If you search for shirts on Amazon and visit: https://www.amazon.com/s?k=shirts&crid=3TOVSW14ZHF8V&sprefix=shirt%2Caps%2C175&ref=nb_sb_noss_1
2. Osprey will only send https://amazon.com/s to any APIs you have enabled.
3. If the APIs report that the page is safe to visit, Osprey caches the result for 24 hours.
4. It will also be cached if you click 'Continue anyway' or 'Add hostname to allowlist' on a blocked site.
5. As long as a URL is cached, no new network requests will be made for it.

The only data the APIs receive is the stripped-down URL, your user agent, and your IP address.

Use a reputable VPN or proxy service if you're concerned about IP-related privacy.

## Installation

You can install **Osprey** from the web stores listed at the top.

For other installations, you can install the extension manually:

### Chrome or Edge

1. Navigate to the [Actions section](https://github.com/Foulest/Osprey/actions/workflows) and click `Compile for Chrome` or `Compile for Edge`.
2. Scroll down to the `Artifacts` section and download the artifact file.
3. Extract the artifact's ZIP file to a folder on your computer.
4. Navigate to `about://extensions` in your browser.
5. Enable `Developer mode` and click `Load unpacked`.
6. Select the downloaded ZIP file and click `Select Folder`.

### Firefox

1. Navigate to the [Actions section](https://github.com/Foulest/Osprey/actions/workflows) and click `Compile for Firefox`.
2. Scroll down to the `Artifacts` section and download the artifact file.
3. Extract the artifact's ZIP file to a folder on your computer.
4. Navigate to `about:addons` in your browser.
5. Click the gear icon and select `Install Add-on From File`.
6. Select the downloaded ZIP file and click `Select Folder`.

**Osprey** should now be installed in your browser.

## Getting Help

For support or queries, please open an issue in the [Issues section](https://github.com/Foulest/Osprey/issues).
