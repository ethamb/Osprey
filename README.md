# Osprey: Browser Protection

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![CodeQL](https://github.com/Foulest/Osprey/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Foulest/Osprey/actions/workflows/github-code-scanning/codeql)
![Chrome Users](https://img.shields.io/chrome-web-store/users/jmnpibhfpmpfjhhkmpadlbgjnbhpjgnd?label=Chrome%20Users&color=00CC00)
![Edge Users](https://img.shields.io/badge/dynamic/json?label=Edge%20Users&color=00CC00&query=%24.activeInstallCount&url=https%3A%2F%2Fmicrosoftedge.microsoft.com%2Faddons%2Fgetproductdetailsbycrxid%2Fnopglhplnghfhpniofkcopmhbjdonlgn)
![Firefox Users](https://img.shields.io/amo/users/osprey-browser-protection?label=Firefox%20Users&color=00CC00)

**Osprey** is a browser extension that protects you from malicious websites.

[Google Chrome](https://chromewebstore.google.com/detail/osprey-browser-protection/jmnpibhfpmpfjhhkmpadlbgjnbhpjgnd)
• [Microsoft Edge](https://microsoftedge.microsoft.com/addons/detail/osprey-browser-protectio/nopglhplnghfhpniofkcopmhbjdonlgn)
• [Firefox](https://addons.mozilla.org/en-US/firefox/addon/osprey-browser-protection)
• [Privacy Policy](https://github.com/Foulest/Osprey/blob/main/.github/PRIVACY.md)
• [Wiki (FAQs)](https://github.com/Foulest/Osprey/wiki)

![Osprey Banner](https://i.imgur.com/K8m11GN.png)

## Detections

Osprey blocks websites that are classified as:

- [Malicious](https://us.norton.com/blog/malware/what-are-malicious-websites)
- [Phishing](https://f-secure.com/us-en/articles/what-is-phishing)
- [Fraud](https://usa.kaspersky.com/resource-center/preemptive-safety/scam-websites)
- [PUAs](https://us.norton.com/blog/malware/what-are-puas-potentially-unwanted-applications)
- [Cryptojacking](https://kaspersky.com/resource-center/definitions/what-is-cryptojacking)
- [Malvertising](https://malwarebytes.com/malvertising)
- [Spam](https://developers.google.com/search/docs/essentials/spam-policies)
- [Compromised](https://malwarebytes.com/glossary/compromised)
- [Untrusted](https://mcafee.com/blogs/internet-security/how-to-tell-whether-a-website-is-safe-or-unsafe)

## Warning

If the website is malicious, Osprey will block the page and display a warning:

![Osprey Warning](https://i.imgur.com/eu7BFrH.png)

From this page, you can report the website as safe, temporarily allow the website, go back to safety, and continue
anyway. By default, Osprey creates a browser notification for blocked pages that
[you can toggle on and off](https://github.com/Foulest/Osprey/wiki/Toggling-Notifications) using the context menu.
You can hide the continue and report buttons, lock down the protection options, and even hide the context menu
entirely using [the system policies](https://github.com/Foulest/Osprey/wiki/Setting-Up-System-Policies).

## Settings

You can configure the extension's protection options in the settings:

![Osprey Settings (Page 1)](https://i.imgur.com/bHaKequ.png)
![Osprey Settings (Page 2)](https://i.imgur.com/IYsA85t.png)

## Protection Providers

The following providers are **enabled** by default:

- [Microsoft SmartScreen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen)
- [Emsisoft Web Protection](https://emsisoft.com/en/help/1636/web-protection)
- [Bitdefender TrafficLight](https://bitdefender.com/en-us/consumer/trafficlight)
- [Norton SafeWeb](https://safeweb.norton.com)
- [G DATA WebProtection](https://gdata.de/help/en/consumer/FAQ/webProtectionWinFAQ)
- [Quad9 Security DNS](https://quad9.net)
- [AdGuard Security DNS](https://adguard-dns.io/en/public-dns.html)
- [Switch.ch Security DNS](https://switch.ch/en/dns-firewall)
- [CERT-EE Security DNS](https://ria.ee/en/news/application-developed-cert-ee-protects-against-phishing-and-malware)
- [Control D Security DNS](https://controld.com)

The following providers are **disabled** by default:

- [Symantec Browser Protection](https://chromewebstore.google.com/detail/symantec-browser-protecti/hielpjjagjimpgppnopiibaefhfpbpfn)
- [MalwareURL Protection](https://www.malwareurl.com)
- [Cloudflare Security DNS](https://blog.cloudflare.com/introducing-1-1-1-1-for-families/#two-flavors-1-1-1-2-no-malware-1-1-1-3-no-malware-or-adult-content)
- [DNS0.eu Security DNS](https://dns0.eu/zero)
- [CleanBrowsing Security DNS](https://cleanbrowsing.org/filters/#step3)
- [CIRA Canadian Shield DNS](https://cira.ca/en/canadian-shield)

Providers disabled by default are either due to frequent reports of false positives or an unreliable support email or 
website for reporting said false positives. If a provider gives you false positives, report the links to them directly 
and disable them in the settings panel. Osprey is designed to be customizable, so you can enable or disable any of the 
providers at any time. Osprey does not have control over the providers' databases or how they classify URLs.

## Privacy

Osprey strips down each URL of tracking parameters before sending it to any APIs.

For example:

1. If you search for shirts on Amazon and
   visit: https://www.amazon.com/s?k=shirts&crid=3TOVSW14ZHF8V&sprefix=shirt%2Caps%2C175&ref=nb_sb_noss_1
2. Osprey will only send https://amazon.com/s to any APIs you have enabled.
3. If the APIs report that the page is safe to visit, Osprey caches the result for 24 hours.
4. It will also be cached if you click 'Continue anyway' or 'Temporarily allow this website' on a blocked site.
5. As long as a URL is cached, no new network requests will be made for it.

The only data the APIs receive is the stripped-down URL, your user agent, and your IP address. Use a reputable VPN or
proxy service if you're concerned about IP-related privacy. There are also extensions that mask your user agent, if
you're so inclined.

As for why Osprey needs to check complete URLs instead of just the domain, many phishing attacks use legitimate
companies to host their phishing campaigns, such as Jotform. If Osprey only checked a website's domain name, it wouldn't
detect those threats. Osprey only sends your hostname to its various DNS API providers, so if you're highly concerned
about URL page privacy, the DNS APIs are there for you.

## Installation

You can install Osprey from the web stores listed at the top.

For other installations, you can install the extension manually:

### Chrome/Edge

1. Navigate to the [Actions section](https://github.com/Foulest/Osprey/actions/workflows) and click `Compile for Chrome`
   or `Compile for Edge`.
2. Scroll down to the `Artifacts` section and download the artifact file.
3. Extract the artifact's ZIP file to a folder on your computer.
4. Navigate to `about://extensions` in your browser.
5. Enable `Developer mode` and click `Load unpacked`.
6. Select the downloaded ZIP file and click `Select Folder`.

### Firefox

> Note: This only works for [builds of Firefox that allow unsigned addons.](https://support.mozilla.org/en-US/kb/add-on-signing-in-firefox#w_what-are-my-options-if-i-want-to-use-an-unsigned-add-on-advanced-users)

1. Navigate to the [Actions section](https://github.com/Foulest/Osprey/actions/workflows) and click
   `Compile for Firefox`.
2. Scroll down to the `Artifacts` section and download the artifact file.
3. Extract the artifact's ZIP file to a folder on your computer.
4. Navigate to `about:addons` in your browser.
5. Click the gear icon and select `Install Add-on From File`.
6. Select the downloaded ZIP file and click `Select Folder`.

Osprey should now be installed in your browser.

## Getting Help

For support or queries, please open an issue in the [Issues section](https://github.com/Foulest/Osprey/issues).
