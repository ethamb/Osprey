"use strict";

// Manages the cache for the allowed security systems.
class CacheManager {
    constructor(storageKey = 'allowedCache', debounceDelay = 5000) {
        this.caches = {
            smartScreen: new Map(),
            comodo: new Map(),
            emsisoft: new Map(),
            bitdefender: new Map(),
            norton: new Map(),
            total: new Map(),
            gData: new Map(),
        };

        this.storageKey = storageKey;
        this.debounceDelay = debounceDelay;
        this.timeoutId = null;

        // Retrieve session cache from Chrome storage when the service worker wakes up
        chrome.storage.session.get([this.storageKey], (sessionData) => {
            if (sessionData[this.storageKey]) {
                const storedCaches = sessionData[this.storageKey];

                Object.keys(this.caches).forEach((cacheName) => {
                    if (storedCaches[cacheName]) {
                        this.caches[cacheName] = new Map(Object.entries(storedCaches[cacheName]));
                    }
                });
            }
        });
    }

    // Debounced function to update session storage with all caches
    updateSessionStorage() {
        if (!this.timeoutId) {
            this.timeoutId = setTimeout(() => {
                this.timeoutId = null;

                const cacheDataToStore = {};
                Object.keys(this.caches).forEach((cacheName) => {
                    cacheDataToStore[cacheName] = Object.fromEntries(this.caches[cacheName]);
                });

                chrome.storage.session.set({[this.storageKey]: cacheDataToStore});
            }, this.debounceDelay);
        }
    }

    // Function to check if the URL is in a specific cache and still valid
    isUrlInCache(url, cacheName) {
        try {
            const normalizedUrl = this.normalizeUrl(url);
            const cache = this.caches[cacheName];

            if (cache && cache.has(normalizedUrl)) {
                const expiration = cache.get(normalizedUrl);

                if (expiration > Date.now()) {
                    return true; // Cache is valid, URL is allowed
                } else {
                    cache.delete(normalizedUrl); // Cache expired, remove entry
                    this.updateSessionStorage();
                }
            }
        } catch (error) {
            console.warn(error);
        }
        return false; // Return false if URL is not in cache or an error occurred
    }

    // Function to add a URL to a specific cache
    addUrlToCache(url, cacheName) {
        try {
            const normalizedUrl = this.normalizeUrl(new URL(url));
            const expirationDate = new Date();
            expirationDate.setDate(expirationDate.getDate() + 1); // Cache expires after 1 day
            const cache = this.caches[cacheName];

            if (cache) {
                cache.set(normalizedUrl, expirationDate.getTime());
                this.updateSessionStorage();
            } else {
                console.warn(`Cache ${cacheName} does not exist.`);
            }
        } catch (error) {
            console.warn(error);
        }
    }

    // Helper function to normalize URLs
    normalizeUrl(url) {
        let normalizedUrl = UrlHelpers.normalizeHostname(url.hostname + url.pathname);

        if (normalizedUrl.endsWith("/")) {
            normalizedUrl = normalizedUrl.slice(0, -1);
        }
        return normalizedUrl;
    }
}
