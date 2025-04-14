"use strict";

// Manages the cache for the allowed security systems.
class CacheManager {
    constructor(storageKey = 'allowedCache', debounceDelay = 5000) {
        this.caches = {
            smartScreen: new Map(),
            symantec: new Map(),
            emsisoft: new Map(),
            bitdefender: new Map(),
            norton: new Map(),
            total: new Map(),
            gData: new Map(),
        };

        this.storageKey = storageKey;
        this.debounceDelay = debounceDelay;
        this.timeoutId = null;

        // Retrieve cache from local storage when the service worker wakes up
        Storage.getFromLocalStore(this.storageKey, (storedCaches) => {
            if (storedCaches) {
                Object.keys(this.caches).forEach((cacheName) => {
                    if (storedCaches[cacheName]) {
                        this.caches[cacheName] = new Map(Object.entries(storedCaches[cacheName]));
                    }
                });
            }
        });
    }

    // Debounced function to update local storage with all caches
    updateStorage() {
        if (!this.timeoutId) {
            this.timeoutId = setTimeout(() => {
                this.timeoutId = null;
                const cacheDataToStore = {};

                Object.keys(this.caches).forEach((cacheName) => {
                    cacheDataToStore[cacheName] = Object.fromEntries(this.caches[cacheName]);
                });

                Storage.setToLocalStore(this.storageKey, cacheDataToStore);
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
                    this.updateStorage();
                }
            }
        } catch (error) {
            console.error(error);
        }
        return false; // Return false if URL is not in cache or an error occurred
    }

    // Function to check if a string is in a specific cache and still valid
    isStringInCache(string, cacheName) {
        try {
            const cache = this.caches[cacheName];

            if (cache && cache.has(string)) {
                const expiration = cache.get(string);

                if (expiration > Date.now()) {
                    return true; // Cache is valid, string is allowed
                } else {
                    cache.delete(string); // Cache expired, remove entry
                    this.updateStorage();
                }
            }
        } catch (error) {
            console.error(error);
        }
        return false; // Return false if string is not in cache or an error occurred
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

                // Clean expired entries and update storage
                if (this.cleanExpiredEntries() === 0) {
                    this.updateStorage();
                }
            } else {
                console.warn(`Cache ${cacheName} does not exist.`);
            }
        } catch (error) {
            console.error(error);
        }
    }

    // Function to add a string to a specific cache
    addStringToCache(string, cacheName) {
        try {
            const expirationDate = new Date();
            expirationDate.setDate(expirationDate.getDate() + 1); // Cache expires after 1 day
            const cache = this.caches[cacheName];

            if (cache) {
                cache.set(string, expirationDate.getTime());

                // Clean expired entries and update storage
                if (this.cleanExpiredEntries() === 0) {
                    this.updateStorage();
                }
            } else {
                console.warn(`Cache ${cacheName} does not exist.`);
            }
        } catch (error) {
            console.error(error);
        }
    }

    // Add a method to clean expired entries all at once
    cleanExpiredEntries() {
        const now = Date.now();
        let entriesRemoved = 0;

        Object.keys(this.caches).forEach((cacheName) => {
            const cache = this.caches[cacheName];
            const keysToDelete = [];

            cache.forEach((expiration, url) => {
                if (expiration < now) {
                    keysToDelete.push(url);
                    entriesRemoved++;
                }
            });

            keysToDelete.forEach((url) => {
                cache.delete(url);
            });
        });

        if (entriesRemoved > 0) {
            console.debug(`Removed ${entriesRemoved} expired entries from caches.`);
            this.updateStorage();
        }
        return entriesRemoved;
    }

    // Helper function to normalize URLs
    normalizeUrl(url) {
        // Parse URL only if it's a string
        const urlObj = typeof url === 'string' ? new URL(url) : url;
        let normalizedUrl = UrlHelpers.normalizeHostname(urlObj.hostname + urlObj.pathname);
        return normalizedUrl.endsWith("/") ? normalizedUrl.slice(0, -1) : normalizedUrl;
    }
}
