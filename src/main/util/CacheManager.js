"use strict";

// Manages the cache for the allowed protection providers.
class CacheManager {
    constructor(allowedKey = 'allowedCache', processingKey = 'processingCache', debounceDelay = 5000) {
        Settings.get(settings => {
            this.expirationTime = settings.cacheExpirationSeconds;
            this.allowedKey = allowedKey;
            this.processingKey = processingKey;
            this.debounceDelay = debounceDelay;
            this.timeoutId = null;

            const providers = [
                "precisionSec", "smartScreen", "symantec", "emsisoft", "bitdefender",
                "norton", "gData", "cloudflare", "quad9", "dns0", "cleanBrowsing",
                "cira", "adGuard", "switchCH", "certEE", "controlD",
            ];

            this.allowedCaches = {};
            this.processingCaches = {};

            providers.forEach(name => {
                this.allowedCaches[name] = new Map();
                this.processingCaches[name] = new Map();
            });

            Storage.getFromLocalStore(this.allowedKey, stored => {
                if (!stored) {
                    return;
                }

                Object.keys(this.allowedCaches).forEach(name => {
                    if (stored[name]) {
                        this.allowedCaches[name] = new Map(Object.entries(stored[name]));
                    }
                });
            });

            Storage.getFromSessionStore(this.processingKey, stored => {
                if (!stored) {
                    return;
                }

                Object.keys(this.processingCaches).forEach(name => {
                    if (stored[name]) {
                        this.processingCaches[name] = new Map(Object.entries(stored[name]));
                    }
                });
            });
        });
    }

    updateLocalStorage(debounced) {
        const write = () => {
            const out = {};

            Object.keys(this.allowedCaches).forEach(name => {
                out[name] = Object.fromEntries(this.allowedCaches[name]);
            });

            Storage.setToLocalStore(this.allowedKey, out);
        };

        if (debounced) {
            if (!this.timeoutId) {
                this.timeoutId = setTimeout(() => {
                    this.timeoutId = null;
                    write();
                }, this.debounceDelay);
            }
        } else {
            write();
        }
    }

    updateSessionStorage(debounced) {
        const write = () => {
            const out = {};

            Object.keys(this.processingCaches).forEach(name => {
                out[name] = Object.fromEntries(this.processingCaches[name]);
            });

            Storage.setToSessionStore(this.processingKey, out);
        };

        if (debounced) {
            if (!this.timeoutId) {
                this.timeoutId = setTimeout(() => {
                    this.timeoutId = null;
                    write();
                }, this.debounceDelay);
            }
        } else {
            write();
        }
    }

    clearAllowedCache() {
        Object.values(this.allowedCaches).forEach(m => m.clear());
        this.updateLocalStorage(false);
    }

    clearProcessingCache() {
        Object.values(this.processingCaches).forEach(m => m.clear());
        this.updateSessionStorage(false);
    }

    cleanExpiredEntries() {
        const now = Date.now();
        let removed = 0;

        const cleanGroup = (group, onDirty) => {
            Object.values(group).forEach(map => {
                for (const [key, exp] of map.entries()) {
                    if (exp < now) {
                        map.delete(key);
                        removed++;
                    }
                }
            });

            if (removed > 0) {
                onDirty(true);
            }
        };

        cleanGroup(this.allowedCaches, () => this.updateLocalStorage(true));
        cleanGroup(this.processingCaches, () => this.updateSessionStorage(true));
        return removed;
    }

    normalizeUrl(url) {
        const u = typeof url === "string" ? new URL(url) : url;
        let norm = UrlHelpers.normalizeHostname(u.hostname + u.pathname);
        return norm.endsWith("/") ? norm.slice(0, -1) : norm;
    }

    isUrlInAllowedCache(url, name) {
        try {
            const key = this.normalizeUrl(url);
            const map = this.allowedCaches[name];

            if (!map) {
                return false;
            }

            if (map.has(key)) {
                const exp = map.get(key);

                if (exp > Date.now()) {
                    return true;
                }

                map.delete(key);
                this.updateLocalStorage(true);
            }
        } catch (e) {
            console.error(e);
        }
        return false;
    }

    isStringInAllowedCache(str, name) {
        try {
            const map = this.allowedCaches[name];

            if (!map) {
                return false;
            }

            if (map.has(str)) {
                const exp = map.get(str);

                if (exp > Date.now()) {
                    return true;
                }

                map.delete(str);
                this.updateLocalStorage(true);
            }
        } catch (e) {
            console.error(e);
        }
        return false;
    }

    addUrlToAllowedCache(url, name) {
        try {
            const key = this.normalizeUrl(new URL(url));
            const expTime = Date.now() + this.expirationTime * 1000;

            if (this.cleanExpiredEntries() === 0) {
                this.updateLocalStorage(true);
            }

            if (name === "all") {
                Object.values(this.allowedCaches).forEach(m => m.set(key, expTime));
            } else if (this.allowedCaches[name]) {
                this.allowedCaches[name].set(key, expTime);
            } else {
                console.warn(`Cache "${name}" not found`);
            }
        } catch (e) {
            console.error(e);
        }
    }

    addStringToAllowedCache(str, name) {
        try {
            const expTime = Date.now() + this.expirationTime * 1000;

            if (this.cleanExpiredEntries() === 0) {
                this.updateLocalStorage(true);
            }

            if (name === "all") {
                Object.values(this.allowedCaches).forEach(m => m.set(str, expTime));
            } else if (this.allowedCaches[name]) {
                this.allowedCaches[name].set(str, expTime);
            } else {
                console.warn(`Cache "${name}" not found`);
            }
        } catch (e) {
            console.error(e);
        }
    }

    removeUrlFromAllowedCache(url, name) {
        try {
            const key = this.normalizeUrl(new URL(url));

            if (name === "all") {
                Object.values(this.allowedCaches).forEach(m => m.delete(key));
            } else if (this.allowedCaches[name]) {
                this.allowedCaches[name].delete(key);
            } else {
                console.warn(`Cache "${name}" not found`);
            }

            this.updateLocalStorage(true);
        } catch (e) {
            console.error(e);
        }
    }

    removeStringFromAllowedCache(str, name) {
        try {
            if (name === "all") {
                Object.values(this.allowedCaches).forEach(m => m.delete(str));
            } else if (this.allowedCaches[name]) {
                this.allowedCaches[name].delete(str);
            } else {
                console.warn(`Cache "${name}" not found`);
            }

            this.updateLocalStorage(true);
        } catch (e) {
            console.error(e);
        }
    }

    isUrlInProcessingCache(url, name) {
        try {
            const key = this.normalizeUrl(url);
            const map = this.processingCaches[name];

            if (!map) {
                return false;
            }

            if (map.has(key)) {
                const exp = map.get(key);

                if (exp > Date.now()) {
                    return true;
                }

                map.delete(key);
                this.updateSessionStorage(true);
            }
        } catch (e) {
            console.error(e);
        }
        return false;
    }

    isStringInProcessingCache(str, name) {
        try {
            const map = this.processingCaches[name];

            if (!map) {
                return false;
            }

            if (map.has(str)) {
                const exp = map.get(str);

                if (exp > Date.now()) {
                    return true;
                }

                map.delete(str);
                this.updateSessionStorage(true);
            }
        } catch (e) {
            console.error(e);
        }
        return false;
    }

    addUrlToProcessingCache(url, name) {
        try {
            const key = this.normalizeUrl(new URL(url));
            const expTime = Date.now() + this.expirationTime * 1000;

            if (this.cleanExpiredEntries() === 0) {
                this.updateSessionStorage(true);
            }

            if (name === "all") {
                Object.values(this.processingCaches).forEach(m => m.set(key, expTime));
            } else if (this.processingCaches[name]) {
                this.processingCaches[name].set(key, expTime);
            } else {
                console.warn(`Processing cache "${name}" not found`);
            }
        } catch (e) {
            console.error(e);
        }
    }

    addStringToProcessingCache(str, name) {
        try {
            const expTime = Date.now() + this.expirationTime * 1000;

            if (this.cleanExpiredEntries() === 0) {
                this.updateSessionStorage(true);
            }

            if (name === "all") {
                Object.values(this.processingCaches).forEach(m => m.set(str, expTime));
            } else if (this.processingCaches[name]) {
                this.processingCaches[name].set(str, expTime);
            } else {
                console.warn(`Processing cache "${name}" not found`);
            }
        } catch (e) {
            console.error(e);
        }
    }

    removeUrlFromProcessingCache(url, name) {
        try {
            const key = this.normalizeUrl(new URL(url));

            if (name === "all") {
                Object.values(this.processingCaches).forEach(m => m.delete(key));
            } else if (this.processingCaches[name]) {
                this.processingCaches[name].delete(key);
            } else {
                console.warn(`Processing cache "${name}" not found`);
            }

            this.updateSessionStorage(true);
        } catch (e) {
            console.error(e);
        }
    }

    removeStringFromProcessingCache(str, name) {
        try {
            if (name === "all") {
                Object.values(this.processingCaches).forEach(m => m.delete(str));
            } else if (this.processingCaches[name]) {
                this.processingCaches[name].delete(str);
            } else {
                console.warn(`Processing cache "${name}" not found`);
            }

            this.updateSessionStorage(true);
        } catch (e) {
            console.error(e);
        }
    }
}
