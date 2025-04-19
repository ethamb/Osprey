"use strict";

// Manages user preferences and configurations.
const Settings = (function () {
    const settingsKey = "Settings"; // Key for storing settings in local storage

    // These default values were chosen based on API response times
    // APIs with less than 100ms of delay are enabled by default

    let defaultSettings = {
        smartScreenEnabled: false, // Default state for SmartScreen
        symantecEnabled: true, // Default state for Symantec
        emsisoftEnabled: true, // Default state for Emsisoft
        bitdefenderEnabled: true, // Default state for Bitdefender
        nortonEnabled: true, // Default state for Norton
        gDataEnabled: true, // Default state for G DATA
        cloudflareEnabled: false, // Default state for Cloudflare
        quad9Enabled: false, // Default state for Quad9
        dns0Enabled: true, // Default state for DNS0
        cleanBrowsingEnabled: true, // Default state for CleanBrowsing
        ciraEnabled: false, // Default state for CIRA
        adGuardEnabled: false, // Default state for AdGuard
        switchCHEnabled: true, // Default state for Switch.ch
        certEEEnabled: false, // Default state for CERT-EE

        notificationsEnabled: true, // Default state for notifications
        ignoreFrameNavigation: true, // Default state for ignoring frame navigation
        hideContinueButtons: false, // Default state for hiding continue buttons

        isInstanceIDInitialized: false, // Flag to check if instance ID is initialized
        instanceID: 0 // Default instance ID
    };

    /**
     * Compares two objects and updates the target object with values from the source object if they differ.
     * @param {Object} target - The target object to update.
     * @param {Object} source - The source object to compare with.
     * @returns {boolean} - Returns true if any values were updated, false otherwise.
     */
    const updateIfChanged = function (target, source) {
        let hasChanges = false;

        if (source) {
            // Iterate through the source object properties
            for (let key in source) {
                // If the values differ, update the target and mark changes
                if (source[key] !== target[key]) {
                    target[key] = source[key];
                    hasChanges = true;
                }
            }
        }
        return hasChanges; // Return whether any changes were made
    };

    return {
        /**
         * Retrieves settings from local storage and merges them with default settings.
         * @param {Function} callback - The function to call with the retrieved settings.
         */
        get: function (callback) {
            Storage.getFromLocalStore(settingsKey, (function (storedSettings) {
                // Clone the default settings object
                let mergedSettings = JSON.parse(JSON.stringify(defaultSettings));

                // Merge any stored settings into the cloned default settings
                updateIfChanged(mergedSettings, storedSettings);

                // Invoke the callback with the merged settings
                callback && callback(mergedSettings);
            }));
        },

        /**
         * Saves settings to local storage, merging them with any previously stored settings.
         * @param {Object} newSettings - The new settings to save.
         * @param {Function} [callback] - Optional callback to call after settings are saved.
         */
        set: function (newSettings, callback) {
            Storage.getFromLocalStore(settingsKey, (function (storedSettings) {
                // Clone the default settings object
                let mergedSettings = JSON.parse(JSON.stringify(defaultSettings));

                // Merge stored settings and new settings into the cloned default settings
                storedSettings && updateIfChanged(mergedSettings, storedSettings);
                updateIfChanged(mergedSettings, newSettings);

                // Save the merged settings back to local storage
                Storage.setToLocalStore(settingsKey, mergedSettings, callback);
            }));
        }
    };
})();
