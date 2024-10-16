"use strict";

// Handles telemetry-related tasks, including generating unique IDs (GUIDs),
// managing session data, and tracking settings and interactions.
const Telemetry = function () {

    // Session ID, used to track the current session.
    let sessionID;

    /**
     * Generates a GUID (Globally Unique Identifier).
     * @returns {string} A new GUID string.
     */
    const generateGuid = function () {
        // Generates a random GUID using crypto for secure random values.
        return ([1.0e7] + -1.0e3 + -4.0e3 + -8.0e3 + -1.0e11).replace(/[018]/g, function (character) {
            return (character ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> character / 4).toString(16);
        });
    };

    /**
     * Generates a new session ID (a secure random string).
     */
    const startNewSession = function () {
        sessionID = function () {
            // Generates a secure random 32-byte session ID.
            let randomBytes = new Uint8Array(32);
            crypto.getRandomValues(randomBytes);
            let sessionIdString = "";

            // Converts each byte to a hex string and appends it to the sessionIdString.
            randomBytes.forEach(function (byte) {
                sessionIdString += byte.toString(16);
            });
            return sessionIdString;
        }();
    };

    return {
        /**
         * Returns a new GUID.
         * @returns {string} A unique GUID.
         */
        generateGuid: generateGuid,

        /**
         * Retrieves the instance ID. If the instance ID is expired or uninitialized, it generates a new one.
         * @param {Function} callback - A function to call with the instance ID.
         */
        getInstanceID: function (callback) {
            Settings.get(function (settings) {
                let instanceID = settings.instanceID;

                // If the instance ID is not initialized or is expired, generate a new one.
                if (!settings.isInstanceIDInitialized || (settings.instanceIDExpiration && settings.instanceIDExpiration < Date.now())) {
                    instanceID = generateGuid();
                    let expirationDate = new Date();

                    // Set the expiration date to one day from now.
                    expirationDate.setDate(expirationDate.getDate() + 1);

                    // Start a new session and update settings with the new instance ID.
                    startNewSession();
                    Settings.set({
                        instanceID: instanceID,
                        isInstanceIDInitialized: true,
                        instanceIDExpiration: expirationDate.getTime()
                    });
                }

                // Return the instance ID via the callback.
                callback(instanceID);
            });
        },

        /**
         * Returns the current session ID.
         * @returns {string} The session ID.
         */
        getSessionID: function () {
            return sessionID;
        },

        /**
         * Starts a new session by generating a new session ID.
         */
        startNewSession: startNewSession,

        // Placeholder function to log settings changes (can be expanded later).
        logSettingsChanged: function (data) {
        },

        // Placeholder function to log user interactions in the popup (can be expanded later).
        logPopupInteraction: function (interaction) {
        },

        // Placeholder function to log interactions on warning pages (can be expanded later).
        logWarningPageInteraction: function (interaction) {
        }
    };
}();
