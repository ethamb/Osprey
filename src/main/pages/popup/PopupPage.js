"use strict";

// Use a global singleton pattern to ensure we don't duplicate resources
window.SecurityPopupSingleton = window.SecurityPopupSingleton || (function () {
    // Track initialization state
    let isInitialized = false;

    // Cache for DOM elements
    const domElements = {};

    // Reference to event listeners for easy removal
    const eventListeners = new Map();

    // Browser API compatibility between Chrome and Firefox
    const browserAPI = typeof browser === 'undefined' ? chrome : browser;

    // Security systems configuration - only defined once
    const securitySystems = [
        {
            name: "smartScreenEnabled",
            title: "Microsoft SmartScreen",
            labelElementId: "smartScreenStatus",
            switchElementId: "smartScreenSwitch",
            messageType: Messages.MessageType.SMARTSCREEN_TOGGLED,
        },
        {
            name: "symantecEnabled",
            title: "Symantec Browser Protection",
            labelElementId: "symantecStatus",
            switchElementId: "symantecSwitch",
            messageType: Messages.MessageType.SYMANTEC_TOGGLED,
        },
        {
            name: "emsisoftEnabled",
            title: "Emsisoft Web Protection",
            labelElementId: "emsisoftStatus",
            switchElementId: "emsisoftSwitch",
            messageType: Messages.MessageType.EMSISOFT_TOGGLED,
        },
        {
            name: "bitdefenderEnabled",
            title: "Bitdefender TrafficLight",
            labelElementId: "bitdefenderStatus",
            switchElementId: "bitdefenderSwitch",
            messageType: Messages.MessageType.BITDEFENDER_TOGGLED,
        },
        {
            name: "nortonEnabled",
            title: "Norton SafeWeb",
            labelElementId: "nortonStatus",
            switchElementId: "nortonSwitch",
            messageType: Messages.MessageType.NORTON_TOGGLED,
        },
        {
            name: "totalEnabled",
            title: "TOTAL WebShield",
            labelElementId: "totalStatus",
            switchElementId: "totalSwitch",
            messageType: Messages.MessageType.TOTAL_TOGGLED,
        },
        {
            name: "gDataEnabled",
            title: "G DATA WebProtection",
            labelElementId: "gDataStatus",
            switchElementId: "gDataSwitch",
            messageType: Messages.MessageType.G_DATA_TOGGLED,
        },
        {
            name: "cloudflareEnabled",
            title: "Cloudflare Security DNS",
            labelElementId: "cloudflareStatus",
            switchElementId: "cloudflareSwitch",
            messageType: Messages.MessageType.CLOUDFLARE_TOGGLED,
        },
        {
            name: "quad9Enabled",
            title: "Quad9 Security DNS",
            labelElementId: "quad9Status",
            switchElementId: "quad9Switch",
            messageType: Messages.MessageType.QUAD9_TOGGLED,
        },
        {
            name: "dns0Enabled",
            title: "DNS0.eu Security DNS",
            labelElementId: "dns0Status",
            switchElementId: "dns0Switch",
            messageType: Messages.MessageType.DNS0_TOGGLED,
        },
        {
            name: "controlDEnabled",
            title: "Control D Security DNS",
            labelElementId: "controlDStatus",
            switchElementId: "controlDSwitch",
            messageType: Messages.MessageType.CONTROL_D_TOGGLED,
        },
        {
            name: "cleanBrowsingEnabled",
            title: "CleanBrowsing Security DNS",
            labelElementId: "cleanBrowsingStatus",
            switchElementId: "cleanBrowsingSwitch",
            messageType: Messages.MessageType.CLEAN_BROWSING_TOGGLED,
        },
        {
            name: "openDNSEnabled",
            title: "OpenDNS Security DNS",
            labelElementId: "openDNSStatus",
            switchElementId: "openDNSSwitch",
            messageType: Messages.MessageType.OPEN_DNS_TOGGLED,
        }
    ];

    /**
     * Get DOM elements for a system, caching them for future use
     *
     * @param {Object} system - The system object
     * @returns {Object} Object containing the label and switch elements
     */
    const getSystemElements = function (system) {
        if (!domElements[system.name]) {
            domElements[system.name] = {
                label: document.getElementById(system.labelElementId),
                switchElement: document.getElementById(system.switchElementId)
            };
        }
        return domElements[system.name];
    };

    /**
     * Safely add event listener with tracking for cleanup
     *
     * @param {EventTarget} target - Element to attach listener to
     * @param {string} type - Event type
     * @param {Function} listener - Event handler
     */
    const safeAddEventListener = function (target, type, listener) {
        target.addEventListener(type, listener);

        if (!eventListeners.has(target)) {
            eventListeners.set(target, new Map());
        }

        eventListeners.get(target).set(type, listener);
    };

    /**
     * Remove all tracked event listeners
     */
    const removeAllEventListeners = function () {
        eventListeners.forEach((typeListeners, target) => {
            typeListeners.forEach((listener, type) => {
                target.removeEventListener(type, listener);
            });
        });

        eventListeners.clear();
    };

    /**
     * Batch updates UI elements for better performance
     *
     * @param {Array} updates - Array of update operations to perform
     */
    const batchDomUpdates = function (updates) {
        window.requestAnimationFrame(() => {
            updates.forEach(update => update());
        });
    };

    /**
     * Updates the UI for a specific security system using batched DOM operations.
     *
     * @param {Object} system - The system object being updated.
     * @param {boolean} isOn - Whether the protection is enabled for the system.
     */
    const updateProtectionStatusUI = function (system, isOn) {
        const updates = [];

        // Get cached DOM elements or fetch them if not cached
        const elements = getSystemElements(system);

        updates.push(() => {
            if (elements.label) {
                elements.label.textContent = isOn ? "On" : "Off";
            }

            if (elements.switchElement) {
                if (isOn) {
                    elements.switchElement.classList.add("on");
                    elements.switchElement.classList.remove("off");
                } else {
                    elements.switchElement.classList.remove("on");
                    elements.switchElement.classList.add("off");
                }
            }
        });

        batchDomUpdates(updates);
    };

    /**
     * Toggles the state of a security system and updates its UI.
     *
     * @param {Object} system - The system object being toggled.
     */
    const toggleProtection = function (system) {
        Settings.get((settings) => {
            const currentState = settings[system.name];
            const newState = !currentState;

            Settings.set({[system.name]: newState}, () => {
                updateProtectionStatusUI(system, newState);

                browserAPI.runtime.sendMessage({
                    messageType: system.messageType,
                    title: system.title,
                    toggleState: newState,
                });
            });
        });
    };

    /**
     * Reset to initial state to prevent memory leaks
     */
    const reset = function () {
        // Remove all event listeners we've registered
        removeAllEventListeners();

        // Remove click handlers from all switches
        securitySystems.forEach((system) => {
            const elements = domElements[system.name];

            if (elements && elements.switchElement) {
                elements.switchElement.onclick = null;
            }
        });

        // Keep the DOM elements cache but reset initialization
        isInitialized = false;
    };

    /**
     * Initialize the popup or refresh if already initialized
     */
    const initialize = function () {
        // If already initialized, reset first
        if (isInitialized) {
            reset();
        }

        // Mark as initialized
        isInitialized = true;

        // Let background script know we're open
        browserAPI.runtime.sendMessage({messageType: Messages.MessageType.POPUP_LAUNCHED});

        // Set up switch elements and click handlers
        securitySystems.forEach((system) => {
            const elements = getSystemElements(system);

            if (elements.switchElement) {
                elements.switchElement.onclick = () => toggleProtection(system);
            }
        });

        // Load and apply settings
        Settings.get((settings) => {
            securitySystems.forEach((system) => {
                const isEnabled = settings[system.name];
                updateProtectionStatusUI(system, isEnabled);
            });
        });

        // Update version display
        const versionElement = document.getElementById("version");
        if (versionElement) {
            const manifest = browserAPI.runtime.getManifest();
            const version = manifest.version;
            versionElement.textContent += version;
        }

        // Register for page unload - but only for cleanup, not prevention
        safeAddEventListener(window, 'unload', () => {
            browserAPI.runtime.sendMessage({messageType: Messages.MessageType.POPUP_CLOSED});
        });

        const page1 = document.getElementById('page1');
        const page2 = document.getElementById('page2');
        const prevPage = document.getElementById('prevPage');
        const nextPage = document.getElementById('nextPage');
        const pageIndicator = document.getElementById('pageIndicator');
        let currentPage = 1;
        const totalPages = 2;

        function updatePageDisplay() {
            // Hide all pages
            page1.classList.remove('active');
            page2.classList.remove('active');

            // Show current page
            if (currentPage === 1) {
                page1.classList.add('active');
            } else {
                page2.classList.add('active');
            }

            // Update page indicator
            pageIndicator.textContent = `${currentPage}/${totalPages}`;
        }

        prevPage.addEventListener('click', function () {
            currentPage = currentPage === 1 ? totalPages : currentPage - 1;
            updatePageDisplay();
        });

        nextPage.addEventListener('click', function () {
            currentPage = currentPage === totalPages ? 1 : currentPage + 1;
            updatePageDisplay();
        });

        // Initialize display
        updatePageDisplay();
    };

    // Public API
    return {
        initialize,
        reset
    };
})();

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    window.SecurityPopupSingleton.initialize();
});
