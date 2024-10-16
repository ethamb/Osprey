"use strict";

(function () {
    // Send a message to indicate that the popup has been launched.
    chrome.runtime.sendMessage({messageType: Messages.MessageType.POPUP_LAUNCHED});

    // Security systems configuration
    const securitySystems = [
        {
            name: "smartScreenEnabled",
            title: "Microsoft SmartScreen",
            labelElementId: "smartScreenStatus",
            switchElementId: "smartScreenSwitch",
            messageType: Messages.MessageType.SMARTSCREEN_TOGGLED,
        },
        {
            name: "comodoEnabled",
            title: "Comodo Valkyrie",
            labelElementId: "comodoStatus",
            switchElementId: "comodoSwitch",
            messageType: Messages.MessageType.COMODO_TOGGLED,
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
            title: "G Data WebProtection",
            labelElementId: "gDataStatus",
            switchElementId: "gDataSwitch",
            messageType: Messages.MessageType.G_DATA_TOGGLED,
        },
    ];

    /**
     * Updates the UI for a specific security system.
     *
     * @param {string} systemName - The name of the system being updated.
     * @param {boolean} isOn - Whether the protection is enabled for the system.
     */
    const updateProtectionStatusUI = function (systemName, isOn) {
        const system = securitySystems.find((sys) => sys.name === systemName);
        const label = document.getElementById(system.labelElementId);
        const switchElement = document.getElementById(system.switchElementId);

        if (isOn) {
            label.textContent = "On";
            switchElement.classList.add("on");
            switchElement.classList.remove("off");
        } else {
            label.textContent = "Off";
            switchElement.classList.remove("on");
            switchElement.classList.add("off");
        }
    };

    /**
     * Toggles the state of a security system and updates its UI.
     * @param {string} systemName - The name of the system being toggled.
     */
    const toggleProtection = function (systemName) {
        // Get the current state directly from Settings before toggling
        Settings.get((settings) => {
            const currentState = settings[systemName];
            const newState = !currentState; // Toggle the protection state

            // Update UI with the new state
            updateProtectionStatusUI(systemName, newState);

            // Save the new state
            Settings.set({[systemName]: newState}, () => {
                // Log the toggle event
                console.debug(`${settings[systemName].title} has been ${newState ? "disabled" : "enabled"}.`);

                // Send message to background after saving the state
                chrome.runtime.sendMessage({
                    messageType: securitySystems.find((sys) => sys.name === systemName).messageType,
                    toggleState: newState,
                });
            });
        });
    };

    // Add event listeners for each security system's switch
    document.addEventListener("DOMContentLoaded", () => {
        securitySystems.forEach((system) => {
            const switchElement = document.getElementById(system.switchElementId);
            if (switchElement) {
                switchElement.onclick = () => toggleProtection(system.name);
            }
        });

        // Retrieve the protection states from settings and update the UI accordingly.
        Settings.get((settings) => {
            securitySystems.forEach((system) => {
                const isEnabled = settings[system.name];
                updateProtectionStatusUI(system.name, isEnabled); // Update the UI based on the state
            });
        });

        // Adds the version number to the popup page.
        const versionElement = document.getElementById("version");
        if (versionElement) {
            const manifest = chrome.runtime.getManifest();
            const version = manifest.version;
            versionElement.textContent += version;
        }
    });
})();
