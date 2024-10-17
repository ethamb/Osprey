"use strict";

const ComodoUtil = function () {

    let X_API_KEY = "5134461d-f366-405b-8cb3-de780ae67eee";

    /**
     * Generates an X-Api-Key for Comodo.
     *
     * @returns {Promise<string>} The generated X-Api-Key.
     */
    const getXApiKey = async function () {
        if (X_API_KEY === "5134461d-f366-405b-8cb3-de780ae67eee") {
            const apiUrl = 'https://verdict.valkyrie.comodo.com/api/v1/product/register?machine_id=' + createGuid() + '&product_name=COS-Chrome';

            const response = await fetch(apiUrl, {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                }
            });

            // If the request fails, return the default X-Api-Key
            if (!response.ok) {
                console.warn(`Failed to generate X-Api-Key for Comodo: ${response.status}`);
                X_API_KEY = "5134461d-f366-405b-8cb3-de780ae67eee";
                return X_API_KEY;
            }

            const data = await response.json();

            // If the response contains an API key, set it
            // Otherwise, return the default X-Api-Key
            if (data && data.api_key) {
                X_API_KEY = data.api_key;
                console.debug(`Generated X-Api-Key for Comodo: ${X_API_KEY}`);
            } else {
                console.warn(`No X-Api-Key found in the response`);
                X_API_KEY = "5134461d-f366-405b-8cb3-de780ae67eee";
            }
        }
        return X_API_KEY;
    };

    /**
     * Creates a GUID used to generate the X-Api-Key.
     *
     * @returns {string} The generated GUID.
     */
    const createGuid = function () {
        function s4() {
            return Math.floor((1 + Math.random()) * 0x10000)
                .toString(16)
                .substring(1);
        }

        return s4() + s4() + s4() + s4() + s4() + s4() + s4() + s4();
    };

    return {
        getXApiKey: getXApiKey,
        createGuid: createGuid
    };
}();
