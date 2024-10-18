"use strict";

!function (input) {

    /**
     * Adds two 32-bit integers with proper handling of carry bits.
     *
     * @param {number} a - The first integer to add.
     * @param {number} b - The second integer to add.
     * @returns {number} The resulting sum of the two integers.
     */
    function addHash(a, b) {
        const lowBits = (65535 & a) + (65535 & b);
        return (a >> 16) + (b >> 16) + (lowBits >> 16) << 16 | 65535 & lowBits;
    }

    /**
     * Performs a shift-based hash computation for the input parameters using specific round constants.
     *
     * @param {number} value - The input value to hash.
     * @param {number} a - The first hash value.
     * @param {number} b - The second hash value.
     * @param {number} shiftAmount - The amount to shift the value.
     * @param {number} constant - The constant value for the shift.
     * @param {number} roundConst - The round constant for the hashing operation.
     * @returns {number} The resulting hash value.
     */
    function computeHash(value, a, b, shiftAmount, constant, roundConst) {
        let sum;
        let shift;
        return addHash((sum = addHash(addHash(a, value), addHash(shiftAmount, roundConst))) << (shift = constant) | sum >>> 32 - shift, b);
    }

    /**
     * Executes the first round of hashing, applying a specific bitwise operation.
     *
     * @param {number} value - The input value to hash.
     * @param {number} a - The first hash value.
     * @param {number} b - The second hash value.
     * @param {number} c - The third hash value.
     * @param {number} shiftAmount - The amount to shift the value.
     * @param {number} constant - The constant value for the shift.
     * @param {number} roundConst - The round constant for the hashing operation.
     * @returns {number} The resulting hash value.
     */
    function roundOne(value, a, b, c, shiftAmount, constant, roundConst) {
        return computeHash(a & b | ~a & c, value, a, shiftAmount, constant, roundConst);
    }

    /**
     * Executes the second round of hashing, applying a different bitwise operation.
     *
     * @param {number} value - The input value to hash.
     * @param {number} a - The first hash value.
     * @param {number} b - The second hash value.
     * @param {number} c - The third hash value.
     * @param {number} shiftAmount - The amount to shift the value.
     * @param {number} constant - The constant value for the shift.
     * @param {number} roundConst - The round constant for the hashing operation.
     * @returns {number} The resulting hash value.
     */
    function roundTwo(value, a, b, c, shiftAmount, constant, roundConst) {
        return computeHash(a & c | b & ~c, value, a, shiftAmount, constant, roundConst);
    }

    /**
     * Executes the third round of hashing, using XOR for bitwise operations.
     *
     * @param {number} value - The input value to hash.
     * @param {number} a - The first hash value.
     * @param {number} b - The second hash value.
     * @param {number} c - The third hash value.
     * @param {number} shiftAmount - The amount to shift the value.
     * @param {number} constant - The constant value for the shift.
     * @param {number} roundConst - The round constant for the hashing operation.
     * @returns {number} The resulting hash value.
     */
    function roundThree(value, a, b, c, shiftAmount, constant, roundConst) {
        return computeHash(a ^ b ^ c, value, a, shiftAmount, constant, roundConst);
    }

    /**
     * Executes the fourth round of hashing, using an OR and NOT combination for bitwise operations.
     *
     * @param {number} value - The input value to hash.
     * @param {number} a - The first hash value.
     * @param {number} b - The second hash value.
     * @param {number} c - The third hash value.
     * @param {number} shiftAmount - The amount to shift the value.
     * @param {number} constant - The constant value for the shift.
     * @param {number} roundConst - The round constant for the hashing operation.
     * @returns {number} The resulting hash value.
     */
    function roundFour(value, a, b, c, shiftAmount, constant, roundConst) {
        return computeHash(b ^ (a | ~c), value, a, shiftAmount, constant, roundConst);
    }

    /**
     * Performs the core hash function by processing the data in blocks, iterating over four rounds of transformations.
     *
     * @param {Array} data - The input data to hash.
     * @param {number} bitLength - The length of the input data in bits.
     * @returns {Array} The resulting hash values.
     */
    function hashFunction(data, bitLength) {
        let tempA;
        let tempB;
        let tempC;
        let tempD;

        // Padding the data and setting the bit length
        data[bitLength >> 5] |= 128 << bitLength % 32;
        data[14 + (bitLength + 64 >>> 9 << 4)] = bitLength;

        // Initial hash values (MD5 specific constants)
        let hashA = 1732584193;
        let hashB = -271733879;
        let hashC = -1732584194;
        let hashD = 271733878;

        // Process each 512-bit block (16 words of 32 bits each)
        for (let blockIndex = 0; blockIndex < data.length; blockIndex += 16) {
            tempA = hashA;
            tempB = hashB;
            tempC = hashC;
            tempD = hashD;

            // First round of hashing
            hashA = roundOne(hashA, hashB, hashC, hashD, data[blockIndex], 7, -680876936);
            hashD = roundOne(hashD, hashA, hashB, hashC, data[blockIndex + 1], 12, -389564586);
            hashC = roundOne(hashC, hashD, hashA, hashB, data[blockIndex + 2], 17, 606105819);
            hashB = roundOne(hashB, hashC, hashD, hashA, data[blockIndex + 3], 22, -1044525330);
            hashA = roundOne(hashA, hashB, hashC, hashD, data[blockIndex + 4], 7, -176418897);
            hashD = roundOne(hashD, hashA, hashB, hashC, data[blockIndex + 5], 12, 1200080426);
            hashC = roundOne(hashC, hashD, hashA, hashB, data[blockIndex + 6], 17, -1473231341);
            hashB = roundOne(hashB, hashC, hashD, hashA, data[blockIndex + 7], 22, -45705983);
            hashA = roundOne(hashA, hashB, hashC, hashD, data[blockIndex + 8], 7, 1770035416);
            hashD = roundOne(hashD, hashA, hashB, hashC, data[blockIndex + 9], 12, -1958414417);
            hashC = roundOne(hashC, hashD, hashA, hashB, data[blockIndex + 10], 17, -42063);
            hashB = roundOne(hashB, hashC, hashD, hashA, data[blockIndex + 11], 22, -1990404162);
            hashA = roundOne(hashA, hashB, hashC, hashD, data[blockIndex + 12], 7, 1804603682);
            hashD = roundOne(hashD, hashA, hashB, hashC, data[blockIndex + 13], 12, -40341101);
            hashC = roundOne(hashC, hashD, hashA, hashB, data[blockIndex + 14], 17, -1502002290);
            hashB = roundOne(hashB, hashC, hashD, hashA, data[blockIndex + 15], 22, 1236535329);

            // Second round of hashing
            hashA = roundTwo(hashA, hashB, hashC, hashD, data[blockIndex + 1], 5, -165796510);
            hashD = roundTwo(hashD, hashA, hashB, hashC, data[blockIndex + 6], 9, -1069501632);
            hashC = roundTwo(hashC, hashD, hashA, hashB, data[blockIndex + 11], 14, 643717713);
            hashB = roundTwo(hashB, hashC, hashD, hashA, data[blockIndex], 20, -373897302);
            hashA = roundTwo(hashA, hashB, hashC, hashD, data[blockIndex + 5], 5, -701558691);
            hashD = roundTwo(hashD, hashA, hashB, hashC, data[blockIndex + 10], 9, 38016083);
            hashC = roundTwo(hashC, hashD, hashA, hashB, data[blockIndex + 15], 14, -660478335);
            hashB = roundTwo(hashB, hashC, hashD, hashA, data[blockIndex + 4], 20, -405537848);
            hashA = roundTwo(hashA, hashB, hashC, hashD, data[blockIndex + 9], 5, 568446438);
            hashD = roundTwo(hashD, hashA, hashB, hashC, data[blockIndex + 14], 9, -1019803690);
            hashC = roundTwo(hashC, hashD, hashA, hashB, data[blockIndex + 3], 14, -187363961);
            hashB = roundTwo(hashB, hashC, hashD, hashA, data[blockIndex + 8], 20, 1163531501);
            hashA = roundTwo(hashA, hashB, hashC, hashD, data[blockIndex + 13], 5, -1444681467);
            hashD = roundTwo(hashD, hashA, hashB, hashC, data[blockIndex + 2], 9, -51403784);
            hashC = roundTwo(hashC, hashD, hashA, hashB, data[blockIndex + 7], 14, 1735328473);
            hashB = roundTwo(hashB, hashC, hashD, hashA, data[blockIndex + 12], 20, -1926607734);

            // Third round of hashing
            hashA = roundThree(hashA, hashB, hashC, hashD, data[blockIndex + 5], 4, -378558);
            hashD = roundThree(hashD, hashA, hashB, hashC, data[blockIndex + 8], 11, -2022574463);
            hashC = roundThree(hashC, hashD, hashA, hashB, data[blockIndex + 11], 16, 1839030562);
            hashB = roundThree(hashB, hashC, hashD, hashA, data[blockIndex + 14], 23, -35309556);
            hashA = roundThree(hashA, hashB, hashC, hashD, data[blockIndex + 1], 4, -1530992060);
            hashD = roundThree(hashD, hashA, hashB, hashC, data[blockIndex + 4], 11, 1272893353);
            hashC = roundThree(hashC, hashD, hashA, hashB, data[blockIndex + 7], 16, -155497632);
            hashB = roundThree(hashB, hashC, hashD, hashA, data[blockIndex + 10], 23, -1094730640);
            hashA = roundThree(hashA, hashB, hashC, hashD, data[blockIndex + 13], 4, 681279174);
            hashD = roundThree(hashD, hashA, hashB, hashC, data[blockIndex], 11, -358537222);
            hashC = roundThree(hashC, hashD, hashA, hashB, data[blockIndex + 3], 16, -722521979);
            hashB = roundThree(hashB, hashC, hashD, hashA, data[blockIndex + 6], 23, 76029189);
            hashA = roundThree(hashA, hashB, hashC, hashD, data[blockIndex + 9], 4, -640364487);
            hashD = roundThree(hashD, hashA, hashB, hashC, data[blockIndex + 12], 11, -421815835);
            hashC = roundThree(hashC, hashD, hashA, hashB, data[blockIndex + 15], 16, 530742520);
            hashB = roundThree(hashB, hashC, hashD, hashA, data[blockIndex + 2], 23, -995338651);

            // Fourth round of hashing
            hashA = roundFour(hashA, hashB, hashC, hashD, data[blockIndex], 6, -198630844);
            hashD = roundFour(hashD, hashA, hashB, hashC, data[blockIndex + 7], 10, 1126891415);
            hashC = roundFour(hashC, hashD, hashA, hashB, data[blockIndex + 14], 15, -1416354905);
            hashB = roundFour(hashB, hashC, hashD, hashA, data[blockIndex + 5], 21, -57434055);
            hashA = roundFour(hashA, hashB, hashC, hashD, data[blockIndex + 12], 6, 1700485571);
            hashD = roundFour(hashD, hashA, hashB, hashC, data[blockIndex + 3], 10, -1894986606);
            hashC = roundFour(hashC, hashD, hashA, hashB, data[blockIndex + 10], 15, -1051523);
            hashB = roundFour(hashB, hashC, hashD, hashA, data[blockIndex + 1], 21, -2054922799);
            hashA = roundFour(hashA, hashB, hashC, hashD, data[blockIndex + 8], 6, 1873313359);
            hashD = roundFour(hashD, hashA, hashB, hashC, data[blockIndex + 15], 10, -30611744);
            hashC = roundFour(hashC, hashD, hashA, hashB, data[blockIndex + 6], 15, -1560198380);
            hashB = roundFour(hashB, hashC, hashD, hashA, data[blockIndex + 13], 21, 1309151649);
            hashA = roundFour(hashA, hashB, hashC, hashD, data[blockIndex + 4], 6, -145523070);
            hashD = roundFour(hashD, hashA, hashB, hashC, data[blockIndex + 11], 10, -1120210379);
            hashC = roundFour(hashC, hashD, hashA, hashB, data[blockIndex + 2], 15, 718787259);
            hashB = roundFour(hashB, hashC, hashD, hashA, data[blockIndex + 9], 21, -343485551);

            // Update hash values after processing the block
            hashA = addHash(hashA, tempA);
            hashB = addHash(hashB, tempB);
            hashC = addHash(hashC, tempC);
            hashD = addHash(hashD, tempD);
        }
        return [hashA, hashB, hashC, hashD];
    }

    /**
     * Converts the input array into a string representation.
     *
     * @param {Array} input - The input array to convert.
     * @returns {string} The string representation of the input array.
     */
    function convertToString(input) {
        let result = "";
        let length = 32 * input.length;

        for (let i = 0; i < length; i += 8) {
            result += String.fromCharCode(input[i >> 5] >>> i % 32 & 255);
        }
        return result;
    }

    /**
     * Converts the input string into an array of words (32-bit integers).
     *
     * @param {string} input - The input string to convert.
     * @returns {Array} The array of words (32-bit integers).
     */
    function convertToWordArray(input) {
        const wordArray = [];
        let i;

        // Initialize the word array to match the required size
        const arrayLength = (input.length >> 2);
        for (i = 0; i < arrayLength; i += 1) {
            wordArray[i] = 0;
        }

        const maxLength = 8 * input.length;

        // Convert input string to word array
        for (i = 0; i < maxLength; i += 8) {
            wordArray[i >> 5] |= (255 & input.charCodeAt(i / 8)) << (i % 32);
        }
        return wordArray;
    }

    /**
     * Converts the input string into a hexadecimal string representation.
     *
     * @param {string} input - The input string to convert.
     * @returns {string} The hexadecimal representation of the input string.
     */
    function convertToHexString(input) {
        const hexDigits = "0123456789abcdef";
        let currentChar;
        let hexString = "";
        let i;

        // Convert each character to its hexadecimal representation
        for (i = 0; i < input.length; i += 1) {
            currentChar = input.charCodeAt(i);
            hexString += hexDigits.charAt(currentChar >>> 4 & 15) + hexDigits.charAt(15 & currentChar);
        }
        return hexString;
    }

    /**
     * Prepares the input string by encoding it into UTF-8.
     *
     * @param input - The input string to prepare.
     * @returns {string} The prepared input string.
     */
    function prepareInput(input) {
        return unescape(encodeURIComponent(input))
    }

    /**
     * Generates the MD5 hash for the given input string.
     *
     * @param input - The input string to hash.
     * @returns {string} The MD5 hash of the input string.
     */
    function generateHash(input) {
        let wordArray = prepareInput(input);
        return convertToString(hashFunction(convertToWordArray(wordArray), 8 * wordArray.length));
    }

    /**
     * Generates an HMAC hash using the input message and key, applying the MD5 hash algorithm.
     *
     * @param input - The input string to hash.
     * @param key - The key to use for hashing.
     * @returns {string} The HMAC hash of the input string.
     */
    function hmacHash(input, key) {
        return function (message, key) {
            let innerPadding = [];
            let outerPadding = [];
            let messageWordArray = convertToWordArray(message);

            // Initialize padding
            if (messageWordArray.length > 16) {
                messageWordArray = hashFunction(messageWordArray, 8 * message.length);
            }
            for (let i = 0; i < 16; i += 1) {
                innerPadding[i] = 0x5C5C5C5C ^ messageWordArray[i];
                outerPadding[i] = 0x36363636 ^ messageWordArray[i];
            }

            let innerHash = hashFunction(innerPadding.concat(convertToWordArray(key)), 512 + 8 * key.length);
            return convertToString(hashFunction(outerPadding.concat(innerHash), 640));
        }(prepareInput(input), prepareInput(key))
    }

    /**
     * Returns the hashed output in the desired format, either as a raw string or hexadecimal string.
     *
     * @param input - The input string to hash.
     * @param key - The key to use for hashing.
     * @param asHex - A flag indicating whether to return the hash as a hexadecimal string.
     * @returns {string} The hashed output in the desired format.
     */
    function getHashedOutput(input, key, asHex) {
        if (key) {
            return asHex ? hmacHash(key, input) : convertToHexString(hmacHash(key, input));
        } else {
            return asHex ? generateHash(input) : convertToHexString(generateHash(input));
        }
    }

    /**
     * Exposes the MD5 hash function to the global scope.
     */
    if (typeof define === "function" && define.amd) {
        define(() => getHashedOutput);
    } else if (typeof module === "object" && module.exports) {
        module.exports = getHashedOutput;
    } else {
        input.MD5 = getHashedOutput;
    }
}(this);
