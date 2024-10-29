"use strict";

/**
 * RC4 Stream Cipher Implementation
 *
 * This function encrypts or decrypts input data using the RC4 algorithm
 * and a given key. The RC4 algorithm is a stream cipher that generates a
 * pseudo-random key-stream based on the key, which is then XORed with the
 * input data to produce the output.
 *
 * @param {string} key - The secret key used for encryption or decryption.
 * @param {string} input - The input string to be encrypted or decrypted.
 * @returns {string} The resulting encrypted or decrypted string.
 */
function RC4(key, input) {

    const stateArray = [];
    let keyIndex = 0;
    let output = '';

    // Initialize the state array
    for (let i = 0; i < 256; i++) {
        stateArray[i] = i;
    }

    // Key-scheduling algorithm
    for (let i = 0; i < 256; i++) {
        keyIndex = (keyIndex + stateArray[i] + key.charCodeAt(i % key.length)) % 256;
        [stateArray[i], stateArray[keyIndex]] = [stateArray[keyIndex], stateArray[i]]; // Swap values
    }

    // Pseudo-random generation algorithm
    let i = 0;
    keyIndex = 0;

    // Encrypt or decrypt the input data
    for (let d = 0; d < input.length; d++) {
        i = (i + 1) % 256;
        keyIndex = (keyIndex + stateArray[i]) % 256;
        [stateArray[i], stateArray[keyIndex]] = [stateArray[keyIndex], stateArray[i]]; // Swap values
        output += String.fromCharCode(input.charCodeAt(d) ^ stateArray[(stateArray[i] + stateArray[keyIndex]) % 256]);
    }
    return output;
}
