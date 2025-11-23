/**
 * Cryptographic Key Utilities
 * 
 * STEP 3: Helper functions for key operations
 * 
 * Provides utility functions for:
 * - Exporting/importing public keys as JWK
 * - Converting between ArrayBuffer and base64
 * - Other key-related operations
 */

/**
 * Export a public CryptoKey to JWK (JSON Web Key) format
 * @param {CryptoKey} publicKey - The public key to export
 * @returns {Promise<object>} The JWK representation of the public key
 */
export const exportPublicKeyToJWK = async (publicKey) => {
  try {
    if (!(publicKey instanceof CryptoKey)) {
      throw new Error('Invalid key: must be a CryptoKey object');
    }

    if (publicKey.type !== 'public') {
      throw new Error('Key must be a public key');
    }

    // Export the key as JWK
    const jwk = await window.crypto.subtle.exportKey('jwk', publicKey);
    return jwk;
  } catch (error) {
    throw new Error(`Failed to export public key to JWK: ${error.message}`);
  }
};

/**
 * Import a public key from JWK (JSON Web Key) format
 * @param {object} jwk - The JWK representation of the public key
 * @returns {Promise<CryptoKey>} The imported public key as a CryptoKey object
 */
export const importPublicKeyFromJWK = async (jwk) => {
  try {
    if (!jwk || typeof jwk !== 'object') {
      throw new Error('Invalid JWK: must be an object');
    }

    // Import the key from JWK
    // For ECC P-256 keys used in key exchange
    const algorithm = {
      name: 'ECDH',
      namedCurve: 'P-256'
    };

    const keyData = await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      algorithm,
      true, // extractable
      ['deriveKey', 'deriveBits'] // usage for ECDH
    );

    return keyData;
  } catch (error) {
    throw new Error(`Failed to import public key from JWK: ${error.message}`);
  }
};

/**
 * Convert an ArrayBuffer to a base64 string
 * @param {ArrayBuffer} buffer - The ArrayBuffer to convert
 * @returns {string} Base64-encoded string
 */
export const bufferToBase64 = (buffer) => {
  try {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  } catch (error) {
    throw new Error(`Failed to convert buffer to base64: ${error.message}`);
  }
};

/**
 * Convert a base64 string to an ArrayBuffer
 * @param {string} base64 - The base64-encoded string
 * @returns {ArrayBuffer} The decoded ArrayBuffer
 */
export const base64ToBuffer = (base64) => {
  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (error) {
    throw new Error(`Failed to convert base64 to buffer: ${error.message}`);
  }
};

/**
 * Convert a JWK object to a JSON string
 * @param {object} jwk - The JWK object
 * @returns {string} JSON string representation
 */
export const jwkToString = (jwk) => {
  try {
    return JSON.stringify(jwk);
  } catch (error) {
    throw new Error(`Failed to convert JWK to string: ${error.message}`);
  }
};

/**
 * Convert a JSON string to a JWK object
 * @param {string} jwkString - The JSON string representation
 * @returns {object} JWK object
 */
export const stringToJWK = (jwkString) => {
  try {
    return JSON.parse(jwkString);
  } catch (error) {
    throw new Error(`Failed to convert string to JWK: ${error.message}`);
  }
};

