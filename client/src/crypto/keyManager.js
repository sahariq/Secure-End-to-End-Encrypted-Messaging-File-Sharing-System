/**
 * Cryptographic Key Manager
 * 
 * STEP 3: High-level key management for ECC key pairs
 * 
 * Handles:
 * - Generation of ECC P-256 key pairs
 * - Secure storage of private keys in IndexedDB
 * - Export of public keys as JWK
 * 
 * NOTE: ECDH key exchange will be implemented in STEP 4
 */

import { saveKey, getKey, deleteKey } from './indexedDB.js';
import { exportPublicKeyToJWK, jwkToString } from './keyUtils.js';

const PRIVATE_KEY_NAME = 'ecc_private_key';
const PUBLIC_KEY_NAME = 'ecc_public_key';
const SIGNING_PRIVATE_KEY_NAME = 'ecdsa_private_key';
const SIGNING_PUBLIC_KEY_NAME = 'ecdsa_public_key';

/**
 * Generate a new ECC P-256 key pair for ECDH (key exchange)
 * 
 * Key specifications:
 * - Algorithm: ECDH (Elliptic Curve Diffie-Hellman)
 * - Curve: P-256 (prime256v1)
 * - Private key: NEVER exported (security requirement)
 * - Public key: extractable = true (for export and sharing)
 * 
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>} The generated key pair
 */
export const generateECCKeyPair = async () => {
  try {
    // Check if Web Crypto API is available
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error('Web Crypto API is not available in this browser');
    }

    // Generate ECC P-256 key pair for ECDH
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true, // Both keys extractable (required to export public key)
      ['deriveKey', 'deriveBits'] // Usage for ECDH key derivation
    );

    return {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey
    };
  } catch (error) {
    throw new Error(`Failed to generate ECC key pair: ${error.message}`);
  }
};

/**
 * Generate a new ECC P-256 key pair for ECDSA (signing)
 * 
 * Key specifications:
 * - Algorithm: ECDSA (Elliptic Curve Digital Signature Algorithm)
 * - Curve: P-256 (prime256v1)
 * - Used for: Signing ECDH public keys during key exchange
 * 
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>} The generated signing key pair
 */
export const generateSigningKeyPair = async () => {
  try {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error('Web Crypto API is not available in this browser');
    }

    // Generate ECC P-256 key pair for ECDSA signing
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true, // Both keys extractable
      ['sign', 'verify'] // Usage for digital signatures
    );

    return {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey
    };
  } catch (error) {
    throw new Error(`Failed to generate signing key pair: ${error.message}`);
  }
};

/**
 * Save a key pair to IndexedDB
 * 
 * Stores:
 * - Private key in IndexedDB (never exported)
 * - Public key in IndexedDB (for quick access)
 * 
 * @param {CryptoKey} privateKey - The private key to store
 * @param {CryptoKey} publicKey - The public key to store
 * @returns {Promise<void>}
 */
export const saveKeyPair = async (privateKey, publicKey) => {
  try {
    if (!(privateKey instanceof CryptoKey) || !(publicKey instanceof CryptoKey)) {
      throw new Error('Both keys must be CryptoKey objects');
    }

    // Store both keys in IndexedDB
    await saveKey(PRIVATE_KEY_NAME, privateKey);
    await saveKey(PUBLIC_KEY_NAME, publicKey);
  } catch (error) {
    throw new Error(`Failed to save key pair: ${error.message}`);
  }
};

/**
 * Save signing key pair to IndexedDB
 * 
 * @param {CryptoKey} privateKey - The signing private key
 * @param {CryptoKey} publicKey - The signing public key  
 * @returns {Promise<void>}
 */
export const saveSigningKeyPair = async (privateKey, publicKey) => {
  try {
    if (!(privateKey instanceof CryptoKey) || !(publicKey instanceof CryptoKey)) {
      throw new Error('Both keys must be CryptoKey objects');
    }

    await saveKey(SIGNING_PRIVATE_KEY_NAME, privateKey);
    await saveKey(SIGNING_PUBLIC_KEY_NAME, publicKey);
  } catch (error) {
    throw new Error(`Failed to save signing key pair: ${error.message}`);
  }
};

/**
 * Load a key pair from IndexedDB
 * 
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}|null>}
 *   The key pair if found, or null if not found
 */
export const loadKeyPair = async () => {
  try {
    const privateKey = await getKey(PRIVATE_KEY_NAME);
    const publicKey = await getKey(PUBLIC_KEY_NAME);

    if (!privateKey || !publicKey) {
      return null;
    }

    return {
      privateKey,
      publicKey
    };
  } catch (error) {
    throw new Error(`Failed to load key pair: ${error.message}`);
  }
};

/**
 * Load signing key pair from IndexedDB
 * 
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}|null>}
 */
export const loadSigningKeyPair = async () => {
  try {
    const privateKey = await getKey(SIGNING_PRIVATE_KEY_NAME);
    const publicKey = await getKey(SIGNING_PUBLIC_KEY_NAME);

    if (!privateKey || !publicKey) {
      return null;
    }

    return {
      privateKey,
      publicKey
    };
  } catch (error) {
    throw new Error(`Failed to load signing key pair: ${error.message}`);
  }
};

/**
 * Delete a key pair from IndexedDB
 * 
 * @returns {Promise<void>}
 */
export const deleteKeyPair = async () => {
  try {
    await deleteKey(PRIVATE_KEY_NAME);
    await deleteKey(PUBLIC_KEY_NAME);
  } catch (error) {
    throw new Error(`Failed to delete key pair: ${error.message}`);
  }
};

/**
 * Export the public key as a JWK string
 * 
 * This exported public key will be sent to the server during
 * key exchange in STEP 4. The private key is NEVER exported.
 * 
 * @returns {Promise<string>} JSON string representation of the public key JWK
 */
export const exportPublicKeyAsJWKString = async () => {
  try {
    const keyPair = await loadKeyPair();
    
    if (!keyPair) {
      throw new Error('No key pair found. Generate keys first.');
    }

    // Export public key as JWK
    const jwk = await exportPublicKeyToJWK(keyPair.publicKey);
    
    // Convert to JSON string
    return jwkToString(jwk);
  } catch (error) {
    throw new Error(`Failed to export public key: ${error.message}`);
  }
};

/**
 * Check if a key pair exists in IndexedDB
 * 
 * @returns {Promise<boolean>} True if key pair exists, false otherwise
 */
export const keyPairExists = async () => {
  try {
    const keyPair = await loadKeyPair();
    return keyPair !== null;
  } catch (error) {
    return false;
  }
};

