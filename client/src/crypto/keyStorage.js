/**
 * Key Storage Module
 * 
 * STEP 2: Temporary localStorage-based implementation
 * 
 * DEPRECATED: This module has been replaced by IndexedDB-based storage
 * in STEP 3. See:
 * - crypto/indexedDB.js for secure CryptoKey storage
 * - crypto/keyManager.js for ECC key pair management
 * 
 * This file is kept for backward compatibility but should not be used
 * for new cryptographic key storage. Use the IndexedDB implementation instead.
 */

/**
 * Save a key to local storage
 * @param {string} keyName - Unique identifier for the key
 * @param {string|ArrayBuffer|CryptoKey} keyData - The key data to store
 * @returns {Promise<void>}
 */
export const saveLocalKey = async (keyName, keyData) => {
  try {
    // Convert keyData to string if it's not already
    let serializedData;
    
    if (keyData instanceof CryptoKey) {
      // For CryptoKey objects, we'll need to export them first
      // This is a placeholder - actual implementation will handle key export
      throw new Error('CryptoKey storage not yet implemented. Will be added in STEP 3.');
    } else if (keyData instanceof ArrayBuffer) {
      // Convert ArrayBuffer to base64 string for storage
      const bytes = new Uint8Array(keyData);
      serializedData = btoa(String.fromCharCode(...bytes));
    } else {
      // Assume it's already a string
      serializedData = keyData;
    }

    // Store in localStorage with a prefix to identify crypto keys
    const storageKey = `crypto_key_${keyName}`;
    localStorage.setItem(storageKey, serializedData);
  } catch (error) {
    console.error(`Error saving key ${keyName}:`, error);
    throw new Error(`Failed to save key: ${error.message}`);
  }
};

/**
 * Retrieve a key from local storage
 * @param {string} keyName - Unique identifier for the key
 * @returns {Promise<string|ArrayBuffer|null>} The stored key data, or null if not found
 */
export const getLocalKey = async (keyName) => {
  try {
    const storageKey = `crypto_key_${keyName}`;
    const storedData = localStorage.getItem(storageKey);
    
    if (!storedData) {
      return null;
    }

    // For now, return as string
    // In STEP 3, we'll handle ArrayBuffer and CryptoKey reconstruction
    return storedData;
  } catch (error) {
    console.error(`Error retrieving key ${keyName}:`, error);
    throw new Error(`Failed to retrieve key: ${error.message}`);
  }
};

/**
 * Delete a key from local storage
 * @param {string} keyName - Unique identifier for the key
 * @returns {Promise<void>}
 */
export const deleteLocalKey = async (keyName) => {
  try {
    const storageKey = `crypto_key_${keyName}`;
    localStorage.removeItem(storageKey);
  } catch (error) {
    console.error(`Error deleting key ${keyName}:`, error);
    throw new Error(`Failed to delete key: ${error.message}`);
  }
};

/**
 * Clear all crypto keys from local storage
 * Useful for logout or security cleanup
 * @returns {Promise<void>}
 */
export const clearAllKeys = async () => {
  try {
    const keys = Object.keys(localStorage);
    keys.forEach(key => {
      if (key.startsWith('crypto_key_')) {
        localStorage.removeItem(key);
      }
    });
  } catch (error) {
    console.error('Error clearing all keys:', error);
    throw new Error(`Failed to clear keys: ${error.message}`);
  }
};

