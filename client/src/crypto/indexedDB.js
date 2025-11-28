/**
 * Secure IndexedDB Wrapper for Cryptographic Keys
 * 
 * STEP 3 & 4: IndexedDB-based storage for CryptoKey objects
 * 
 * Provides secure storage for:
 * - Identity key pairs (STEP 3)
 * - Session keys (STEP 4)
 * 
 * Uses IndexedDB which offers better security isolation than localStorage
 * and can store structured objects like CryptoKey directly.
 */

const DB_NAME = 'secureKeysDB';
const DB_VERSION = 2; // Version 2: Added sessionKeys store
const STORE_NAME = 'keys';
const SESSION_STORE_NAME = 'sessionKeys';

/**
 * Open or create the IndexedDB database
 * @returns {Promise<IDBDatabase>} The database instance
 */
export const openDB = () => {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => {
      reject(new Error(`Failed to open database: ${request.error}`));
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      
      // Create keys store if it doesn't exist (STEP 3 - Identity keys)
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const objectStore = db.createObjectStore(STORE_NAME, { keyPath: 'name' });
        // Create index for faster lookups if needed
        objectStore.createIndex('name', 'name', { unique: true });
      }

      // Create session keys store if it doesn't exist (STEP 4 - Session keys)
      if (!db.objectStoreNames.contains(SESSION_STORE_NAME)) {
        const sessionStore = db.createObjectStore(SESSION_STORE_NAME, { keyPath: 'peerId' });
        // Index by peer user ID for fast lookups
        sessionStore.createIndex('peerId', 'peerId', { unique: true });
      }
    };
  });
};

/**
 * Save a CryptoKey to IndexedDB
 * @param {string} name - Unique identifier for the key
 * @param {CryptoKey} cryptoKey - The CryptoKey object to store
 * @returns {Promise<void>}
 */
export const saveKey = async (name, cryptoKey) => {
  try {
    const db = await openDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      
      // Use structuredClone to store the CryptoKey
      // Note: structuredClone is available in modern browsers
      // and can handle CryptoKey objects
      const keyData = {
        name: name,
        key: cryptoKey
      };

      const request = store.put(keyData);

      request.onsuccess = () => {
        resolve();
      };

      request.onerror = () => {
        reject(new Error(`Failed to save key ${name}: ${request.error}`));
      };

      transaction.oncomplete = () => {
        db.close();
      };

      transaction.onerror = () => {
        reject(new Error(`Transaction failed: ${transaction.error}`));
      };
    });
  } catch (error) {
    throw new Error(`Error saving key to IndexedDB: ${error.message}`);
  }
};

/**
 * Retrieve a CryptoKey from IndexedDB
 * @param {string} name - Unique identifier for the key
 * @returns {Promise<CryptoKey|null>} The CryptoKey object, or null if not found
 */
export const getKey = async (name) => {
  try {
    const db = await openDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readonly');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(name);

      request.onsuccess = () => {
        const result = request.result;
        if (result && result.key) {
          resolve(result.key);
        } else {
          resolve(null);
        }
        db.close();
      };

      request.onerror = () => {
        reject(new Error(`Failed to retrieve key ${name}: ${request.error}`));
        db.close();
      };
    });
  } catch (error) {
    throw new Error(`Error retrieving key from IndexedDB: ${error.message}`);
  }
};

/**
 * Delete a CryptoKey from IndexedDB
 * @param {string} name - Unique identifier for the key
 * @returns {Promise<void>}
 */
export const deleteKey = async (name) => {
  try {
    const db = await openDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.delete(name);

      request.onsuccess = () => {
        resolve();
        db.close();
      };

      request.onerror = () => {
        reject(new Error(`Failed to delete key ${name}: ${request.error}`));
        db.close();
      };
    });
  } catch (error) {
    throw new Error(`Error deleting key from IndexedDB: ${error.message}`);
  }
};

/**
 * Clear all keys from IndexedDB
 * Useful for logout or security cleanup
 * @returns {Promise<void>}
 */
export const clearAllKeys = async () => {
  try {
    const db = await openDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.clear();

      request.onsuccess = () => {
        resolve();
        db.close();
      };

      request.onerror = () => {
        reject(new Error(`Failed to clear keys: ${request.error}`));
        db.close();
      };
    });
  } catch (error) {
    throw new Error(`Error clearing keys from IndexedDB: ${error.message}`);
  }
};

