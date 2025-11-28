/**
 * Session Key Storage Module
 * 
 * STEP 4: Secure storage for derived session keys
 * 
 * After ECDH key exchange, the derived symmetric session key (AES-GCM)
 * is stored in IndexedDB indexed by peer user ID.
 * 
 * This allows:
 * - Persistent session keys across page reloads
 * - Quick lookup by peer ID for encryption/decryption
 * - Secure isolation from localStorage
 * 
 * Security Note: Session keys are stored locally and never transmitted.
 * They are derived independently by both parties using ECDH.
 */

import { openDB } from './indexedDB.js';

const SESSION_STORE_NAME = 'sessionKeys';
const DB_NAME = 'secureKeysDB';
const DB_VERSION = 2; // Increment version to add new object store

/**
 * Open or create the IndexedDB database with session keys store
 * @returns {Promise<IDBDatabase>} The database instance
 */
export const openSessionDB = () => {
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
      
      // Create keys store if it doesn't exist (from STEP 3)
      if (!db.objectStoreNames.contains('keys')) {
        const keysStore = db.createObjectStore('keys', { keyPath: 'name' });
        keysStore.createIndex('name', 'name', { unique: true });
      }

      // Create session keys store if it doesn't exist
      if (!db.objectStoreNames.contains(SESSION_STORE_NAME)) {
        const sessionStore = db.createObjectStore(SESSION_STORE_NAME, { keyPath: 'peerId' });
        // Index by peer user ID for fast lookups
        sessionStore.createIndex('peerId', 'peerId', { unique: true });
      }
    };
  });
};

/**
 * Save a session key for a specific peer
 * 
 * @param {string} peerId - The user ID of the peer (conversation partner)
 * @param {CryptoKey} sessionKey - The derived AES-GCM session key
 * @returns {Promise<void>}
 */
export const saveSessionKey = async (peerId, sessionKey) => {
  try {
    if (!peerId) {
      throw new Error('Peer ID is required');
    }

    if (!(sessionKey instanceof CryptoKey)) {
      throw new Error('Session key must be a CryptoKey object');
    }

    const db = await openSessionDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_STORE_NAME], 'readwrite');
      const store = transaction.objectStore(SESSION_STORE_NAME);
      
      const sessionData = {
        peerId: peerId,
        key: sessionKey,
        timestamp: Date.now() // Track when key was established
      };

      const request = store.put(sessionData);

      request.onsuccess = () => {
        console.log(`Session key saved for peer: ${peerId}`);
        resolve();
      };

      request.onerror = () => {
        reject(new Error(`Failed to save session key for ${peerId}: ${request.error}`));
      };

      transaction.oncomplete = () => {
        db.close();
      };

      transaction.onerror = () => {
        reject(new Error(`Transaction failed: ${transaction.error}`));
      };
    });
  } catch (error) {
    throw new Error(`Error saving session key: ${error.message}`);
  }
};

/**
 * Retrieve a session key for a specific peer
 * 
 * @param {string} peerId - The user ID of the peer
 * @returns {Promise<CryptoKey|null>} The session key, or null if not found
 */
export const getSessionKey = async (peerId) => {
  try {
    if (!peerId) {
      throw new Error('Peer ID is required');
    }

    const db = await openSessionDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_STORE_NAME], 'readonly');
      const store = transaction.objectStore(SESSION_STORE_NAME);
      const request = store.get(peerId);

      request.onsuccess = () => {
        const result = request.result;
        if (result && result.key) {
          console.log(`Session key retrieved for peer: ${peerId}`);
          resolve(result.key);
        } else {
          console.log(`No session key found for peer: ${peerId}`);
          resolve(null);
        }
        db.close();
      };

      request.onerror = () => {
        reject(new Error(`Failed to retrieve session key for ${peerId}: ${request.error}`));
        db.close();
      };
    });
  } catch (error) {
    throw new Error(`Error retrieving session key: ${error.message}`);
  }
};

/**
 * Delete a session key for a specific peer
 * 
 * Use cases:
 * - User manually resets the secure channel
 * - Security policy requires key rotation
 * - Logout or account deletion
 * 
 * @param {string} peerId - The user ID of the peer
 * @returns {Promise<void>}
 */
export const deleteSessionKey = async (peerId) => {
  try {
    if (!peerId) {
      throw new Error('Peer ID is required');
    }

    const db = await openSessionDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_STORE_NAME], 'readwrite');
      const store = transaction.objectStore(SESSION_STORE_NAME);
      const request = store.delete(peerId);

      request.onsuccess = () => {
        console.log(`Session key deleted for peer: ${peerId}`);
        resolve();
        db.close();
      };

      request.onerror = () => {
        reject(new Error(`Failed to delete session key for ${peerId}: ${request.error}`));
        db.close();
      };
    });
  } catch (error) {
    throw new Error(`Error deleting session key: ${error.message}`);
  }
};

/**
 * Clear all session keys
 * 
 * Use for:
 * - Global logout
 * - Security reset
 * - Account deletion
 * 
 * @returns {Promise<void>}
 */
export const clearAllSessionKeys = async () => {
  try {
    const db = await openSessionDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_STORE_NAME], 'readwrite');
      const store = transaction.objectStore(SESSION_STORE_NAME);
      const request = store.clear();

      request.onsuccess = () => {
        console.log('All session keys cleared');
        resolve();
        db.close();
      };

      request.onerror = () => {
        reject(new Error(`Failed to clear session keys: ${request.error}`));
        db.close();
      };
    });
  } catch (error) {
    throw new Error(`Error clearing session keys: ${error.message}`);
  }
};

/**
 * Check if a session key exists for a peer
 * 
 * @param {string} peerId - The user ID of the peer
 * @returns {Promise<boolean>} True if session key exists
 */
export const hasSessionKey = async (peerId) => {
  try {
    const key = await getSessionKey(peerId);
    return key !== null;
  } catch (error) {
    console.error('Error checking session key existence:', error);
    return false;
  }
};
