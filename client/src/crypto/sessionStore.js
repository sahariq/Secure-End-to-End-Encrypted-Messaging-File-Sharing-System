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
const SEQUENCE_STORE_NAME = 'sequenceNumbers';

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

    const db = await openDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_STORE_NAME], 'readwrite');
      const store = transaction.objectStore(SESSION_STORE_NAME);

      const sessionData = {
        peerId: peerId,
        key: sessionKey,
        key: sessionKey,
        timestamp: Date.now() // Track when key was established
      };

      // Reset sequence numbers for this new session
      // We do this implicitly by deleting the old record
      // Note: This is async but we don't strictly need to wait for it to block the UI
      // But for correctness, let's do it.
      // Actually, we can't easily await inside this transaction callback structure without nesting.
      // Let's just rely on the caller to clear it, OR do it here if we change structure.
      // Better: The caller (keyExchange.js) knows when a NEW session is starting.


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

    const db = await openDB();

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

    const db = await openDB();

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
    const db = await openDB();

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
/**
 * Get the next sequence number for sending to a peer
 * 
 * @param {string} peerId 
 * @returns {Promise<number>} The next sequence number (increments automatically)
 */
export const getNextSequenceNumber = async (peerId) => {
  try {
    const db = await openDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SEQUENCE_STORE_NAME], 'readwrite');
      const store = transaction.objectStore(SEQUENCE_STORE_NAME);
      const request = store.get(peerId);

      request.onsuccess = () => {
        let data = request.result;
        if (!data) {
          data = { peerId, lastSent: 0, lastReceived: 0 };
        }

        // Increment sent counter
        data.lastSent += 1;
        const nextSeq = data.lastSent;

        // Save back
        store.put(data);
        resolve(nextSeq);
      };

      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    throw new Error(`Failed to get sequence number: ${error.message}`);
  }
};

/**
 * Verify and update received sequence number
 * 
 * @param {string} peerId 
 * @param {number} sequenceNumber 
 * @returns {Promise<boolean>} True if valid (new), False if replay/old
 */
export const verifyReceivedSequenceNumber = async (peerId, sequenceNumber) => {
  try {
    const db = await openDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SEQUENCE_STORE_NAME], 'readwrite');
      const store = transaction.objectStore(SEQUENCE_STORE_NAME);
      const request = store.get(peerId);

      request.onsuccess = () => {
        let data = request.result;
        if (!data) {
          data = { peerId, lastSent: 0, lastReceived: 0 };
        }

        // Check if replay (assuming strict ordering for now, or at least > last)
        // For simple replay protection, just needs to be > lastReceived
        if (sequenceNumber <= data.lastReceived) {
          console.warn(`Replay detected! Seq ${sequenceNumber} <= Last ${data.lastReceived}`);
          resolve(false);
          return;
        }

        // Valid - update lastReceived
        data.lastReceived = sequenceNumber;
        store.put(data);
        resolve(true);
      };

      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    console.error('Sequence verification error:', error);
    return false;
  }
};
/**
 * Clear sequence numbers for a peer
 * 
 * Use when resetting a session (e.g., new key exchange)
 * 
 * @param {string} peerId 
 */
export const clearSequenceNumbers = async (peerId) => {
  try {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SEQUENCE_STORE_NAME], 'readwrite');
      const store = transaction.objectStore(SEQUENCE_STORE_NAME);
      const request = store.delete(peerId);

      request.onsuccess = () => {
        console.log(`Sequence numbers cleared for peer: ${peerId}`);
        resolve();
      };
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    console.error('Error clearing sequence numbers:', error);
  }
};
