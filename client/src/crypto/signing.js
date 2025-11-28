/**
 * Digital Signature Module
 * 
 * STEP 4: ECDSA signing and verification
 * 
 * Purpose: Authenticate ECDH key exchange to prevent MITM attacks
 * 
 * Security Model:
 * - Each user signs their ECDH public key with their identity private key
 * - Recipient verifies the signature using sender's identity public key
 * - This proves the ECDH public key came from the claimed sender
 * 
 * Why This Prevents MITM:
 * - Attacker cannot forge signatures without the private key
 * - Even if attacker intercepts ECDH public keys, they can't sign them
 * - Both parties verify signatures before deriving shared secret
 * - Authenticated key exchange = no impersonation possible
 * 
 * Algorithm: ECDSA with P-256 curve and SHA-256 hash
 */

/**
 * Sign data using a private key
 * 
 * Used to authenticate:
 * - ECDH public keys during key exchange
 * - Key confirmation messages
 * - Any data requiring non-repudiation
 * 
 * @param {CryptoKey} privateKey - The signer's ECDSA private key
 * @param {string|ArrayBuffer} data - The data to sign
 * @returns {Promise<ArrayBuffer>} The digital signature
 */
export const signMessage = async (privateKey, data) => {
  try {
    // Validate inputs
    if (!(privateKey instanceof CryptoKey)) {
      throw new Error('Private key must be a CryptoKey object');
    }

    if (privateKey.type !== 'private') {
      throw new Error('Key must be a private key for signing');
    }

    // Convert string data to ArrayBuffer if needed
    let dataBuffer;
    if (typeof data === 'string') {
      const encoder = new TextEncoder();
      dataBuffer = encoder.encode(data);
    } else if (data instanceof ArrayBuffer) {
      dataBuffer = data;
    } else {
      throw new Error('Data must be a string or ArrayBuffer');
    }

    // Sign using ECDSA with SHA-256
    // This creates a digital signature that:
    // 1. Proves the data came from the holder of this private key
    // 2. Proves the data hasn't been tampered with
    const signature = await window.crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      privateKey,
      dataBuffer
    );

    return signature;
  } catch (error) {
    throw new Error(`Failed to sign message: ${error.message}`);
  }
};

/**
 * Verify a digital signature
 * 
 * Confirms that:
 * 1. The data was signed by the holder of the corresponding private key
 * 2. The data has not been modified since signing
 * 
 * @param {CryptoKey} publicKey - The signer's ECDSA public key
 * @param {string|ArrayBuffer} data - The original data that was signed
 * @param {ArrayBuffer} signature - The signature to verify
 * @returns {Promise<boolean>} True if signature is valid, false otherwise
 */
export const verifySignature = async (publicKey, data, signature) => {
  try {
    // Validate inputs
    if (!(publicKey instanceof CryptoKey)) {
      throw new Error('Public key must be a CryptoKey object');
    }

    if (publicKey.type !== 'public') {
      throw new Error('Key must be a public key for verification');
    }

    if (!(signature instanceof ArrayBuffer)) {
      throw new Error('Signature must be an ArrayBuffer');
    }

    // Convert string data to ArrayBuffer if needed
    let dataBuffer;
    if (typeof data === 'string') {
      const encoder = new TextEncoder();
      dataBuffer = encoder.encode(data);
    } else if (data instanceof ArrayBuffer) {
      dataBuffer = data;
    } else {
      throw new Error('Data must be a string or ArrayBuffer');
    }

    // Verify the signature using ECDSA with SHA-256
    const isValid = await window.crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      publicKey,
      signature,
      dataBuffer
    );

    return isValid;
  } catch (error) {
    console.error('Signature verification error:', error);
    // Return false on error rather than throwing
    // This prevents protocol disruption from malformed signatures
    return false;
  }
};

/**
 * Sign a JSON object
 * 
 * Convenience function for signing structured data.
 * Serializes the object deterministically before signing.
 * 
 * @param {CryptoKey} privateKey - The signer's ECDSA private key
 * @param {Object} obj - The object to sign
 * @returns {Promise<ArrayBuffer>} The digital signature
 */
export const signObject = async (privateKey, obj) => {
  try {
    // Serialize to JSON string
    // Note: JSON.stringify is deterministic for simple objects
    // For production, consider canonical JSON serialization
    const jsonString = JSON.stringify(obj);
    return await signMessage(privateKey, jsonString);
  } catch (error) {
    throw new Error(`Failed to sign object: ${error.message}`);
  }
};

/**
 * Verify a signature on a JSON object
 * 
 * @param {CryptoKey} publicKey - The signer's ECDSA public key
 * @param {Object} obj - The object that was signed
 * @param {ArrayBuffer} signature - The signature to verify
 * @returns {Promise<boolean>} True if signature is valid
 */
export const verifyObjectSignature = async (publicKey, obj, signature) => {
  try {
    const jsonString = JSON.stringify(obj);
    return await verifySignature(publicKey, jsonString, signature);
  } catch (error) {
    console.error('Object signature verification error:', error);
    return false;
  }
};

/**
 * Convert ArrayBuffer signature to Base64 string
 * 
 * Useful for:
 * - Transmitting signatures over JSON APIs
 * - Storing signatures in databases
 * 
 * @param {ArrayBuffer} signature - The signature buffer
 * @returns {string} Base64-encoded signature
 */
export const signatureToBase64 = (signature) => {
  const bytes = new Uint8Array(signature);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

/**
 * Convert Base64 string to ArrayBuffer signature
 * 
 * @param {string} base64 - Base64-encoded signature
 * @returns {ArrayBuffer} The signature buffer
 */
export const base64ToSignature = (base64) => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};
