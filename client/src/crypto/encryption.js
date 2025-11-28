/**
 * AES-GCM Encryption Module
 * 
 * STEP 5: End-to-End Message Encryption
 * 
 * Purpose:
 * - Encrypt messages client-side using AES-256-GCM
 * - Decrypt messages client-side using session keys from STEP 4
 * - Server NEVER sees plaintext
 * 
 * Algorithm: AES-GCM (Galois/Counter Mode)
 * - Key Size: 256 bits
 * - IV Size: 96 bits (12 bytes)
 * - Authentication: Built-in auth tag (128 bits)
 * 
 * Security Properties:
 * ✓ Confidentiality: AES-256 encryption
 * ✓ Integrity: GCM authentication tag
 * ✓ Authenticity: Session key derived via authenticated ECDH
 * ✓ Replay Protection: Fresh IV per message
 * 
 * CRITICAL: Never reuse an IV with the same key!
 * Each message MUST generate a fresh random IV.
 */

/**
 * Generate a cryptographically secure random IV
 * 
 * IV = Initialization Vector (also called nonce)
 * - Must be unique for each encryption with the same key
 * - Does NOT need to be secret (transmitted with ciphertext)
 * - 12 bytes (96 bits) is standard for AES-GCM
 * 
 * @returns {Uint8Array} 12-byte random IV
 */
const generateIV = () => {
  // Generate 12 random bytes using the browser's CSPRNG
  const iv = new Uint8Array(12);
  window.crypto.getRandomValues(iv);
  return iv;
};

/**
 * Convert ArrayBuffer to Base64 string
 * 
 * Used for transmitting binary data (IV, ciphertext) over JSON APIs
 * 
 * @param {ArrayBuffer} buffer - The buffer to encode
 * @returns {string} Base64-encoded string
 */
const arrayBufferToBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

/**
 * Convert Base64 string to ArrayBuffer
 * 
 * Used for receiving binary data from JSON APIs
 * 
 * @param {string} base64 - Base64-encoded string
 * @returns {ArrayBuffer} The decoded buffer
 */
const base64ToArrayBuffer = (base64) => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};

/**
 * Encrypt a plaintext message using AES-256-GCM
 * 
 * Process:
 * 1. Generate a fresh random IV (12 bytes)
 * 2. Encode plaintext string to UTF-8 bytes
 * 3. Encrypt with AES-GCM (produces ciphertext + auth tag)
 * 4. Base64-encode both IV and ciphertext for transmission
 * 
 * The auth tag is automatically appended to the ciphertext by Web Crypto API.
 * 
 * @param {CryptoKey} sessionKey - AES-GCM 256-bit session key
 * @param {string} plaintext - The message to encrypt
 * @returns {Promise<{ciphertextBase64: string, ivBase64: string}>}
 */
export const encryptMessage = async (sessionKey, plaintext) => {
  try {
    // Validate inputs
    if (!(sessionKey instanceof CryptoKey)) {
      throw new Error('Session key must be a CryptoKey object');
    }

    if (sessionKey.algorithm.name !== 'AES-GCM') {
      throw new Error('Session key must be an AES-GCM key');
    }

    if (typeof plaintext !== 'string') {
      throw new Error('Plaintext must be a string');
    }

    if (plaintext.length === 0) {
      throw new Error('Cannot encrypt empty message');
    }

    // STEP 1: Generate fresh random IV
    // CRITICAL: Never reuse an IV with the same key!
    const iv = generateIV();

    // STEP 2: Encode plaintext to UTF-8 bytes
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(plaintext);

    // STEP 3: Encrypt using AES-GCM
    // The Web Crypto API automatically:
    // - Encrypts the data
    // - Computes authentication tag
    // - Appends auth tag to ciphertext
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        // Optional: Additional Authenticated Data (AAD)
        // additionalData: ... (not used here, but available for metadata)
      },
      sessionKey,
      plaintextBytes
    );

    // STEP 4: Base64-encode for transmission
    const ciphertextBase64 = arrayBufferToBase64(ciphertextBuffer);
    const ivBase64 = arrayBufferToBase64(iv);

    console.log('✓ Message encrypted successfully');
    console.log(`  - Plaintext length: ${plaintext.length} chars`);
    console.log(`  - Ciphertext length: ${ciphertextBase64.length} chars`);
    console.log(`  - IV (Base64): ${ivBase64}`);

    return {
      ciphertextBase64,
      ivBase64
    };
  } catch (error) {
    console.error('❌ Encryption failed:', error);
    throw new Error(`Failed to encrypt message: ${error.message}`);
  }
};

/**
 * Decrypt a ciphertext message using AES-256-GCM
 * 
 * Process:
 * 1. Base64-decode the IV and ciphertext
 * 2. Decrypt using AES-GCM with the session key
 * 3. Verify authentication tag (automatic in GCM)
 * 4. Decode UTF-8 bytes back to string
 * 
 * Security:
 * - If the ciphertext has been tampered with, GCM will detect it
 * - If the wrong key is used, decryption will fail
 * - If the IV is wrong, decryption will produce garbage
 * 
 * @param {CryptoKey} sessionKey - AES-GCM 256-bit session key
 * @param {string} ciphertextBase64 - Base64-encoded ciphertext (includes auth tag)
 * @param {string} ivBase64 - Base64-encoded IV
 * @returns {Promise<string>} The decrypted plaintext message
 * @throws {Error} If decryption fails (wrong key, tampering, etc.)
 */
export const decryptMessage = async (sessionKey, ciphertextBase64, ivBase64) => {
  try {
    // Validate inputs
    if (!(sessionKey instanceof CryptoKey)) {
      throw new Error('Session key must be a CryptoKey object');
    }

    if (sessionKey.algorithm.name !== 'AES-GCM') {
      throw new Error('Session key must be an AES-GCM key');
    }

    if (typeof ciphertextBase64 !== 'string' || typeof ivBase64 !== 'string') {
      throw new Error('Ciphertext and IV must be Base64 strings');
    }

    // STEP 1: Base64-decode to ArrayBuffers
    const ciphertextBuffer = base64ToArrayBuffer(ciphertextBase64);
    const iv = base64ToArrayBuffer(ivBase64);

    // Validate IV length (must be 12 bytes for AES-GCM)
    if (iv.byteLength !== 12) {
      throw new Error(`Invalid IV length: ${iv.byteLength} bytes (expected 12)`);
    }

    // STEP 2: Decrypt using AES-GCM
    // This will:
    // - Decrypt the ciphertext
    // - Verify the authentication tag
    // - Throw an error if tag verification fails (tampering detected)
    const plaintextBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      sessionKey,
      ciphertextBuffer
    );

    // STEP 3: Decode UTF-8 bytes to string
    const decoder = new TextDecoder();
    const plaintext = decoder.decode(plaintextBuffer);

    console.log('✓ Message decrypted successfully');
    console.log(`  - Plaintext length: ${plaintext.length} chars`);

    return plaintext;
  } catch (error) {
    // GCM authentication failure or wrong key
    if (error.name === 'OperationError') {
      console.error('❌ Decryption failed: Authentication tag verification failed');
      throw new Error('Decryption failed: Message may have been tampered with or wrong key used');
    }
    
    console.error('❌ Decryption failed:', error);
    throw new Error(`Failed to decrypt message: ${error.message}`);
  }
};

/**
 * Test if encryption/decryption works with a given session key
 * 
 * Useful for debugging and verifying key exchange was successful.
 * 
 * @param {CryptoKey} sessionKey - The session key to test
 * @returns {Promise<boolean>} True if encryption/decryption works
 */
export const testEncryption = async (sessionKey) => {
  try {
    const testMessage = 'Hello, this is a test message! 🔐';
    
    console.log('Testing encryption/decryption...');
    console.log(`Test message: "${testMessage}"`);
    
    // Encrypt
    const { ciphertextBase64, ivBase64 } = await encryptMessage(sessionKey, testMessage);
    console.log('✓ Encryption successful');
    
    // Decrypt
    const decrypted = await decryptMessage(sessionKey, ciphertextBase64, ivBase64);
    console.log('✓ Decryption successful');
    
    // Verify
    const success = decrypted === testMessage;
    if (success) {
      console.log('✓ Encryption test PASSED: Decrypted message matches original');
    } else {
      console.error('❌ Encryption test FAILED: Messages do not match');
      console.error(`  Original: "${testMessage}"`);
      console.error(`  Decrypted: "${decrypted}"`);
    }
    
    return success;
  } catch (error) {
    console.error('❌ Encryption test FAILED:', error);
    return false;
  }
};
