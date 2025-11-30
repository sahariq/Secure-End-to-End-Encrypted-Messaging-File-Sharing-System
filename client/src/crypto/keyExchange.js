/**
 * Signed ECDH Key Exchange Protocol
 * 
 * STEP 4: Complete implementation of authenticated key exchange
 * 
 * ═══════════════════════════════════════════════════════════════════
 * PROTOCOL OVERVIEW
 * ═══════════════════════════════════════════════════════════════════
 * 
 * Goal: Establish a shared symmetric session key between two users
 *       without ever transmitting the key itself.
 * 
 * Security Properties:
 * ✓ Confidentiality: Shared secret derived via ECDH (elliptic curve math)
 * ✓ Authentication: Digital signatures prove identity
 * ✓ Integrity: Signatures prevent tampering
 * ✓ MITM Protection: Attacker cannot impersonate without private key
 * 
 * ═══════════════════════════════════════════════════════════════════
 * KEY EXCHANGE FLOW (Alice → Bob)
 * ═══════════════════════════════════════════════════════════════════
 * 
 * PHASE 1: Setup
 * --------------
 * 1. Alice uploads her identity public key to server
 * 2. Bob uploads his identity public key to server
 * 
 * PHASE 2: Key Exchange Initiation (Alice starts)
 * ------------------------------------------------
 * 3. Alice generates ephemeral ECDH key pair (A_eph_priv, A_eph_pub)
 * 4. Alice exports A_eph_pub as SPKI (raw bytes) and signs it → signature_A
 * 5. Alice retrieves Bob's identity public key from server
 * 6. Alice sends {A_eph_pub (JWK), signature_A} to Bob (via server)
 * 
 * PHASE 3: Key Exchange Response (Bob responds)
 * ----------------------------------------------
 * 7. Bob imports A_eph_pub (JWK), exports as SPKI, and verifies signature_A
 * 8. If valid, Bob generates ephemeral ECDH key pair (B_eph_priv, B_eph_pub)
 * 9. Bob exports B_eph_pub as SPKI and signs it → signature_B
 * 10. Bob computes: sharedSecret = ECDH(B_eph_priv, A_eph_pub)
 * 11. Bob derives: sessionKey = HKDF(sharedSecret, salt, info)
 * 12. Bob generates Key Confirmation: Encrypt("Key Confirmation") with sessionKey
 * 13. Bob sends {B_eph_pub (JWK), signature_B, keyConfirmation} to Alice
 * 14. Bob stores sessionKey in IndexedDB
 * 
 * PHASE 4: Session Key Derivation (Alice completes)
 * --------------------------------------------------
 * 15. Alice imports B_eph_pub (JWK), exports as SPKI, and verifies signature_B
 * 16. If valid, Alice computes: sharedSecret = ECDH(A_eph_priv, B_eph_pub)
 * 17. Alice derives: sessionKey = HKDF(sharedSecret, salt, info)
 * 18. Alice verifies Key Confirmation: Decrypt(keyConfirmation) == "Key Confirmation"
 * 19. Alice stores sessionKey in IndexedDB
 * 
 * RESULT: Both have identical sessionKey (AES-GCM key for messaging)
 * 
 * ═══════════════════════════════════════════════════════════════════
 * WHY SIGNATURES PREVENT MITM ATTACKS
 * ═══════════════════════════════════════════════════════════════════
 * 
 * Without signatures:
 * - Attacker intercepts A_eph_pub, replaces with Attacker_pub
 * - Bob derives sessionKey with attacker
 * - Attacker decrypts all messages
 * 
 * With signatures:
 * - Attacker cannot forge Alice's signature (needs her private key)
 * - Bob verifies signature fails → rejects key exchange
 * - MITM attack prevented
 * 
 * ═══════════════════════════════════════════════════════════════════
 */

import { loadKeyPair, loadSigningKeyPair } from './keyManager.js';
import { signMessage, verifySignature, signatureToBase64, base64ToSignature } from './signing.js';
import { saveSessionKey, getSessionKey, clearSequenceNumbers } from './sessionStore.js';


import { encryptMessage, decryptMessage } from './encryption.js';
import apiClient from '../utils/api.js';

/**
 * Upload current user's identity public key to server
 * 
 * This must be done once after registration or login.
 * The server stores ONLY the public key (never private).
 * 
 * @param {string} userId - Current user's ID
 * @param {string} publicKeyJwk - Public key as JWK string
 * @returns {Promise<void>}
 */
export const uploadMyPublicKey = async (userId, publicKeyJwk) => {
  try {
    if (!userId || !publicKeyJwk) {
      throw new Error('User ID and public key are required');
    }

    const response = await apiClient.post('/keys/upload', {
      userId,
      publicKeyJwk
    });

    console.log('✓ Public key uploaded to server');
    return response.data;
  } catch (error) {
    throw new Error(`Failed to upload public key: ${error.message}`);
  }
};

/**
 * Retrieve a peer's identity public key from server
 * 
 * @param {string} userId - The peer's user ID
 * @returns {Promise<CryptoKey>} The peer's public key as CryptoKey
 */
export const requestPublicKeyFromServer = async (userId) => {
  try {
    if (!userId) {
      throw new Error('User ID is required');
    }

    const response = await apiClient.get(`/keys/${userId}`);

    if (!response.data || !response.data.publicKeyJwk) {
      throw new Error('Peer has not uploaded their public key yet');
    }

    // Parse JWK string to object
    const jwk = JSON.parse(response.data.publicKeyJwk);

    // Import as CryptoKey
    // Note: We need both 'verify' (for signature verification) 
    // and 'deriveKey'/'deriveBits' (for ECDH in some flows)
    const publicKey = await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDSA', // Identity keys use ECDSA for signing
        namedCurve: 'P-256'
      },
      true,
      ['verify'] // Used to verify signatures
    );

    console.log(`✓ Retrieved public key for user: ${userId}`);
    return publicKey;
  } catch (error) {
    throw new Error(`Failed to retrieve public key: ${error.message}`);
  }
};

/**
 * Generate an ephemeral ECDH key pair for key exchange
 * 
 * Ephemeral = temporary, used only for this key exchange session.
 * After deriving the session key, these can be discarded.
 * 
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>}
 */
const generateEphemeralECDHKeyPair = async () => {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true, // Extractable (we need to export public key)
      ['deriveKey', 'deriveBits'] // For ECDH operations
    );

    return keyPair;
  } catch (error) {
    throw new Error(`Failed to generate ephemeral key pair: ${error.message}`);
  }
};

/**
 * Derive shared secret using ECDH
 * 
 * Mathematical basis:
 * - Alice computes: sharedSecret = A_priv * B_pub (elliptic curve multiplication)
 * - Bob computes: sharedSecret = B_priv * A_pub
 * - Due to ECDH math: A_priv * B_pub = B_priv * A_pub (same result!)
 * 
 * @param {CryptoKey} myPrivateKey - My ephemeral ECDH private key
 * @param {CryptoKey} peerPublicKey - Peer's ephemeral ECDH public key
 * @returns {Promise<ArrayBuffer>} The shared secret (raw bits)
 */
export const deriveSharedSecret = async (myPrivateKey, peerPublicKey) => {
  try {
    if (!(myPrivateKey instanceof CryptoKey) || !(peerPublicKey instanceof CryptoKey)) {
      throw new Error('Both keys must be CryptoKey objects');
    }

    // ECDH derivation
    const sharedSecret = await window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: peerPublicKey
      },
      myPrivateKey,
      256 // 256 bits = 32 bytes
    );

    console.log('✓ ECDH shared secret derived');
    return sharedSecret;
  } catch (error) {
    throw new Error(`Failed to derive shared secret: ${error.message}`);
  }
};

/**
 * Derive session key from shared secret using HKDF
 * 
 * HKDF (HMAC-based Key Derivation Function):
 * - Extracts entropy from shared secret
 * - Expands to desired key length
 * - Adds salt and context info for domain separation
 * 
 * Output: AES-GCM 256-bit key for message encryption
 * 
 * @param {ArrayBuffer} sharedSecret - The ECDH shared secret
 * @param {string} salt - Random salt (should be same for both parties)
 * @param {string} info - Context information (e.g., "messaging-session")
 * @returns {Promise<CryptoKey>} AES-GCM session key
 */
export const deriveSessionKeyHKDF = async (sharedSecret, salt = 'secure-messaging-v1', info = 'session-key') => {
  try {
    if (!(sharedSecret instanceof ArrayBuffer)) {
      throw new Error('Shared secret must be an ArrayBuffer');
    }

    // Convert salt and info to ArrayBuffer
    const encoder = new TextEncoder();
    const saltBuffer = encoder.encode(salt);
    const infoBuffer = encoder.encode(info);

    // Import shared secret as raw key material
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    // Derive AES-GCM key using HKDF
    const sessionKey = await window.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: saltBuffer,
        info: infoBuffer
      },
      keyMaterial,
      {
        name: 'AES-GCM',
        length: 256 // 256-bit AES key
      },
      false, // Non-extractable (for security)
      ['encrypt', 'decrypt'] // For message encryption/decryption
    );

    console.log('✓ Session key derived via HKDF');
    return sessionKey;
  } catch (error) {
    throw new Error(`Failed to derive session key: ${error.message}`);
  }
};

/**
 * Initiate key exchange (Alice's role)
 * 
 * This function performs PHASE 2 of the protocol:
 * - Generates ephemeral ECDH key pair
 * - Exports public key as SPKI (for signing) and JWK (for transport)
 * - Signs the SPKI bytes
 * - Retrieves peer's identity public key
 * 
 * @param {string} peerUserId - The user ID of the peer (Bob)
 * @returns {Promise<{ephemeralKeyPair: Object, ephemeralPublicKeyJwk: Object, signature: string, peerIdentityPublicKey: CryptoKey}>}
 */
export const initiateKeyExchange = async (peerUserId) => {
  try {
    console.log('\n═══════════════════════════════════════════════════════');
    console.log('🔐 INITIATING SIGNED ECDH KEY EXCHANGE');
    console.log('═══════════════════════════════════════════════════════');
    console.log(`Peer User ID: ${peerUserId}\n`);

    // STEP 1: Load identity key pairs (ECDH for key exchange, ECDSA for signing)
    console.log('[1/6] Loading identity key pairs...');
    const myIdentityKeys = await loadKeyPair();
    const mySigningKeys = await loadSigningKeyPair();
    if (!myIdentityKeys || !mySigningKeys) {
      throw new Error('No identity key pairs found. Please log in or register.');
    }

    // STEP 2: Generate ephemeral ECDH key pair
    console.log('[2/6] Generating ephemeral ECDH key pair...');
    const ephemeralKeyPair = await generateEphemeralECDHKeyPair();

    // STEP 3: Export ephemeral public key as SPKI (for signing) and JWK (for transport)
    console.log('[3/6] Exporting ephemeral public key...');
    const ephemeralPublicKeySpki = await window.crypto.subtle.exportKey(
      'spki',
      ephemeralKeyPair.publicKey
    );
    const ephemeralPublicKeyJwk = await window.crypto.subtle.exportKey(
      'jwk',
      ephemeralKeyPair.publicKey
    );

    // STEP 4: Sign ephemeral public key (SPKI bytes) with identity signing private key
    console.log('[4/6] Signing ephemeral public key (SPKI)...');

    // We sign the SPKI bytes directly to avoid JSON serialization issues
    const signature = await signMessage(mySigningKeys.privateKey, ephemeralPublicKeySpki);
    const signatureBase64 = signatureToBase64(signature);

    // STEP 5: Retrieve peer's identity public key
    console.log('[5/6] Retrieving peer\'s identity public key from server...');
    const peerIdentityPublicKey = await requestPublicKeyFromServer(peerUserId);

    // STEP 6: Return data to be sent to peer
    console.log('[6/6] Key exchange initiated successfully!');
    console.log('Ephemeral public key (JWK):', ephemeralPublicKeyJwk);
    console.log('Signature (Base64):', signatureBase64);
    console.log('\n[NEXT] Waiting for peer\'s response...\n');

    return {
      ephemeralKeyPair,
      ephemeralPublicKeyJwk,
      signature: signatureBase64,
      peerIdentityPublicKey
    };
  } catch (error) {
    console.error('❌ Key exchange initiation failed:', error);
    throw new Error(`Failed to initiate key exchange: ${error.message}`);
  }
};

/**
 * Respond to key exchange (Bob's role)
 * 
 * This function performs PHASE 3 of the protocol:
 * - Verifies peer's signature on their ephemeral public key (reconstructed SPKI)
 * - Generates own ephemeral ECDH key pair
 * - Derives shared secret and session key
 * - Signs own ephemeral public key
 * - Generates Key Confirmation
 * 
 * @param {string} peerUserId - The user ID of the peer (Alice)
 * @param {Object} receivedEphemeralPubKeyJwk - Peer's ephemeral public key (JWK)
 * @param {string} receivedSignatureBase64 - Peer's signature (Base64)
 * @returns {Promise<{sessionKey: CryptoKey, ephemeralPublicKeyJwk: Object, signature: string, keyConfirmation: Object}>}
 */
export const respondToKeyExchange = async (peerUserId, receivedEphemeralPubKeyJwk, receivedSignatureBase64) => {
  try {
    console.log('\n═══════════════════════════════════════════════════════');
    console.log('🔐 RESPONDING TO SIGNED ECDH KEY EXCHANGE');
    console.log('═══════════════════════════════════════════════════════');
    console.log(`Peer User ID: ${peerUserId}\n`);

    // STEP 1: Retrieve peer's identity public key
    console.log('[1/9] Retrieving peer\'s identity public key...');
    const peerIdentityPublicKey = await requestPublicKeyFromServer(peerUserId);

    // STEP 2: Import peer's ephemeral public key
    console.log('[2/9] Importing peer\'s ephemeral public key...');
    const peerEphemeralPublicKey = await window.crypto.subtle.importKey(
      'jwk',
      receivedEphemeralPubKeyJwk,
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      [] // No operations needed (used as peer key in ECDH)
    );

    // STEP 3: Verify peer's signature using SPKI
    console.log('[3/9] Verifying peer\'s signature...');
    // Export to SPKI to verify signature (must match what sender signed)
    const peerEphemeralPublicKeySpki = await window.crypto.subtle.exportKey(
      'spki',
      peerEphemeralPublicKey
    );

    const receivedSignature = base64ToSignature(receivedSignatureBase64);

    const isSignatureValid = await verifySignature(
      peerIdentityPublicKey,
      peerEphemeralPublicKeySpki,
      receivedSignature
    );

    if (!isSignatureValid) {
      throw new Error('⚠️  SIGNATURE VERIFICATION FAILED! Possible MITM attack.');
    }
    console.log('✓ Signature verified! Peer identity authenticated.');

    // STEP 4: Generate my ephemeral ECDH key pair
    console.log('[4/9] Generating my ephemeral ECDH key pair...');
    const myEphemeralKeyPair = await generateEphemeralECDHKeyPair();

    // STEP 5: Derive shared secret using ECDH
    console.log('[5/9] Deriving ECDH shared secret...');
    const sharedSecret = await deriveSharedSecret(
      myEphemeralKeyPair.privateKey,
      peerEphemeralPublicKey
    );

    // STEP 6: Derive session key using HKDF
    console.log('[6/9] Deriving session key via HKDF...');
    const sessionKey = await deriveSessionKeyHKDF(sharedSecret);

    // STEP 7: Store session key in IndexedDB
    console.log('[7/9] Storing session key in IndexedDB...');
    await clearSequenceNumbers(peerUserId);
    await saveSessionKey(peerUserId, sessionKey);

    // STEP 8: Sign my ephemeral public key (SPKI)
    console.log('[8/9] Signing my ephemeral public key...');
    const mySigningKeys = await loadSigningKeyPair();

    // Export to SPKI for signing
    const myEphemeralPublicKeySpki = await window.crypto.subtle.exportKey(
      'spki',
      myEphemeralKeyPair.publicKey
    );
    // Export to JWK for transport
    const myEphemeralPublicKeyJwk = await window.crypto.subtle.exportKey(
      'jwk',
      myEphemeralKeyPair.publicKey
    );

    const mySignature = await signMessage(mySigningKeys.privateKey, myEphemeralPublicKeySpki);
    const mySignatureBase64 = signatureToBase64(mySignature);

    // STEP 9: Generate Key Confirmation
    console.log('[9/9] Generating Key Confirmation...');
    const keyConfirmation = await encryptMessage(sessionKey, "Key Confirmation");

    console.log('\n✓ Key exchange response complete!');
    console.log('✓ Session key established and stored');
    console.log('My ephemeral public key (JWK):', myEphemeralPublicKeyJwk);
    console.log('My signature (Base64):', mySignatureBase64);
    console.log('\n[RESULT] Session key ready for encrypted messaging\n');

    return {
      sessionKey,
      ephemeralPublicKeyJwk: myEphemeralPublicKeyJwk,
      signature: mySignatureBase64,
      keyConfirmation
    };
  } catch (error) {
    console.error('❌ Key exchange response failed:', error);
    throw new Error(`Failed to respond to key exchange: ${error.message}`);
  }
};

/**
 * Complete key exchange (Alice's final step)
 * 
 * This function performs PHASE 4 of the protocol:
 * - Verifies Bob's signature on his ephemeral public key
 * - Derives shared secret and session key
 * - Verifies Key Confirmation
 * - Stores session key
 * 
 * @param {string} peerUserId - The user ID of the peer (Bob)
 * @param {Object} myEphemeralKeyPair - My ephemeral key pair from initiation
 * @param {Object} receivedEphemeralPubKeyJwk - Peer's ephemeral public key (JWK)
 * @param {string} receivedSignatureBase64 - Peer's signature (Base64)
 * @param {Object} keyConfirmation - Key confirmation data (ciphertext + IV)
 * @param {CryptoKey} peerIdentityPublicKey - Peer's identity public key
 * @returns {Promise<CryptoKey>} The derived session key
 */
export const completeKeyExchange = async (
  peerUserId,
  myEphemeralKeyPair,
  receivedEphemeralPubKeyJwk,
  receivedSignatureBase64,
  keyConfirmation,
  peerIdentityPublicKey
) => {
  try {
    console.log('\n═══════════════════════════════════════════════════════');
    console.log('🔐 COMPLETING SIGNED ECDH KEY EXCHANGE');
    console.log('═══════════════════════════════════════════════════════');
    console.log(`Peer User ID: ${peerUserId}\n`);

    // STEP 1: Import peer's ephemeral public key
    console.log('[1/6] Importing peer\'s ephemeral public key...');
    const peerEphemeralPublicKey = await window.crypto.subtle.importKey(
      'jwk',
      receivedEphemeralPubKeyJwk,
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      []
    );

    // STEP 2: Verify peer's signature using SPKI
    console.log('[2/6] Verifying peer\'s signature...');
    const peerEphemeralPublicKeySpki = await window.crypto.subtle.exportKey(
      'spki',
      peerEphemeralPublicKey
    );

    const receivedSignature = base64ToSignature(receivedSignatureBase64);

    const isSignatureValid = await verifySignature(
      peerIdentityPublicKey,
      peerEphemeralPublicKeySpki,
      receivedSignature
    );

    if (!isSignatureValid) {
      throw new Error('⚠️  SIGNATURE VERIFICATION FAILED! Possible MITM attack.');
    }
    console.log('✓ Signature verified! Peer identity authenticated.');

    // STEP 3: Derive shared secret using ECDH
    console.log('[3/6] Deriving ECDH shared secret...');
    const sharedSecret = await deriveSharedSecret(
      myEphemeralKeyPair.privateKey,
      peerEphemeralPublicKey
    );

    // STEP 4: Derive session key using HKDF
    console.log('[4/6] Deriving session key via HKDF...');
    const sessionKey = await deriveSessionKeyHKDF(sharedSecret);

    // STEP 5: Verify Key Confirmation
    console.log('[5/6] Verifying Key Confirmation...');
    if (!keyConfirmation || !keyConfirmation.ciphertextBase64 || !keyConfirmation.ivBase64) {
      throw new Error('Missing Key Confirmation data');
    }

    try {
      const confirmationPlaintext = await decryptMessage(
        sessionKey,
        keyConfirmation.ciphertextBase64,
        keyConfirmation.ivBase64
      );

      if (confirmationPlaintext !== "Key Confirmation") {
        throw new Error('Key Confirmation message mismatch');
      }
      console.log('✓ Key Confirmation verified! Keys match.');
    } catch (error) {
      throw new Error(`Key Confirmation Failed: ${error.message}`);
    }

    // STEP 6: Store session key in IndexedDB
    console.log('[6/6] Storing session key in IndexedDB...');
    await clearSequenceNumbers(peerUserId);
    await saveSessionKey(peerUserId, sessionKey);

    console.log('\n✓ Key exchange completed successfully!');
    console.log('✓ Session key established and stored');
    console.log('\n[RESULT] Both parties now share identical session key');
    console.log('[READY] Secure end-to-end encrypted messaging enabled\n');

    return sessionKey;
  } catch (error) {
    console.error('❌ Key exchange completion failed:', error);
    throw new Error(`Failed to complete key exchange: ${error.message}`);
  }
};

/**
 * Check if session key exists for a peer
 * 
 * @param {string} peerUserId - The peer's user ID
 * @returns {Promise<boolean>} True if session key exists
 */
export const hasSessionKeyWithPeer = async (peerUserId) => {
  try {
    const sessionKey = await getSessionKey(peerUserId);
    return sessionKey !== null;
  } catch (error) {
    return false;
  }
};
