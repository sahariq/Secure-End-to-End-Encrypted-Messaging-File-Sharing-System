import crypto from 'crypto';

// ════════════════════════════════════════════════════════════════════════════
// MITM ATTACK DEMONSTRATION
// ════════════════════════════════════════════════════════════════════════════
// This script demonstrates two scenarios:
// 1. Unsecured ECDH: Vulnerable to Man-in-the-Middle (MITM) attacks.
// 2. Signed ECDH: Protected against MITM using Digital Signatures.
// ════════════════════════════════════════════════════════════════════════════

// --- HELPER FUNCTIONS ---

// Generate ECDH Key Pair (P-256)
const generateECDHKeyPair = () => {
    return crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
};

// Generate ECDSA Identity Key Pair (P-256)
const generateIdentityKeyPair = () => {
    return crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
};

// Derive Shared Secret (ECDH)
const deriveSharedSecret = (privateKeyPem, publicKeyPem) => {
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const publicKey = crypto.createPublicKey(publicKeyPem);
    return crypto.diffieHellman({ privateKey, publicKey });
};

// Sign Data (ECDSA)
const signData = (privateKeyPem, data) => {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKeyPem, 'base64');
};

// Verify Signature (ECDSA)
const verifySignature = (publicKeyPem, data, signatureBase64) => {
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKeyPem, signatureBase64, 'base64');
};

// Encrypt Message (AES-256-GCM)
const encryptMessage = (key, plaintext) => {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag().toString('base64');
    return { ciphertext: encrypted, iv: iv.toString('base64'), authTag };
};

// Decrypt Message (AES-256-GCM)
const decryptMessage = (key, ciphertext, ivBase64, authTagBase64) => {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivBase64, 'base64'));
    decipher.setAuthTag(Buffer.from(authTagBase64, 'base64'));
    let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};

// Derive Session Key (Simple HKDF-like hash for demo)
const deriveKey = (sharedSecret) => {
    return crypto.createHash('sha256').update(sharedSecret).digest();
};

// ════════════════════════════════════════════════════════════════════════════
// SCENARIO 1: UNSECURED ECDH (MITM SUCCESS)
// ════════════════════════════════════════════════════════════════════════════
const runUnsecuredDemo = () => {
    console.log('\n🔴 SCENARIO 1: UNSECURED ECDH (MITM SUCCESS)');
    console.log('---------------------------------------------');

    // 1. Setup
    const alice = generateECDHKeyPair();
    const bob = generateECDHKeyPair();
    const mallory = generateECDHKeyPair(); // Attacker

    console.log('1. Alice generates ECDH keys.');
    console.log('2. Bob generates ECDH keys.');
    console.log('3. Mallory (Attacker) is listening.');

    // 2. Alice sends Public Key to Bob (Intercepted by Mallory)
    console.log('\n[Alice] -> Sends PubKey_A -> [Bob]');
    console.log('⚠️  INTERCEPTED BY MALLORY!');

    // Mallory replaces Alice's key with her own
    const keyForBob = mallory.publicKey;
    console.log('[Mallory] -> Sends PubKey_M (pretending to be Alice) -> [Bob]');

    // 3. Bob sends Public Key to Alice (Intercepted by Mallory)
    console.log('\n[Bob] -> Sends PubKey_B -> [Alice]');
    console.log('⚠️  INTERCEPTED BY MALLORY!');

    // Mallory replaces Bob's key with her own
    const keyForAlice = mallory.publicKey;
    console.log('[Mallory] -> Sends PubKey_M (pretending to be Bob) -> [Alice]');

    // 4. Key Derivation
    // Alice thinks she's talking to Bob, but computes secret with Mallory
    const secret_Alice_Mallory = deriveSharedSecret(alice.privateKey, keyForAlice);
    const key_Alice = deriveKey(secret_Alice_Mallory);

    // Bob thinks he's talking to Alice, but computes secret with Mallory
    const secret_Bob_Mallory = deriveSharedSecret(bob.privateKey, keyForBob);
    const key_Bob = deriveKey(secret_Bob_Mallory);

    // Mallory computes BOTH secrets
    const secret_Mallory_Alice = deriveSharedSecret(mallory.privateKey, alice.publicKey);
    const key_Mallory_Alice = deriveKey(secret_Mallory_Alice);

    const secret_Mallory_Bob = deriveSharedSecret(mallory.privateKey, bob.publicKey);
    const key_Mallory_Bob = deriveKey(secret_Mallory_Bob);

    console.log('\n✓ Keys Established:');
    console.log(`  Alice's Key:   ${key_Alice.toString('hex').substring(0, 10)}...`);
    console.log(`  Mallory's Key: ${key_Mallory_Alice.toString('hex').substring(0, 10)}... (MATCH!)`);
    console.log(`  Bob's Key:     ${key_Bob.toString('hex').substring(0, 10)}...`);

    // 5. The Attack (Decrypting the Message)
    console.log('\n[Alice] -> Encrypts "Meet me at 9PM" -> [Bob]');
    const message = "Meet me at 9PM";
    const encrypted = encryptMessage(key_Alice, message);

    console.log('⚠️  INTERCEPTED BY MALLORY!');

    // Mallory decrypts it!
    try {
        const decrypted = decryptMessage(key_Mallory_Alice, encrypted.ciphertext, encrypted.iv, encrypted.authTag);
        console.log(`🔓 MALLORY DECRYPTED MESSAGE: "${decrypted}"`);
        console.log('❌ MITM ATTACK SUCCESSFUL! Confidentiality broken.');
    } catch (e) {
        console.log('Mallory failed to decrypt.');
    }
};

// ════════════════════════════════════════════════════════════════════════════
// SCENARIO 2: SIGNED ECDH (MITM FAILURE)
// ════════════════════════════════════════════════════════════════════════════
const runSecuredDemo = () => {
    console.log('\n\n🟢 SCENARIO 2: SIGNED ECDH (MITM FAILURE)');
    console.log('-------------------------------------------');

    // 1. Setup Identities (Long-term keys)
    const aliceIdentity = generateIdentityKeyPair();
    const bobIdentity = generateIdentityKeyPair();

    // Assume public keys are already exchanged/verified via trusted server
    console.log('1. Alice & Bob have exchanged trusted Identity Public Keys.');

    // 2. Ephemeral Setup
    const aliceEph = generateECDHKeyPair();
    const malloryEph = generateECDHKeyPair(); // Attacker

    // 3. Alice Sends Signed Key
    console.log('\n[Alice] -> Generates Ephemeral Key + SIGNATURE');
    const signature = signData(aliceIdentity.privateKey, aliceEph.publicKey);

    console.log('[Alice] -> Sends { PubKey_A, Signature_A } -> [Bob]');
    console.log('⚠️  INTERCEPTED BY MALLORY!');

    // 4. Mallory Attempts Attack
    console.log('\n[Mallory] Attempts to replace PubKey_A with PubKey_M...');

    // OPTION A: Mallory sends her key but keeps Alice's signature
    console.log('👉 Attempt A: Send PubKey_M + Alice\'s Signature');
    const validA = verifySignature(aliceIdentity.publicKey, malloryEph.publicKey, signature);
    if (!validA) {
        console.log('🛡️  BOB REJECTS: Signature verification failed! (Signature does not match Key)');
    } else {
        console.error('❌ ERROR: Bob accepted invalid key!');
    }

    // OPTION B: Mallory signs her key with HER identity key (but Bob expects Alice)
    console.log('👉 Attempt B: Send PubKey_M + Mallory\'s Signature');
    const malloryIdentity = generateIdentityKeyPair();
    const mallorySig = signData(malloryIdentity.privateKey, malloryEph.publicKey);

    // Bob verifies using ALICE'S identity key (because he thinks he's talking to Alice)
    const validB = verifySignature(aliceIdentity.publicKey, malloryEph.publicKey, mallorySig);
    if (!validB) {
        console.log('🛡️  BOB REJECTS: Signature verification failed! (Signed by wrong key)');
    } else {
        console.error('❌ ERROR: Bob accepted invalid key!');
    }

    console.log('\n✅ MITM ATTACK PREVENTED! Bob refused to establish connection.');
};

// Run Demos
runUnsecuredDemo();
runSecuredDemo();
