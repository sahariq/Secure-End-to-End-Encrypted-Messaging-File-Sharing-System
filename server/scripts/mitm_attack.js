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
    const amitabh_bachan = generateECDHKeyPair();
    const sher_shah_suri = generateECDHKeyPair();
    const dobby_deol = generateECDHKeyPair(); // Attacker

    console.log('1. Amitabh Bachan generates ECDH keys.');
    console.log('2. Sher Shah Suri generates ECDH keys.');
    console.log('3. Dobby Deol (Attacker) is listening.');

    // 2. Amitabh sends Public Key to Sher Shah (Intercepted by Dobby)
    console.log('\n[Amitabh] -> Sends PubKey_Amitabh -> [Sher Shah]');
    console.log('⚠️  INTERCEPTED BY DOBBY DEOL!');

    // Dobby replaces Amitabh's key with his own
    const keyForSherShah = dobby_deol.publicKey;
    console.log('[Dobby] -> Sends PubKey_Dobby (pretending to be Amitabh) -> [Sher Shah]');

    // 3. Sher Shah sends Public Key to Amitabh (Intercepted by Dobby)
    console.log('\n[Sher Shah] -> Sends PubKey_SherShah -> [Amitabh]');
    console.log('⚠️  INTERCEPTED BY DOBBY DEOL!');

    // Dobby replaces Sher Shah's key with his own
    const keyForAmitabh = dobby_deol.publicKey;
    console.log('[Dobby] -> Sends PubKey_Dobby (pretending to be Sher Shah) -> [Amitabh]');

    // 4. Key Derivation
    // Amitabh thinks he's talking to Sher Shah, but computes secret with Dobby
    const secret_Amitabh_Dobby = deriveSharedSecret(amitabh_bachan.privateKey, keyForAmitabh);
    const key_Amitabh = deriveKey(secret_Amitabh_Dobby);

    // Sher Shah thinks he's talking to Amitabh, but computes secret with Dobby
    const secret_SherShah_Dobby = deriveSharedSecret(sher_shah_suri.privateKey, keyForSherShah);
    const key_SherShah = deriveKey(secret_SherShah_Dobby);

    // Dobby computes BOTH secrets
    const secret_Dobby_Amitabh = deriveSharedSecret(dobby_deol.privateKey, amitabh_bachan.publicKey);
    const key_Dobby_Amitabh = deriveKey(secret_Dobby_Amitabh);

    const secret_Dobby_SherShah = deriveSharedSecret(dobby_deol.privateKey, sher_shah_suri.publicKey);
    const key_Dobby_SherShah = deriveKey(secret_Dobby_SherShah);

    console.log('\n✓ Keys Established:');
    console.log(`  Amitabh's Key: ${key_Amitabh.toString('hex').substring(0, 10)}...`);
    console.log(`  Dobby's Key:   ${key_Dobby_Amitabh.toString('hex').substring(0, 10)}... (MATCH!)`);
    console.log(`  Sher Shah's Key:   ${key_SherShah.toString('hex').substring(0, 10)}...`);

    // 5. The Attack (Decrypting the Message)
    console.log('\n[Amitabh] -> Encrypts "Meet me at 9PM" -> [Sher Shah]');
    const message = "Meet me at 9PM";
    const encrypted = encryptMessage(key_Amitabh, message);

    console.log('⚠️  INTERCEPTED BY DOBBY DEOL!');

    // Dobby decrypts it!
    try {
        const decrypted = decryptMessage(key_Dobby_Amitabh, encrypted.ciphertext, encrypted.iv, encrypted.authTag);
        console.log(`🔓 DOBBY DECRYPTED MESSAGE: "${decrypted}"`);
        console.log('❌ MITM ATTACK SUCCESSFUL! Confidentiality broken.');
    } catch (e) {
        console.log('Dobby failed to decrypt.');
    }
};

// ════════════════════════════════════════════════════════════════════════════
// SCENARIO 2: SIGNED ECDH (MITM FAILURE)
// ════════════════════════════════════════════════════════════════════════════
const runSecuredDemo = () => {
    console.log('\n\n🟢 SCENARIO 2: SIGNED ECDH (MITM FAILURE)');
    console.log('-------------------------------------------');

    // 1. Setup Identities (Long-term keys)
    const amitabhIdentity = generateIdentityKeyPair();
    const sherShahIdentity = generateIdentityKeyPair();

    // Assume public keys are already exchanged/verified via trusted server
    console.log('1. Amitabh & Sher Shah have exchanged trusted Identity Public Keys.');

    // 2. Ephemeral Setup
    const amitabhEph = generateECDHKeyPair();
    const dobbyEph = generateECDHKeyPair(); // Attacker

    // 3. Amitabh Sends Signed Key
    console.log('\n[Amitabh] -> Generates Ephemeral Key + SIGNATURE');
    const signature = signData(amitabhIdentity.privateKey, amitabhEph.publicKey);

    console.log('[Amitabh] -> Sends { PubKey_Amitabh, Signature_Amitabh } -> [Sher Shah]');
    console.log('⚠️  INTERCEPTED BY DOBBY DEOL!');

    // 4. Dobby Attempts Attack
    console.log('\n[Dobby] Attempts to replace PubKey_Amitabh with PubKey_Dobby...');

    // OPTION A: Dobby sends his key but keeps Amitabh's signature
    console.log('👉 Attempt A: Send PubKey_Dobby + Amitabh\'s Signature');
    const validA = verifySignature(amitabhIdentity.publicKey, dobbyEph.publicKey, signature);
    if (!validA) {
        console.log('🛡️  SHER SHAH REJECTS: Signature verification failed! (Signature does not match Key)');
    } else {
        console.error('❌ ERROR: Sher Shah accepted invalid key!');
    }

    // OPTION B: Dobby signs his key with HIS identity key (but Sher Shah expects Amitabh)
    console.log('👉 Attempt B: Send PubKey_Dobby + Dobby\'s Signature');
    const dobbyIdentity = generateIdentityKeyPair();
    const dobbySig = signData(dobbyIdentity.privateKey, dobbyEph.publicKey);

    // Sher Shah verifies using AMITABH'S identity key (because he thinks he's talking to Amitabh)
    const validB = verifySignature(amitabhIdentity.publicKey, dobbyEph.publicKey, dobbySig);
    if (!validB) {
        console.log('🛡️  SHER SHAH REJECTS: Signature verification failed! (Signed by wrong key)');
    } else {
        console.error('❌ ERROR: Sher Shah accepted invalid key!');
    }

    console.log('\n✅ MITM ATTACK PREVENTED! Sher Shah refused to establish connection.');
};

// Run Demos
runUnsecuredDemo();
runSecuredDemo();
