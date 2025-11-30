import axios from 'axios';
import crypto from 'crypto';

const API_URL = 'http://localhost:5000/api';

// Helper to generate key pair
const generateKeyPair = () => {
    return crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
};

// Helper to export JWK from PEM public key
const pemToJwk = (pem) => {
    const key = crypto.createPublicKey(pem);
    return key.export({ format: 'jwk' });
};

// Helper to sign data
const signData = (privateKeyPem, data) => {
    const sign = crypto.createSign('SHA256');
    sign.update(JSON.stringify(data));
    sign.end();
    return sign.sign(privateKeyPem, 'base64');
};

const runAttackSimulation = async () => {
    try {
        console.log('🚀 Starting Replay Attack Simulation...');

        // 1. Register User A (Attacker/Victim)
        const username = `user_${Date.now()}`;
        const password = 'password123';

        console.log(`\n1. Registering User: ${username}`);
        await axios.post(`${API_URL}/auth/register`, { username, password });

        // 2. Login
        const loginRes = await axios.post(`${API_URL}/auth/login`, { username, password });
        const token = loginRes.data.token;
        const userId = loginRes.data.userId;
        const authHeaders = { headers: { Authorization: `Bearer ${token}` } };
        console.log('✓ Logged in');

        // 3. Upload Public Key
        console.log('\n2. Uploading Identity Public Key...');
        const { publicKey, privateKey } = generateKeyPair();
        const publicKeyJwk = pemToJwk(publicKey);

        await axios.post(`${API_URL}/keys/upload`, {
            userId,
            publicKeyJwk: JSON.stringify(publicKeyJwk)
        }, authHeaders);
        console.log('✓ Public Key Uploaded');

        // 4. Send Valid Message
        console.log('\n3. Sending VALID Message...');
        const nonce = crypto.randomBytes(16).toString('hex');
        const timestamp = new Date().toISOString();
        const sequenceNumber = 1;

        const payload = {
            senderId: userId,
            receiverId: userId, // Send to self for simplicity
            ciphertext: 'SGVsbG8gV29ybGQ=', // "Hello World" base64 (dummy)
            iv: crypto.randomBytes(12).toString('base64'), // Random IV
            nonce,
            timestamp,
            sequenceNumber
        };

        const signature = signData(privateKey, payload);

        const validMsgRes = await axios.post(`${API_URL}/messages`, {
            ...payload,
            signature
        }, authHeaders);

        console.log(`✓ Valid message accepted (ID: ${validMsgRes.data.messageId})`);

        // 5. REPLAY ATTACK: Resend exact same payload
        console.log('\n4. Executing REPLAY ATTACK (Same Payload)...');
        try {
            await axios.post(`${API_URL}/messages`, {
                ...payload,
                signature
            }, authHeaders);
            console.error('❌ FAILED: Replay attack was ACCEPTED (Should be rejected)');
        } catch (error) {
            if (error.response && error.response.status === 403) {
                console.log('✓ SUCCESS: Replay attack rejected (403 Forbidden)');
                console.log(`  Reason: ${error.response.data.message}`);
            } else {
                console.error('❌ FAILED: Unexpected error:', error.message);
            }
        }

        // 6. OLD TIMESTAMP ATTACK
        console.log('\n5. Executing OLD TIMESTAMP ATTACK...');
        const oldTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString(); // 10 mins ago
        const oldNonce = crypto.randomBytes(16).toString('hex');

        const oldPayload = {
            ...payload,
            nonce: oldNonce,
            timestamp: oldTimestamp,
            sequenceNumber: 2
        };
        const oldSignature = signData(privateKey, oldPayload);

        try {
            await axios.post(`${API_URL}/messages`, {
                ...oldPayload,
                signature: oldSignature
            }, authHeaders);
            console.error('❌ FAILED: Old timestamp was ACCEPTED');
        } catch (error) {
            if (error.response && error.response.status === 400) {
                console.log('✓ SUCCESS: Old timestamp rejected (400 Bad Request)');
                console.log(`  Reason: ${error.response.data.message}`);
            } else {
                console.error('❌ FAILED: Unexpected error:', error.message);
            }
        }

        // 7. SEQUENCE NUMBER ATTACK (Reusing Seq 1)
        console.log('\n6. Executing SEQUENCE NUMBER ATTACK (Reusing Seq 1)...');
        const newNonce = crypto.randomBytes(16).toString('hex');
        const newTimestamp = new Date().toISOString();

        const seqPayload = {
            ...payload,
            nonce: newNonce,
            timestamp: newTimestamp,
            sequenceNumber: 1 // Reusing 1, but we already sent 1
        };
        const seqSignature = signData(privateKey, seqPayload);

        try {
            await axios.post(`${API_URL}/messages`, {
                ...seqPayload,
                signature: seqSignature
            }, authHeaders);
            console.error('❌ FAILED: Bad sequence number was ACCEPTED');
        } catch (error) {
            if (error.response && error.response.status === 403) {
                console.log('✓ SUCCESS: Bad sequence number rejected (403 Forbidden)');
                console.log(`  Reason: ${error.response.data.message}`);
            } else {
                console.error('❌ FAILED: Unexpected error:', error.message);
            }
        }

        console.log('\n══════════════════════════════════════════');
        console.log('✅ REPLAY DEFENSE VERIFICATION COMPLETE');
        console.log('══════════════════════════════════════════');

    } catch (error) {
        console.error('\n❌ Simulation Failed:', error.message);
        console.error('Stack:', error.stack);
        if (error.response) {
            console.error('Response Data:', error.response.data);
            console.error('Response Status:', error.response.status);
        } else if (error.request) {
            console.error('No response received. Request:', error.request);
        } else {
            console.error('Error config:', error.config);
        }
    }
};

runAttackSimulation();
