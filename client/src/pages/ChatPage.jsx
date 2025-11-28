import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import apiClient from '../utils/api';
import { 
  initiateKeyExchange, 
  respondToKeyExchange, 
  completeKeyExchange,
  uploadMyPublicKey,
  hasSessionKeyWithPeer
} from '../crypto/keyExchange';
import { getSessionKey, saveSessionKey } from '../crypto/sessionStore';
import { loadKeyPair, loadSigningKeyPair, exportPublicKeyAsJWKString } from '../crypto/keyManager';
import { encryptMessage, decryptMessage } from '../crypto/encryption';
import './ChatPage.css';

function ChatPage() {
  const [messages, setMessages] = useState([]);
  const [messageInput, setMessageInput] = useState('');
  const [selectedContact, setSelectedContact] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [keyExchangeStatus, setKeyExchangeStatus] = useState('');
  const [hasSessionKey, setHasSessionKey] = useState(false);
  const [keyExchangeData, setKeyExchangeData] = useState(null); // Store initiation data
  const [contacts, setContacts] = useState([]); // Fetch real users from backend
  const navigate = useNavigate();

  const currentUserId = localStorage.getItem('userId');
  const currentUsername = localStorage.getItem('username');

  useEffect(() => {
    // Check if user is logged in
    if (!localStorage.getItem('authToken')) {
      navigate('/login');
      return;
    }

    // Fetch real users from backend
    loadContacts();
  }, [navigate]);

  const loadContacts = async () => {
    try {
      const response = await apiClient.get('/auth/users');
      setContacts(response.data);
      
      // Set first contact as selected by default
      if (response.data.length > 0 && !selectedContact) {
        setSelectedContact(response.data[0]);
      }
    } catch (err) {
      console.error('Error loading contacts:', err);
      setError('Failed to load contacts');
    }
  };

  useEffect(() => {
    if (selectedContact && currentUserId) {
      loadMessages();
      checkSessionKeyStatus();
    }
    
    // Cleanup polling interval on unmount
    return () => {
      if (window.keyExchangePollInterval) {
        clearInterval(window.keyExchangePollInterval);
      }
    };
  }, [selectedContact, currentUserId]);

  const checkSessionKeyStatus = async () => {
    if (!selectedContact) return;
    
    try {
      const exists = await hasSessionKeyWithPeer(selectedContact._id);
      setHasSessionKey(exists);
      
      if (exists) {
        const sessionKey = await getSessionKey(selectedContact._id);
        console.log('✓ Session key exists for peer:', selectedContact.username);
        console.log('Session Key:', sessionKey);
      }
    } catch (err) {
      console.error('Error checking session key:', err);
    }
  };

  const loadMessages = async () => {
    if (!selectedContact || !currentUserId) return;

    try {
      // Create conversation ID (sorted user IDs)
      const userIds = [currentUserId, selectedContact._id].sort();
      const conversationId = userIds.join('_');

      // API request includes JWT token via axios interceptor
      const response = await apiClient.get(`/messages/${conversationId}`);
      const encryptedMessages = response.data.messages || [];

      // Decrypt messages if session key exists
      const sessionKey = await getSessionKey(selectedContact._id);
      
      const decryptedMessages = await Promise.all(
        encryptedMessages.map(async (msg) => {
          // Try to decrypt the message
          if (sessionKey) {
            try {
              const plaintext = await decryptMessage(sessionKey, msg.ciphertext, msg.iv);
              return {
                ...msg,
                plaintext, // Decrypted message
                decrypted: true
              };
            } catch (decryptErr) {
              console.error('Failed to decrypt message:', decryptErr);
              return {
                ...msg,
                plaintext: '[Decryption failed - message may be corrupted]',
                decrypted: false
              };
            }
          } else {
            // No session key - can't decrypt
            return {
              ...msg,
              plaintext: '[Encrypted message - no valid session key]',
              decrypted: false
            };
          }
        })
      );

      setMessages(decryptedMessages);
    } catch (err) {
      console.error('Error loading messages:', err);
      setError('Failed to load messages');
    }
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!messageInput.trim() || !selectedContact || !currentUserId) return;

    // STEP 5: Check if session key exists before sending
    if (!hasSessionKey) {
      setError('⚠️ No secure session established. Please run key exchange first.');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // Load session key from IndexedDB
      const sessionKey = await getSessionKey(selectedContact._id);
      
      if (!sessionKey) {
        throw new Error('Session key not found. Please run key exchange.');
      }

      console.log('\n🔐 Encrypting message...');
      console.log('Plaintext:', messageInput);

      // STEP 5: Encrypt message client-side using AES-GCM
      const { ciphertextBase64, ivBase64 } = await encryptMessage(sessionKey, messageInput);

      console.log('Ciphertext (Base64):', ciphertextBase64);
      console.log('IV (Base64):', ivBase64);
      console.log('✓ Message encrypted successfully\n');

      // Send encrypted message to server
      // Server NEVER sees plaintext
      await apiClient.post('/messages', {
        receiverId: selectedContact._id,
        ciphertext: ciphertextBase64,
        iv: ivBase64,
        timestamp: new Date().toISOString()
      });

      console.log('✓ Encrypted message sent to server');

      setMessageInput('');
      // Reload messages (will decrypt on display)
      await loadMessages();
    } catch (err) {
      console.error('❌ Failed to send encrypted message:', err);
      setError(err.response?.data?.message || err.message || 'Failed to send message');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('userId');
    localStorage.removeItem('username');
    navigate('/login');
  };

  /**
   * STEP 4: Upload Public Key to Server
   * 
   * This should be done once after login.
   * Uploads the user's identity public key to the server
   * so other users can retrieve it for key exchange.
   */
  const handleUploadPublicKey = async () => {
    try {
      setKeyExchangeStatus('Uploading public key...');
      setError('');

      // Load ECDSA signing key pair from IndexedDB (used for verifying signatures)
      const signingKeyPair = await loadSigningKeyPair();
      if (!signingKeyPair) {
        throw new Error('No signing key pair found. Please log in again.');
      }

      // Export ECDSA public key as JWK
      const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', signingKeyPair.publicKey);
      const publicKeyJwkString = JSON.stringify(publicKeyJwk);

      // Upload to server
      await uploadMyPublicKey(currentUserId, publicKeyJwkString);

      setKeyExchangeStatus('✓ Public key uploaded successfully!');
      console.log('✓ Public key uploaded to server');
      
      setTimeout(() => setKeyExchangeStatus(''), 3000);
    } catch (err) {
      console.error('Error uploading public key:', err);
      setError(`Failed to upload public key: ${err.message}`);
      setKeyExchangeStatus('');
    }
  };

  /**
   * STEP 4: Start Secure Key Exchange
   * 
   * Initiates the signed ECDH key exchange protocol with the selected contact.
   * This is Phase 2 of the protocol (Alice's initiation).
   * 
   * For demonstration purposes, this simplified version:
   * 1. Initiates key exchange (generates ephemeral keys, signs)
   * 2. Simulates peer response
   * 3. Completes the exchange
   * 
   * In production, steps 2-3 would involve actual message exchange via server.
   */
  /**
   * STEP 4: Start Secure Key Exchange
   * 
   * Full Signed ECDH Protocol Implementation:
   * 1. User A initiates: generates ephemeral keys, signs with identity key
   * 2. Fetches User B's identity public key from server
   * 3. Both users derive shared secret via ECDH
   * 4. Both derive session key via HKDF
   * 5. Signatures prevent MITM attacks
   * 
   * For 2-tab testing: Both users click "Start Key Exchange" on their contact
   */
  const handleStartKeyExchange = async () => {
    if (!selectedContact) {
      setError('Please select a contact first');
      return;
    }

    try {
      setKeyExchangeStatus('Starting key exchange...');
      setError('');

      console.log('\n🚀 Starting Signed ECDH Key Exchange with:', selectedContact.username);
      console.log('═══════════════════════════════════════════════════════\n');

      // STEP 1: Load my keys (ECDH for key exchange, ECDSA for signing)
      console.log('[1/6] Loading my identity keys...');
      const myIdentityKeys = await loadKeyPair(); // ECDH keys
      const mySigningKeys = await loadSigningKeyPair(); // ECDSA keys
      
      if (!myIdentityKeys || !mySigningKeys) {
        throw new Error('Identity keys not found. Please re-login.');
      }

      // STEP 2: Generate ephemeral ECDH key pair for this session
      console.log('[2/6] Generating ephemeral ECDH key pair...');
      const ephemeralKeyPair = await window.crypto.subtle.generateKey(
        {
          name: 'ECDH',
          namedCurve: 'P-256'
        },
        true,
        ['deriveKey', 'deriveBits']
      );

      // STEP 3: Export and sign my ephemeral public key
      console.log('[3/6] Signing ephemeral public key...');
      const myEphemeralPubKeyJwk = await window.crypto.subtle.exportKey('jwk', ephemeralKeyPair.publicKey);
      const myEphemeralPubKeyString = JSON.stringify(myEphemeralPubKeyJwk);
      
      const { signMessage, signatureToBase64 } = await import('../crypto/signing.js');
      const mySignature = await signMessage(mySigningKeys.privateKey, myEphemeralPubKeyString);
      const mySignatureBase64 = signatureToBase64(mySignature);

      // STEP 4: Fetch peer's identity public key from server
      console.log('[4/6] Fetching peer\'s identity public key from server...');
      const { requestPublicKeyFromServer } = await import('../crypto/keyExchange.js');
      const peerIdentityPublicKey = await requestPublicKeyFromServer(selectedContact._id);
      
      console.log('✓ Peer\'s public key retrieved');

      // STEP 5: For 2-tab demo, store my exchange data in localStorage for peer to retrieve
      console.log('[5/6] Publishing my signed ephemeral key...');
      const myExchangeData = {
        userId: currentUserId,
        ephemeralPublicKeyJwk: myEphemeralPubKeyJwk,
        signature: mySignatureBase64,
        timestamp: Date.now()
      };
      
      // Store in localStorage with key based on conversation
      const conversationKey = `key_exchange_${currentUserId}_to_${selectedContact._id}`;
      localStorage.setItem(conversationKey, JSON.stringify(myExchangeData));

      // STEP 6: Check if peer's exchange data already exists
      console.log('[6/6] Checking for peer\'s exchange data...');
      const peerConversationKey = `key_exchange_${selectedContact._id}_to_${currentUserId}`;
      const peerExchangeDataStr = localStorage.getItem(peerConversationKey);

      if (peerExchangeDataStr) {
        // Peer's data exists - complete immediately
        console.log('✓ Peer\'s exchange data found! Completing exchange...');
        const peerExchangeData = JSON.parse(peerExchangeDataStr);
        await completeDerivedKey(peerExchangeData, ephemeralKeyPair, peerIdentityPublicKey);
        return;
      }

      // Peer hasn't initiated yet - poll for their data
      setKeyExchangeStatus('⏳ Waiting for peer to accept key exchange...');
      console.log('\n⏳ Waiting for peer to initiate their side...');
      console.log('💡 Have the other user (in another tab) select you and click "Start Key Exchange"');
      
      // Aggressive polling every 500ms
      let attempts = 0;
      const maxAttempts = 120; // 60 seconds total
      
      const pollInterval = setInterval(async () => {
        attempts++;
        const peerData = localStorage.getItem(peerConversationKey);
        
        if (peerData) {
          clearInterval(pollInterval);
          console.log('✓ Peer\'s exchange data received!');
          const peerExchangeData = JSON.parse(peerData);
          await completeDerivedKey(peerExchangeData, ephemeralKeyPair, peerIdentityPublicKey);
        } else if (attempts >= maxAttempts) {
          clearInterval(pollInterval);
          setKeyExchangeStatus('⏱️ Key exchange timed out. Try again.');
          setError('Peer did not respond to key exchange');
        }
      }, 500);
      
      // Store interval ID for cleanup
      window.keyExchangePollInterval = pollInterval;

    } catch (err) {
      console.error('❌ Key exchange failed:', err);
      setError(`Key exchange failed: ${err.message}`);
      setKeyExchangeStatus('');
    }
  };

  // Helper function to complete key derivation
  const completeDerivedKey = async (peerExchangeData, myEphemeralKeyPair, peerIdentityPublicKey) => {
    try {
      console.log('\n[COMPLETING KEY EXCHANGE]');
      
      // Verify peer's signature
      console.log('[7/9] Verifying peer\'s signature...');
      const { verifySignature, base64ToSignature } = await import('../crypto/signing.js');
      const peerEphemeralPubKeyString = JSON.stringify(peerExchangeData.ephemeralPublicKeyJwk);
      const peerSignature = base64ToSignature(peerExchangeData.signature);
      
      const isValid = await verifySignature(peerIdentityPublicKey, peerEphemeralPubKeyString, peerSignature);
      
      if (!isValid) {
        throw new Error('⚠️ SIGNATURE VERIFICATION FAILED! Possible MITM attack.');
      }
      console.log('✓ Peer signature verified - identity authenticated');

      // Import peer's ephemeral public key
      console.log('[8/9] Importing peer\'s ephemeral public key...');
      const peerEphemeralPublicKey = await window.crypto.subtle.importKey(
        'jwk',
        peerExchangeData.ephemeralPublicKeyJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        []
      );

      // Derive shared secret using ECDH
      console.log('[9/9] Deriving shared secret and session key...');
      const sharedSecretBits = await window.crypto.subtle.deriveBits(
        {
          name: 'ECDH',
          public: peerEphemeralPublicKey
        },
        myEphemeralKeyPair.privateKey,
        256
      );

      // Derive session key using HKDF
      const sharedSecretKey = await window.crypto.subtle.importKey(
        'raw',
        sharedSecretBits,
        'HKDF',
        false,
        ['deriveKey']
      );

      const encoder = new TextEncoder();
      const sessionKey = await window.crypto.subtle.deriveKey(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: encoder.encode('secure-messaging-v1'),
          info: encoder.encode('aes-gcm-session-key')
        },
        sharedSecretKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );

      // Store session key
      await saveSessionKey(selectedContact._id, sessionKey);
      
      // Update UI
      setHasSessionKey(true);
      setKeyExchangeStatus('✓ Secure session established!');
      
      console.log('\n═══════════════════════════════════════════════════════');
      console.log('✅ SIGNED ECDH KEY EXCHANGE COMPLETE');
      console.log('═══════════════════════════════════════════════════════');
      console.log('✓ Shared secret derived via ECDH');
      console.log('✓ Session key derived via HKDF-SHA256');
      console.log('✓ Signatures verified - MITM protection active');
      console.log('✓ Ready for AES-256-GCM encrypted messaging!');
      console.log('═══════════════════════════════════════════════════════\n');

      setTimeout(() => setKeyExchangeStatus(''), 3000);
    } catch (err) {
      console.error('❌ Key derivation failed:', err);
      setError(`Key derivation failed: ${err.message}`);
      setKeyExchangeStatus('');
    }
  };

  return (
    <div className="chat-page">
      <div className="chat-header">
        <h2>Secure Messaging</h2>
        <div className="user-info">
          <span>Logged in as: {currentUsername}</span>
          <button onClick={handleLogout} className="logout-btn">Logout</button>
        </div>
      </div>
      <div className="chat-container">
        <div className="contacts-sidebar">
          <h3>Contacts</h3>
          <ul>
            {contacts.map(contact => (
              <li
                key={contact._id}
                className={selectedContact?._id === contact._id ? 'active' : ''}
                onClick={() => setSelectedContact(contact)}
              >
                {contact.username}
              </li>
            ))}
          </ul>
        </div>
        <div className="chat-main">
          {selectedContact ? (
            <>
              <div className="chat-header-bar">
                <h3>Chat with {selectedContact.username}</h3>
                <div className="key-exchange-controls">
                  <button 
                    onClick={handleUploadPublicKey}
                    className="key-exchange-btn"
                    title="Upload your public key to server"
                  >
                    📤 Upload Public Key
                  </button>
                  <button 
                    onClick={handleStartKeyExchange}
                    className="key-exchange-btn"
                    disabled={loading}
                    title="Start signed ECDH key exchange"
                  >
                    🔐 Start Secure Key Exchange
                  </button>
                  {hasSessionKey && (
                    <span className="session-key-indicator" title="Secure session established">
                      ✓ Secure
                    </span>
                  )}
                </div>
              </div>
              {keyExchangeStatus && (
                <div className={keyExchangeStatus.includes('✓') ? 'success-message' : 'info-message'}>
                  {keyExchangeStatus}
                </div>
              )}
              <div className="messages-container">
                {messages.length === 0 ? (
                  <div className="no-messages">No messages yet. Start a conversation!</div>
                ) : (
                  messages.map((msg) => (
                    <div
                      key={msg.id}
                      className={`message ${msg.senderId === currentUserId ? 'sent' : 'received'}`}
                    >
                      <div className="message-header">
                        <span className="sender">
                          {msg.senderId === currentUserId ? 'You' : msg.senderUsername}
                        </span>
                        <span className="timestamp">
                          {new Date(msg.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <div className="message-content">
                        {msg.decrypted ? (
                          <>{msg.plaintext}</>
                        ) : (
                          <span className="encrypted-placeholder">
                            {msg.plaintext}
                          </span>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
              <form onSubmit={handleSendMessage} className="message-input-form">
                {error && <div className="error-message">{error}</div>}
                <div className="input-group">
                  <input
                    type="text"
                    value={messageInput}
                    onChange={(e) => setMessageInput(e.target.value)}
                    placeholder={hasSessionKey ? "Type an encrypted message..." : "Establish secure session first..."}
                    disabled={loading || !hasSessionKey}
                  />
                  <button type="submit" disabled={loading || !messageInput.trim()}>
                    {loading ? 'Sending...' : 'Send'}
                  </button>
                </div>
              </form>
            </>
          ) : (
            <div className="no-contact-selected">Select a contact to start chatting</div>
          )}
        </div>
      </div>
    </div>
  );
}

export default ChatPage;

