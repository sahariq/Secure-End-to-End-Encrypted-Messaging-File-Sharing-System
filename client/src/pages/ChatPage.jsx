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
import { getSessionKey } from '../crypto/sessionStore';
import { loadKeyPair, exportPublicKeyAsJWKString } from '../crypto/keyManager';
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
  const navigate = useNavigate();

  // TODO: Replace with real user list from backend
  // For now, using dummy contacts for encryption demo
  // In production: Fetch via GET /api/users to get actual registered users
  // This ensures conversation IDs and session keys align with real user IDs
  const contacts = [
    { id: '1', username: 'Alice' },
    { id: '2', username: 'Bob' },
    { id: '3', username: 'Charlie' }
  ];

  const currentUserId = localStorage.getItem('userId');
  const currentUsername = localStorage.getItem('username');

  useEffect(() => {
    // Check if user is logged in
    if (!localStorage.getItem('authToken')) {
      navigate('/login');
      return;
    }

    // Set first contact as selected by default
    if (contacts.length > 0 && !selectedContact) {
      setSelectedContact(contacts[0]);
    }
  }, [navigate]);

  useEffect(() => {
    if (selectedContact && currentUserId) {
      loadMessages();
      checkSessionKeyStatus();
    }
  }, [selectedContact, currentUserId]);

  const checkSessionKeyStatus = async () => {
    if (!selectedContact) return;
    
    try {
      const exists = await hasSessionKeyWithPeer(selectedContact.id);
      setHasSessionKey(exists);
      
      if (exists) {
        const sessionKey = await getSessionKey(selectedContact.id);
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
      const userIds = [currentUserId, selectedContact.id].sort();
      const conversationId = userIds.join('_');

      // API request includes JWT token via axios interceptor
      const response = await apiClient.get(`/messages/${conversationId}`);
      const encryptedMessages = response.data.messages || [];

      // Decrypt messages if session key exists
      const sessionKey = await getSessionKey(selectedContact.id);
      
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
      const sessionKey = await getSessionKey(selectedContact.id);
      
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
        receiverId: selectedContact.id,
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

      // Load key pair from IndexedDB
      const keyPair = await loadKeyPair();
      if (!keyPair) {
        throw new Error('No key pair found. Please log in again.');
      }

      // Export public key as JWK string
      const publicKeyJwk = await exportPublicKeyAsJWKString();

      // Upload to server
      await uploadMyPublicKey(currentUserId, publicKeyJwk);

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

      // PHASE 1: Initiate key exchange (Alice's role)
      const initiationData = await initiateKeyExchange(selectedContact.id);
      
      setKeyExchangeStatus('Key exchange initiated. Simulating peer response...');
      
      // Store initiation data for later completion
      setKeyExchangeData(initiationData);

      // ─────────────────────────────────────────────────────────────────
      // SIMULATION: In real implementation, you would:
      // 1. Send initiationData to peer via encrypted message/server
      // 2. Peer calls respondToKeyExchange() and sends back their data
      // 3. You call completeKeyExchange() with peer's response
      // ─────────────────────────────────────────────────────────────────

      console.log('\n[SIMULATION] Simulating peer response...');
      console.log('In production, peer would receive your ephemeral public key');
      console.log('and respond with their own signed ephemeral public key.\n');

      // PHASE 2: Simulate peer response (Bob's role)
      // In reality, selectedContact would do this on their device
      const peerResponseData = await respondToKeyExchange(
        currentUserId, // Peer sees us as the peer
        initiationData.ephemeralPublicKeyJwk,
        initiationData.signature
      );

      setKeyExchangeStatus('Received peer response. Completing exchange...');

      // PHASE 3: Complete key exchange (Alice completes)
      const sessionKey = await completeKeyExchange(
        selectedContact.id,
        initiationData.ephemeralKeyPair,
        peerResponseData.ephemeralPublicKeyJwk,
        peerResponseData.signature,
        initiationData.peerIdentityPublicKey
      );

      // Update UI
      setHasSessionKey(true);
      setKeyExchangeStatus('✓ Secure session established!');
      
      console.log('\n═══════════════════════════════════════════════════════');
      console.log('✅ KEY EXCHANGE COMPLETE');
      console.log('═══════════════════════════════════════════════════════');
      console.log('Session Key Object:', sessionKey);
      console.log('Session key type:', sessionKey.type);
      console.log('Session key algorithm:', sessionKey.algorithm.name);
      console.log('Session key length:', sessionKey.algorithm.length, 'bits');
      console.log('Session key usages:', sessionKey.usages);
      console.log('\n✓ Ready for end-to-end encrypted messaging!');
      console.log('═══════════════════════════════════════════════════════\n');

      setTimeout(() => setKeyExchangeStatus(''), 5000);
    } catch (err) {
      console.error('❌ Key exchange failed:', err);
      setError(`Key exchange failed: ${err.message}`);
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
                key={contact.id}
                className={selectedContact?.id === contact.id ? 'active' : ''}
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

