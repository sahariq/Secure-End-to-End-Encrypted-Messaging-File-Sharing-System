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
      setKeyExchangeStatus(''); // Clear status when switching contacts
      setError('');
    }

    // Cleanup polling interval on unmount
    return () => {
      if (window.keyExchangePollInterval) {
        clearInterval(window.keyExchangePollInterval);
      }
    };
  }, [selectedContact, currentUserId]);

  // Purge stale data on mount
  useEffect(() => {
    const purgeStaleData = async () => {
      try {
        await apiClient.delete('/keys/exchange/purge');
        console.log('✓ Stale key exchange data purged from server');
      } catch (err) {
        console.error('Failed to purge stale data:', err);
      }
    };

    if (currentUserId) {
      purgeStaleData();
    }
  }, [currentUserId]);

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
      setKeyExchangeStatus(''); // Clear status after sending message
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
   * Full Signed ECDH Protocol Implementation:
   * 1. Check if peer has already initiated (and data is fresh)
   * 2. If yes: Respond (Phase 3)
   * 3. If no: Initiate (Phase 2) and wait for response (Phase 4)
   * 4. Handle collisions (both initiated) via User ID tie-breaker
   */
  const handleStartKeyExchange = async () => {
    if (!selectedContact) {
      setError('Please select a contact first');
      return;
    }

    try {
      setKeyExchangeStatus('Checking for existing exchange...');
      setError('');
      setLoading(true);

      console.log('\n🚀 Starting Signed ECDH Key Exchange with:', selectedContact.username);
      console.log('═══════════════════════════════════════════════════════\n');

      // Check if peer has already initiated key exchange
      let peerExchangeData = null;
      try {
        const response = await apiClient.get(`/keys/exchange/${selectedContact._id}`);
        const data = response.data;

        // Check for stale data (older than 2 minutes)
        if (data && data.timestamp) {
          const exchangeTime = new Date(data.timestamp).getTime();
          const now = Date.now();
          const twoMinutes = 2 * 60 * 1000;

          if (now - exchangeTime > twoMinutes) {
            console.log('⚠️ Found stale exchange data from peer. Ignoring.');
            peerExchangeData = null;
          } else {
            peerExchangeData = data;
          }
        }
      } catch (err) {
        if (err.response?.status !== 404) {
          throw err;
        }
        // 404 means peer hasn't initiated yet
      }

      if (peerExchangeData && !peerExchangeData.keyConfirmation) {
        // CASE A: Peer already initiated (and it's not a completed response). We act as RESPONDER.
        console.log('✓ Peer has already initiated. Acting as RESPONDER.');
        setKeyExchangeStatus('Responding to key exchange...');

        const {
          sessionKey,
          ephemeralPublicKeyJwk,
          signature,
          keyConfirmation
        } = await respondToKeyExchange(
          selectedContact._id,
          peerExchangeData.ephemeralPublicKeyJwk,
          peerExchangeData.signature
        );

        // Publish our response
        console.log('📤 Publishing response to server...');
        await apiClient.post('/keys/exchange/initiate', {
          targetUserId: selectedContact._id,
          ephemeralPublicKeyJwk,
          signature,
          keyConfirmation
        });

        setKeyExchangeStatus('✓ Key exchange completed (Responder)!');
        setHasSessionKey(true);
        setLoading(false);
        console.log('✓ Secure session established as Responder');

        // Auto-hide success message
        setTimeout(() => setKeyExchangeStatus(''), 5000);

      } else {
        // CASE B: Peer hasn't initiated (or data is stale/completed). We act as INITIATOR.
        console.log('✓ No active initiation found. Acting as INITIATOR.');
        setKeyExchangeStatus('Initiating key exchange...');

        const {
          ephemeralKeyPair,
          ephemeralPublicKeyJwk,
          signature,
          peerIdentityPublicKey
        } = await initiateKeyExchange(selectedContact._id);

        // Publish our initiation
        console.log('📤 Publishing initiation to server...');
        await apiClient.post('/keys/exchange/initiate', {
          targetUserId: selectedContact._id,
          ephemeralPublicKeyJwk,
          signature
        });

        setKeyExchangeStatus('⏳ Waiting for peer to respond...');
        console.log('⏳ Waiting for peer to respond...');
        console.log('💡 Ask the other user to click "Start Key Exchange"');

        // Poll for response
        let attempts = 0;
        const maxAttempts = 30; // 60 seconds

        const pollInterval = setInterval(async () => {
          attempts++;
          try {
            const response = await apiClient.get(`/keys/exchange/${selectedContact._id}`);
            const responseData = response.data;

            if (responseData) {
              // Check for stale data (older than 2 minutes)
              if (responseData.timestamp) {
                const exchangeTime = new Date(responseData.timestamp).getTime();
                const now = Date.now();
                const twoMinutes = 2 * 60 * 1000;

                if (now - exchangeTime > twoMinutes) {
                  console.log('⚠️ Polling found stale data. Ignoring and waiting for fresh update...');
                  return; // Skip this iteration
                }
              }

              // Check if this is a response (contains keyConfirmation)
              if (responseData.keyConfirmation) {
                clearInterval(pollInterval);
                console.log('✓ Received response from peer. Completing exchange...');
                setKeyExchangeStatus('Completing key exchange...');

                await completeKeyExchange(
                  selectedContact._id,
                  ephemeralKeyPair,
                  responseData.ephemeralPublicKeyJwk,
                  responseData.signature,
                  responseData.keyConfirmation,
                  peerIdentityPublicKey
                );

                setKeyExchangeStatus('✓ Key exchange completed (Initiator)!');
                setHasSessionKey(true);
                setLoading(false);
                console.log('✓ Secure session established as Initiator');

                // Auto-hide success message
                setTimeout(() => setKeyExchangeStatus(''), 5000);
              }
              // COLLISION HANDLING: Both initiated
              else if (!responseData.keyConfirmation) {
                console.log('⚠️ Collision detected: Peer also initiated.');

                // Tie-breaker: Compare User IDs (lexicographical)
                // If MyID < PeerID: I become RESPONDER
                // If MyID > PeerID: I stay INITIATOR (wait for them to respond)

                if (currentUserId < selectedContact._id) {
                  console.log('🔄 Tie-breaker: Switching to RESPONDER role.');
                  clearInterval(pollInterval);
                  setKeyExchangeStatus('Switching to Responder...');

                  const {
                    sessionKey,
                    ephemeralPublicKeyJwk: myRespPubKey,
                    signature: myRespSig,
                    keyConfirmation
                  } = await respondToKeyExchange(
                    selectedContact._id,
                    responseData.ephemeralPublicKeyJwk,
                    responseData.signature
                  );

                  // Publish our response (overwriting our previous initiation)
                  console.log('📤 Publishing response to server...');
                  await apiClient.post('/keys/exchange/initiate', {
                    targetUserId: selectedContact._id,
                    ephemeralPublicKeyJwk: myRespPubKey,
                    signature: myRespSig,
                    keyConfirmation
                  });

                  setKeyExchangeStatus('✓ Key exchange completed (Switched to Responder)!');
                  setHasSessionKey(true);
                  setLoading(false);
                  console.log('✓ Secure session established (Switched to Responder)');

                  // Auto-hide success message
                  setTimeout(() => setKeyExchangeStatus(''), 5000);
                } else {
                  console.log('⏳ Tie-breaker: Staying INITIATOR. Waiting for peer to switch...');
                  // Do nothing, keep polling. Peer should switch and send response.
                }
              }
            }
          } catch (err) {
            if (err.response?.status === 404) {
              if (attempts >= maxAttempts) {
                clearInterval(pollInterval);
                setKeyExchangeStatus('⏱️ Timed out waiting for peer.');
                setError('Peer did not respond in time.');
                setLoading(false);
              }
            } else {
              clearInterval(pollInterval);
              console.error('Polling error:', err);
            }
          }
        }, 2000);

        // Cleanup
        window.keyExchangePollInterval = pollInterval;
      }

    } catch (err) {
      console.error('❌ Key exchange failed:', err);
      setError(`Key exchange failed: ${err.message}`);
      setKeyExchangeStatus('');
      setLoading(false);
    } finally {
      if (!window.keyExchangePollInterval && !loading) {
        setLoading(false);
      }
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
