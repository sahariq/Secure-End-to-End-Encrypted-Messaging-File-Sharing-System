import { useState, useEffect, useRef } from 'react';
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
import { loadSigningKeyPair } from '../crypto/keyManager';
import { encryptFile, decryptFile } from '../crypto/encryption';
import { sendSecureMessage, processIncomingMessage } from '../crypto/secureMessaging';
import './ChatPage.css';

function ChatPage() {
  const [messages, setMessages] = useState([]);
  const [messageInput, setMessageInput] = useState('');
  const [selectedContact, setSelectedContact] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [keyExchangeStatus, setKeyExchangeStatus] = useState('');
  const [hasSessionKey, setHasSessionKey] = useState(false);
  const [contacts, setContacts] = useState([]); // Fetch real users from backend
  const navigate = useNavigate();
  const fileInputRef = useRef(null);

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
    let messagePollInterval;

    if (selectedContact && currentUserId) {
      loadMessages();
      checkSessionKeyStatus();
      setKeyExchangeStatus(''); // Clear status when switching contacts
      setError('');

      // Poll for new messages every 2 seconds
      messagePollInterval = setInterval(() => {
        loadMessages();
      }, 2000);
    }

    // Cleanup polling intervals on unmount or contact change
    return () => {
      if (messagePollInterval) {
        clearInterval(messagePollInterval);
      }
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

      const processedMessages = await Promise.all(
        encryptedMessages.map(async (msg) => {
          // Process message (Verify Signature + Decrypt)
          const processed = await processIncomingMessage(msg);

          if (processed.decrypted) {
            // Check if message is a file metadata JSON
            try {
              const parsed = JSON.parse(processed.plaintext);
              if (parsed && parsed.type === 'file') {
                return { ...processed, isFile: true, fileData: parsed };
              }
            } catch (e) {
              // Not JSON, treat as regular text
            }
          }
          return processed;
        })
      );

      setMessages(processedMessages);
    } catch (err) {
      console.error('Error loading messages:', err);
      // Don't show error to user on every poll failure
    }
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!messageInput.trim() || !selectedContact || !currentUserId) return;

    if (!hasSessionKey) {
      setError('⚠️ No secure session established. Please run key exchange first.');
      return;
    }

    setLoading(true);
    setError('');

    try {
      console.log('\n🔐 Sending secure message...');

      // Send secure message (Encrypt + Sign + Replay Protection)
      await sendSecureMessage(selectedContact._id, messageInput);

      console.log('✓ Secure message sent to server');

      setMessageInput('');
      setKeyExchangeStatus(''); // Clear status after sending message
      await loadMessages();
    } catch (err) {
      console.error('❌ Failed to send secure message:', err);
      setError(err.response?.data?.message || err.message || 'Failed to send message');
    } finally {
      setLoading(false);
    }
  };

  const handleFileSelect = async (e) => {
    const file = e.target.files[0];
    if (!file || !selectedContact || !currentUserId) return;

    if (!hasSessionKey) {
      setError('⚠️ No secure session established. Please run key exchange first.');
      return;
    }

    setLoading(true);
    setError('');
    setKeyExchangeStatus('Encrypting and uploading file...');

    try {
      const sessionKey = await getSessionKey(selectedContact._id);
      if (!sessionKey) throw new Error('Session key not found');

      console.log(`\n📂 Processing file: ${file.name} (${file.size} bytes)`);

      // 1. Read file as ArrayBuffer
      const fileBuffer = await file.arrayBuffer();

      // 2. Encrypt file client-side
      console.log('🔐 Encrypting file...');
      const { encryptedBlob, ivBase64: fileIv } = await encryptFile(sessionKey, fileBuffer);
      console.log(`✓ File encrypted. Blob size: ${encryptedBlob.size}`);

      // 3. Upload encrypted blob
      console.log('📤 Uploading encrypted blob...');
      const formData = new FormData();
      formData.append('file', encryptedBlob, 'encrypted_blob');
      formData.append('receiverId', selectedContact._id);

      const uploadRes = await apiClient.post('/files/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      const { fileId } = uploadRes.data;
      console.log(`✓ Upload complete. File ID: ${fileId}`);

      // 4. Send metadata message SECURELY
      const metadata = {
        type: 'file',
        fileId,
        filename: file.name,
        filesize: file.size,
        fileIv
      };

      console.log('📨 Sending file metadata message...');
      await sendSecureMessage(selectedContact._id, JSON.stringify(metadata));

      console.log('✓ File sent successfully');
      setKeyExchangeStatus('✓ File sent successfully');
      setTimeout(() => setKeyExchangeStatus(''), 3000);

      // Reset input
      if (fileInputRef.current) fileInputRef.current.value = '';
      await loadMessages();

    } catch (err) {
      console.error('❌ File upload failed:', err);
      setError(`File upload failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadFile = async (fileData) => {
    try {
      console.log(`\n⬇️ Downloading file: ${fileData.filename}`);
      setKeyExchangeStatus(`Downloading ${fileData.filename}...`);

      // 1. Fetch encrypted blob
      const response = await apiClient.get(`/files/${fileData.fileId}`, {
        responseType: 'arraybuffer'
      });

      const encryptedBuffer = response.data;
      console.log(`✓ Downloaded ${encryptedBuffer.byteLength} bytes`);

      // 2. Decrypt file
      const sessionKey = await getSessionKey(selectedContact._id);
      if (!sessionKey) throw new Error('Session key not found');

      console.log('🔓 Decrypting file...');
      const plaintextBuffer = await decryptFile(sessionKey, encryptedBuffer, fileData.fileIv);
      console.log('✓ File decrypted successfully');

      // 3. Trigger download
      const blob = new Blob([plaintextBuffer]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileData.filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setKeyExchangeStatus('✓ Download complete');
      setTimeout(() => setKeyExchangeStatus(''), 3000);

    } catch (err) {
      console.error('❌ Download failed:', err);
      setError(`Download failed: ${err.message}`);
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
   */
  const handleUploadPublicKey = async () => {
    try {
      setKeyExchangeStatus('Uploading public key...');
      setError('');

      const signingKeyPair = await loadSigningKeyPair();
      if (!signingKeyPair) {
        throw new Error('No signing key pair found. Please log in again.');
      }

      const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', signingKeyPair.publicKey);
      const publicKeyJwkString = JSON.stringify(publicKeyJwk);

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

      // Check if peer has already initiated key exchange
      let peerExchangeData = null;
      try {
        const response = await apiClient.get(`/keys/exchange/${selectedContact._id}`);
        const data = response.data;

        // Check for stale data (older than 2 minutes)
        if (data && data.timestamp) {
          const exchangeTime = new Date(data.timestamp).getTime();
          const now = Date.now();
          const fiveMinutes = 5 * 60 * 1000;

          if (now - exchangeTime > fiveMinutes) {
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
      }

      if (peerExchangeData && !peerExchangeData.keyConfirmation) {
        // CASE A: Peer already initiated. Act as RESPONDER.
        console.log('✓ Peer has already initiated. Acting as RESPONDER.');
        setKeyExchangeStatus('Responding to key exchange...');

        const {
          ephemeralPublicKeyJwk,
          signature,
          keyConfirmation
        } = await respondToKeyExchange(
          selectedContact._id,
          peerExchangeData.ephemeralPublicKeyJwk,
          peerExchangeData.signature
        );

        await apiClient.post('/keys/exchange/initiate', {
          targetUserId: selectedContact._id,
          ephemeralPublicKeyJwk,
          signature,
          keyConfirmation
        });

        // Clear conversation history
        const userIds = [currentUserId, selectedContact._id].sort();
        const conversationId = userIds.join('_');
        await apiClient.delete(`/messages/${conversationId}`);
        setMessages([]);

        setKeyExchangeStatus('✓ Key exchange completed (Responder)!');
        setHasSessionKey(true);
        setLoading(false);
        setTimeout(() => setKeyExchangeStatus(''), 5000);

      } else {
        // CASE B: Act as INITIATOR.
        console.log('✓ No active initiation found. Acting as INITIATOR.');
        setKeyExchangeStatus('Initiating key exchange...');

        const {
          ephemeralKeyPair,
          ephemeralPublicKeyJwk,
          signature,
          peerIdentityPublicKey
        } = await initiateKeyExchange(selectedContact._id);

        await apiClient.post('/keys/exchange/initiate', {
          targetUserId: selectedContact._id,
          ephemeralPublicKeyJwk,
          signature
        });

        setKeyExchangeStatus('⏳ Waiting for peer to respond...');
        console.log('⏳ Waiting for peer to respond...');

        // Poll for response
        let attempts = 0;
        const maxAttempts = 150; // 5 minutes (150 * 2s)

        const pollInterval = setInterval(async () => {
          attempts++;
          try {
            const response = await apiClient.get(`/keys/exchange/${selectedContact._id}`);
            const responseData = response.data;

            if (responseData) {
              if (responseData.timestamp) {
                const exchangeTime = new Date(responseData.timestamp).getTime();
                const now = Date.now();
                if (now - exchangeTime > 5 * 60 * 1000) return; // 5 minutes
              }

              if (responseData.keyConfirmation) {
                clearInterval(pollInterval);
                setKeyExchangeStatus('Completing key exchange...');

                await completeKeyExchange(
                  selectedContact._id,
                  ephemeralKeyPair,
                  responseData.ephemeralPublicKeyJwk,
                  responseData.signature,
                  responseData.keyConfirmation,
                  peerIdentityPublicKey
                );

                const userIds = [currentUserId, selectedContact._id].sort();
                const conversationId = userIds.join('_');
                await apiClient.delete(`/messages/${conversationId}`);
                setMessages([]);

                setKeyExchangeStatus('✓ Key exchange completed (Initiator)!');
                setHasSessionKey(true);
                setLoading(false);
                setTimeout(() => setKeyExchangeStatus(''), 5000);
              }
              else if (!responseData.keyConfirmation) {
                // Collision handling
                if (currentUserId < selectedContact._id) {
                  console.log('🔄 Tie-breaker: Switching to RESPONDER role.');
                  clearInterval(pollInterval);
                  setKeyExchangeStatus('Switching to Responder...');

                  const {
                    ephemeralPublicKeyJwk: myRespPubKey,
                    signature: myRespSig,
                    keyConfirmation
                  } = await respondToKeyExchange(
                    selectedContact._id,
                    responseData.ephemeralPublicKeyJwk,
                    responseData.signature
                  );

                  await apiClient.post('/keys/exchange/initiate', {
                    targetUserId: selectedContact._id,
                    ephemeralPublicKeyJwk: myRespPubKey,
                    signature: myRespSig,
                    keyConfirmation
                  });

                  const userIds = [currentUserId, selectedContact._id].sort();
                  const conversationId = userIds.join('_');
                  await apiClient.delete(`/messages/${conversationId}`);
                  setMessages([]);

                  setKeyExchangeStatus('✓ Key exchange completed (Switched to Responder)!');
                  setHasSessionKey(true);
                  setLoading(false);
                  setTimeout(() => setKeyExchangeStatus(''), 5000);
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
            }
          }
        }, 2000);

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
                          msg.isFile ? (
                            <div className="file-attachment">
                              <div className="file-info">
                                <span className="file-icon">📄</span>
                                <span className="file-name">{msg.fileData.filename}</span>
                                <span className="file-size">({Math.round(msg.fileData.filesize / 1024)} KB)</span>
                              </div>
                              <button
                                onClick={() => handleDownloadFile(msg.fileData)}
                                className="download-btn"
                              >
                                ⬇️ Download & Decrypt
                              </button>
                            </div>
                          ) : (
                            <>{msg.plaintext}</>
                          )
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
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileSelect}
                    style={{ display: 'none' }}
                  />
                  <button
                    type="button"
                    className="attach-btn"
                    onClick={() => fileInputRef.current.click()}
                    disabled={loading || !hasSessionKey}
                    title="Send encrypted file"
                  >
                    📎
                  </button>
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
