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

// New Components
import AppShell from '../components/AppShell';
import Sidebar from '../components/Sidebar';
import ChatPanel from '../components/ChatPanel';

function ChatPage() {
  const [messages, setMessages] = useState([]);
  const [messageInput, setMessageInput] = useState('');
  const [selectedContact, setSelectedContact] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [keyExchangeStatus, setKeyExchangeStatus] = useState('');
  const [hasSessionKey, setHasSessionKey] = useState(false);
  const [contacts, setContacts] = useState([]);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const navigate = useNavigate();
  const fileInputRef = useRef(null);

  const currentUserId = localStorage.getItem('userId');
  const currentUsername = localStorage.getItem('username');

  // --- Effects ---

  useEffect(() => {
    if (!localStorage.getItem('authToken')) {
      navigate('/login');
      return;
    }
    loadContacts();
  }, [navigate]);

  useEffect(() => {
    let messagePollInterval;

    if (selectedContact && currentUserId) {
      loadMessages();
      checkSessionKeyStatus();
      setKeyExchangeStatus('');
      setError('');

      messagePollInterval = setInterval(() => {
        loadMessages();
      }, 2000);
    }

    return () => {
      if (messagePollInterval) clearInterval(messagePollInterval);
      if (window.keyExchangePollInterval) clearInterval(window.keyExchangePollInterval);
    };
  }, [selectedContact, currentUserId]);

  useEffect(() => {
    const purgeStaleData = async () => {
      try {
        await apiClient.delete('/keys/exchange/purge');
      } catch (err) {
        console.error('Failed to purge stale data:', err);
      }
    };
    if (currentUserId) purgeStaleData();
  }, [currentUserId]);

  // --- Data Loading ---

  const loadContacts = async () => {
    try {
      const response = await apiClient.get('/auth/users');
      setContacts(response.data);
      if (response.data.length > 0 && !selectedContact) {
        setSelectedContact(response.data[0]);
      }
    } catch (err) {
      console.error('Error loading contacts:', err);
      setError('Failed to load contacts');
    }
  };

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
      const userIds = [currentUserId, selectedContact._id].sort();
      const conversationId = userIds.join('_');
      const response = await apiClient.get(`/messages/${conversationId}`);
      const encryptedMessages = response.data.messages || [];

      const processedMessages = await Promise.all(
        encryptedMessages.map(async (msg) => {
          const processed = await processIncomingMessage(msg);
          if (processed.decrypted) {
            try {
              const parsed = JSON.parse(processed.plaintext);
              if (parsed && parsed.type === 'file') {
                return { ...processed, isFile: true, fileData: parsed };
              }
            } catch (e) { /* Not JSON */ }
          }
          return processed;
        })
      );

      setMessages(processedMessages);
    } catch (err) {
      console.error('Error loading messages:', err);
    }
  };

  // --- Handlers ---

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('userId');
    localStorage.removeItem('username');
    navigate('/login');
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
      await sendSecureMessage(selectedContact._id, messageInput);
      setMessageInput('');
      setKeyExchangeStatus('');
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

      const fileBuffer = await file.arrayBuffer();
      const { encryptedBlob, ivBase64: fileIv } = await encryptFile(sessionKey, fileBuffer);

      const formData = new FormData();
      formData.append('file', encryptedBlob, 'encrypted_blob');
      formData.append('receiverId', selectedContact._id);

      const uploadRes = await apiClient.post('/files/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      const { fileId } = uploadRes.data;
      const metadata = {
        type: 'file',
        fileId,
        filename: file.name,
        filesize: file.size,
        fileIv
      };

      await sendSecureMessage(selectedContact._id, JSON.stringify(metadata));
      setKeyExchangeStatus('✓ File sent successfully');
      setTimeout(() => setKeyExchangeStatus(''), 3000);

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
      setKeyExchangeStatus(`Downloading ${fileData.filename}...`);
      const response = await apiClient.get(`/files/${fileData.fileId}`, {
        responseType: 'arraybuffer'
      });

      const encryptedBuffer = response.data;
      const sessionKey = await getSessionKey(selectedContact._id);
      if (!sessionKey) throw new Error('Session key not found');

      const plaintextBuffer = await decryptFile(sessionKey, encryptedBuffer, fileData.fileIv);

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

  const handleUploadPublicKey = async () => {
    try {
      setKeyExchangeStatus('Uploading public key...');
      setError('');
      const signingKeyPair = await loadSigningKeyPair();
      if (!signingKeyPair) throw new Error('No signing key pair found. Please log in again.');

      const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', signingKeyPair.publicKey);
      await uploadMyPublicKey(currentUserId, JSON.stringify(publicKeyJwk));

      setKeyExchangeStatus('✓ Public key uploaded successfully!');
      setTimeout(() => setKeyExchangeStatus(''), 3000);
    } catch (err) {
      console.error('Error uploading public key:', err);
      setError(`Failed to upload public key: ${err.message}`);
      setKeyExchangeStatus('');
    }
  };

  const handleStartKeyExchange = async () => {
    if (!selectedContact) {
      setError('Please select a contact first');
      return;
    }

    try {
      setKeyExchangeStatus('Checking for existing exchange...');
      setError('');
      setLoading(true);

      let peerExchangeData = null;
      try {
        const response = await apiClient.get(`/keys/exchange/${selectedContact._id}`);
        const data = response.data;
        if (data && data.timestamp) {
          const exchangeTime = new Date(data.timestamp).getTime();
          if (Date.now() - exchangeTime <= 5 * 60 * 1000) {
            peerExchangeData = data;
          }
        }
      } catch (err) {
        if (err.response?.status !== 404) throw err;
      }

      if (peerExchangeData && !peerExchangeData.keyConfirmation) {
        // RESPONDER
        setKeyExchangeStatus('Responding to key exchange...');
        const { ephemeralPublicKeyJwk, signature, keyConfirmation } = await respondToKeyExchange(
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

        await clearConversation();
        setKeyExchangeStatus('✓ Key exchange completed (Responder)!');
        setHasSessionKey(true);
        setLoading(false);
        setTimeout(() => setKeyExchangeStatus(''), 5000);

      } else {
        // INITIATOR
        setKeyExchangeStatus('Initiating key exchange...');
        const { ephemeralKeyPair, ephemeralPublicKeyJwk, signature, peerIdentityPublicKey } = await initiateKeyExchange(selectedContact._id);

        await apiClient.post('/keys/exchange/initiate', {
          targetUserId: selectedContact._id,
          ephemeralPublicKeyJwk,
          signature
        });

        setKeyExchangeStatus('⏳ Waiting for peer to respond...');
        pollForResponse(ephemeralKeyPair, peerIdentityPublicKey);
      }
    } catch (err) {
      console.error('❌ Key exchange failed:', err);
      setError(`Key exchange failed: ${err.message}`);
      setKeyExchangeStatus('');
      setLoading(false);
    }
  };

  const pollForResponse = (ephemeralKeyPair, peerIdentityPublicKey) => {
    let attempts = 0;
    const maxAttempts = 150;
    const pollInterval = setInterval(async () => {
      attempts++;
      try {
        const response = await apiClient.get(`/keys/exchange/${selectedContact._id}`);
        const responseData = response.data;

        if (responseData) {
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
            await clearConversation();
            setKeyExchangeStatus('✓ Key exchange completed (Initiator)!');
            setHasSessionKey(true);
            setLoading(false);
            setTimeout(() => setKeyExchangeStatus(''), 5000);
          } else if (!responseData.keyConfirmation && currentUserId < selectedContact._id) {
            // Collision: Switch to Responder
            clearInterval(pollInterval);
            setKeyExchangeStatus('Switching to Responder...');
            const { ephemeralPublicKeyJwk, signature, keyConfirmation } = await respondToKeyExchange(
              selectedContact._id,
              responseData.ephemeralPublicKeyJwk,
              responseData.signature
            );
            await apiClient.post('/keys/exchange/initiate', {
              targetUserId: selectedContact._id,
              ephemeralPublicKeyJwk,
              signature,
              keyConfirmation
            });
            await clearConversation();
            setKeyExchangeStatus('✓ Key exchange completed (Switched)!');
            setHasSessionKey(true);
            setLoading(false);
            setTimeout(() => setKeyExchangeStatus(''), 5000);
          }
        }
      } catch (err) {
        if (err.response?.status === 404 && attempts >= maxAttempts) {
          clearInterval(pollInterval);
          setKeyExchangeStatus('⏱️ Timed out waiting for peer.');
          setError('Peer did not respond in time.');
          setLoading(false);
        }
      }
    }, 2000);
    window.keyExchangePollInterval = pollInterval;
  };

  const clearConversation = async () => {
    const userIds = [currentUserId, selectedContact._id].sort();
    const conversationId = userIds.join('_');
    await apiClient.delete(`/messages/${conversationId}`);
    setMessages([]);
  };

  return (
    <AppShell
      user={{ username: currentUsername }}
      onLogout={handleLogout}
      onToggleSidebar={() => setIsSidebarOpen(!isSidebarOpen)}
      isSidebarOpen={isSidebarOpen}
    >
      <Sidebar
        contacts={contacts}
        selectedContact={selectedContact}
        onSelectContact={(contact) => {
          setSelectedContact(contact);
          setIsSidebarOpen(false); // Close sidebar on selection (mobile)
        }}
        isOpen={isSidebarOpen}
      />
      <ChatPanel
        selectedContact={selectedContact}
        messages={messages}
        currentUserId={currentUserId}
        messageInput={messageInput}
        setMessageInput={setMessageInput}
        onSendMessage={handleSendMessage}
        onFileSelect={handleFileSelect}
        onDownloadFile={handleDownloadFile}
        loading={loading}
        error={error}
        hasSessionKey={hasSessionKey}
        keyExchangeStatus={keyExchangeStatus}
        onUploadPublicKey={handleUploadPublicKey}
        onStartKeyExchange={handleStartKeyExchange}
        fileInputRef={fileInputRef}
      />
    </AppShell>
  );
}

export default ChatPage;
