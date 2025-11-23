import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import apiClient from '../utils/api';
import './ChatPage.css';

function ChatPage() {
  const [messages, setMessages] = useState([]);
  const [messageInput, setMessageInput] = useState('');
  const [selectedContact, setSelectedContact] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  // Dummy contacts for now
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
    }
  }, [selectedContact, currentUserId]);

  const loadMessages = async () => {
    if (!selectedContact || !currentUserId) return;

    try {
      // Create conversation ID (sorted user IDs)
      const userIds = [currentUserId, selectedContact.id].sort();
      const conversationId = userIds.join('_');

      // API request includes JWT token via axios interceptor
      const response = await apiClient.get(`/messages/${conversationId}`);
      setMessages(response.data.messages || []);
    } catch (err) {
      console.error('Error loading messages:', err);
      setError('Failed to load messages');
    }
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!messageInput.trim() || !selectedContact || !currentUserId) return;

    setLoading(true);
    setError('');

    try {
      // Generate dummy IV (placeholder)
      const dummyIV = `iv_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      // API request includes JWT token via axios interceptor
      // senderId is automatically set from JWT token on backend
      await apiClient.post('/messages', {
        receiverId: selectedContact.id,
        ciphertext: 'DUMMY_CIPHERTEXT', // Placeholder - will be real encrypted data in STEP 3
        iv: dummyIV,
        timestamp: new Date().toISOString()
      });

      setMessageInput('');
      // Reload messages
      await loadMessages();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to send message');
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
              </div>
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
                        <strong>Ciphertext:</strong> {msg.ciphertext}
                        <br />
                        <strong>IV:</strong> {msg.iv}
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
                    placeholder="Type a message (will be encrypted later)..."
                    disabled={loading}
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

