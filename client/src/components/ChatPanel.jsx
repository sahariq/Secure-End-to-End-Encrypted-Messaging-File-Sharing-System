import React from 'react';
import MessageList from './MessageList';

const ChatPanel = ({
    selectedContact,
    messages,
    currentUserId,
    messageInput,
    setMessageInput,
    onSendMessage,
    onFileSelect,
    onDownloadFile,
    loading,
    error,
    hasSessionKey,
    keyExchangeStatus,
    onUploadPublicKey,
    onStartKeyExchange,
    fileInputRef
}) => {
    if (!selectedContact) {
        return (
            <section className="chat" style={{ alignItems: 'center', justifyContent: 'center' }}>
                <div style={{ textAlign: 'center', color: 'var(--color-text-secondary)' }}>
                    <div style={{
                        width: '64px', height: '64px',
                        background: 'var(--color-bg)',
                        borderRadius: '50%',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        margin: '0 auto 16px',
                        fontSize: '24px',
                        color: 'var(--color-primary)'
                    }}>
                        👋
                    </div>
                    <h3 style={{ color: 'var(--color-text-primary)', marginBottom: '8px', fontSize: '18px' }}>Welcome</h3>
                    <p style={{ fontSize: '14px' }}>Select a contact to start messaging.</p>
                </div>
            </section>
        );
    }

    return (
        <section className="chat">
            {/* Header */}
            <div className="chat__header">
                <div className="chat__title">
                    {selectedContact.username}
                </div>
                <div className="chat__actions">
                    {hasSessionKey ? (
                        <span className="badge badge--secure">
                            Secure
                        </span>
                    ) : (
                        <span className="badge badge--insecure">
                            Unsecured
                        </span>
                    )}
                </div>
            </div>

            {/* Key Exchange Actions Bar */}
            <div style={{ padding: '10px 24px', borderBottom: '1px solid var(--color-border)', backgroundColor: 'rgba(255,255,255,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <button
                        className="btn"
                        onClick={onUploadPublicKey}
                    >
                        Upload ID
                    </button>
                    <button
                        className="btn btn--secondary"
                        onClick={onStartKeyExchange}
                        disabled={loading}
                    >
                        Exchange Keys
                    </button>
                </div>

                {(keyExchangeStatus || error) && (
                    <div style={{ fontSize: '12px', color: error ? 'var(--color-error)' : 'var(--color-secondary)', fontWeight: 600 }}>
                        {error || keyExchangeStatus}
                    </div>
                )}
            </div>

            {/* Messages Area */}
            <MessageList
                messages={messages}
                currentUserId={currentUserId}
                onDownloadFile={onDownloadFile}
            />

            {/* Footer / Input Area */}
            <div className="chat__footer">
                <form onSubmit={onSendMessage} className="chat__input-group">
                    <input
                        type="file"
                        ref={fileInputRef}
                        onChange={onFileSelect}
                        style={{ display: 'none' }}
                    />
                    <button
                        type="button"
                        className="chat__attach-btn"
                        onClick={() => fileInputRef.current?.click()}
                        disabled={loading || !hasSessionKey}
                        title="Attach file"
                    >
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"></path>
                        </svg>
                    </button>

                    <input
                        type="text"
                        className="chat__input"
                        placeholder={hasSessionKey ? "Type a message..." : "Establish secure session first..."}
                        value={messageInput}
                        onChange={(e) => setMessageInput(e.target.value)}
                        disabled={loading || !hasSessionKey}
                    />

                    <button
                        type="submit"
                        className="chat__send-btn"
                        disabled={loading || !messageInput.trim() || !hasSessionKey}
                        title="Send Message"
                    >
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <line x1="22" y1="2" x2="11" y2="13"></line>
                            <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                        </svg>
                    </button>
                </form>
            </div>
        </section>
    );
};

export default ChatPanel;
