import React from 'react';
import { motion } from 'framer-motion';

const MessageBubble = ({ message, isOwn, onDownload }) => {
    const isFile = message.isFile;
    const isEncrypted = !message.decrypted;

    return (
        <motion.div
            className={`message ${isOwn ? 'message--outgoing' : 'message--incoming'}`}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2 }}
        >
            <div className="message__bubble">
                {isEncrypted ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontStyle: 'italic', opacity: 0.9 }}>
                        <span>🔒</span> Encrypted Message
                    </div>
                ) : isFile ? (
                    <div className="file-attachment">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
                            <div style={{
                                width: '40px', height: '40px',
                                background: isOwn ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.05)',
                                borderRadius: '8px',
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                fontSize: '20px'
                            }}>
                                📄
                            </div>
                            <div>
                                <div style={{ fontWeight: 600, fontSize: '15px' }}>{message.fileData.filename}</div>
                                <div style={{ fontSize: '12px', opacity: 0.8 }}>
                                    {Math.round(message.fileData.filesize / 1024)} KB
                                </div>
                            </div>
                        </div>
                        <button
                            className="btn"
                            style={{
                                width: '100%',
                                justifyContent: 'center',
                                background: isOwn ? 'rgba(255,255,255,0.15)' : '#FFFFFF',
                                border: isOwn ? '1px solid rgba(255,255,255,0.3)' : '1px solid rgba(0,0,0,0.1)',
                                color: 'inherit',
                                fontSize: '13px'
                            }}
                            onClick={() => onDownload(message.fileData)}
                        >
                            Download
                        </button>
                    </div>
                ) : (
                    message.plaintext
                )}
            </div>

            {!isEncrypted && (
                <div className="message__meta">
                    <span>{new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                </div>
            )}
        </motion.div>
    );
};

export default MessageBubble;
