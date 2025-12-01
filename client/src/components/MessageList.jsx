import React, { useEffect, useRef } from 'react';
import MessageBubble from './MessageBubble';

const MessageList = ({ messages, currentUserId, onDownloadFile }) => {
    const bottomRef = useRef(null);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    if (messages.length === 0) {
        return (
            <div className="chat__messages flex-center">
                <div className="text-center text-muted">
                    <p style={{ fontSize: '48px', marginBottom: '16px' }}>👋</p>
                    <p>No messages yet.</p>
                    <p>Start the conversation!</p>
                </div>
            </div>
        );
    }

    return (
        <div className="chat__messages">
            {messages.map((msg) => (
                <MessageBubble
                    key={msg.id}
                    message={msg}
                    isOwn={msg.senderId === currentUserId}
                    onDownload={onDownloadFile}
                />
            ))}
            <div ref={bottomRef} />
        </div>
    );
};

export default MessageList;
