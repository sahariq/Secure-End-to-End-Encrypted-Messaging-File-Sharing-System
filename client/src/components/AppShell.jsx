import React from 'react';
import '../styles/main.css';

const AppShell = ({
    children,
    user,
    onLogout,
    onToggleSidebar,
    isSidebarOpen
}) => {
    return (
        <div className="app">
            {/* Header outside the card */}
            <header className="app__header">
                <div className="app__header-content">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <button
                            className="btn mobile-only"
                            onClick={onToggleSidebar}
                            style={{ display: window.innerWidth <= 768 ? 'block' : 'none', padding: '8px', border: 'none', background: 'transparent' }}
                        >
                            <span style={{ fontSize: '20px', color: 'var(--color-primary)' }}>☰</span>
                        </button>
                        <div className="app__header-title">
                            <span style={{ color: 'var(--color-primary)' }}>❖</span> Secure Messaging
                        </div>
                    </div>

                    <div className="app__header-actions" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                        {user && (
                            <div style={{ fontSize: '13px', color: 'var(--color-text-primary)', fontWeight: 600 }}>
                                {user.username}
                            </div>
                        )}
                        <button
                            onClick={onLogout}
                            className="btn"
                            style={{
                                color: 'var(--color-primary-active)',
                                borderColor: 'transparent',
                                fontSize: '12px'
                            }}
                        >
                            Logout
                        </button>
                    </div>
                </div>
            </header>

            {/* Unified Card Container */}
            <main className="app__layout">
                <div className="app__card">
                    {children}
                </div>
            </main>
        </div>
    );
};

export default AppShell;
