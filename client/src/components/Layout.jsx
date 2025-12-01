import React from 'react';
import '../styles/main.css';

const Layout = ({
    children,
    user,
    onLogout,
    onToggleSidebar,
    isSidebarOpen
}) => {
    return (
        <div className="app">
            <header className="app__header">
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <button
                        className="btn btn--icon mobile-only"
                        onClick={onToggleSidebar}
                        style={{ display: window.innerWidth <= 768 ? 'block' : 'none' }}
                    >
                        ☰
                    </button>
                    <div className="app__header-title">Secure Messaging</div>
                </div>

                <div className="app__header-actions">
                    {user && (
                        <div className="app__user-info">
                            Logged in as <strong>{user.username}</strong>
                        </div>
                    )}
                    <button onClick={onLogout} className="btn btn--secondary">
                        Logout
                    </button>
                </div>
            </header>

            <main className="app__layout">
                {children}
            </main>
        </div>
    );
};

export default Layout;
