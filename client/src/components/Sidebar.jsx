import React from 'react';

const Sidebar = ({
    contacts,
    selectedContact,
    onSelectContact,
    isOpen
}) => {
    return (
        <aside className={`sidebar ${isOpen ? 'sidebar--open' : ''}`}>
            <div className="sidebar__header">
                <span>Contacts</span>
                {contacts.length > 0 && (
                    <span style={{
                        fontSize: '11px',
                        backgroundColor: 'var(--color-primary-light)',
                        color: 'var(--color-primary)',
                        padding: '2px 6px',
                        borderRadius: '4px'
                    }}>
                        {contacts.length}
                    </span>
                )}
            </div>
            <ul className="sidebar__list">
                {contacts.length === 0 ? (
                    <li style={{ padding: '24px', color: 'var(--color-text-secondary)', textAlign: 'center', fontSize: '13px' }}>
                        No contacts found
                    </li>
                ) : (
                    contacts.map((contact) => (
                        <li
                            key={contact._id}
                            className={`sidebar__item ${selectedContact?._id === contact._id ? 'sidebar__item--active' : ''}`}
                            onClick={() => onSelectContact(contact)}
                        >
                            <div className="sidebar__item-avatar">
                                {contact.username.charAt(0).toUpperCase()}
                            </div>
                            <span className="sidebar__item-name">{contact.username}</span>
                        </li>
                    ))
                )}
            </ul>
        </aside>
    );
};

export default Sidebar;
