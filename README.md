# Secure End-to-End Encrypted Messaging & File-Sharing System

A fully functional, secure messaging application featuring **End-to-End Encryption (E2EE)**, **Secure File Sharing**, and a modern **Warm Tactile UI**.

## Key Features

### 🔒 Security & Cryptography
- **End-to-End Encryption**: Messages are encrypted on the client using **AES-GCM (256-bit)** before transmission. The server never sees the plaintext.
- **Key Exchange**: Secure **ECDH (Elliptic Curve Diffie-Hellman)** key exchange using the **Web Crypto API** (P-256 curve).
- **Identity Verification**: ECDSA signatures ensure that public keys cannot be spoofed (MITM protection).
- **Forward Secrecy**: Unique session keys are generated for each conversation.
- **Secure File Sharing**: Files are encrypted in the browser, uploaded as encrypted blobs, and decrypted only by the intended recipient.

### 🎨 UI/UX
- **Warm Tactile Design**: A custom "Unified Card" interface using a warm paper palette (`#E1CCA7` base) and crisp white cards.
- **Unified Layout**: Seamless sidebar and chat integration for a professional desktop-app feel.
- **Physics-Based Animations**: Smooth transitions powered by `framer-motion`.
- **Responsive**: Fully responsive layout that adapts to mobile devices.

### 🛡️ Auditing & Compliance
- **Audit Logging**: Comprehensive server-side logging of security events (login attempts, key exchanges, replay attacks).
- **Threat Modeling**: Full **STRIDE** analysis implemented and documented.

## Project Structure

```
.
├── client/          # React frontend (Vite + Framer Motion)
│   ├── src/
│   │   ├── components/ # UI Components (AppShell, ChatPanel, Sidebar)
│   │   ├── crypto/     # Cryptographic modules (Web Crypto API)
│   │   ├── styles/     # CSS Design System (Warm Tactile)
│   │   └── pages/      # Application Pages
│   └── ...
│
└── server/          # Node.js + Express backend
    ├── models/      # MongoDB Schemas (User, Message, File, AuditLog)
    ├── routes/      # Secure API Endpoints
    └── ...
```

## Setup Instructions

### Prerequisites
- Node.js (v18+)
- MongoDB (Local or Atlas)

### 1. Backend Setup
```bash
cd server
npm install
```
Create a `.env` file:
```env
MONGODB_URI=mongodb://localhost:27017/secure-messaging
PORT=5000
JWT_SECRET=your-secure-secret
```
Start the server:
```bash
npm start
```

### 2. Frontend Setup
```bash
cd client
npm install
npm run dev
```
Access the app at `http://localhost:5173`.

## Implementation Status

### ✅ Completed Features
- [x] **User Authentication** (JWT + bcrypt)
- [x] **ECDH Key Exchange** (P-256)
- [x] **AES-GCM Message Encryption**
- [x] **Encrypted File Sharing**
- [x] **MITM Protection** (ECDSA Signatures)
- [x] **Audit Logging**
- [x] **UI Polish** (Warm Tactile Unified Card)

### 🚀 Future Roadmap
- [ ] Group Chat E2EE (Sender Keys)
- [ ] Voice/Video Calls (WebRTC)
- [ ] Push Notifications

## Security Architecture

For a deep dive into the security architecture, threat model, and cryptographic protocols, please refer to the [Project Report](./Project_Report.md) and [STRIDE Analysis](./STRIDE_Analysis.md).
