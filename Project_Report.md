# Secure End-to-End Encrypted Messaging System - Project Report

## 1. Introduction
This project implements a secure, end-to-end encrypted (E2EE) messaging and file sharing system. It addresses the critical need for private communication by ensuring that the service provider (server) has zero knowledge of the message content. The system defends against common attacks such as Man-in-the-Middle (MITM), Replay, and Tampering.

### Problem Statement
Traditional messaging systems often store messages in plaintext or use encryption keys managed by the server, leaving user data vulnerable to server-side breaches, insider threats, and mass surveillance. This project aims to solve this by implementing client-side encryption where only the communicating users hold the decryption keys.

---

## 2. System Architecture

The system follows a client-server architecture where the server acts as a blind relay and storage for encrypted data.

### High-Level Architecture

```mermaid
graph TD
    ClientA["Client A (Alice)"] -->|HTTPS / REST API| Server["Node.js Server"]
    ClientB["Client B (Bob)"] -->|HTTPS / REST API| Server
    Server -->|Persist Data| DB[("MongoDB")]
    
    subgraph "Client Side (Browser)"
        ClientA
        ClientB
        WebCrypto["Web Crypto API"]
        IndexedDB[("IndexedDB - Keys")]
    end

    subgraph "Server Side"
        Server
        Auth["JWT Auth"]
        Logs["Audit Logs"]
    end
```

**Technology Stack:**
*   **Frontend:** React, Vite, TailwindCSS
*   **Backend:** Node.js, Express.js
*   **Database:** MongoDB (Mongoose)
*   **Cryptography:** Web Crypto API (Client), Node.js Crypto (Server)

---

## 3. Cryptographic Design

The security of the system relies on a hybrid encryption scheme combining Elliptic Curve Cryptography (ECC) and AES.

### Algorithms
*   **Key Exchange:** ECDH (Elliptic Curve Diffie-Hellman) using NIST P-256 curve.
*   **Digital Signatures:** ECDSA (Elliptic Curve Digital Signature Algorithm) with P-256 and SHA-256.
*   **Symmetric Encryption:** AES-256-GCM (Galois/Counter Mode) for authenticated encryption of messages.
*   **Key Derivation:** HKDF (HMAC-based Key Derivation Function) with SHA-256 to derive session keys from shared secrets.
*   **Hashing:** SHA-256 for integrity checks and signatures.

### Key Management
1.  **Identity Keys (Long-term):**
    *   Generated once per user.
    *   **Private Identity Key:** Stored securely in the browser's IndexedDB (non-exportable where possible).
    *   **Public Identity Key:** Uploaded to the server for other users to verify identity.
2.  **Session Keys (Ephemeral):**
    *   Derived via ECDH for each conversation pair.
    *   Rotated per session (implementation supports rotation).
    *   Stored in IndexedDB.

---

## 4. Protocols

### 4.1 Signed ECDH Key Exchange
To prevent MITM attacks, all ephemeral keys used for ECDH are signed with the user's long-term Identity Key.

```mermaid
sequenceDiagram
    participant Alice
    participant Server
    participant Bob

    Note over Alice, Bob: 1. Identity Setup
    Alice->>Server: Upload Identity Public Key (Pub_ID_A)
    Bob->>Server: Upload Identity Public Key (Pub_ID_B)

    Note over Alice, Bob: 2. Key Exchange Initiation
    Alice->>Alice: Generate Ephemeral Key (Eph_A)
    Alice->>Alice: Sign Eph_A with Priv_ID_A
    Alice->>Server: Send { Eph_A, Signature_A }
    
    Note over Bob: 3. Response
    Bob->>Server: Fetch { Eph_A, Signature_A }
    Bob->>Server: Fetch Pub_ID_A
    Bob->>Bob: Verify Signature_A using Pub_ID_A
    Bob->>Bob: Generate Ephemeral Key (Eph_B)
    Bob->>Bob: Compute Shared Secret (Eph_B + Eph_A)
    Bob->>Bob: Derive Session Key
    Bob->>Bob: Sign Eph_B with Priv_ID_B
    Bob->>Server: Send { Eph_B, Signature_B }

    Note over Alice: 4. Completion
    Alice->>Server: Fetch { Eph_B, Signature_B }
    Alice->>Server: Fetch Pub_ID_B
    Alice->>Alice: Verify Signature_B using Pub_ID_B
    Alice->>Alice: Compute Shared Secret (Eph_A + Eph_B)
    Alice->>Alice: Derive Session Key

    Note over Alice, Bob: Secure Channel Established (AES-256-GCM)
```

### 4.2 Encryption & Decryption Workflow

```mermaid
flowchart LR
    subgraph Sender
        Input[Plaintext] --> Encrypt[AES-GCM Encrypt]
        SessionKey --> Encrypt
        Encrypt --> Ciphertext
        Encrypt --> AuthTag
        
        Ciphertext --> Sign[ECDSA Sign]
        AuthTag --> Sign
        PrivID[Private Identity Key] --> Sign
        Sign --> Signature
    end

    Sender -->|Payload: Ciphertext, IV, Nonce, Signature| Receiver

    subgraph Receiver
        Signature --> Verify[Verify Signature]
        PubID[Sender Public Identity Key] --> Verify
        
        Verify -- Valid --> Decrypt[AES-GCM Decrypt]
        Verify -- Invalid --> Reject[Reject Message]
        
        Decrypt --> Output[Plaintext]
        SessionKey --> Decrypt
    end
```

---

## 5. Database Schema Design

### User
*   `username`: String (Unique)
*   `passwordHash`: String (Bcrypt)

### PublicKey
*   `userId`: ObjectId (Ref: User)
*   `publicKeyJwk`: String (JSON Web Key format)

### ConversationState (Replay Protection)
*   `senderId`: ObjectId
*   `receiverId`: ObjectId
*   `lastSequenceNumber`: Number (Strictly increasing)

### ReplayLog
*   `nonce`: String (Unique index)
*   `timestamp`: Date (TTL index for expiry)

### AuditLog
*   `eventType`: String (LOGIN, KEY_EXCHANGE, REPLAY_DETECTED, etc.)
*   `userId`: ObjectId
*   `status`: String (SUCCESS, FAILURE)
*   `severity`: String (INFO, WARNING, CRITICAL)
*   `details`: Object (JSON)

---

## 6. Threat Model (STRIDE)

A detailed STRIDE analysis was performed (see `Stride.md`).

| Threat | Mitigation |
| :--- | :--- |
| **Spoofing** | Signed ECDH Key Exchange, JWT Authentication. |
| **Tampering** | AES-GCM (Authenticated Encryption), Digital Signatures. |
| **Repudiation** | Digital Signatures on all messages, Audit Logging. |
| **Information Disclosure** | End-to-End Encryption (Zero-Knowledge Server). |
| **Denial of Service** | Replay Protection (Nonces/Timestamps), Rate Limiting. |
| **Elevation of Privilege** | Strict Ownership Checks, Authorization Middleware. |

---

## 7. Attack Demonstrations

### 7.1 Man-in-the-Middle (MITM) Attack
*   **Script**: `server/scripts/mitm_attack.js`
*   **Scenario 1 (Unsecured)**: Attacker intercepts keys and successfully decrypts messages.
*   **Scenario 2 (Secured)**: Attacker attempts to inject their key. The victim verifies the signature against the trusted Identity Key, detects the mismatch, and **aborts the connection**.
*   **Result**: The system is proven secure against active MITM attacks.

### 7.2 Replay Attack
*   **Script**: `server/scripts/replay_attack.js`
*   **Scenario**: Attacker captures a valid encrypted message and attempts to resend it later.
*   **Defense**:
    1.  **Nonce Check**: Server rejects reused nonces.
    2.  **Sequence Number**: Server rejects messages with `seq <= lastSeq`.
    3.  **Timestamp**: Server rejects messages older than 5 minutes.
*   **Result**: The server responds with `403 Forbidden` and logs a `REPLAY_DETECTED` security event.

---

## 8. Logging & Auditing

The system maintains a centralized `AuditLog` in MongoDB.

**Logged Events:**
*   `LOGIN_ATTEMPT` / `REGISTER_ATTEMPT`
*   `KEY_EXCHANGE_INITIATE`
*   `MESSAGE_SEND`
*   `REPLAY_DETECTED` (Critical)
*   `SIGNATURE_INVALID` (Critical)
*   `DECRYPTION_FAILURE` (Reported by Client)

**Sample Log Entry:**
```json
{
  "timestamp": "2025-11-30T21:45:00.000Z",
  "eventType": "REPLAY_DETECTED",
  "status": "FAILURE",
  "severity": "CRITICAL",
  "userId": "64f...",
  "details": { "reason": "Nonce reused", "nonce": "a1b2..." }
}
```

---

## 9. Deployment

### Prerequisites
*   Node.js (v16+)
*   MongoDB (Local or Atlas)

### Steps
1.  **Clone Repository**
2.  **Install Dependencies**:
    ```bash
    cd server && npm install
    cd ../client && npm install
    ```
3.  **Configure Environment**:
    *   Create `server/.env` with `MONGODB_URI`, `JWT_SECRET`, `PORT`.
4.  **Start Server**:
    ```bash
    cd server && npm start
    ```
5.  **Start Client**:
    ```bash
    cd client && npm run dev
    ```

---

## 10. Conclusion

This project successfully demonstrates a secure, privacy-focused messaging system. By implementing robust End-to-End Encryption, Signed ECDH key exchange, and comprehensive replay protection, the system ensures that user data remains confidential and integral, even in the face of network interception or server compromise. The inclusion of a detailed audit logging system further enhances security by providing visibility into potential attacks.
