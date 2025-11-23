# Secure End-to-End Encrypted Messaging & File-Sharing System

This is the initial skeleton for a secure messaging system. **No real cryptography is implemented yet** - this is Step 1 of the project focusing on structure, routes, and placeholder logic.

## Project Structure

```
.
├── client/          # React frontend (Vite)
│   ├── src/
│   │   ├── pages/   # React components (RegisterPage, LoginPage, ChatPage, FilesPage)
│   │   ├── App.jsx
│   │   └── main.jsx
│   └── package.json
│
└── server/          # Node.js + Express backend
    ├── config/      # Database configuration
    ├── models/      # MongoDB models (User, Message, File)
    ├── routes/      # API routes (authRoutes, messageRoutes, fileRoutes)
    ├── server.js    # Main entry point
    └── package.json
```

## Setup Instructions

### Prerequisites
- Node.js (v18 or higher)
- MongoDB (running locally or connection string)

### Backend Setup

1. Navigate to the server directory:
   ```bash
   cd server
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file in the `server` directory:
   ```env
   MONGODB_URI=mongodb://localhost:27017/secure-messaging
   PORT=5000
   NODE_ENV=development
   JWT_SECRET=your-secret-key-here-change-in-production
   ```

4. Start the server:
   ```bash
   npm start
   ```
   Or for development with auto-reload:
   ```bash
   npm run dev
   ```

   The server will run on `http://localhost:5000`

### Frontend Setup

1. Navigate to the client directory:
   ```bash
   cd client
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

   The frontend will run on `http://localhost:5173`

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login and get token

### Messages
- `POST /api/messages` - Store message metadata (ciphertext, IV)
- `GET /api/messages/:conversationId` - Get all messages for a conversation

### Files
- `POST /api/files/metadata` - Store file metadata
- `GET /api/files/:id/metadata` - Get file metadata by ID

## Current Implementation Status

### ✅ STEP 1 - Skeleton (Completed)
- Project structure and folder organization
- MongoDB models (User, Message, File)
- Express routes with stub logic
- Security middleware (helmet, cors, rate limiting)
- React frontend with routing
- Basic UI components for all pages
- Placeholder authentication (plain password storage)
- Dummy ciphertext storage

### ✅ STEP 2 - Secure Authentication (Completed)
- **Password Security**: bcrypt hashing with 12 salt rounds
- **JWT Authentication**: Real JWT tokens (HS256) with 7-day expiration
- **Route Protection**: All sensitive routes require valid JWT tokens
- **Authorization**: Users can only access their own data
- **API Client**: Automatic JWT token inclusion in authenticated requests
- **Key Storage Infrastructure**: Placeholder functions for future key management

### ❌ Not Yet Implemented (Future Steps)
- Web Crypto API integration
- ECDH key exchange
- AES-GCM encryption/decryption
- Real file upload and storage
- Socket.io for real-time messaging
- Secure IndexedDB key storage (replacing localStorage)

## Important Notes

1. **Passwords are hashed with bcrypt** - STEP 2 implemented secure password hashing with 12 salt rounds.

2. **JWT tokens** - Real JWT tokens (HS256) are generated on login and required for all protected routes.

3. **Dummy ciphertext** - Messages are still stored with "DUMMY_CIPHERTEXT" placeholder. Real encryption will be implemented in STEP 3.

4. **No file storage** - Only metadata is stored. Actual file upload and encrypted storage will be added later.

5. **Key storage** - Placeholder localStorage-based key storage is implemented. Will be upgraded to IndexedDB in STEP 3.

6. **No real-time updates** - REST API only. Socket.io integration planned for later.

## Request Flow

1. **User Registration/Login:**
   - Frontend → `POST /api/auth/register` or `/api/auth/login`
   - Backend validates and stores in MongoDB
   - Returns token (stored in localStorage)

2. **Sending a Message:**
   - Frontend → `POST /api/messages` with senderId, receiverId, ciphertext, IV
   - Backend stores message metadata in MongoDB
   - No plaintext is ever stored

3. **Loading Messages:**
   - Frontend → `GET /api/messages/:conversationId`
   - Backend queries MongoDB and returns message documents
   - Frontend displays ciphertext (will decrypt later)

4. **File Upload:**
   - Frontend → `POST /api/files/metadata` with file metadata
   - Backend stores metadata in MongoDB
   - Actual file storage will be implemented later

## Next Steps (STEP 3)

1. Implement Web Crypto API for key generation (ECC key pairs)
2. Upgrade key storage from localStorage to secure IndexedDB
3. Add ECDH key exchange protocol between users
4. Implement AES-GCM encryption/decryption for messages
5. Add real file upload and encrypted storage
6. Integrate Socket.io for real-time messaging
7. Implement secure key derivation and wrapping

