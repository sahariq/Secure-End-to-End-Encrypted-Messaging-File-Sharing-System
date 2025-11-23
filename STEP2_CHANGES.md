# STEP 2 Implementation Summary

## Overview
STEP 2 focuses on **secure authentication** and **preparation for cryptographic key handling**. No actual encryption is implemented yet - this step establishes the foundation for future cryptographic operations.

## Changes Made

### Backend Changes

#### 1. Password Security (bcrypt)
- **Updated `server/models/User.js`**: Changed `password` field to `passwordHash`
- **Updated `server/package.json`**: Added `bcrypt` dependency
- **Updated `server/routes/authRoutes.js`**:
  - Registration now hashes passwords with bcrypt (12 salt rounds)
  - Login verifies passwords using `bcrypt.compare()`
  - Generic error messages to prevent username enumeration

#### 2. JWT Authentication
- **Created `server/utils/jwt.js`**:
  - `generateJWT(userId)`: Creates HS256 JWT tokens with 7-day expiration
  - `verifyJWT(token)`: Verifies and decodes JWT tokens
- **Created `server/middleware/authMiddleware.js`**:
  - `authenticate` middleware extracts Bearer token from Authorization header
  - Verifies JWT and attaches `req.user` with `userId`
  - Returns 401 for missing/invalid tokens

#### 3. Protected Routes
- **Updated `server/routes/messageRoutes.js`**:
  - Added `authenticate` middleware to all routes
  - `POST /api/messages`: Uses `req.user.userId` as senderId (no longer accepts from body)
  - `GET /api/messages/:conversationId`: Verifies user is part of conversation
- **Updated `server/routes/fileRoutes.js`**:
  - Added `authenticate` middleware to all routes
  - `POST /api/files/metadata`: Uses `req.user.userId` as senderId
  - `GET /api/files/:id/metadata`: Verifies user has access to file

### Frontend Changes

#### 1. API Client with JWT Support
- **Created `client/src/utils/api.js`**:
  - Axios instance with base URL configuration
  - Request interceptor: Automatically adds `Authorization: Bearer <token>` header
  - Response interceptor: Handles 401 errors, clears auth data, redirects to login

#### 2. Updated Components
- **Updated `client/src/pages/ChatPage.jsx`**:
  - Uses `apiClient` instead of direct axios
  - Removed `senderId` from request body (set automatically from JWT)
  - All API calls now include JWT token automatically
- **Updated `client/src/pages/FilesPage.jsx`**:
  - Uses `apiClient` instead of direct axios
  - Removed `senderId` from request body
- **Updated `client/src/pages/LoginPage.jsx`**:
  - Added comment about future secure storage improvements
  - Still uses direct axios (no token needed for login)

#### 3. Key Storage Infrastructure
- **Created `client/src/crypto/keyStorage.js`**:
  - `saveLocalKey(keyName, keyData)`: Stores keys in localStorage (temporary)
  - `getLocalKey(keyName)`: Retrieves keys from localStorage
  - `deleteLocalKey(keyName)`: Removes a specific key
  - `clearAllKeys()`: Clears all crypto keys (useful for logout)
  - **Important**: Contains comments indicating this will be replaced with IndexedDB in STEP 3
  - **Note**: Does NOT yet handle CryptoKey objects (placeholder for future)

## Security Improvements

1. **Password Hashing**: Passwords are now hashed with bcrypt (12 rounds), making them resistant to rainbow table attacks
2. **JWT Tokens**: Replaced dummy tokens with real, signed JWT tokens (HS256)
3. **Route Protection**: All sensitive routes require valid JWT tokens
4. **Authorization**: Routes verify that users can only access their own data
5. **Automatic Token Handling**: Frontend automatically includes tokens in all authenticated requests

## API Changes

### Authentication Endpoints (No Changes)
- `POST /api/auth/register` - Still public, but now hashes passwords
- `POST /api/auth/login` - Still public, but returns real JWT tokens

### Protected Endpoints (Now Require JWT)
- `POST /api/messages` - Requires JWT, senderId from token
- `GET /api/messages/:conversationId` - Requires JWT, verifies user access
- `POST /api/files/metadata` - Requires JWT, senderId from token
- `GET /api/files/:id/metadata` - Requires JWT, verifies user access

## Migration Notes

### For Existing Users
If you have existing users in the database from STEP 1:
- Their passwords are stored as plain text in the `password` field
- The new code expects `passwordHash` field
- **Action Required**: Either:
  1. Delete existing users and re-register, OR
  2. Manually hash existing passwords and update the field name

### Environment Variables
No new environment variables required - uses existing `JWT_SECRET` from `.env`

## Next Steps (STEP 3)

The following will be implemented in STEP 3:
1. **Client-side Key Generation**: Generate ECC key pairs using Web Crypto API
2. **Key Storage Upgrade**: Replace localStorage with secure IndexedDB storage
3. **Key Exchange Protocol**: Implement ECDH key exchange between users
4. **AES-GCM Encryption**: Encrypt messages and files using shared keys
5. **Key Management**: Secure key derivation, wrapping, and unwrapping

## Testing Checklist

- [ ] Register new user (password should be hashed in DB)
- [ ] Login with correct password (should receive JWT token)
- [ ] Login with incorrect password (should fail)
- [ ] Access protected routes without token (should get 401)
- [ ] Access protected routes with invalid token (should get 401)
- [ ] Send message with valid token (should succeed)
- [ ] View messages in conversation (should only see own conversations)
- [ ] Upload file metadata with valid token (should succeed)
- [ ] View file metadata (should only see own files)
- [ ] Logout clears token and redirects

## Files Modified

### Backend
- `server/package.json` - Added bcrypt, jsonwebtoken
- `server/models/User.js` - Changed password to passwordHash
- `server/routes/authRoutes.js` - Added bcrypt hashing and JWT generation
- `server/routes/messageRoutes.js` - Added auth middleware, authorization checks
- `server/routes/fileRoutes.js` - Added auth middleware, authorization checks

### Backend (New Files)
- `server/utils/jwt.js` - JWT generation and verification
- `server/middleware/authMiddleware.js` - Authentication middleware

### Frontend
- `client/src/pages/ChatPage.jsx` - Uses apiClient with JWT
- `client/src/pages/FilesPage.jsx` - Uses apiClient with JWT
- `client/src/pages/LoginPage.jsx` - Updated comments

### Frontend (New Files)
- `client/src/utils/api.js` - Axios client with JWT interceptor
- `client/src/crypto/keyStorage.js` - Key storage infrastructure (placeholder)

