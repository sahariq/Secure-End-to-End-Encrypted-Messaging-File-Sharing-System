# Testing Guide - STEP 3 Implementation

## Prerequisites

1. **MongoDB** must be running
2. **Backend** dependencies installed (`npm install` in `/server`)
3. **Frontend** dependencies installed (`npm install` in `/client`)
4. **Environment** variables configured (`.env` file in `/server`)

## Quick Start Testing

### Step 1: Start Backend Server

```bash
cd server
npm install  # If not already done
npm start
# or for development: npm run dev
```

Expected output:
```
MongoDB Connected: localhost:27017
Server running on port 5000
```

### Step 2: Start Frontend Client

Open a **new terminal**:

```bash
cd client
npm install  # If not already done
npm run dev
```

Expected output:
```
  VITE v5.x.x  ready in xxx ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

### Step 3: Test Registration & Key Generation

1. **Open browser** to `http://localhost:5173`
2. **Click "Register here"** or navigate to `/register`
3. **Fill in registration form**:
   - Username: `testuser` (or any username)
   - Password: `testpass123`
4. **Click "Register"**

**Expected Behavior:**
- ✅ Button shows "Registering..."
- ✅ Status message: "Generating secure device keys..."
- ✅ Status message changes to: "Keys generated successfully!"
- ✅ Redirects to login page after ~1 second
- ✅ **Check browser console** (F12) - should see:
  ```
  Generated ECC key pair successfully
  Public Key (JWK): {"kty":"EC","crv":"P-256","x":"...","y":"..."}
  ```

### Step 4: Test Login & Key Loading

1. **On login page**, enter credentials:
   - Username: `testuser`
   - Password: `testpass123`
2. **Click "Login"**

**Expected Behavior:**
- ✅ Button shows "Logging in..."
- ✅ Status message: "Checking for device keys..."
- ✅ Status message: "Keys loaded successfully."
- ✅ Redirects to chat page
- ✅ **Check browser console** - should see:
  ```
  Loaded existing ECC key pair
  Public Key (JWK): {"kty":"EC","crv":"P-256","x":"...","y":"..."}
  ```

### Step 5: Verify IndexedDB Storage

1. **Open browser DevTools** (F12)
2. **Go to Application tab** (Chrome) or **Storage tab** (Firefox)
3. **Navigate to IndexedDB** section
4. **Look for database**: `secureKeysDB`
5. **Expand** → `keys` object store
6. **Verify keys exist**:
   - `ecc_private_key` (should be present)
   - `ecc_public_key` (should be present)

**Expected:**
- ✅ Database `secureKeysDB` exists
- ✅ Object store `keys` contains 2 entries
- ✅ Keys are stored as CryptoKey objects (structuredClone)

### Step 6: Test New Device Scenario

1. **Clear IndexedDB** (in DevTools):
   - Right-click `secureKeysDB` → Delete
   - Or: Application → Storage → Clear site data
2. **Login again** with same credentials

**Expected Behavior:**
- ✅ Status message: "No keys found, generating fresh ones..."
- ✅ Status message: "Keys generated successfully!"
- ✅ New keys generated and stored
- ✅ Console shows: "Generated new ECC key pair"

## Detailed Testing Checklist

### ✅ Authentication Flow
- [ ] Registration creates user in MongoDB
- [ ] Password is hashed (check MongoDB - should see `passwordHash` field, not plain text)
- [ ] Login returns JWT token
- [ ] JWT token is stored in localStorage
- [ ] Invalid credentials show error message

### ✅ Key Generation (Registration)
- [ ] ECC key pair is generated after registration
- [ ] Keys are stored in IndexedDB
- [ ] Public key is exported as JWK
- [ ] Public key JWK is logged to console
- [ ] UI shows key generation status messages
- [ ] Redirect happens after key generation

### ✅ Key Loading (Login)
- [ ] Existing keys are loaded from IndexedDB
- [ ] If no keys found, new keys are generated
- [ ] Public key is exported and logged
- [ ] UI shows appropriate status messages
- [ ] Redirect happens after key operations

### ✅ IndexedDB Storage
- [ ] Database `secureKeysDB` is created
- [ ] Object store `keys` exists
- [ ] Private key stored as `ecc_private_key`
- [ ] Public key stored as `ecc_public_key`
- [ ] Keys are CryptoKey objects (not strings)

### ✅ Security Checks
- [ ] Private key is NOT exported (check console - no private key in logs)
- [ ] Only public key JWK is logged
- [ ] Keys are stored in IndexedDB (not localStorage)
- [ ] JWT token is required for protected routes

### ✅ Error Handling
- [ ] Registration with duplicate username shows error
- [ ] Invalid login credentials show error
- [ ] Key generation failure shows appropriate message
- [ ] Network errors are handled gracefully

## Browser Compatibility Testing

Test in multiple browsers:

- [ ] **Chrome/Edge** (Chromium) - Full support
- [ ] **Firefox** - Full support
- [ ] **Safari** - May need to test (IndexedDB support varies)

## Common Issues & Solutions

### Issue: "Web Crypto API is not available"
**Solution**: Use a modern browser (Chrome, Firefox, Edge). HTTPS may be required in some cases.

### Issue: "Failed to open database"
**Solution**: 
- Check browser permissions
- Clear browser cache
- Try incognito/private mode

### Issue: Keys not generating
**Solution**:
- Check browser console for errors
- Verify Web Crypto API is available: `window.crypto.subtle` should exist
- Check IndexedDB is enabled in browser settings

### Issue: "MongoDB connection error"
**Solution**:
- Ensure MongoDB is running: `mongod` or start MongoDB service
- Check `.env` file has correct `MONGODB_URI`
- Verify MongoDB is accessible on the specified port

### Issue: "JWT_SECRET not defined"
**Solution**:
- Check `.env` file exists in `/server` directory
- Verify `JWT_SECRET` is set in `.env`

## Manual Verification Steps

### 1. Verify Public Key Format

The public key JWK should look like:
```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "base64-encoded-x-coordinate",
  "y": "base64-encoded-y-coordinate"
}
```

### 2. Verify Key Pair Validity

In browser console, you can test:
```javascript
// This should work (public key is extractable)
const keyManager = await import('./src/crypto/keyManager.js');
const jwk = await keyManager.exportPublicKeyAsJWKString();
console.log(JSON.parse(jwk));

// This should NOT work (private key is not exported)
// (No function exists to export private key - by design)
```

### 3. Verify IndexedDB Contents

In DevTools Console:
```javascript
// Open database
const request = indexedDB.open('secureKeysDB', 1);
request.onsuccess = (e) => {
  const db = e.target.result;
  const tx = db.transaction('keys', 'readonly');
  const store = tx.objectStore('keys');
  store.getAll().onsuccess = (e) => {
    console.log('Stored keys:', e.target.result);
  };
};
```

## Next Steps After Testing

Once all tests pass:
1. ✅ Keys are generated and stored securely
2. ✅ Public keys are ready for STEP 4 key exchange
3. ✅ Authentication is working with JWT
4. ✅ Ready to implement ECDH key exchange in STEP 4

## Test Results Template

```
Date: ___________
Browser: ___________
OS: ___________

Registration:
[ ] User created successfully
[ ] Keys generated
[ ] Public key logged
[ ] IndexedDB populated

Login:
[ ] JWT token received
[ ] Keys loaded/generated
[ ] Public key logged
[ ] Redirect successful

IndexedDB:
[ ] Database exists
[ ] Keys stored correctly
[ ] Can retrieve keys

Issues Found:
_________________________________
_________________________________
```

