# Quick Test Guide - STEP 3

## 🚀 Quick Start

### 1. Install Dependencies (if not done)

**Backend:**
```powershell
cd server
npm install
```

**Frontend:**
```powershell
cd client
npm install
```

### 2. Start Backend Server

```powershell
cd server
npm start
```

**Expected:** Server running on port 5000

### 3. Start Frontend (New Terminal)

```powershell
cd client
npm run dev
```

**Expected:** Frontend running on http://localhost:5173

## ✅ Test Steps

### Test 1: Registration & Key Generation

1. Open browser → `http://localhost:5173`
2. Click "Register here"
3. Enter:
   - Username: `alice`
   - Password: `password123`
4. Click "Register"

**✅ What to Check:**
- [ ] Status shows "Generating secure device keys..."
- [ ] Status changes to "Keys generated successfully!"
- [ ] Redirects to login page
- [ ] **Open Console (F12)** → Should see:
  ```
  Generated ECC key pair successfully
  Public Key (JWK): {"kty":"EC","crv":"P-256",...}
  ```

### Test 2: Login & Key Loading

1. On login page, enter:
   - Username: `alice`
   - Password: `password123`
2. Click "Login"

**✅ What to Check:**
- [ ] Status shows "Checking for device keys..."
- [ ] Status shows "Keys loaded successfully."
- [ ] Redirects to chat page
- [ ] **Console** → Should see:
  ```
  Loaded existing ECC key pair
  Public Key (JWK): {"kty":"EC","crv":"P-256",...}
  ```

### Test 3: Verify IndexedDB

1. Open DevTools (F12)
2. Go to **Application** tab (Chrome) or **Storage** tab (Firefox)
3. Expand **IndexedDB** → `secureKeysDB` → `keys`

**✅ What to Check:**
- [ ] Database `secureKeysDB` exists
- [ ] Object store `keys` has 2 entries:
  - `ecc_private_key`
  - `ecc_public_key`

### Test 4: New Device (Clear & Re-login)

1. In DevTools → **Application** → **Storage**
2. Right-click `secureKeysDB` → **Delete database**
3. Login again with same credentials

**✅ What to Check:**
- [ ] Status shows "No keys found, generating fresh ones..."
- [ ] New keys are generated
- [ ] IndexedDB repopulated

## 🔍 Console Commands for Testing

Open browser console (F12) and try:

```javascript
// Check if Web Crypto API is available
console.log('Crypto API:', !!window.crypto?.subtle);

// Check IndexedDB
const request = indexedDB.open('secureKeysDB', 1);
request.onsuccess = () => {
  console.log('IndexedDB accessible:', true);
};

// Test key manager (if on a page that imports it)
// This won't work directly, but you can check the network tab
// to see if modules load correctly
```

## ⚠️ Common Issues

### "Web Crypto API is not available"
- Use Chrome, Firefox, or Edge (latest versions)
- Some browsers require HTTPS for crypto operations

### "Failed to open database"
- Clear browser cache
- Try incognito mode
- Check browser permissions

### "MongoDB connection error"
- Ensure MongoDB is running
- Check `.env` file in `/server` has correct `MONGODB_URI`

### Keys not generating
- Check browser console for errors
- Verify IndexedDB is enabled
- Try a different browser

## 📋 Expected Results

After successful testing, you should have:

✅ User registered in MongoDB with hashed password  
✅ JWT token stored in localStorage  
✅ ECC P-256 key pair generated  
✅ Keys stored in IndexedDB  
✅ Public key exported as JWK (logged to console)  
✅ Ready for STEP 4 (key exchange)

## 🎯 Success Criteria

- [ ] Registration creates user and generates keys
- [ ] Login loads existing keys or generates new ones
- [ ] Keys are stored in IndexedDB (not localStorage)
- [ ] Public key is exportable as JWK
- [ ] Private key is NOT exported (security)
- [ ] UI shows appropriate status messages
- [ ] No errors in browser console

---

**Ready for STEP 4?** Once all tests pass, you're ready to implement ECDH key exchange!

