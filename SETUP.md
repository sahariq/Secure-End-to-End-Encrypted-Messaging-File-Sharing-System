# Setup Guide - Exact Commands

Follow these commands step-by-step to set up the project.

## Prerequisites

Make sure you have installed:
- Node.js (v18 or higher) - [Download](https://nodejs.org/)
- MongoDB - [Download](https://www.mongodb.com/try/download/community) or use MongoDB Atlas

## Step 1: Backend Setup

```bash
# Navigate to server directory
cd server

# Install all dependencies
npm install

# Create .env file (copy this content into a new .env file)
# Windows PowerShell:
@"
MONGODB_URI=mongodb://localhost:27017/secure-messaging
PORT=5000
NODE_ENV=development
JWT_SECRET=your-secret-key-here-change-in-production
"@ | Out-File -FilePath .env -Encoding utf8

# Or manually create .env file with:
# MONGODB_URI=mongodb://localhost:27017/secure-messaging
# PORT=5000
# NODE_ENV=development
# JWT_SECRET=your-secret-key-here-change-in-production

# Start the server
npm start

# Or for development with auto-reload:
npm run dev
```

The backend will run on `http://localhost:5000`

## Step 2: Frontend Setup

Open a **new terminal window** (keep the backend running):

```bash
# Navigate to client directory
cd client

# Install all dependencies
npm install

# Start the development server
npm run dev
```

The frontend will run on `http://localhost:5173`

## Step 3: Verify Setup

1. Open your browser and go to `http://localhost:5173`
2. You should see the Login page
3. Click "Register here" to create a new account
4. After registration, you'll be redirected to login
5. Login with your credentials
6. You should see the Chat page with dummy contacts

## Troubleshooting

### MongoDB Connection Error
- Make sure MongoDB is running: `mongod` (or start MongoDB service)
- Or update `MONGODB_URI` in `.env` to your MongoDB Atlas connection string

### Port Already in Use
- Change `PORT` in server `.env` file
- Update `CLIENT_URL` in server `.env` if needed
- Update `API_URL` in frontend components if you change the port

### Module Not Found Errors
- Make sure you ran `npm install` in both `server/` and `client/` directories
- Delete `node_modules` and `package-lock.json`, then run `npm install` again

## Project Structure

```
.
├── client/              # React frontend
│   ├── src/
│   │   ├── pages/      # All page components
│   │   ├── App.jsx     # Main app with routing
│   │   └── main.jsx    # Entry point
│   └── package.json
│
└── server/              # Express backend
    ├── config/         # Database config
    ├── models/         # MongoDB models
    ├── routes/         # API routes
    ├── server.js       # Entry point
    └── package.json
```

