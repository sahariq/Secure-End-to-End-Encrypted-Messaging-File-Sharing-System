import express from 'express';
import bcrypt from 'bcrypt';
import User from '../models/User.js';
import { generateJWT } from '../utils/jwt.js';
import { authenticate } from '../middleware/authMiddleware.js';
import { logEvent } from '../utils/logger.js';

const router = express.Router();

// Bcrypt salt rounds (higher = more secure but slower)
const SALT_ROUNDS = 12;

// POST /api/auth/register
router.post('/register', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    if (username.length < 3 || username.length > 30) {
      return res.status(400).json({ message: 'Username must be between 3 and 30 characters' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      logEvent({
        eventType: 'REGISTER_ATTEMPT',
        status: 'FAILURE',
        username,
        details: { reason: 'Username already exists' },
        req,
        severity: 'WARNING'
      });
      return res.status(409).json({ message: 'Username already exists' });
    }

    // Hash password with bcrypt (includes salt automatically)
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    // Create user with hashed password
    const user = new User({
      username,
      passwordHash
    });

    await user.save();

    logEvent({
      eventType: 'REGISTER_ATTEMPT',
      status: 'SUCCESS',
      userId: user._id,
      username: user.username,
      req
    });

    res.status(201).json({
      message: 'User registered successfully',
      userId: user._id,
      username: user.username
    });
  } catch (error) {
    next(error);
  }
});

// POST /api/auth/login
router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      logEvent({
        eventType: 'LOGIN_ATTEMPT',
        status: 'FAILURE',
        username,
        details: { reason: 'User not found' },
        req,
        severity: 'WARNING'
      });
      // Use generic message to prevent username enumeration
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Verify password using bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      logEvent({
        eventType: 'LOGIN_ATTEMPT',
        status: 'FAILURE',
        userId: user._id,
        username: user.username,
        details: { reason: 'Invalid password' },
        req,
        severity: 'WARNING'
      });
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = generateJWT(user._id);

    logEvent({
      eventType: 'LOGIN_ATTEMPT',
      status: 'SUCCESS',
      userId: user._id,
      username: user.username,
      req
    });

    res.json({
      message: 'Login successful',
      token: token,
      userId: user._id,
      username: user.username
    });
  } catch (error) {
    next(error);
  }
});

// GET /api/auth/users - Get all users except current user
router.get('/users', authenticate, async (req, res, next) => {
  try {
    const currentUserId = req.user.userId; // Fixed: req.user.userId not req.userId

    // Find all users except the current user
    const users = await User.find(
      { _id: { $ne: currentUserId } },
      'username _id' // Only return username and _id
    ).sort({ username: 1 });

    // Optional: Log metadata access (can be noisy)
    // logEvent({
    //   eventType: 'METADATA_ACCESS',
    //   status: 'SUCCESS',
    //   userId: currentUserId,
    //   details: { action: 'list_users' },
    //   req
    // });

    res.json(users);
  } catch (error) {
    next(error);
  }
});

export default router;

