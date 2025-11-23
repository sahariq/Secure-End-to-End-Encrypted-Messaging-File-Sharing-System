import express from 'express';
import bcrypt from 'bcrypt';
import User from '../models/User.js';
import { generateJWT } from '../utils/jwt.js';

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
      // Use generic message to prevent username enumeration
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Verify password using bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = generateJWT(user._id);

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

export default router;

