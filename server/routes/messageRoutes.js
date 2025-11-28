import express from 'express';
import Message from '../models/Message.js';
import { authenticate } from '../middleware/authMiddleware.js';

const router = express.Router();

// All message routes require authentication
router.use(authenticate);

// POST /api/messages
// Protected route - requires valid JWT token
// SECURITY: Server NEVER sees or stores plaintext messages
// Only ciphertext (encrypted data + auth tag) and IV are stored
router.post('/', async (req, res, next) => {
  try {
    // Use authenticated user's ID from token
    const senderId = req.user.userId;
    const { receiverId, ciphertext, iv, timestamp } = req.body;

    // Validation
    if (!receiverId || !ciphertext || !iv) {
      return res.status(400).json({ 
        message: 'receiverId, ciphertext, and iv are required' 
      });
    }

    // SECURITY CHECK: Reject if any plaintext field is present
    if (req.body.plaintext || req.body.message || req.body.text) {
      return res.status(400).json({
        message: 'Plaintext messages are not accepted. Messages must be encrypted client-side.'
      });
    }

    // Create message metadata (ciphertext only)
    const message = new Message({
      senderId,
      receiverId,
      ciphertext,
      iv,
      timestamp: timestamp || new Date()
    });

    await message.save();

    // DO NOT log ciphertext or IV to console (security best practice)
    console.log(`✓ Encrypted message stored: ${senderId} -> ${receiverId}`);

    res.status(201).json({
      message: 'Message stored successfully',
      messageId: message._id,
      timestamp: message.timestamp
    });
  } catch (error) {
    next(error);
  }
});

// GET /api/messages/:conversationId
// Protected route - requires valid JWT token
// SECURITY: Returns only ciphertext and IV, never plaintext
// Decryption happens client-side only
// Note: conversationId is a combination of two user IDs
// For simplicity, we'll use format: userId1_userId2 (sorted)
router.get('/:conversationId', async (req, res, next) => {
  try {
    const { conversationId } = req.params;
    const currentUserId = req.user.userId;
    
    // Parse conversation ID (format: userId1_userId2)
    const [userId1, userId2] = conversationId.split('_');
    
    if (!userId1 || !userId2) {
      return res.status(400).json({ message: 'Invalid conversation ID format' });
    }

    // Verify that the authenticated user is part of this conversation
    if (currentUserId !== userId1 && currentUserId !== userId2) {
      return res.status(403).json({ 
        message: 'Access denied. You are not part of this conversation.' 
      });
    }

    // Find all messages between these two users
    const messages = await Message.find({
      $or: [
        { senderId: userId1, receiverId: userId2 },
        { senderId: userId2, receiverId: userId1 }
      ]
    })
    .sort({ timestamp: 1 }) // Sort by timestamp ascending
    .populate('senderId', 'username')
    .populate('receiverId', 'username');

    res.json({
      conversationId,
      messages: messages.map(msg => ({
        id: msg._id,
        senderId: msg.senderId._id || msg.senderId,
        senderUsername: msg.senderId.username || null,
        receiverId: msg.receiverId._id || msg.receiverId,
        receiverUsername: msg.receiverId.username || null,
        ciphertext: msg.ciphertext,
        iv: msg.iv,
        timestamp: msg.timestamp
      }))
    });
  } catch (error) {
    next(error);
  }
});

export default router;

