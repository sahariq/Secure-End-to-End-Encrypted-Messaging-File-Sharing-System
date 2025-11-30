import express from 'express';
import Message from '../models/Message.js';
import { authenticate } from '../middleware/authMiddleware.js';
import ReplayLog from '../models/ReplayLog.js';
import ConversationState from '../models/ConversationState.js';
import PublicKey from '../models/PublicKey.js';
import { verifyObjectSignature } from '../utils/cryptoUtils.js';
import { logEvent } from '../utils/logger.js';

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
    const {
      receiverId,
      ciphertext,
      iv,
      nonce,
      timestamp,
      sequenceNumber,
      signature
    } = req.body;

    // 1. Validation of required fields
    if (!receiverId || !ciphertext || !iv || !nonce || !timestamp || !sequenceNumber || !signature) {
      return res.status(400).json({
        message: 'Missing required fields: receiverId, ciphertext, iv, nonce, timestamp, sequenceNumber, signature'
      });
    }

    // SECURITY CHECK: Reject if any plaintext field is present
    if (req.body.plaintext || req.body.message || req.body.text) {
      logEvent({
        eventType: 'MESSAGE_SEND',
        status: 'FAILURE',
        userId: senderId,
        details: { reason: 'Plaintext message rejected' },
        req,
        severity: 'WARNING'
      });
      return res.status(400).json({
        message: 'Plaintext messages are not accepted. Messages must be encrypted client-side.'
      });
    }

    // 2. Timestamp Check (Replay Protection)
    // Reject messages older than 5 minutes or from the future (allow 1 min drift)
    const msgTime = new Date(timestamp).getTime();
    const now = Date.now();
    const fiveMinutes = 5 * 60 * 1000;

    if (now - msgTime > fiveMinutes) {
      logEvent({
        eventType: 'REPLAY_DETECTED',
        status: 'FAILURE',
        userId: senderId,
        details: { reason: 'Message expired', timestamp, now },
        req,
        severity: 'WARNING'
      });
      return res.status(400).json({ message: 'Message expired (timestamp too old)' });
    }
    if (msgTime - now > 60 * 1000) {
      logEvent({
        eventType: 'REPLAY_DETECTED',
        status: 'FAILURE',
        userId: senderId,
        details: { reason: 'Future timestamp', timestamp, now },
        req,
        severity: 'WARNING'
      });
      return res.status(400).json({ message: 'Invalid timestamp (in the future)' });
    }

    // 3. Nonce Check (Replay Protection)
    // Check if this nonce has been used recently
    const existingNonce = await ReplayLog.findOne({ nonce });
    if (existingNonce) {
      console.warn(`⚠️ Replay attack detected! Nonce reused: ${nonce}`);
      logEvent({
        eventType: 'REPLAY_DETECTED',
        status: 'FAILURE',
        userId: senderId,
        details: { reason: 'Nonce reused', nonce },
        req,
        severity: 'CRITICAL'
      });
      return res.status(403).json({ message: 'Replay detected: Nonce already used' });
    }

    // 4. Signature Verification (Integrity + Authenticity)
    // Fetch sender's public key
    const senderKey = await PublicKey.findOne({ userId: senderId });
    if (!senderKey) {
      return res.status(400).json({ message: 'Sender public key not found. Please register keys first.' });
    }

    // Construct the payload object that was signed
    // MUST match the client's structure exactly
    const payloadToVerify = {
      senderId,
      receiverId,
      ciphertext,
      iv,
      nonce,
      timestamp,
      sequenceNumber
    };

    const isValid = verifyObjectSignature(
      JSON.parse(senderKey.publicKeyJwk),
      payloadToVerify,
      signature
    );

    if (!isValid) {
      console.warn(`⚠️ Invalid signature from user ${senderId}`);
      logEvent({
        eventType: 'SIGNATURE_INVALID',
        status: 'FAILURE',
        userId: senderId,
        details: { reason: 'Signature verification failed', receiverId },
        req,
        severity: 'CRITICAL'
      });
      return res.status(403).json({ message: 'Invalid signature: Message integrity check failed' });
    }

    // 5. Sequence Number Check (Reordering/Replay Protection)
    // Get the last sequence number for this conversation direction
    let convState = await ConversationState.findOne({ senderId, receiverId });

    if (!convState) {
      // First message in this direction, initialize state
      // We accept sequenceNumber 1 (or whatever start value)
      // For robustness, we might just set it to current - 1 if it's the first one?
      // Or strictly enforce 1? Let's enforce > 0.
      convState = new ConversationState({
        senderId,
        receiverId,
        lastSequenceNumber: 0
      });
    }

    if (sequenceNumber <= convState.lastSequenceNumber) {
      console.warn(`⚠️ Replay/Reorder detected! Seq ${sequenceNumber} <= Last ${convState.lastSequenceNumber}`);
      logEvent({
        eventType: 'REPLAY_DETECTED',
        status: 'FAILURE',
        userId: senderId,
        details: { reason: 'Sequence number too low', sequenceNumber, lastSequenceNumber: convState.lastSequenceNumber },
        req,
        severity: 'WARNING'
      });
      return res.status(403).json({
        message: `Invalid sequence number. Expected > ${convState.lastSequenceNumber}, got ${sequenceNumber}`
      });
    }

    // 6. Persist Everything (Atomic-ish)

    // Save message
    const message = new Message({
      senderId,
      receiverId,
      ciphertext,
      iv,
      nonce,
      sequenceNumber,
      signature,
      timestamp: new Date(timestamp)
    });
    await message.save();

    // Save nonce to replay log
    await ReplayLog.create({
      nonce,
      senderId
    });

    // Update conversation state
    convState.lastSequenceNumber = sequenceNumber;
    convState.updatedAt = new Date();
    await convState.save();

    // DO NOT log ciphertext or IV to console (security best practice)
    console.log(`✓ Secure message stored: ${senderId} -> ${receiverId} (Seq: ${sequenceNumber})`);

    logEvent({
      eventType: 'MESSAGE_SEND',
      status: 'SUCCESS',
      userId: senderId,
      details: { receiverId, sequenceNumber },
      req
    });

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
        nonce: msg.nonce,
        sequenceNumber: msg.sequenceNumber,
        signature: msg.signature,
        timestamp: msg.timestamp
      }))
    });
  } catch (error) {
    next(error);
  }
});

// DELETE /api/messages/:conversationId
// Protected route - requires valid JWT token
// Clears all messages in a conversation
router.delete('/:conversationId', async (req, res, next) => {
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

    // Delete all messages between these two users
    await Message.deleteMany({
      $or: [
        { senderId: userId1, receiverId: userId2 },
        { senderId: userId2, receiverId: userId1 }
      ]
    });

    console.log(`✓ Conversation cleared: ${userId1} <-> ${userId2}`);

    res.json({ message: 'Conversation cleared successfully' });
  } catch (error) {
    next(error);
  }
});

export default router;
