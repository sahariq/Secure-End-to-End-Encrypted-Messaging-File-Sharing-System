import express from 'express';
import File from '../models/File.js';
import { authenticate } from '../middleware/authMiddleware.js';

const router = express.Router();

// All file routes require authentication
router.use(authenticate);

// POST /api/files/metadata
// Protected route - requires valid JWT token
router.post('/metadata', async (req, res, next) => {
  try {
    // Use authenticated user's ID from token
    const senderId = req.user.userId;
    const { receiverId, filename, filesize, storagePath, timestamp } = req.body;

    // Validation
    if (!receiverId || !filename || !filesize || !storagePath) {
      return res.status(400).json({ 
        message: 'receiverId, filename, filesize, and storagePath are required' 
      });
    }

    // Create file metadata
    const file = new File({
      senderId,
      receiverId,
      filename,
      filesize,
      storagePath,
      timestamp: timestamp || new Date()
    });

    await file.save();

    res.status(201).json({
      message: 'File metadata stored successfully',
      fileId: file._id,
      filename: file.filename,
      timestamp: file.timestamp
    });
  } catch (error) {
    next(error);
  }
});

// GET /api/files/:id/metadata
// Protected route - requires valid JWT token
router.get('/:id/metadata', async (req, res, next) => {
  try {
    const { id } = req.params;
    const currentUserId = req.user.userId;

    const file = await File.findById(id)
      .populate('senderId', 'username')
      .populate('receiverId', 'username');

    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Verify that the authenticated user is the sender or receiver
    const senderIdStr = file.senderId._id?.toString() || file.senderId.toString();
    const receiverIdStr = file.receiverId._id?.toString() || file.receiverId.toString();
    
    if (currentUserId !== senderIdStr && currentUserId !== receiverIdStr) {
      return res.status(403).json({ 
        message: 'Access denied. You do not have permission to view this file.' 
      });
    }

    res.json({
      id: file._id,
      senderId: file.senderId._id || file.senderId,
      senderUsername: file.senderId.username || null,
      receiverId: file.receiverId._id || file.receiverId,
      receiverUsername: file.receiverId.username || null,
      filename: file.filename,
      filesize: file.filesize,
      storagePath: file.storagePath,
      timestamp: file.timestamp
    });
  } catch (error) {
    next(error);
  }
});

export default router;

