import express from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import File from '../models/File.js';
import { authenticate } from '../middleware/authMiddleware.js';

const router = express.Router();

// Configure Multer for disk storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    // Ensure upload directory exists
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate unique filename: timestamp-random-originalName
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 50 * 1024 * 1024 // Limit to 50MB for prototype safety
  }
});

// All file routes require authentication
router.use(authenticate);

// POST /api/files/upload
// Uploads an encrypted file blob
router.post('/upload', upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const senderId = req.user.userId;
    const { receiverId } = req.body;

    if (!receiverId) {
      // Clean up uploaded file if validation fails
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ message: 'receiverId is required' });
    }

    // Create file record in DB
    const file = new File({
      senderId,
      receiverId,
      filename: req.file.originalname, // This will be "encrypted_blob" or similar
      filesize: req.file.size,
      storagePath: req.file.path,
      timestamp: new Date()
    });

    await file.save();

    res.status(201).json({
      message: 'File uploaded successfully',
      fileId: file._id,
      filename: file.filename,
      size: file.filesize
    });
  } catch (error) {
    // Clean up file if DB save fails
    if (req.file && req.file.path) {
      fs.unlinkSync(req.file.path);
    }
    next(error);
  }
});

// GET /api/files/:id
// Downloads the encrypted file blob
router.get('/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const currentUserId = req.user.userId;

    const file = await File.findById(id);

    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Verify permissions
    const senderIdStr = file.senderId.toString();
    const receiverIdStr = file.receiverId.toString();

    if (currentUserId !== senderIdStr && currentUserId !== receiverIdStr) {
      return res.status(403).json({
        message: 'Access denied. You do not have permission to download this file.'
      });
    }

    // Check if file exists on disk
    if (!fs.existsSync(file.storagePath)) {
      return res.status(404).json({ message: 'File not found on server disk' });
    }

    // Stream file to client
    res.download(file.storagePath, file.filename);
  } catch (error) {
    next(error);
  }
});

export default router;
