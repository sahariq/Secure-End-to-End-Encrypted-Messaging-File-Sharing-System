import mongoose from 'mongoose';

const fileSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  receiverId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  filename: {
    type: String,
    required: true
  },
  filesize: {
    type: Number,
    required: true
  },
  storagePath: {
    type: String,
    required: true
    // Path where the encrypted file is stored
  },
  timestamp: {
    type: Date,
    default: Date.now,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index for efficient querying
fileSchema.index({ senderId: 1, receiverId: 1, timestamp: -1 });
fileSchema.index({ receiverId: 1, senderId: 1, timestamp: -1 });

const File = mongoose.model('File', fileSchema);

export default File;

