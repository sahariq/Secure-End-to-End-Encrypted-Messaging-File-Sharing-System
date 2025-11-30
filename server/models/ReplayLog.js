import mongoose from 'mongoose';

/**
 * ReplayLog Model
 * 
 * Purpose:
 * - Prevent Replay Attacks by tracking used nonces
 * - Nonces are unique random strings generated for each message
 * - If a nonce is seen again within the validity window, it's a replay
 * 
 * TTL (Time To Live):
 * - Records automatically expire after 5 minutes
 * - This matches the timestamp validity window
 */

const replayLogSchema = new mongoose.Schema({
    nonce: {
        type: String,
        required: true,
        unique: true
    },
    senderId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 300 // 300 seconds = 5 minutes
    }
});

const ReplayLog = mongoose.model('ReplayLog', replayLogSchema);

export default ReplayLog;
