import mongoose from 'mongoose';

/**
 * ConversationState Model
 * 
 * Purpose:
 * - Prevent Replay and Reordering Attacks using Sequence Numbers
 * - Tracks the last processed sequence number for each direction of a conversation
 * 
 * Logic:
 * - For a given (senderId, receiverId) pair, sequence numbers must be strictly increasing
 * - If received sequenceNumber <= lastSequenceNumber, it's a replay or old message -> REJECT
 */

const conversationStateSchema = new mongoose.Schema({
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
    lastSequenceNumber: {
        type: Number,
        required: true,
        default: 0
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Ensure unique state per direction
conversationStateSchema.index({ senderId: 1, receiverId: 1 }, { unique: true });

const ConversationState = mongoose.model('ConversationState', conversationStateSchema);

export default ConversationState;
