import mongoose from 'mongoose';

const auditLogSchema = new mongoose.Schema({
    timestamp: {
        type: Date,
        default: Date.now,
        required: true,
        index: true // Indexed for time-based queries
    },
    eventType: {
        type: String,
        required: true,
        enum: [
            'LOGIN_ATTEMPT',
            'REGISTER_ATTEMPT',
            'KEY_UPLOAD',
            'KEY_EXCHANGE_INITIATE',
            'MESSAGE_SEND',
            'REPLAY_DETECTED',
            'SIGNATURE_INVALID',
            'DECRYPTION_FAILURE', // Client-reported
            'METADATA_ACCESS',
            'CLIENT_ERROR'
        ]
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: false // Some events might be anonymous (e.g. failed login)
    },
    username: {
        type: String, // Snapshot of username at time of log
        required: false
    },
    details: {
        type: mongoose.Schema.Types.Mixed, // Flexible object for event-specific data
        required: false
    },
    ipAddress: {
        type: String,
        required: false
    },
    status: {
        type: String,
        enum: ['SUCCESS', 'FAILURE', 'WARNING'],
        required: true
    },
    severity: {
        type: String,
        enum: ['INFO', 'WARNING', 'CRITICAL'],
        default: 'INFO'
    }
});

// Index for filtering by event type and user
auditLogSchema.index({ eventType: 1, userId: 1 });

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

export default AuditLog;
