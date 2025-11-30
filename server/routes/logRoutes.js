import express from 'express';
import { authenticate } from '../middleware/authMiddleware.js';
import { logEvent } from '../utils/logger.js';

const router = express.Router();

// POST /api/logs/client
// Receives logs from the client (e.g. failed decryptions)
router.post('/client', authenticate, async (req, res, next) => {
    try {
        const { eventType, details, severity } = req.body;
        const userId = req.user.userId;

        // Validate allowed event types to prevent spam/abuse
        const ALLOWED_EVENTS = ['DECRYPTION_FAILURE', 'CLIENT_ERROR'];
        if (!ALLOWED_EVENTS.includes(eventType)) {
            return res.status(400).json({ message: 'Invalid event type' });
        }

        logEvent({
            eventType,
            status: 'FAILURE', // Client logs are usually errors
            userId,
            details,
            req,
            severity: severity || 'WARNING'
        });

        res.status(200).json({ message: 'Log received' });
    } catch (error) {
        next(error);
    }
});

export default router;
