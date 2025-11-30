import AuditLog from '../models/AuditLog.js';

/**
 * Log a security event to the database and console
 * 
 * @param {Object} params - Log parameters
 * @param {string} params.eventType - Type of event (e.g., LOGIN_ATTEMPT)
 * @param {string} params.status - SUCCESS, FAILURE, or WARNING
 * @param {string} [params.userId] - ID of the user involved
 * @param {string} [params.username] - Username of the user involved
 * @param {Object} [params.details] - Additional context
 * @param {Object} [params.req] - Express request object (to extract IP)
 * @param {string} [params.severity] - INFO, WARNING, CRITICAL
 */
export const logEvent = async ({
    eventType,
    status,
    userId = null,
    username = null,
    details = {},
    req = null,
    severity = 'INFO'
}) => {
    try {
        // Extract IP address if request object is provided
        let ipAddress = null;
        if (req) {
            ipAddress = req.ip || req.connection.remoteAddress;
        }

        // Console logging (for immediate feedback)
        const logMessage = `[${new Date().toISOString()}] [${eventType}] [${status}] ${username || userId || 'Anonymous'} - ${JSON.stringify(details)}`;
        if (severity === 'CRITICAL' || status === 'FAILURE') {
            console.error(logMessage);
        } else if (severity === 'WARNING') {
            console.warn(logMessage);
        } else {
            console.log(logMessage);
        }

        // Database logging (async, don't await to avoid blocking response)
        AuditLog.create({
            eventType,
            status,
            userId,
            username,
            details,
            ipAddress,
            severity
        }).catch(err => {
            console.error('Failed to write audit log to DB:', err);
        });

    } catch (error) {
        console.error('Logger error:', error);
    }
};
