import { verifyJWT } from '../utils/jwt.js';

/**
 * Authentication middleware to verify JWT tokens
 * Attaches user information to req.user if token is valid
 * Returns 401 if token is missing or invalid
 */
export const authenticate = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        message: 'Authentication required. Please provide a valid token.' 
      });
    }

    // Extract token (remove 'Bearer ' prefix)
    const token = authHeader.substring(7);

    if (!token) {
      return res.status(401).json({ 
        message: 'Authentication required. Token is missing.' 
      });
    }

    // Verify token
    const decoded = verifyJWT(token);

    // Attach user info to request object
    req.user = {
      userId: decoded.userId
    };

    next();
  } catch (error) {
    return res.status(401).json({ 
      message: error.message || 'Authentication failed. Invalid or expired token.' 
    });
  }
};

