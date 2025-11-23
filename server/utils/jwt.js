import jwt from 'jsonwebtoken';

/**
 * Generate a JWT token for a user
 * @param {string} userId - The user's MongoDB ObjectId
 * @returns {string} JWT token
 */
export const generateJWT = (userId) => {
  const secret = process.env.JWT_SECRET;
  
  if (!secret) {
    throw new Error('JWT_SECRET is not defined in environment variables');
  }

  const payload = {
    userId: userId.toString(),
    iat: Math.floor(Date.now() / 1000)
  };

  // Token expires in 7 days
  const options = {
    expiresIn: '7d',
    algorithm: 'HS256'
  };

  return jwt.sign(payload, secret, options);
};

/**
 * Verify and decode a JWT token
 * @param {string} token - The JWT token to verify
 * @returns {object} Decoded token payload
 * @throws {Error} If token is invalid or expired
 */
export const verifyJWT = (token) => {
  const secret = process.env.JWT_SECRET;
  
  if (!secret) {
    throw new Error('JWT_SECRET is not defined in environment variables');
  }

  try {
    const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
    return decoded;
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Token has expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid token');
    } else {
      throw new Error('Token verification failed');
    }
  }
};

