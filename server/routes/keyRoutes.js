import express from 'express';
import PublicKey from '../models/PublicKey.js';
import { authenticate } from '../middleware/authMiddleware.js';

/**
 * Key Exchange Routes
 * 
 * STEP 4: API endpoints for public key exchange
 * 
 * Security Requirements:
 * ✓ JWT authentication required for all routes
 * ✓ Store ONLY public keys (never private keys)
 * ✓ Validate key format before storage
 * ✓ One public key per user (update on re-upload)
 * 
 * Routes:
 * - POST /api/keys/upload - Upload user's identity public key
 * - GET /api/keys/:userId - Retrieve a user's public key
 */

const router = express.Router();

/**
 * POST /api/keys/upload
 * 
 * Upload the authenticated user's identity public key
 * 
 * Request body:
 * {
 *   "userId": "user_id",
 *   "publicKeyJwk": "{\"kty\":\"EC\",\"crv\":\"P-256\",...}"
 * }
 * 
 * Authorization: Requires valid JWT token
 * 
 * Security checks:
 * - User must be authenticated
 * - User can only upload their own public key
 * - Key format must be valid JSON
 */
router.post('/upload', authenticate, async (req, res, next) => {
  try {
    const { userId, publicKeyJwk } = req.body;

    // Validation
    if (!userId || !publicKeyJwk) {
      return res.status(400).json({
        message: 'User ID and public key are required'
      });
    }

    // Authorization: User can only upload their own key
    if (req.user.userId !== userId) {
      return res.status(403).json({
        message: 'You can only upload your own public key'
      });
    }

    // Validate JWK format (basic check)
    try {
      const jwkObj = JSON.parse(publicKeyJwk);

      // Basic JWK validation for P-256 EC key
      if (!jwkObj.kty || jwkObj.kty !== 'EC') {
        return res.status(400).json({
          message: 'Invalid key type. Must be EC (Elliptic Curve)'
        });
      }

      if (!jwkObj.crv || jwkObj.crv !== 'P-256') {
        return res.status(400).json({
          message: 'Invalid curve. Must be P-256'
        });
      }

      if (!jwkObj.x || !jwkObj.y) {
        return res.status(400).json({
          message: 'Invalid JWK format. Missing x or y coordinates'
        });
      }
    } catch (parseError) {
      return res.status(400).json({
        message: 'Invalid JWK format. Must be valid JSON'
      });
    }

    // Upsert: Update if exists, create if not
    const publicKey = await PublicKey.findOneAndUpdate(
      { userId },
      {
        userId,
        publicKeyJwk,
        updatedAt: Date.now()
      },
      {
        upsert: true, // Create if doesn't exist
        new: true,    // Return the updated document
        setDefaultsOnInsert: true
      }
    );

    console.log(`✓ Public key uploaded for user: ${userId}`);

    res.status(200).json({
      message: 'Public key uploaded successfully',
      publicKeyId: publicKey._id,
      userId: publicKey.userId
    });
  } catch (error) {
    console.error('Error uploading public key:', error);
    next(error);
  }
});

/**
 * GET /api/keys/:userId
 * 
 * Retrieve a user's identity public key
 * 
 * Path parameter:
 * - userId: The ID of the user whose public key to retrieve
 * 
 * Authorization: Requires valid JWT token
 * 
 * Response:
 * {
 *   "userId": "user_id",
 *   "publicKeyJwk": "{\"kty\":\"EC\",...}",
 *   "createdAt": "2025-11-29T...",
 *   "updatedAt": "2025-11-29T..."
 * }
 * 
 * Security notes:
 * - Public keys are safe to share (they're public by design)
 * - Used for signature verification during key exchange
 * - Authenticated users can retrieve any user's public key
 */
router.get('/:userId', authenticate, async (req, res, next) => {
  try {
    const { userId } = req.params;

    // Validation
    if (!userId) {
      return res.status(400).json({
        message: 'User ID is required'
      });
    }

    // Find public key
    const publicKey = await PublicKey.findOne({ userId });

    if (!publicKey) {
      return res.status(404).json({
        message: 'Public key not found for this user',
        hint: 'User may not have uploaded their public key yet'
      });
    }

    console.log(`✓ Public key retrieved for user: ${userId}`);

    res.json({
      userId: publicKey.userId,
      publicKeyJwk: publicKey.publicKeyJwk,
      createdAt: publicKey.createdAt,
      updatedAt: publicKey.updatedAt
    });
  } catch (error) {
    console.error('Error retrieving public key:', error);
    next(error);
  }
});

/**
 * DELETE /api/keys/:userId
 * 
 * Delete a user's public key (optional - for key rotation or account deletion)
 * 
 * Authorization: User can only delete their own key
 */
router.delete('/:userId', authenticate, async (req, res, next) => {
  try {
    const { userId } = req.params;

    // Authorization: User can only delete their own key
    if (req.user.userId !== userId) {
      return res.status(403).json({
        message: 'You can only delete your own public key'
      });
    }

    const result = await PublicKey.findOneAndDelete({ userId });

    if (!result) {
      return res.status(404).json({
        message: 'Public key not found'
      });
    }

    console.log(`✓ Public key deleted for user: ${userId}`);

    res.json({
      message: 'Public key deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting public key:', error);
    next(error);
  }
});

/**
 * POST /api/keys/exchange/initiate
 * 
 * Initiate key exchange by publishing ephemeral public key
 * Stores ephemeral key exchange data temporarily (in-memory or DB)
 */
const keyExchangeStore = new Map(); // In-memory store for demo

router.post('/exchange/initiate', authenticate, async (req, res, next) => {
  try {
    const { targetUserId, ephemeralPublicKeyJwk, signature, keyConfirmation } = req.body;
    const initiatorUserId = req.user.userId; // Get from JWT token

    if (!targetUserId || !ephemeralPublicKeyJwk || !signature) {
      return res.status(400).json({
        message: 'Target user ID, ephemeral public key, and signature are required'
      });
    }

    // Store exchange data with key: initiator_to_target
    const exchangeKey = `${initiatorUserId}_to_${targetUserId}`;
    keyExchangeStore.set(exchangeKey, {
      initiatorUserId,
      targetUserId,
      ephemeralPublicKeyJwk,
      signature,
      keyConfirmation, // Optional: only present in response
      timestamp: Date.now()
    });

    console.log(`✓ Key exchange initiated: ${initiatorUserId} → ${targetUserId}`);

    res.json({
      message: 'Key exchange data published',
      exchangeKey
    });
  } catch (error) {
    console.error('Error initiating key exchange:', error);
    next(error);
  }
});

/**
 * GET /api/keys/exchange/:fromUserId
 * 
 * Retrieve ephemeral key exchange data from another user
 */
router.get('/exchange/:fromUserId', authenticate, async (req, res, next) => {
  try {
    const fromUserId = req.params.fromUserId;
    const toUserId = req.user.userId; // Get from JWT token

    const exchangeKey = `${fromUserId}_to_${toUserId}`;
    const exchangeData = keyExchangeStore.get(exchangeKey);

    if (!exchangeData) {
      return res.status(404).json({
        message: 'No key exchange data found from this user'
      });
    }

    console.log(`✓ Key exchange data retrieved: ${fromUserId} → ${toUserId}`);

    res.json(exchangeData);
  } catch (error) {
    console.error('Error retrieving key exchange data:', error);
    next(error);
  }
});

/**
 * DELETE /api/keys/exchange/purge
 * 
 * Purge all key exchange data involving the authenticated user.
 * Useful for cleaning up stale data on login or startup.
 */
router.delete('/exchange/purge', authenticate, async (req, res, next) => {
  try {
    const userId = req.user.userId;
    let deletedCount = 0;

    // Iterate over map and delete entries involving this user
    for (const [key, data] of keyExchangeStore.entries()) {
      if (data.initiatorUserId === userId || data.targetUserId === userId) {
        keyExchangeStore.delete(key);
        deletedCount++;
      }
    }

    console.log(`✓ Purged ${deletedCount} stale key exchange entries for user: ${userId}`);

    res.json({
      message: 'Stale key exchange data purged',
      deletedCount
    });
  } catch (error) {
    console.error('Error purging key exchange data:', error);
    next(error);
  }
});

export default router;
