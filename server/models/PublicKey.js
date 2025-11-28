import mongoose from 'mongoose';

/**
 * PublicKey Model
 * 
 * STEP 4: Storage for user identity public keys
 * 
 * Purpose:
 * - Store ONLY public keys (never private keys)
 * - Enable users to retrieve each other's public keys for key exchange
 * - Support signature verification during ECDH protocol
 * 
 * Security Notes:
 * - Public keys are safe to store on server (they're public by design)
 * - Private keys NEVER leave the client device
 * - Each user can have only one active public key (unique userId)
 * 
 * Schema Fields:
 * - userId: Reference to User document
 * - publicKeyJwk: JSON Web Key format (industry standard)
 * - createdAt/updatedAt: Audit trail
 */

const publicKeySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true, // One public key per user
    index: true // Fast lookups by userId
  },
  publicKeyJwk: {
    type: String,
    required: true,
    // Stores the public key in JWK (JSON Web Key) format
    // Example structure:
    // {
    //   "kty": "EC",
    //   "crv": "P-256",
    //   "x": "...",
    //   "y": "...",
    //   "ext": true
    // }
  },
  createdAt: {
    type: Date,
    default: Date.now,
    required: true
  },
  updatedAt: {
    type: Date,
    default: Date.now,
    required: true
  }
});

// Update the updatedAt field before saving
publicKeySchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Index for efficient queries
publicKeySchema.index({ userId: 1 });

const PublicKey = mongoose.model('PublicKey', publicKeySchema);

export default PublicKey;
