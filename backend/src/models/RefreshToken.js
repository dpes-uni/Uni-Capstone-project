const mongoose = require('mongoose');
const crypto = require('crypto');

const refreshTokenSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    // Store only a hash of the opaque refresh token (never the raw token).
    tokenHash: { type: String, required: true, select: false },
    ip: { type: String },
    userAgent: { type: String },
    expiresAt: { type: Date, required: true, index: { expires: 0 } },
    revoked: { type: Boolean, default: false },
    revokedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

refreshTokenSchema.index({ user: 1, revoked: 1, expiresAt: 1 });

/**
 * Issue a new opaque refresh token for a user, persisting its hash.
 * Returns the raw token (to hand to the client via cookie) and the saved doc.
 */
refreshTokenSchema.statics.issue = async function issue(userId, { ip, userAgent, expiresInMs }) {
  const raw = crypto.randomBytes(48).toString('hex');
  const doc = await this.create({
    user: userId,
    tokenHash: crypto.createHash('sha256').update(raw).digest('hex'),
    ip,
    userAgent,
    expiresAt: new Date(Date.now() + expiresInMs),
  });
  return { rawToken: raw, doc };
};

/**
 * Consume (rotate) a refresh token: verify, revoke it, and return the user.
 * Returns null if the token is invalid, expired, or revoked.
 */
refreshTokenSchema.statics.consume = async function consume(rawToken) {
  if (!rawToken) return null;
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  const token = await this.findOne({
    tokenHash,
    revoked: false,
    expiresAt: { $gt: new Date() },
  }).select('+tokenHash');

  if (!token) return null;

  token.revoked = true;
  token.revokedAt = new Date();
  await token.save();

  return token;
};

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);
