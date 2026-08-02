const mongoose = require('mongoose');

const refreshSessionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  usernameNormalized: { type: String, required: true },
  tokenHash: { type: String, required: true },
  tokenFamilyId: { type: String, required: true },
  sessionId: { type: String, required: true },
  lastUsedAt: { type: Date, required: true },
  expiresAt: { type: Date, required: true },
  revokedAt: { type: Date, default: null },
  replacedByTokenHash: { type: String, default: null },
  ipHash: { type: String, default: null },
  userAgentHash: { type: String, default: null }
}, { timestamps: { createdAt: true, updatedAt: false }, collection: 'refresh_sessions' });

refreshSessionSchema.index({ tokenHash: 1 }, { unique: true, name: 'uniq_refresh_sessions_token_hash' });
refreshSessionSchema.index({ userId: 1, revokedAt: 1, expiresAt: 1 }, { name: 'idx_refresh_sessions_user_active' });
refreshSessionSchema.index({ tokenFamilyId: 1, createdAt: -1 }, { name: 'idx_refresh_sessions_family' });
refreshSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, name: 'ttl_refresh_sessions_expires_at' });

module.exports = {
  RefreshSession: mongoose.models.RefreshSession || mongoose.model('RefreshSession', refreshSessionSchema),
  refreshSessionSchema
};
