const mongoose = require('mongoose');

const publicKeyBundleSchema = new mongoose.Schema({}, { _id: false, strict: false });

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, immutable: true },
  usernameNormalized: { type: String, required: true, immutable: true },
  passwordHash: { type: String, required: true, select: false },
  displayName: { type: String, required: true },
  avatarUrl: { type: String, default: null },
  publicKeyBundle: { type: publicKeyBundleSchema, required: true },
  retiredPublicKeyBundles: { type: [publicKeyBundleSchema], required: true, default: [] },
  identityVersion: { type: Number, required: true, default: 1 },
  identityResetAt: { type: Date, default: null }
}, { timestamps: true, collection: 'users' });

userSchema.index({ usernameNormalized: 1 }, { unique: true, name: 'uniq_users_username_normalized' });
userSchema.index({ 'publicKeyBundle.fingerprint': 1 }, { name: 'idx_users_public_key_fingerprint' });
userSchema.index({ updatedAt: -1 }, { name: 'idx_users_updated_at' });

function publicUser(user) {
  const source = typeof user.toObject === 'function' ? user.toObject() : user;
  return {
    username: source.username,
    displayName: source.displayName,
    avatarUrl: source.avatarUrl ?? null,
    publicKeyBundle: source.publicKeyBundle,
    identityVersion: source.identityVersion
  };
}

module.exports = {
  User: mongoose.models.User || mongoose.model('User', userSchema),
  publicUser,
  userSchema
};
