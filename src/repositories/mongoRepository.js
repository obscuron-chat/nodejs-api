const { RefreshSession, User } = require('../models');

function createMongoRepository(mongo) {
  function normalizeUser(user) {
    if (!user) return null;
    const object = typeof user.toObject === 'function' ? user.toObject() : user;
    return { ...object, id: String(object._id || object.id) };
  }

  return {
    async findUserByUsername(username, { includePasswordHash = false } = {}) {
      let query = User.findOne({ usernameNormalized: username });
      if (includePasswordHash) query = query.select('+passwordHash');
      return normalizeUser(await query.lean());
    },

    async createUser(user) {
      try {
        const [created] = await User.create([user]);
        return normalizeUser(created);
      } catch (error) {
        if (error && error.code === 11000) {
          const duplicate = new Error('duplicate user');
          duplicate.code = 'DUPLICATE_USER';
          throw duplicate;
        }
        throw error;
      }
    },

    async updateUserProfile(username, patch) {
      const update = {};
      if (patch.displayName !== undefined) update.displayName = patch.displayName;
      if (patch.avatarUrl !== undefined) update.avatarUrl = patch.avatarUrl;
      return normalizeUser(await User.findOneAndUpdate({ usernameNormalized: username }, { $set: update }, { new: true }).lean());
    },

    async listPublicUsersExcept(username) {
      return (await User.find({ usernameNormalized: { $ne: username } }).lean()).map(normalizeUser);
    },

    async resetIdentity(username, publicKeyBundle, now) {
      const user = await User.findOne({ usernameNormalized: username }).lean();
      if (!user) return null;
      return normalizeUser(await User.findOneAndUpdate(
        { usernameNormalized: username },
        {
          $set: {
            publicKeyBundle,
            identityVersion: user.identityVersion + 1,
            identityResetAt: now
          },
          $push: { retiredPublicKeyBundles: user.publicKeyBundle }
        },
        { new: true }
      ).lean());
    },

    async createRefreshSession(session) {
      const [created] = await RefreshSession.create([session]);
      return created.toObject();
    },

    async findRefreshSessionByHash(tokenHash) {
      return RefreshSession.findOne({ tokenHash }).lean();
    },

    async rotateRefreshSession({ tokenHash, replacedByTokenHash, nextSession, now }) {
      return mongo.connection.transaction(async (session) => {
        const current = await RefreshSession.findOneAndUpdate(
          { tokenHash, revokedAt: null, replacedByTokenHash: null, expiresAt: { $gt: now } },
          { $set: { replacedByTokenHash, lastUsedAt: now } },
          { new: true, session }
        ).lean();
        if (!current) return null;
        const [created] = await RefreshSession.create([nextSession], { session });
        return created.toObject();
      });
    },

    async revokeRefreshFamily(tokenFamilyId, now) {
      await RefreshSession.updateMany(
        { tokenFamilyId, revokedAt: null },
        { $set: { revokedAt: now } }
      );
    }
  };
}

module.exports = {
  createMongoRepository
};
