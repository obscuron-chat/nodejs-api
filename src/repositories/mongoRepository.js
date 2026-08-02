const { RefreshSession, User } = require('../models');

function createMongoRepository(mongo, models = { RefreshSession, User }) {
  const RefreshSessionModel = models.RefreshSession;
  const UserModel = models.User;

  function normalizeUser(user) {
    if (!user) return null;
    const object = typeof user.toObject === 'function' ? user.toObject() : user;
    return { ...object, id: String(object._id || object.id) };
  }

  return {
    async findUserByUsername(username, { includePasswordHash = false } = {}) {
      let query = UserModel.findOne({ usernameNormalized: username });
      if (includePasswordHash) query = query.select('+passwordHash');
      return normalizeUser(await query.lean());
    },

    async createUser(user) {
      try {
        const [created] = await UserModel.create([user]);
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
      return normalizeUser(await UserModel.findOneAndUpdate({ usernameNormalized: username }, { $set: update }, { new: true }).lean());
    },

    async listPublicUsersExcept(username) {
      return (await UserModel.find({ usernameNormalized: { $ne: username } }).lean()).map(normalizeUser);
    },

    async resetIdentity(username, publicKeyBundle, now) {
      return normalizeUser(await UserModel.findOneAndUpdate(
        { usernameNormalized: username },
        [
          {
            $set: {
              retiredPublicKeyBundles: {
                $concatArrays: [
                  { $ifNull: ['$retiredPublicKeyBundles', []] },
                  ['$publicKeyBundle']
                ]
              },
              publicKeyBundle,
              identityVersion: { $add: ['$identityVersion', 1] },
              identityResetAt: now,
              updatedAt: now
            }
          }
        ],
        { new: true }
      ).lean());
    },

    async createRefreshSession(session) {
      const [created] = await RefreshSessionModel.create([session]);
      return created.toObject();
    },

    async findRefreshSessionByHash(tokenHash) {
      return RefreshSessionModel.findOne({ tokenHash }).lean();
    },

    async rotateRefreshSession({ tokenHash, replacedByTokenHash, nextSession, now }) {
      const existing = await RefreshSessionModel.findOne({ tokenHash }).lean();
      if (!existing || await hasRevokedFamilyMarker(existing.tokenFamilyId)) return null;
      const current = await RefreshSessionModel.findOneAndUpdate(
        { tokenHash, revokedAt: null, replacedByTokenHash: null, expiresAt: { $gt: now } },
        { $set: { replacedByTokenHash, lastUsedAt: now } },
        { new: true }
      ).lean();
      if (!current) return null;
      try {
        const [created] = await RefreshSessionModel.create([nextSession]);
        if (await hasRevokedFamilyMarker(current.tokenFamilyId)) {
          await this.revokeRefreshFamily(current.tokenFamilyId, now);
          return null;
        }
        return created.toObject();
      } catch (error) {
        await this.revokeRefreshFamily(current.tokenFamilyId, now);
        throw error;
      }
    },

    async revokeRefreshFamily(tokenFamilyId, now) {
      await RefreshSessionModel.findOneAndUpdate(
        { tokenFamilyId },
        { $set: { revokedAt: now } },
        { sort: { createdAt: 1 }, new: true }
      ).lean();
      await RefreshSessionModel.updateMany(
        { tokenFamilyId, revokedAt: null },
        { $set: { revokedAt: now } }
      );
    }
  };

  async function hasRevokedFamilyMarker(tokenFamilyId) {
    return Boolean(await RefreshSessionModel.findOne({ tokenFamilyId, revokedAt: { $ne: null } }).lean());
  }
}

module.exports = {
  createMongoRepository
};
