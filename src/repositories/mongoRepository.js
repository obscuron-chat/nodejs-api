const { EncryptedMessage, RefreshSession, User } = require('../models');
const { storedEnvelope } = require('../models/encryptedMessage');

function createMongoRepository(mongo, models = { EncryptedMessage, RefreshSession, User }) {
  const EncryptedMessageModel = models.EncryptedMessage;
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
    },

    async storeEncryptedMessage(envelope, { now, expiresAt }) {
      const document = {
        ...envelope,
        sentAt: new Date(envelope.sentAt),
        serverReceivedAt: now,
        deliveredAt: null,
        deliveryState: 'stored',
        expiresAt
      };
      try {
        const [created] = await EncryptedMessageModel.create([document]);
        return { status: 'stored', message: storedEnvelope(created), duplicate: false };
      } catch (error) {
        if (!error || error.code !== 11000) throw error;
        const existing = await EncryptedMessageModel.findOne({ messageId: envelope.messageId }).lean();
        if (existing && encryptedEnvelopeMatches(existing, envelope)) {
          return { status: 'stored', message: originalAckEnvelope(existing), duplicate: true };
        }
        return { status: 'conflict', message: existing ? storedEnvelope(existing) : null, duplicate: false };
      }
    },

    async markMessageDelivered(username, messageId, now) {
      const transitioned = await EncryptedMessageModel.findOneAndUpdate(
        { messageId, receiver: username, deliveryState: 'stored' },
        { $set: { deliveredAt: now, deliveryState: 'delivered' } },
        { new: true }
      ).lean();
      if (transitioned) return storedEnvelope(transitioned);
      const existing = await EncryptedMessageModel.findOne({ messageId, receiver: username, deliveryState: 'delivered', deliveredAt: { $ne: null } }).lean();
      return existing ? storedEnvelope(existing) : null;
    },

    async listMessagesForParticipant(username, peer, { limit, cursor, now, order = 'desc' } = {}) {
      const query = {
        expiresAt: { $gt: now },
        $or: [
          { sender: username, receiver: peer },
          { sender: peer, receiver: username }
        ]
      };
      addCursorQuery(query, cursor, order);
      const messages = await EncryptedMessageModel.find(query)
        .sort(order === 'desc' ? { serverReceivedAt: -1, sentAt: -1, messageId: -1 } : { serverReceivedAt: 1, sentAt: 1, messageId: 1 })
        .limit(limit)
        .lean();
      return messages.map(storedEnvelope);
    },

    async listUndeliveredMessages(username, { limit, cursor, now, order = 'asc' } = {}) {
      const query = { receiver: username, expiresAt: { $gt: now } };
      addCursorQuery(query, cursor, order);
      const messages = await EncryptedMessageModel.find(query)
        .sort(order === 'desc' ? { serverReceivedAt: -1, sentAt: -1, messageId: -1 } : { serverReceivedAt: 1, sentAt: 1, messageId: 1 })
        .limit(limit)
        .lean();
      return messages.map(storedEnvelope);
    },

    async listDeliveryReceiptsForSender(username, { limit, cursor, now, order = 'asc' } = {}) {
      const query = { sender: username, deliveryState: 'delivered', deliveredAt: { $ne: null }, expiresAt: { $gt: now } };
      addDeliveryCursorQuery(query, cursor, order);
      const messages = await EncryptedMessageModel.find(query)
        .sort(order === 'desc' ? { deliveredAt: -1, messageId: -1 } : { deliveredAt: 1, messageId: 1 })
        .limit(limit)
        .lean();
      return messages.map(storedEnvelope);
    },

    async findReplayCursorMessage(username, cursor, now) {
      if (cursor.event === 'high_water') return cursor.serverReceivedAt <= now ? { highWater: true } : null;
      const timeField = cursor.event === 'delivery' ? 'deliveredAt' : 'serverReceivedAt';
      const message = await EncryptedMessageModel.findOne({
        messageId: cursor.messageId,
        [timeField]: cursor.serverReceivedAt,
        expiresAt: { $gt: now },
        $or: [{ sender: username }, { receiver: username }]
      }).lean();
      return message ? storedEnvelope(message) : null;
    },

    async findHistoryCursorMessage(username, peer, cursor, now) {
      const message = await EncryptedMessageModel.findOne({
        messageId: cursor.messageId,
        serverReceivedAt: cursor.serverReceivedAt,
        expiresAt: { $gt: now },
        $or: [
          { sender: username, receiver: peer },
          { sender: peer, receiver: username }
        ]
      }).lean();
      return message ? storedEnvelope(message) : null;
    }
  };

  async function hasRevokedFamilyMarker(tokenFamilyId) {
    return Boolean(await RefreshSessionModel.findOne({ tokenFamilyId, revokedAt: { $ne: null } }).lean());
  }
}

function encryptedEnvelopeMatches(existing, envelope) {
  return [
    'version',
    'messageId',
    'conversationId',
    'sender',
    'receiver',
    'senderEncryptionKeyId',
    'receiverEncryptionKeyId',
    'senderSigningKeyId',
    'senderPublicKeyFingerprint',
    'hkdfSalt',
    'nonce',
    'ciphertext'
  ].every((key) => existing[key] === envelope[key])
    && dateIso(existing.sentAt) === new Date(envelope.sentAt).toISOString();
}

function dateIso(value) {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function originalAckEnvelope(message) {
  return { ...storedEnvelope(message), deliveredAt: null, deliveryState: 'stored' };
}

function addCursorQuery(query, cursor, order) {
  if (!cursor) return;
  const direction = order === 'desc' ? '$lt' : '$gt';
  query.$and = [{
    $or: [
      { serverReceivedAt: { [direction]: cursor.serverReceivedAt } },
      { serverReceivedAt: cursor.serverReceivedAt, sentAt: { [direction]: cursor.sentAt || new Date(0) } },
      { serverReceivedAt: cursor.serverReceivedAt, sentAt: cursor.sentAt || new Date(0), messageId: { [direction]: cursor.messageId } }
    ]
  }];
}

function addDeliveryCursorQuery(query, cursor, order) {
  if (!cursor) return;
  const direction = order === 'desc' ? '$lt' : '$gt';
  query.$and = [{
    $or: [
      { deliveredAt: { [direction]: cursor.serverReceivedAt } },
      { deliveredAt: cursor.serverReceivedAt, messageId: { [direction]: cursor.messageId } }
    ]
  }];
}

module.exports = {
  createMongoRepository
};
