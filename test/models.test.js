const assert = require('node:assert/strict');
const test = require('node:test');
const vectors = require('./fixtures/protocol/vectors.json');
const { encryptedMessageSchema, storedEnvelope } = require('../src/models/encryptedMessage');
const { refreshSessionSchema } = require('../src/models/refreshSession');
const { publicUser, userSchema } = require('../src/models/user');

function indexMap(schema) {
  return new Map(schema.indexes().map(([fields, options]) => [options.name, { fields, options }]));
}

test('users model defines required named indexes and safe serializer', () => {
  const indexes = indexMap(userSchema);
  assert.deepEqual(indexes.get('uniq_users_username_normalized').fields, { usernameNormalized: 1 });
  assert.equal(indexes.get('uniq_users_username_normalized').options.unique, true);
  assert.deepEqual(indexes.get('idx_users_public_key_fingerprint').fields, { 'publicKeyBundle.fingerprint': 1 });
  assert.deepEqual(indexes.get('idx_users_updated_at').fields, { updatedAt: -1 });

  const serialized = publicUser({
    _id: 'internal',
    __v: 1,
    username: 'alice',
    usernameNormalized: 'alice',
    passwordHash: 'hash',
    displayName: 'Alice',
    avatarUrl: null,
    publicKeyBundle: vectors.publicKeyBundle,
    retiredPublicKeyBundles: [],
    identityVersion: 1
  });
  assert.deepEqual(Object.keys(serialized), ['username', 'displayName', 'avatarUrl', 'publicKeyBundle', 'identityVersion']);
});

test('refresh_sessions model defines required named indexes including TTL', () => {
  const indexes = indexMap(refreshSessionSchema);
  assert.deepEqual(indexes.get('uniq_refresh_sessions_token_hash').fields, { tokenHash: 1 });
  assert.equal(indexes.get('uniq_refresh_sessions_token_hash').options.unique, true);
  assert.deepEqual(indexes.get('idx_refresh_sessions_user_active').fields, { userId: 1, revokedAt: 1, expiresAt: 1 });
  assert.deepEqual(indexes.get('idx_refresh_sessions_family').fields, { tokenFamilyId: 1, createdAt: -1 });
  assert.deepEqual(indexes.get('ttl_refresh_sessions_expires_at').fields, { expiresAt: 1 });
  assert.equal(indexes.get('ttl_refresh_sessions_expires_at').options.expireAfterSeconds, 0);
});

test('encrypted_messages model defines required named indexes and serializer excludes internals', () => {
  const indexes = indexMap(encryptedMessageSchema);
  assert.deepEqual(indexes.get('uniq_encrypted_messages_message_id').fields, { messageId: 1 });
  assert.equal(indexes.get('uniq_encrypted_messages_message_id').options.unique, true);
  assert.deepEqual(indexes.get('idx_encrypted_messages_conversation_time').fields, { conversationId: 1, serverReceivedAt: -1, messageId: 1 });
  assert.deepEqual(indexes.get('idx_encrypted_messages_receiver_delivery').fields, { receiver: 1, deliveryState: 1, serverReceivedAt: 1 });
  assert.deepEqual(indexes.get('idx_encrypted_messages_sender_time').fields, { sender: 1, serverReceivedAt: -1 });
  assert.equal(indexes.get('ttl_encrypted_messages_expires_at').options.expireAfterSeconds, 0);

  const stored = storedEnvelope({
    _id: 'internal',
    __v: 1,
    ...vectors.encryptedMessageEnvelope,
    sentAt: new Date(vectors.encryptedMessageEnvelope.sentAt),
    serverReceivedAt: new Date('2026-08-02T00:00:01.000Z'),
    deliveredAt: null,
    deliveryState: 'stored',
    expiresAt: new Date('2026-10-31T00:00:01.000Z')
  });
  assert.deepEqual(Object.keys(stored), [
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
    'ciphertext',
    'sentAt',
    'serverReceivedAt',
    'deliveredAt',
    'deliveryState',
    'expiresAt'
  ]);
});
