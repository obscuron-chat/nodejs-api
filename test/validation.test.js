const assert = require('node:assert/strict');
const test = require('node:test');
const vectors = require('./fixtures/protocol/vectors.json');
const {
  findForbiddenFields,
  validateAvatarUrl,
  validateDisplayName,
  validateEncryptedMessageEnvelope,
  validatePassword,
  validatePublicKeyBundle,
  validateUsername
} = require('../src/validation');

test('username validation follows the lowercase release contract after trim', () => {
  assert.deepEqual(validateUsername(' alice_01 ').details, []);
  for (const value of ['Alice', 'al.ice', 'al-ice', 'ab', 'a'.repeat(33), '   ']) {
    assert.notEqual(validateUsername(value).details.length, 0, value);
  }
});

test('profile and password validation reject unsafe edge cases', () => {
  assert.deepEqual(validatePassword('correct horse battery staple').details, []);
  assert.notEqual(validatePassword('short').details.length, 0);
  assert.notEqual(validatePassword('   '.repeat(6)).details.length, 0);
  assert.deepEqual(validateDisplayName(' Alice ').value, 'Alice');
  assert.notEqual(validateDisplayName('').details.length, 0);
  assert.deepEqual(validateAvatarUrl('https://example.com/a.png').details, []);
  assert.notEqual(validateAvatarUrl('http://example.com/a.png').details.length, 0);
});

test('public key bundle accepts fixture public material and rejects private/vault fields', () => {
  assert.deepEqual(validatePublicKeyBundle(vectors.publicKeyBundle).details, []);
  const invalid = {
    ...vectors.publicKeyBundle,
    signingPrivateKey: vectors.privateKeyPlaintext.signingPrivateKey
  };
  const details = validatePublicKeyBundle(invalid).details;
  assert.ok(details.some((detail) => detail.field === 'publicKeyBundle.signingPrivateKey'));
});

test('encrypted message envelope accepts ciphertext fixture and rejects plaintext or server-owned fields', () => {
  assert.deepEqual(validateEncryptedMessageEnvelope(vectors.encryptedMessageEnvelope).details, []);
  const invalid = {
    ...vectors.encryptedMessageEnvelope,
    plaintextMessage: vectors.signedMessagePayload.transcript.plaintextMessage,
    deliveryState: 'delivered'
  };
  const details = validateEncryptedMessageEnvelope(invalid).details;
  assert.ok(details.some((detail) => detail.field === 'envelope.plaintextMessage'));
  assert.ok(details.some((detail) => detail.field === 'envelope.deliveryState'));
});

test('forbidden field scanner catches nested server-dangerous fields', () => {
  const details = findForbiddenFields({
    nested: {
      encryptedKeyBundle: {},
      token: 'abc',
      body: 'plaintext'
    }
  });
  assert.deepEqual(details.map((detail) => detail.field), ['nested.encryptedKeyBundle', 'nested.token', 'nested.body']);
});
