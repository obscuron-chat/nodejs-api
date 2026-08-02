const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const fixtureDir = path.join(__dirname, 'fixtures', 'protocol');
const peerFixtureDir = path.join(__dirname, '..', '..', 'obscuron-web', 'src', 'test', 'fixtures', 'protocol');
const fixtureFiles = ['conflict-ledger.json', 'schemas.json', 'vectors.json'];

function readJson(file) {
  return JSON.parse(fs.readFileSync(path.join(fixtureDir, file), 'utf8'));
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function jcs(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
}

function sha3Base64Url(value) {
  return crypto.createHash('sha3-256').update(value).digest('base64url');
}

function validate(schema, value, rootSchemas) {
  if (schema.$ref === 'PublicKeyBundle.v1.json') {
    return validate(rootSchemas.PublicKeyBundle, value, rootSchemas);
  }
  if (schema.const !== undefined) assert.deepEqual(value, schema.const);
  if (schema.enum) assert.ok(schema.enum.includes(value));
  if (schema.type === 'object') {
    assert.equal(typeof value, 'object');
    assert.notEqual(value, null);
    assert.equal(Array.isArray(value), false);
    for (const key of schema.required || []) assert.ok(Object.hasOwn(value, key), `missing ${key}`);
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) assert.ok(Object.hasOwn(schema.properties, key), `unknown ${key}`);
    }
    for (const [key, childSchema] of Object.entries(schema.properties || {})) {
      if (Object.hasOwn(value, key)) validate(childSchema, value[key], rootSchemas);
    }
  }
  if (schema.type === 'string') {
    assert.equal(typeof value, 'string');
    if (schema.minLength !== undefined) assert.ok(value.length >= schema.minLength);
    if (schema.maxLength !== undefined) assert.ok(value.length <= schema.maxLength);
    if (schema.pattern) assert.match(value, new RegExp(schema.pattern));
    if (schema.format === 'date-time') assert.ok(!Number.isNaN(Date.parse(value)));
  }
}

test('fixture manifest hashes match local files and frontend mirror', () => {
  const manifest = readJson('manifest.json');
  for (const file of fixtureFiles) {
    assert.equal(manifest.files[file].sha256, sha256File(path.join(fixtureDir, file)));
    assert.equal(manifest.files[file].sha256, sha256File(path.join(peerFixtureDir, file)));
  }
  const peerManifest = JSON.parse(fs.readFileSync(path.join(peerFixtureDir, 'manifest.json'), 'utf8'));
  assert.deepEqual(manifest.parity, peerManifest.parity);
});

test('conflict ledger freezes username and websocket close-code constants', () => {
  const ledger = readJson('conflict-ledger.json');
  const username = new RegExp(ledger.username.pattern);
  for (const value of ledger.username.accept) assert.match(value.trim(), username);
  for (const value of ledger.username.reject) assert.doesNotMatch(value, username);
  assert.deepEqual(ledger.firstFrameDecisions, {
    noFrameWithinFiveSeconds: 'authenticationTimeout',
    validJsonNonAuthenticateEvent: 'authenticationRequired',
    malformedJson: 'badRequest',
    invalidSchema: 'badRequest'
  });
  assert.equal(ledger.webSocketCloseCodes.authenticationTimeout.code, 4408);
  assert.equal(ledger.webSocketCloseCodes.badRequest.reason, 'bad_request');
  assert.equal(ledger.webSocketCloseCodes.authenticationRequired.code, 4401);
});

test('schemas accept fixture objects and reject forbidden plaintext/private fields', () => {
  const { schemas } = readJson('schemas.json');
  const vectors = readJson('vectors.json');
  validate(schemas.PublicKeyBundle, vectors.publicKeyBundle, schemas);
  validate(schemas.SignedMessagePayload, vectors.signedMessagePayload, schemas);
  validate(schemas.EncryptedMessageEnvelope, vectors.encryptedMessageEnvelope, schemas);
  validate(schemas.EncryptedKeyBundle, vectors.encryptedKeyBundle, schemas);

  assert.throws(() => validate(schemas.EncryptedMessageEnvelope, {
    ...vectors.encryptedMessageEnvelope,
    plaintextMessage: vectors.signedMessagePayload.transcript.plaintextMessage
  }, schemas), /unknown plaintextMessage/);
  assert.throws(() => validate(schemas.EncryptedKeyBundle, {
    ...vectors.encryptedKeyBundle,
    signingPrivateKey: vectors.privateKeyPlaintext.signingPrivateKey
  }, schemas), /unknown signingPrivateKey/);
});

test('JCS, SHA3, key ID, fingerprint, bundle hash, and AAD vectors are stable', () => {
  const vectors = readJson('vectors.json');
  assert.equal(jcs(vectors.cryptoVectors.jcs.input), vectors.cryptoVectors.jcs.canonical);
  assert.equal(`sha3-256:${sha3Base64Url(vectors.cryptoVectors.sha3.plaintext)}`, vectors.cryptoVectors.sha3.messageHash);
  assert.equal(`sha3-256:${sha3Base64Url(jcs(vectors.signedMessagePayload.transcript))}`, `sha3-256:${vectors.cryptoVectors.sha3.transcriptDigest}`);
  assert.equal(`k1_${sha3Base64Url(Buffer.from(vectors.cryptoVectors.keys.signingPublicKey, 'base64url')).slice(0, 22)}`, vectors.cryptoVectors.keys.signingKeyId);
  assert.equal(vectors.publicKeyBundle.fingerprint, vectors.cryptoVectors.keys.publicKeyFingerprint);
  const withoutBundleHash = { ...vectors.encryptedKeyBundle };
  delete withoutBundleHash.bundleHash;
  assert.equal(`sha3-256:${sha3Base64Url(jcs(withoutBundleHash))}`, vectors.encryptedKeyBundle.bundleHash);
  assert.equal(vectors.cryptoVectors.encryption.aadCanonical, jcs({
    version: vectors.encryptedMessageEnvelope.version,
    messageId: vectors.encryptedMessageEnvelope.messageId,
    conversationId: vectors.encryptedMessageEnvelope.conversationId,
    sender: vectors.encryptedMessageEnvelope.sender,
    receiver: vectors.encryptedMessageEnvelope.receiver,
    senderEncryptionKeyId: vectors.encryptedMessageEnvelope.senderEncryptionKeyId,
    receiverEncryptionKeyId: vectors.encryptedMessageEnvelope.receiverEncryptionKeyId,
    senderSigningKeyId: vectors.encryptedMessageEnvelope.senderSigningKeyId,
    senderPublicKeyFingerprint: vectors.encryptedMessageEnvelope.senderPublicKeyFingerprint,
    hkdfSalt: vectors.encryptedMessageEnvelope.hkdfSalt,
    sentAt: vectors.encryptedMessageEnvelope.sentAt
  }));
});
