const USERNAME_PATTERN = /^[a-z0-9_]{3,32}$/;
const KEY_ID_PATTERN = /^k1_[A-Za-z0-9_-]{22}$/;
const BASE64URL_43 = /^[A-Za-z0-9_-]{43}$/;
const FORBIDDEN_SERVER_FIELDS = new Set([
  'encryptedKeyBundle',
  'privateKey',
  'signingPrivateKey',
  'encryptionPrivateKey',
  'plaintext',
  'plaintextMessage',
  'message',
  'text',
  'body',
  'preview',
  'hashed_message',
  'hash',
  'password',
  'token',
  'refreshToken',
  'accessToken'
]);

function normalizeUsername(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function validateUsername(value, field = 'username') {
  const username = normalizeUsername(value);
  return USERNAME_PATTERN.test(username) ? { value: username, details: [] } : {
    value: username,
    details: [{ field, reason: 'Must match ^[a-z0-9_]{3,32}$.' }]
  };
}

function validatePassword(value, field = 'password') {
  if (typeof value !== 'string' || value.trim() === '' || [...value].length < 12 || [...value].length > 128) {
    return { details: [{ field, reason: 'Must be 12-128 non-whitespace Unicode characters.' }] };
  }
  return { details: [] };
}

function validateDisplayName(value, field = 'displayName') {
  const displayName = typeof value === 'string' ? value.trim() : '';
  const length = [...displayName].length;
  return length >= 1 && length <= 80 ? { value: displayName, details: [] } : {
    value: displayName,
    details: [{ field, reason: 'Must be 1-80 displayed characters.' }]
  };
}

function validateAvatarUrl(value, field = 'avatarUrl') {
  if (value === undefined || value === null || value === '') return { value: null, details: [] };
  if (typeof value !== 'string' || Buffer.byteLength(value) > 2048) {
    return { value, details: [{ field, reason: 'Must be an HTTPS URL up to 2048 bytes.' }] };
  }
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:') throw new Error('not https');
    return { value, details: [] };
  } catch {
    return { value, details: [{ field, reason: 'Must be an absolute HTTPS URL.' }] };
  }
}

function findForbiddenFields(value, path = '') {
  if (!value || typeof value !== 'object') return [];
  const details = [];
  for (const [key, child] of Object.entries(value)) {
    const childPath = path ? `${path}.${key}` : key;
    if (FORBIDDEN_SERVER_FIELDS.has(key)) details.push({ field: childPath, reason: 'Field is not accepted by this server contract.' });
    details.push(...findForbiddenFields(child, childPath));
  }
  return details;
}

function requireObject(value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return [{ field, reason: 'Must be an object.' }];
  }
  return [];
}

function exactKeys(value, allowed, required, field) {
  const details = [];
  for (const key of required) {
    if (!Object.hasOwn(value, key)) details.push({ field: `${field}.${key}`, reason: 'Is required.' });
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) details.push({ field: `${field}.${key}`, reason: 'Unknown field.' });
  }
  return details;
}

function validatePublicKeyBundle(bundle, field = 'publicKeyBundle') {
  let details = requireObject(bundle, field);
  if (details.length > 0) return { details };
  details = details.concat(findForbiddenFields(bundle, field));
  details = details.concat(exactKeys(bundle, ['version', 'userId', 'createdAt', 'signingKey', 'encryptionKey', 'fingerprint'], ['version', 'userId', 'createdAt', 'signingKey', 'encryptionKey', 'fingerprint'], field));
  if (bundle.version !== 1) details.push({ field: `${field}.version`, reason: 'Must be 1.' });
  if (typeof bundle.userId !== 'string' || bundle.userId.length < 1 || bundle.userId.length > 128) details.push({ field: `${field}.userId`, reason: 'Must be 1-128 characters.' });
  if (Number.isNaN(Date.parse(bundle.createdAt))) details.push({ field: `${field}.createdAt`, reason: 'Must be an RFC 3339 timestamp.' });
  details = details.concat(validateKey(bundle.signingKey, `${field}.signingKey`, 'ECDSA-secp256k1-SHA3-256', /^[A-Za-z0-9_-]{44}$/));
  details = details.concat(validateKey(bundle.encryptionKey, `${field}.encryptionKey`, 'X25519-HKDF-SHA-256-AES-256-GCM', /^[A-Za-z0-9_-]{43}$/));
  if (typeof bundle.fingerprint !== 'string' || !/^sha3-256:[A-Za-z0-9_-]{43}$/.test(bundle.fingerprint)) {
    details.push({ field: `${field}.fingerprint`, reason: 'Must be a sha3-256 base64url fingerprint.' });
  }
  return { details };
}

function validateKey(key, field, algorithm, publicKeyPattern) {
  let details = requireObject(key, field);
  if (details.length > 0) return details;
  details = details.concat(exactKeys(key, ['keyId', 'algorithm', 'publicKey'], ['keyId', 'algorithm', 'publicKey'], field));
  if (typeof key.keyId !== 'string' || !KEY_ID_PATTERN.test(key.keyId)) details.push({ field: `${field}.keyId`, reason: 'Invalid key id.' });
  if (key.algorithm !== algorithm) details.push({ field: `${field}.algorithm`, reason: `Must be ${algorithm}.` });
  if (typeof key.publicKey !== 'string' || !publicKeyPattern.test(key.publicKey) || Buffer.byteLength(key.publicKey) > 8192) {
    details.push({ field: `${field}.publicKey`, reason: 'Invalid public key encoding.' });
  }
  return details;
}

function validateEncryptedMessageEnvelope(envelope, field = 'envelope') {
  let details = requireObject(envelope, field);
  if (details.length > 0) return { details };
  const required = ['version', 'messageId', 'conversationId', 'sender', 'receiver', 'senderEncryptionKeyId', 'receiverEncryptionKeyId', 'senderSigningKeyId', 'senderPublicKeyFingerprint', 'hkdfSalt', 'nonce', 'ciphertext', 'sentAt'];
  details = details.concat(findForbiddenFields(envelope, field));
  details = details.concat(exactKeys(envelope, required, required, field));
  if (envelope.version !== 1) details.push({ field: `${field}.version`, reason: 'Must be 1.' });
  if (typeof envelope.messageId !== 'string' || !/^msg_[A-Za-z0-9_-]{26,64}$/.test(envelope.messageId)) details.push({ field: `${field}.messageId`, reason: 'Invalid message id.' });
  if (typeof envelope.conversationId !== 'string' || !/^conv_[A-Za-z0-9_-]{16,64}$/.test(envelope.conversationId)) details.push({ field: `${field}.conversationId`, reason: 'Invalid conversation id.' });
  details = details.concat(validateUsername(envelope.sender, `${field}.sender`).details, validateUsername(envelope.receiver, `${field}.receiver`).details);
  for (const key of ['senderEncryptionKeyId', 'receiverEncryptionKeyId', 'senderSigningKeyId']) {
    if (typeof envelope[key] !== 'string' || !KEY_ID_PATTERN.test(envelope[key])) details.push({ field: `${field}.${key}`, reason: 'Invalid key id.' });
  }
  if (typeof envelope.senderPublicKeyFingerprint !== 'string' || !/^sha3-256:[A-Za-z0-9_-]{43}$/.test(envelope.senderPublicKeyFingerprint)) {
    details.push({ field: `${field}.senderPublicKeyFingerprint`, reason: 'Invalid fingerprint.' });
  }
  if (typeof envelope.hkdfSalt !== 'string' || !BASE64URL_43.test(envelope.hkdfSalt)) details.push({ field: `${field}.hkdfSalt`, reason: 'Invalid HKDF salt.' });
  if (typeof envelope.nonce !== 'string' || !/^[A-Za-z0-9_-]{16}$/.test(envelope.nonce)) details.push({ field: `${field}.nonce`, reason: 'Invalid nonce.' });
  if (typeof envelope.ciphertext !== 'string' || !/^[A-Za-z0-9_-]+$/.test(envelope.ciphertext)) details.push({ field: `${field}.ciphertext`, reason: 'Invalid ciphertext.' });
  if (Number.isNaN(Date.parse(envelope.sentAt))) details.push({ field: `${field}.sentAt`, reason: 'Must be an RFC 3339 timestamp.' });
  return { details };
}

module.exports = {
  FORBIDDEN_SERVER_FIELDS,
  USERNAME_PATTERN,
  findForbiddenFields,
  normalizeUsername,
  validateAvatarUrl,
  validateDisplayName,
  validateEncryptedMessageEnvelope,
  validatePassword,
  validatePublicKeyBundle,
  validateUsername
};
