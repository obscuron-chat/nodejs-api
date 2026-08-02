const assert = require('node:assert/strict');
const test = require('node:test');
const { REDACTED, redact, redactedJson } = require('../src/redaction');

test('redaction handles nested mixed-case headers and secret-shaped keys', () => {
  const redacted = redact({
    headers: {
      Authorization: 'Bearer token',
      cookie: '__Host-obscuron_refresh=raw',
      'public_key': 'full-public-key'
    },
    query: {
      avatarURL: 'https://example.com/private/profile.png',
      safe: 'value'
    },
    nested: [{ hkdf_salt: 'salt', nonce: 'nonce' }]
  });
  assert.equal(redacted.headers.Authorization, REDACTED);
  assert.equal(redacted.headers.cookie, REDACTED);
  assert.equal(redacted.headers.public_key, REDACTED);
  assert.equal(redacted.query.avatarURL, REDACTED);
  assert.equal(redacted.query.safe, 'value');
  assert.equal(redacted.nested[0].hkdf_salt, REDACTED);
});

test('redaction removes credentials from driver errors and query strings', () => {
  const json = redactedJson({
    error: 'MongoServerSelectionError mongodb://admin:password@mongodb:27017/obscuron?token=abc&password=raw'
  });
  assert.doesNotMatch(json, /admin:password/);
  assert.doesNotMatch(json, /token=abc/);
  assert.doesNotMatch(json, /password=raw/);
  assert.match(json, /mongodb:\/\/\[REDACTED\]@/);
});
