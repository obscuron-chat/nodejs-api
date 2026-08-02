const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

test('Mongo repository uses standalone-compatible atomic updates for refresh and identity reset', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'repositories', 'mongoRepository.js'), 'utf8');
  assert.doesNotMatch(source, /connection\.transaction/);
  assert.match(source, /findOneAndUpdate\(\s*\n\s*\{ tokenHash, revokedAt: null, replacedByTokenHash: null, expiresAt: \{ \$gt: now \} \}/);
  assert.match(source, /\$concatArrays/);
  assert.match(source, /\$add: \['\$identityVersion', 1\]/);
});
