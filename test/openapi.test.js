const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { createAuthService } = require('../src/auth');
const { loadConfig } = require('../src/config');
const { createRealtimeService } = require('../src/realtime');
const { createApp } = require('../src/server');
const { createFakeRepository, fakeMongo, validEnv } = require('./helpers');

const SPEC = fs.readFileSync(path.join(__dirname, '..', 'openapi.yaml'), 'utf8');
// `/` is an unversioned service banner, not part of the published contract.
const UNDOCUMENTED_ROUTES = new Set(['/']);

// Reads the top-level keys under `paths:` without pulling in a YAML dependency.
function documentedPaths(spec) {
  const lines = spec.split('\n');
  const start = lines.findIndex((line) => line === 'paths:');
  assert.notEqual(start, -1, 'openapi.yaml must declare a paths section');
  const paths = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break;
    const match = /^ {2}(\/\S*):\s*$/.exec(line);
    if (match) paths.push(match[1]);
  }
  return paths;
}

function registeredRoutes() {
  const config = loadConfig(validEnv());
  const repository = createFakeRepository();
  const authService = createAuthService({ config, repository });
  const app = createApp({
    config,
    mongo: fakeMongo(),
    wsState: { acceptingUpgrades: true },
    dbState: { indexesReady: true },
    authService,
    realtimeService: createRealtimeService({ config, repository, authService })
  });
  return (app.router || app._router).stack
    .filter((layer) => layer.route)
    .map((layer) => layer.route.path.replace(/:(\w+)/g, '{$1}'));
}

// The document must preserve the implemented endpoint paths.
test('every implemented HTTP route is documented and every documented route exists', () => {
  const documented = new Set(documentedPaths(SPEC));
  const registered = registeredRoutes().filter((route) => !UNDOCUMENTED_ROUTES.has(route));
  for (const route of registered) {
    assert.ok(documented.has(route), `route ${route} is missing from openapi.yaml`);
  }
  for (const route of documented) {
    // /ws is a protocol upgrade rather than an Express route.
    if (route === '/ws') continue;
    assert.ok(registered.includes(route), `openapi.yaml documents unimplemented route ${route}`);
  }
});

// The crypto contract must be documented for the API to be usable.
test('openapi documents the public key bundle and encrypted envelope schemas', () => {
  for (const schema of ['PublicKeyBundle:', 'EncryptedMessageEnvelope:', 'StoredMessage:']) {
    assert.ok(SPEC.includes(`    ${schema}`), `missing schema ${schema}`);
  }
  assert.ok(SPEC.includes('ECDSA-secp256k1-SHA3-256'));
  assert.ok(SPEC.includes('X25519-HKDF-SHA-256-AES-256-GCM'));
});

// Both envelopes and the stable error code list must be described.
test('openapi documents the ok and error envelopes with stable error codes', () => {
  assert.ok(SPEC.includes('SuccessEnvelope:'));
  assert.ok(SPEC.includes('ErrorEnvelope:'));
  for (const code of ['VALIDATION_FAILED', 'UNAUTHENTICATED', 'MESSAGE_ID_CONFLICT', 'CURSOR_EXPIRED', 'RATE_LIMITED']) {
    assert.ok(SPEC.includes(code), `missing error code ${code}`);
  }
});

// The spec must never describe private key or plaintext fields.
test('openapi never describes private key material or plaintext message bodies', () => {
  for (const forbidden of ['encryptedKeyBundle:', 'signingPrivateKey', 'encryptionPrivateKey', 'plaintextMessage:', 'passwordHash']) {
    assert.ok(!SPEC.includes(forbidden), `openapi.yaml must not define ${forbidden}`);
  }
});
