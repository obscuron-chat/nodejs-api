const assert = require('node:assert/strict');
const test = require('node:test');
const { ConfigError, PRODUCTION_ORIGIN, loadConfig } = require('../src/config');
const { validEnv } = require('./helpers');

test('loadConfig returns exact security constants without side effects', () => {
  const config = loadConfig(validEnv());
  assert.equal(config.bcryptCost, 12);
  assert.equal(config.jwtAccessTtl, '15m');
  assert.equal(config.wsMaxPayloadBytes, 65536);
  assert.equal(config.wsPerMessageDeflate, false);
  assert.equal(config.wsHeartbeatIntervalSeconds, 30);
  assert.equal(config.wsHeartbeatMissesAllowed, 2);
  assert.equal(config.wsMaxConnectionsPerUser, 5);
  assert.equal(config.wsMessagesPerMinute, 60);
  assert.equal(config.messageRetentionDays, 90);
});

test('loadConfig rejects missing required values before startup can bind or connect', () => {
  assert.throws(() => loadConfig({}), (error) => {
    assert.ok(error instanceof ConfigError);
    assert.ok(error.details.some((detail) => detail.field === 'MONGODB_URI'));
    assert.ok(error.details.some((detail) => detail.field === 'JWT_ACCESS_SECRET'));
    return true;
  });
});

test('production rejects example secrets, localhost mongo, wildcard, and trailing slash origins', () => {
  assert.throws(() => loadConfig(validEnv({
    NODE_ENV: 'production',
    MONGODB_URI: 'mongodb://tester:secret@localhost:27017/obscuron?authSource=admin',
    JWT_ACCESS_SECRET: 'local_access_secret_replace_me_32_bytes_minimum',
    REFRESH_TOKEN_SECRET: 'local_refresh_secret_replace_me_32_bytes_minimum',
    CORS_ALLOWED_ORIGINS: `${PRODUCTION_ORIGIN}/,*`,
    WS_ALLOWED_ORIGINS: `${PRODUCTION_ORIGIN}/,*`
  })), (error) => {
    const reasons = error.details.map((detail) => `${detail.field}:${detail.reason}`).join('\n');
    assert.match(reasons, /MONGODB_URI:production must not point to localhost/);
    assert.match(reasons, /JWT_ACCESS_SECRET:must not use the documented example value/);
    assert.match(reasons, /REFRESH_TOKEN_SECRET:must not use the documented example value/);
    assert.match(reasons, /CORS_ALLOWED_ORIGINS:must not include trailing slashes/);
    assert.match(reasons, /WS_ALLOWED_ORIGINS:must be an exact allowlist/);
    return true;
  });
});
