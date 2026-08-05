const assert = require('node:assert/strict');
const test = require('node:test');
const vectors = require('./fixtures/protocol/vectors.json');
const { AUDIT_EVENTS, createAuditLogger } = require('../src/audit');
const { createAuthService } = require('../src/auth');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/server');
const { createFakeRepository, fakeMongo, validEnv, withServer } = require('./helpers');

function collectingSink() {
  const records = [];
  return {
    records,
    log: (line) => records.push(JSON.parse(line)),
    warn: (line) => records.push(JSON.parse(line))
  };
}

function makeHarness(envOverrides = {}) {
  const config = loadConfig(validEnv(envOverrides));
  const sink = collectingSink();
  const audit = createAuditLogger({ config, sink });
  const repository = createFakeRepository();
  const authService = createAuthService({ config, repository });
  const app = createApp({
    config,
    mongo: fakeMongo(),
    wsState: { acceptingUpgrades: true },
    dbState: { indexesReady: true },
    authService,
    audit
  });
  return { app, sink };
}

function jsonRequest(body, headers = {}) {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body)
  };
}

function registerBody(username = 'alice') {
  return {
    username,
    password: 'correct horse battery staple',
    displayName: 'Alice',
    publicKeyBundle: { ...vectors.publicKeyBundle, userId: username }
  };
}

// The emitter refuses any event outside the required set.
test('audit logger accepts only the required event names', () => {
  const sink = collectingSink();
  const audit = createAuditLogger({ config: { logLevel: 'info' }, sink });
  for (const event of AUDIT_EVENTS) audit(event, {});
  assert.equal(sink.records.length, AUDIT_EVENTS.length);
  assert.throws(() => audit('auth.login.maybe', {}), /Unknown audit event/);
});

// Every record carries the required non-sensitive context fields.
test('audit records carry timestamp, event, ids, source, origin, result, and reason', () => {
  const sink = collectingSink();
  const audit = createAuditLogger({
    config: { logLevel: 'info' },
    clock: () => new Date('2026-08-02T00:00:00.000Z'),
    sink
  });
  audit('auth.login.failure', {
    requestId: 'req_1',
    username: 'alice',
    sourceIp: '203.0.113.5',
    origin: 'http://localhost:5173',
    reason: 'UNAUTHENTICATED'
  });
  assert.deepEqual(sink.records[0], {
    timestamp: '2026-08-02T00:00:00.000Z',
    event: 'auth.login.failure',
    level: 'warn',
    result: 'failure',
    requestId: 'req_1',
    connectionId: null,
    username: 'alice',
    sourceIp: '203.0.113.5',
    origin: 'http://localhost:5173',
    reason: 'UNAUTHENTICATED'
  });
});

// Audit output must not carry credentials even when callers pass them.
test('audit records redact secret-bearing fields and connection strings', () => {
  const sink = collectingSink();
  const audit = createAuditLogger({ config: { logLevel: 'info' }, sink });
  audit('config.startup_failed', { reason: 'mongodb://admin:hunter2@mongodb:27017/obscuron' });
  assert.equal(sink.records[0].reason, 'mongodb://[REDACTED]@mongodb:27017/obscuron');
});

test('audit logger honours the configured log level', () => {
  const sink = collectingSink();
  const audit = createAuditLogger({ config: { logLevel: 'warn' }, sink });
  assert.equal(audit('auth.login.success', {}), null);
  assert.ok(audit('auth.login.failure', {}));
  assert.deepEqual(sink.records.map((record) => record.event), ['auth.login.failure']);
});

// The HTTP auth surface emits its required lifecycle events.
test('auth routes emit register, login, failure, refresh, and logout audit events', async () => {
  const { app, sink } = makeHarness();
  await withServer(app, async (baseUrl) => {
    const registered = await fetch(`${baseUrl}/auth/register`, jsonRequest(registerBody()));
    const cookie = registered.headers.get('set-cookie').split(';')[0];
    await fetch(`${baseUrl}/auth/login`, jsonRequest({ username: 'alice', password: 'wrong password!' }));
    await fetch(`${baseUrl}/auth/login`, jsonRequest({ username: 'alice', password: 'correct horse battery staple' }));
    await fetch(`${baseUrl}/auth/refresh`, jsonRequest({}, { Cookie: cookie }));
    await fetch(`${baseUrl}/auth/refresh`, jsonRequest({}, { Cookie: cookie }));
    await fetch(`${baseUrl}/auth/logout`, jsonRequest({}, { Cookie: cookie }));

    assert.deepEqual(sink.records.map((record) => record.event), [
      'auth.register.success',
      'auth.login.failure',
      'auth.login.success',
      'auth.refresh.success',
      'auth.refresh.reuse_detected',
      'auth.logout'
    ]);
    assert.equal(sink.records[1].username, 'alice');
    assert.ok(sink.records.every((record) => typeof record.requestId === 'string'));
  });
});
