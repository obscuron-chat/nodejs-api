const assert = require('node:assert/strict');
const test = require('node:test');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/server');
const { fakeMongo, validEnv, withServer } = require('./helpers');

function appFor({ mongo = fakeMongo(), wsState = { acceptingUpgrades: true }, dbState = { indexesReady: true } } = {}) {
  return createApp({ config: loadConfig(validEnv()), mongo, wsState, dbState });
}

test('/healthz returns 200 without MongoDB readiness', async () => {
  await withServer(appFor({ mongo: fakeMongo({ ready: false }) }), async (baseUrl) => {
    const response = await fetch(`${baseUrl}/healthz`);
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.deepEqual(body, { ok: true, data: { status: 'ok' } });
  });
});

test('/readyz requires Mongo ping, index readiness, and websocket upgrade readiness', async () => {
  for (const app of [
    appFor({ mongo: fakeMongo({ ready: false }) }),
    appFor({ mongo: fakeMongo({ ping: false }) }),
    appFor({ dbState: { indexesReady: false } }),
    appFor({ wsState: { acceptingUpgrades: false } })
  ]) {
    await withServer(app, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/readyz`);
      const body = await response.json();
      assert.equal(response.status, 503);
      assert.equal(body.ok, false);
      assert.equal(body.error.code, 'INTERNAL_ERROR');
      assert.ok(body.error.requestId.startsWith('req_'));
    });
  }

  await withServer(appFor(), async (baseUrl) => {
    const response = await fetch(`${baseUrl}/readyz`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true, data: { status: 'ready' } });
  });
});

test('CORS uses exact allowlist and rejects unlisted origins including preflight', async () => {
  await withServer(appFor(), async (baseUrl) => {
    const allowed = await fetch(`${baseUrl}/healthz`, { headers: { Origin: 'http://localhost:5173' } });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.headers.get('access-control-allow-origin'), 'http://localhost:5173');

    const rejected = await fetch(`${baseUrl}/healthz`, { headers: { Origin: 'http://evil.example' } });
    assert.equal(rejected.status, 403);
    assert.equal((await rejected.json()).error.code, 'FORBIDDEN');

    const rejectedPreflight = await fetch(`${baseUrl}/healthz`, {
      method: 'OPTIONS',
      headers: { Origin: 'http://evil.example', 'Access-Control-Request-Method': 'GET' }
    });
    assert.equal(rejectedPreflight.status, 403);
  });
});

test('malformed JSON and body limit failures return safe envelopes', async () => {
  await withServer(appFor(), async (baseUrl) => {
    const malformed = await fetch(`${baseUrl}/missing`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"bad"'
    });
    const malformedBody = await malformed.json();
    assert.equal(malformed.status, 400);
    assert.equal(malformedBody.ok, false);
    assert.equal(malformedBody.error.code, 'VALIDATION_FAILED');
    assert.doesNotMatch(JSON.stringify(malformedBody), /SyntaxError|stack|Unexpected/);

    const oversized = await fetch(`${baseUrl}/missing`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ padding: 'x'.repeat(70 * 1024) })
    });
    const oversizedBody = await oversized.json();
    assert.equal(oversized.status, 400);
    assert.equal(oversizedBody.error.code, 'VALIDATION_FAILED');
  });
});
