const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const test = require('node:test');
const WebSocket = require('ws');
const vectors = require('./fixtures/protocol/vectors.json');
const { createAuthService } = require('../src/auth');
const { loadConfig } = require('../src/config');
const { CLOSE, deriveConversationId, parseHistoryOptions } = require('../src/realtime');
const { createServer } = require('../src/server');
const { createFakeRepository, fakeMongo, validEnv, withHttpServer } = require('./helpers');

const ORIGIN = 'http://localhost:5173';
const openClients = new Set();

test.afterEach(async () => {
  for (const ws of openClients) {
    if (ws.readyState !== WebSocket.CLOSED) ws.terminate();
  }
  openClients.clear();
  await new Promise((resolve) => setImmediate(resolve));
});

function makeHarness(overrides = {}) {
  const config = loadConfig(validEnv());
  Object.assign(config, overrides.config || {});
  const repository = createFakeRepository();
  const authService = createAuthService({ config, repository });
  return {
    ...createServer({
      config,
      mongo: fakeMongo(),
      authService,
      repository,
      dbState: { indexesReady: true },
      realtimeOptions: overrides.realtimeOptions || {}
    }),
    authService,
    config,
    repository
  };
}

async function seedUser(repository, username, overrides = {}) {
  const bundle = {
    ...vectors.publicKeyBundle,
    userId: username,
    signingKey: { ...vectors.publicKeyBundle.signingKey, ...(overrides.signingKey || {}) },
    encryptionKey: { ...vectors.publicKeyBundle.encryptionKey, ...(overrides.encryptionKey || {}) },
    fingerprint: overrides.fingerprint || vectors.publicKeyBundle.fingerprint
  };
  return repository.createUser({
    username,
    usernameNormalized: username,
    passwordHash: '$2b$12$wThDT6GJX/YAyB1u0vR3Jus3oI6JdWMndZM9aa00exAIhX3tySUIm',
    displayName: username,
    avatarUrl: null,
    publicKeyBundle: bundle,
    retiredPublicKeyBundles: [],
    identityVersion: 1,
    identityResetAt: null,
    createdAt: new Date('2026-08-02T00:00:00.000Z'),
    updatedAt: new Date('2026-08-02T00:00:00.000Z')
  });
}

async function seedAliceBob(repository) {
  await seedUser(repository, 'alice');
  await seedUser(repository, 'bob', {
    encryptionKey: { keyId: vectors.encryptedMessageEnvelope.receiverEncryptionKeyId }
  });
}

function envelope(overrides = {}) {
  const sender = overrides.sender || 'alice';
  const receiver = overrides.receiver || 'bob';
  return {
    ...vectors.encryptedMessageEnvelope,
    messageId: overrides.messageId || vectors.encryptedMessageEnvelope.messageId,
    conversationId: overrides.conversationId || deriveConversationId(sender, receiver),
    sender,
    receiver,
    ciphertext: overrides.ciphertext || vectors.encryptedMessageEnvelope.ciphertext,
    sentAt: overrides.sentAt || vectors.encryptedMessageEnvelope.sentAt
  };
}

function signedHighWaterCursor(serverReceivedAt, secret) {
  const payload = {
    event: 'high_water',
    serverReceivedAt,
    sentAt: serverReceivedAt,
    messageId: 'msg_high_water_cursor'
  };
  const sig = crypto.createHmac('sha256', secret)
    .update('obscuron:ws:high_water_cursor:v1')
    .update('\0')
    .update(JSON.stringify(payload))
    .digest('base64url');
  return Buffer.from(JSON.stringify({ ...payload, sig })).toString('base64url');
}

async function openSocket(url) {
  const ws = new WebSocket(url, { headers: { Origin: ORIGIN } });
  openClients.add(ws);
  ws.on('close', () => openClients.delete(ws));
  installInbox(ws);
  await once(ws, 'open');
  return ws;
}

async function authenticate(ws, token, requestId = 'req_auth', label = requestId) {
  ws.send(JSON.stringify({ type: 'authenticate', requestId, accessToken: token, replay: { limit: 100 } }));
  return readJson(ws, `authenticated ${label}`);
}

function sendMessageFrame(ws, requestId, message) {
  ws.send(JSON.stringify({
    type: 'message.send',
    requestId,
    messageId: message.messageId,
    receiver: message.receiver,
    envelope: message
  }));
}

function readJson(ws, label = 'message') {
  if (ws.__inbox.length > 0) return Promise.resolve(JSON.parse(ws.__inbox.shift().toString()));
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for ${label}`));
    }, 1000);
    timeout.unref();
    const waiter = {
      resolve(data) {
        cleanup();
        resolve(JSON.parse(data.toString()));
      },
      reject(error) {
        cleanup();
        reject(error);
      }
    };
    const cleanup = () => {
      clearTimeout(timeout);
      const index = ws.__waiters.indexOf(waiter);
      if (index >= 0) ws.__waiters.splice(index, 1);
    };
    ws.__waiters.push(waiter);
  });
}

function installInbox(ws) {
  ws.__inbox = [];
  ws.__waiters = [];
  ws.on('message', (data) => {
    const waiter = ws.__waiters.shift();
    if (waiter) return waiter.resolve(data);
    ws.__inbox.push(data);
  });
  ws.on('close', (code, reason) => {
    const error = new Error(`Socket closed while waiting for message: ${code} ${reason.toString()}`);
    for (const waiter of ws.__waiters.splice(0)) waiter.reject(error);
  });
  ws.on('error', (error) => {
    for (const waiter of ws.__waiters.splice(0)) waiter.reject(error);
  });
}

function once(emitter, event, label = event) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for ${label}`));
    }, 1000);
    timeout.unref();
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onEvent = (...args) => {
      cleanup();
      resolve(args);
    };
    const cleanup = () => {
      clearTimeout(timeout);
      emitter.off(event, onEvent);
      emitter.off('error', onError);
    };
    emitter.once(event, onEvent);
    emitter.once('error', onError);
  });
}

function closeInfo(ws) {
  return once(ws, 'close').then(([code, reason]) => ({ code, reason: reason.toString() }));
}

async function closeSocket(ws) {
  if (ws.readyState === WebSocket.CLOSED) return;
  const closed = closeInfo(ws);
  if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.terminate();
  await closed;
}

function expectUpgradeRejected(server, url, origin = ORIGIN) {
  const socket = {
    writes: [],
    destroyed: false,
    write(chunk) {
      this.writes.push(String(chunk));
    },
    destroy() {
      this.destroyed = true;
    }
  };
  server.emit('upgrade', { url, headers: { origin } }, socket, Buffer.alloc(0));
  assert.equal(socket.destroyed, true);
  assert.match(socket.writes.join(''), /^HTTP\/1\.1 403 Forbidden/);
}

test('upgrade accepts exact /ws origin only and rejects room paths, queries, and unlisted origins', async () => {
  const { server, authService, repository } = makeHarness();
  await seedUser(repository, 'alice');
  await withHttpServer(server, async (baseUrl) => {
    const wsBase = baseUrl.replace('http:', 'ws:');
    expectUpgradeRejected(server, '/room/abc');
    expectUpgradeRejected(server, '/ws?accessToken=abc');
    expectUpgradeRejected(server, '/ws', 'http://evil.example');

    const ws = await openSocket(`${wsBase}/ws`);
    const authenticated = await authenticate(ws, authService.issueAccessToken(await repository.findUserByUsername('alice')));
    assert.equal(authenticated.type, 'authenticated');
    assert.equal(authenticated.requestId, 'req_auth');
    assert.match(authenticated.connectionId, /^conn_/);
    assert.equal(typeof authenticated.serverTime, 'string');
    assert.deepEqual(authenticated.user, { username: 'alice' });
    assert.equal(typeof authenticated.replayCursor, 'string');
    await closeSocket(ws);
  });
});

test('close semantics and first unsupported event error are stable', async () => {
  const { server, authService, repository } = makeHarness();
  await seedUser(repository, 'alice');
  await withHttpServer(server, async (baseUrl) => {
    const wsBase = baseUrl.replace('http:', 'ws:');

    const nonAuth = await openSocket(`${wsBase}/ws`);
    const nonAuthClose = closeInfo(nonAuth);
    nonAuth.send(JSON.stringify({ type: 'message.delivered', requestId: 'req_first', messageId: 'msg_aaaaaaaaaaaaaaaaaaaaaaaaaa' }));
    assert.deepEqual(await nonAuthClose, CLOSE.AUTH_REQUIRED);

    const unsupported = await openSocket(`${wsBase}/ws`);
    await authenticate(unsupported, authService.issueAccessToken(await repository.findUserByUsername('alice')));
    unsupported.send(JSON.stringify({ type: 'history.request', requestId: 'req_bad' }));
    assert.deepEqual(await readJson(unsupported), {
      type: 'error',
      requestId: 'req_bad',
      error: { code: 'VALIDATION_FAILED', message: 'Request validation failed.', details: [] }
    });
    const repeatedClose = closeInfo(unsupported);
    unsupported.send(JSON.stringify({ type: 'ping', requestId: 'req_bad_2' }));
    assert.deepEqual(await repeatedClose, CLOSE.BAD_REQUEST);

    const malformed = await openSocket(`${wsBase}/ws`);
    const malformedClose = closeInfo(malformed);
    malformed.send('{bad');
    assert.deepEqual(await malformedClose, CLOSE.BAD_REQUEST);

    const schema = await openSocket(`${wsBase}/ws`);
    const schemaClose = closeInfo(schema);
    schema.send(JSON.stringify({ type: 'authenticate', requestId: 'req_schema', accessToken: authService.issueAccessToken(await repository.findUserByUsername('alice')), extra: true }));
    assert.deepEqual(await schemaClose, CLOSE.BAD_REQUEST);

    const expired = await openSocket(`${wsBase}/ws`);
    const expiredClose = closeInfo(expired);
    expired.send(JSON.stringify({
      type: 'authenticate',
      requestId: 'req_expired',
      accessToken: jwt.sign({ username: 'alice' }, loadConfig(validEnv()).jwtAccessSecret, { expiresIn: -1 })
    }));
    assert.deepEqual(await expiredClose, CLOSE.EXPIRED);
  });
});

test('immediate double authenticate closes the connection with bad_request', async () => {
  const { server, authService, repository } = makeHarness();
  await seedUser(repository, 'alice');
  await withHttpServer(server, async (baseUrl) => {
    const ws = await openSocket(`${baseUrl.replace('http:', 'ws:')}/ws`);
    const token = authService.issueAccessToken(await repository.findUserByUsername('alice'));
    const closed = closeInfo(ws);
    ws.send(JSON.stringify({ type: 'authenticate', requestId: 'req_auth_1', accessToken: token, replay: { limit: 100 } }));
    ws.send(JSON.stringify({ type: 'authenticate', requestId: 'req_auth_2', accessToken: token, replay: { limit: 100 } }));
    assert.deepEqual(await closed, CLOSE.BAD_REQUEST);
  });
});

test('authenticate timeout uses 4408 timeout', async () => {
  const { server } = makeHarness({
    realtimeOptions: {
      setTimer(fn, ms) {
        return setTimeout(fn, ms === 5000 ? 10 : ms);
      }
    }
  });
  await withHttpServer(server, async (baseUrl) => {
    const ws = await openSocket(`${baseUrl.replace('http:', 'ws:')}/ws`);
    assert.deepEqual(await closeInfo(ws), CLOSE.TIMEOUT);
  });
});

test('message send persists before ack, fans out ciphertext-only message, supports exact duplicate ack, and conflicts on mutation', async () => {
  const { server, authService, repository } = makeHarness();
  await seedAliceBob(repository);
  await withHttpServer(server, async (baseUrl) => {
    const wsBase = baseUrl.replace('http:', 'ws:');
    const alice = await openSocket(`${wsBase}/ws`);
    const bob = await openSocket(`${wsBase}/ws`);
    await authenticate(alice, authService.issueAccessToken(await repository.findUserByUsername('alice')));
    await authenticate(bob, authService.issueAccessToken(await repository.findUserByUsername('bob')));

    sendMessageFrame(alice, 'req_send_1', envelope());
    const ack = await readJson(alice, 'alice first ack');
    const pushed = await readJson(bob, 'bob first push');
    assert.equal(ack.type, 'message.ack');
    assert.equal(ack.requestId, 'req_send_1');
    assert.equal(ack.deliveryState, 'stored');
    assert.equal(Object.hasOwn(ack, 'duplicate'), false);
    assert.equal(typeof ack.serverReceivedAt, 'string');
    assert.equal(repository.state.messages.length, 1);
    assert.equal(pushed.type, 'message.new');
    assert.equal(pushed.message.ciphertext, envelope().ciphertext);
    assert.equal(pushed.cursor, ack.cursor);
    assert.doesNotMatch(JSON.stringify(pushed), /"plaintext"|"body"|"text"|"expiresAt"/);

    sendMessageFrame(alice, 'req_send_2', envelope());
    const duplicate = await readJson(alice, 'alice duplicate ack');
    assert.equal(duplicate.type, 'message.ack');
    assert.equal(duplicate.requestId, 'req_send_2');
    assert.equal(duplicate.serverReceivedAt, ack.serverReceivedAt);
    assert.equal(duplicate.cursor, ack.cursor);
    assert.equal(Object.hasOwn(duplicate, 'duplicate'), false);
    assert.equal(repository.state.messages.length, 1);

    sendMessageFrame(alice, 'req_send_3', envelope({ ciphertext: 'AAAA' }));
    const conflict = await readJson(alice, 'alice conflict error');
    assert.deepEqual(conflict, {
      type: 'error',
      requestId: 'req_send_3',
      error: {
        code: 'MESSAGE_ID_CONFLICT',
        message: 'Message id conflicts with existing state.',
        details: [{ field: 'messageId', reason: 'Conflicts with a stored encrypted envelope.' }]
      }
    });
    assert.equal(repository.state.messages.length, 1);

    await closeSocket(alice);
    await closeSocket(bob);
  });
});

test('conversation, active keys, authoritative sender, receiver existence, binary, and oversized actions are rejected', async () => {
  const { server, authService, repository } = makeHarness();
  await seedAliceBob(repository);
  await withHttpServer(server, async (baseUrl) => {
    const wsBase = baseUrl.replace('http:', 'ws:');

    for (const badMessage of [
      envelope({ sender: 'bob', receiver: 'alice' }),
      envelope({ receiver: 'nobody' }),
      envelope({ conversationId: deriveConversationId('alice', 'carol') }),
      { ...envelope(), senderSigningKeyId: 'k1_AAAAAAAAAAAAAAAAAAAAAA' },
      { ...envelope(), receiverEncryptionKeyId: 'k1_AAAAAAAAAAAAAAAAAAAAAA' }
    ]) {
      const ws = await openSocket(`${wsBase}/ws`);
      await authenticate(ws, authService.issueAccessToken(await repository.findUserByUsername('alice')));
      const closed = closeInfo(ws);
      sendMessageFrame(ws, 'req_bad_send', badMessage);
      assert.deepEqual(await closed, CLOSE.FORBIDDEN);
    }

    const binary = await openSocket(`${wsBase}/ws`);
    await authenticate(binary, authService.issueAccessToken(await repository.findUserByUsername('alice')));
    const binaryClose = closeInfo(binary);
    binary.send(Buffer.from([1, 2, 3]), { binary: true });
    assert.deepEqual(await binaryClose, CLOSE.BAD_REQUEST);

    const oversized = await openSocket(`${wsBase}/ws`);
    await authenticate(oversized, authService.issueAccessToken(await repository.findUserByUsername('alice')));
    const oversizedClose = closeInfo(oversized);
    oversized.send(JSON.stringify({ type: 'message.delivered', requestId: 'req_big', messageId: 'x'.repeat(70 * 1024) }));
    assert.notEqual((await oversizedClose).code, 1000);
  });
});

test('receiver-only delivered receipts persist and notify sender with cursors', async () => {
  const { server, authService, repository } = makeHarness();
  await seedAliceBob(repository);
  await withHttpServer(server, async (baseUrl) => {
    const wsBase = baseUrl.replace('http:', 'ws:');
    const alice = await openSocket(`${wsBase}/ws`);
    const bob = await openSocket(`${wsBase}/ws`);
    await authenticate(alice, authService.issueAccessToken(await repository.findUserByUsername('alice')));
    await authenticate(bob, authService.issueAccessToken(await repository.findUserByUsername('bob')));
    sendMessageFrame(alice, 'req_send', envelope());
    const sendAck = await readJson(alice);
    await readJson(bob);

    const aliceBad = await openSocket(`${wsBase}/ws`);
    await authenticate(aliceBad, authService.issueAccessToken(await repository.findUserByUsername('alice')));
    const unauthorized = closeInfo(aliceBad);
    aliceBad.send(JSON.stringify({ type: 'message.delivered', requestId: 'req_bad_receipt', messageId: envelope().messageId }));
    assert.deepEqual(await unauthorized, CLOSE.FORBIDDEN);

    bob.send(JSON.stringify({ type: 'message.delivered', requestId: 'req_receipt', messageId: envelope().messageId }));
    const bobReceipt = await readJson(bob);
    const aliceReceipt = await readJson(alice);
    assert.equal(bobReceipt.type, 'message.delivered');
    assert.equal(bobReceipt.requestId, 'req_receipt');
    assert.equal(aliceReceipt.requestId, 'req_receipt');
    assert.equal(aliceReceipt.cursor, bobReceipt.cursor);
    assert.equal(repository.state.messages[0].deliveryState, 'delivered');
    assert.equal(repository.state.messages[0].deliveredAt, bobReceipt.deliveredAt);
    bob.send(JSON.stringify({ type: 'message.delivered', requestId: 'req_receipt_repeat', messageId: envelope().messageId }));
    const repeatReceipt = await readJson(bob);
    await readJson(alice);
    assert.equal(repeatReceipt.deliveredAt, bobReceipt.deliveredAt);
    sendMessageFrame(alice, 'req_duplicate_after_delivery', envelope());
    const duplicateAck = await readJson(alice);
    assert.equal(duplicateAck.deliveryState, 'stored');
    assert.equal(duplicateAck.serverReceivedAt, sendAck.serverReceivedAt);
    assert.equal(duplicateAck.cursor, sendAck.cursor);
    await closeSocket(alice);
    await closeSocket(bob);
  });
});

test('offline replay emits events, REST history descends with nextCursor, filters expired records, and isolates participants', async () => {
  const { server, authService, repository } = makeHarness();
  await seedAliceBob(repository);
  await seedUser(repository, 'carol', { encryptionKey: { keyId: vectors.encryptedMessageEnvelope.receiverEncryptionKeyId } });
  await repository.storeEncryptedMessage(envelope({ messageId: 'msg_aaaaaaaaaaaaaaaaaaaaaaaaaa', sentAt: '2026-08-02T00:00:00.000Z' }), {
    now: new Date('2026-08-02T00:00:01.000Z'),
    expiresAt: new Date('2026-09-02T00:00:01.000Z')
  });
  await repository.storeEncryptedMessage(envelope({ messageId: 'msg_bbbbbbbbbbbbbbbbbbbbbbbbbb', sentAt: '2026-08-02T00:00:02.000Z' }), {
    now: new Date('2026-08-02T00:00:02.000Z'),
    expiresAt: new Date('2026-09-02T00:00:02.000Z')
  });
  await repository.storeEncryptedMessage(envelope({ messageId: 'msg_cccccccccccccccccccccccccc', sender: 'carol', receiver: 'bob' }), {
    now: new Date('2026-08-02T00:00:03.000Z'),
    expiresAt: new Date('2026-09-02T00:00:03.000Z')
  });
  await repository.storeEncryptedMessage(envelope({ messageId: 'msg_dddddddddddddddddddddddddd' }), {
    now: new Date('2026-08-02T00:00:04.000Z'),
    expiresAt: new Date('2026-08-01T00:00:04.000Z')
  });

  await withHttpServer(server, async (baseUrl) => {
    const bobToken = authService.issueAccessToken(await repository.findUserByUsername('bob'));
    const ws = await openSocket(`${baseUrl.replace('http:', 'ws:')}/ws`);
    const authenticated = await authenticate(ws, bobToken, 'req_auth', 'offline replay');
    assert.equal(authenticated.type, 'authenticated');
    assert.equal(authenticated.replayCursor !== undefined, true);
    const replay = [await readJson(ws), await readJson(ws), await readJson(ws)];
    assert.deepEqual(replay.map((event) => event.message.messageId), [
      'msg_aaaaaaaaaaaaaaaaaaaaaaaaaa',
      'msg_bbbbbbbbbbbbbbbbbbbbbbbbbb',
      'msg_cccccccccccccccccccccccccc'
    ]);
    assert.doesNotMatch(JSON.stringify(replay), /"plaintext"|"body"|"text"|"expiresAt"/);

    const firstPage = await fetch(`${baseUrl}/messages/alice?limit=1`, { headers: { Authorization: `Bearer ${bobToken}` } });
    assert.equal(firstPage.status, 200);
    const firstBody = await firstPage.json();
    assert.deepEqual(firstBody.data.messages.map((message) => message.messageId), ['msg_bbbbbbbbbbbbbbbbbbbbbbbbbb']);
    assert.equal(typeof firstBody.data.nextCursor, 'string');

    const secondPage = await fetch(`${baseUrl}/messages/alice?limit=100&cursor=${encodeURIComponent(firstBody.data.nextCursor)}`, { headers: { Authorization: `Bearer ${bobToken}` } });
    const secondBody = await secondPage.json();
    assert.equal(secondPage.status, 200);
    assert.deepEqual(secondBody.data.messages.map((message) => message.messageId), ['msg_aaaaaaaaaaaaaaaaaaaaaaaaaa']);

    const isolated = await fetch(`${baseUrl}/messages/carol`, { headers: { Authorization: `Bearer ${authService.issueAccessToken(await repository.findUserByUsername('alice'))}` } });
    assert.equal(isolated.status, 200);
    assert.deepEqual((await isolated.json()).data.messages, []);

    const tooLarge = await fetch(`${baseUrl}/messages/alice?limit=101`, { headers: { Authorization: `Bearer ${bobToken}` } });
    assert.equal(tooLarge.status, 400);
    const self = await fetch(`${baseUrl}/messages/bob`, { headers: { Authorization: `Bearer ${bobToken}` } });
    assert.equal(self.status, 400);
    const unknownCursor = Buffer.from(JSON.stringify({
      serverReceivedAt: '2026-08-02T00:00:09.000Z',
      sentAt: envelope().sentAt,
      messageId: 'msg_unknownunknownunknownunkn'
    })).toString('base64url');
    const unknown = await fetch(`${baseUrl}/messages/alice?cursor=${encodeURIComponent(unknownCursor)}`, { headers: { Authorization: `Bearer ${bobToken}` } });
    assert.equal(unknown.status, 400);
    await closeSocket(ws);
  });
});

test('syntactically valid stale replay cursor emits CURSOR_EXPIRED fallback error', async () => {
  const { server, authService, repository } = makeHarness();
  await seedAliceBob(repository);
  await repository.storeEncryptedMessage(envelope(), {
    now: new Date('2026-08-02T00:00:01.000Z'),
    expiresAt: new Date('2026-08-01T00:00:01.000Z')
  });
  const staleCursor = Buffer.from(JSON.stringify({
    serverReceivedAt: '2026-08-02T00:00:01.000Z',
    sentAt: envelope().sentAt,
    messageId: envelope().messageId
  })).toString('base64url');

  await withHttpServer(server, async (baseUrl) => {
    const ws = await openSocket(`${baseUrl.replace('http:', 'ws:')}/ws`);
    ws.send(JSON.stringify({
      type: 'authenticate',
      requestId: 'req_stale_cursor',
      accessToken: authService.issueAccessToken(await repository.findUserByUsername('bob')),
      replay: { afterCursor: staleCursor, limit: 100 }
    }));
    const authenticated = await readJson(ws);
    assert.equal(authenticated.type, 'authenticated');
    assert.equal(authenticated.requestId, 'req_stale_cursor');
    assert.equal(authenticated.replayCursor, staleCursor);
    assert.deepEqual(await readJson(ws), {
      type: 'error',
      requestId: 'req_stale_cursor',
      error: {
        code: 'CURSOR_EXPIRED',
        message: 'Cursor expired.',
        details: [{ field: 'replay.afterCursor', reason: 'Use GET /messages/:peer to fetch fallback history.' }]
      }
    });
    await closeSocket(ws);
  });
});

test('bad replay limit is recoverable after authentication', async () => {
  const { server, authService, repository } = makeHarness();
  await seedUser(repository, 'alice');
  await withHttpServer(server, async (baseUrl) => {
    const ws = await openSocket(`${baseUrl.replace('http:', 'ws:')}/ws`);
    ws.send(JSON.stringify({
      type: 'authenticate',
      requestId: 'req_bad_replay_limit',
      accessToken: authService.issueAccessToken(await repository.findUserByUsername('alice')),
      replay: { limit: 101 }
    }));
    const authenticated = await readJson(ws);
    assert.equal(authenticated.type, 'authenticated');
    assert.equal(typeof authenticated.replayCursor, 'string');
    assert.deepEqual(await readJson(ws), {
      type: 'error',
      requestId: 'req_bad_replay_limit',
      error: { code: 'VALIDATION_FAILED', message: 'Request validation failed.', details: [] }
    });
    await closeSocket(ws);
  });
});

test('too-old high-water replay cursor emits CURSOR_EXPIRED after authentication', async () => {
  const now = new Date('2026-08-02T00:00:00.000Z');
  const { server, authService, repository } = makeHarness({
    realtimeOptions: { clock: () => now }
  });
  await seedUser(repository, 'alice');
  const oldCursor = signedHighWaterCursor('2020-01-01T00:00:00.000Z', loadConfig(validEnv()).jwtAccessSecret);

  await withHttpServer(server, async (baseUrl) => {
    const ws = await openSocket(`${baseUrl.replace('http:', 'ws:')}/ws`);
    ws.send(JSON.stringify({
      type: 'authenticate',
      requestId: 'req_old_high_water',
      accessToken: authService.issueAccessToken(await repository.findUserByUsername('alice')),
      replay: { afterCursor: oldCursor, limit: 100 }
    }));
    assert.equal((await readJson(ws)).type, 'authenticated');
    assert.deepEqual(await readJson(ws), {
      type: 'error',
      requestId: 'req_old_high_water',
      error: {
        code: 'CURSOR_EXPIRED',
        message: 'Cursor expired.',
        details: [{ field: 'replay.afterCursor', reason: 'Use GET /messages/:peer to fetch fallback history.' }]
      }
    });
    await closeSocket(ws);
  });
});

test('current high-water replay cursor with missing signature emits CURSOR_EXPIRED after authentication', async () => {
  const now = new Date('2026-08-02T00:00:01.000Z');
  const { server, authService, repository } = makeHarness({
    realtimeOptions: { clock: () => now }
  });
  await seedUser(repository, 'alice');
  const forgedCursor = Buffer.from(JSON.stringify({
    event: 'high_water',
    serverReceivedAt: now.toISOString(),
    sentAt: now.toISOString(),
    messageId: 'msg_high_water_cursor'
  })).toString('base64url');

  await withHttpServer(server, async (baseUrl) => {
    const ws = await openSocket(`${baseUrl.replace('http:', 'ws:')}/ws`);
    ws.send(JSON.stringify({
      type: 'authenticate',
      requestId: 'req_forged_high_water',
      accessToken: authService.issueAccessToken(await repository.findUserByUsername('alice')),
      replay: { afterCursor: forgedCursor, limit: 100 }
    }));
    assert.equal((await readJson(ws)).type, 'authenticated');
    assert.deepEqual(await readJson(ws), {
      type: 'error',
      requestId: 'req_forged_high_water',
      error: {
        code: 'CURSOR_EXPIRED',
        message: 'Cursor expired.',
        details: [{ field: 'replay.afterCursor', reason: 'Use GET /messages/:peer to fetch fallback history.' }]
      }
    });
    await closeSocket(ws);
  });
});

test('delivery replay cursor advances on deliveredAt rather than original message time', async () => {
  const { server, authService, repository } = makeHarness();
  await seedAliceBob(repository);
  const first = envelope({ messageId: 'msg_aaaaaaaaaaaaaaaaaaaaaaaaaa', sentAt: '2026-08-02T00:00:00.000Z' });
  const second = envelope({ messageId: 'msg_bbbbbbbbbbbbbbbbbbbbbbbbbb', sentAt: '2026-08-02T00:00:05.000Z' });
  await repository.storeEncryptedMessage(first, {
    now: new Date('2026-08-02T00:00:01.000Z'),
    expiresAt: new Date('2026-09-02T00:00:01.000Z')
  });
  const storedSecond = await repository.storeEncryptedMessage(second, {
    now: new Date('2026-08-02T00:00:05.000Z'),
    expiresAt: new Date('2026-09-02T00:00:05.000Z')
  });
  await repository.markMessageDelivered('bob', first.messageId, new Date('2026-08-02T00:00:10.000Z'));
  const afterSecondMessageCursor = Buffer.from(JSON.stringify({
    event: 'message',
    serverReceivedAt: storedSecond.message.serverReceivedAt,
    sentAt: storedSecond.message.sentAt,
    messageId: storedSecond.message.messageId
  })).toString('base64url');

  await withHttpServer(server, async (baseUrl) => {
    const ws = await openSocket(`${baseUrl.replace('http:', 'ws:')}/ws`);
    ws.send(JSON.stringify({
      type: 'authenticate',
      requestId: 'req_delivery_cursor',
      accessToken: authService.issueAccessToken(await repository.findUserByUsername('alice')),
      replay: { afterCursor: afterSecondMessageCursor, limit: 100 }
    }));
    assert.equal((await readJson(ws)).type, 'authenticated');
    const receipt = await readJson(ws);
    assert.equal(receipt.type, 'message.delivered');
    assert.equal(receipt.messageId, first.messageId);
    const decodedCursor = JSON.parse(Buffer.from(receipt.cursor, 'base64url').toString('utf8'));
    assert.equal(decodedCursor.event, 'delivery');
    assert.equal(decodedCursor.serverReceivedAt, '2026-08-02T00:00:10.000Z');
    await closeSocket(ws);
  });
});

test('receiver replay includes retained ciphertext after delivery from an earlier high-water cursor', async () => {
  let now = new Date('2026-08-02T00:00:00.000Z');
  const { server, authService, repository } = makeHarness({
    realtimeOptions: { clock: () => now }
  });
  await seedAliceBob(repository);
  const message = envelope({ messageId: 'msg_aaaaaaaaaaaaaaaaaaaaaaaaaa', sentAt: '2026-08-02T00:00:00.000Z' });

  await withHttpServer(server, async (baseUrl) => {
    const initial = await openSocket(`${baseUrl.replace('http:', 'ws:')}/ws`);
    const initialAuth = await authenticate(initial, authService.issueAccessToken(await repository.findUserByUsername('bob')), 'req_empty_replay');
    const beforeMessageCursor = initialAuth.replayCursor;
    assert.equal(typeof beforeMessageCursor, 'string');
    assert.equal(initial.__inbox.length, 0);
    await closeSocket(initial);

    now = new Date('2026-08-02T00:00:01.000Z');
    await repository.storeEncryptedMessage(message, {
      now,
      expiresAt: new Date('2026-09-02T00:00:01.000Z')
    });
    now = new Date('2026-08-02T00:00:10.000Z');
    await repository.markMessageDelivered('bob', message.messageId, now);
    now = new Date('2026-08-02T00:00:11.000Z');

    const ws = await openSocket(`${baseUrl.replace('http:', 'ws:')}/ws`);
    ws.send(JSON.stringify({
      type: 'authenticate',
      requestId: 'req_replay_delivered',
      accessToken: authService.issueAccessToken(await repository.findUserByUsername('bob')),
      replay: { afterCursor: beforeMessageCursor, limit: 100 }
    }));
    assert.equal((await readJson(ws)).type, 'authenticated');
    const replay = await readJson(ws);
    assert.equal(replay.type, 'message.new');
    assert.equal(replay.message.messageId, message.messageId);
    assert.equal(replay.message.deliveryState, 'delivered');
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(ws.__inbox.length, 0);
    await closeSocket(ws);
  });
});

test('max five sockets per user and sixty messages per minute are enforced across connections', async () => {
  const { server, authService, repository } = makeHarness();
  await seedAliceBob(repository);
  await withHttpServer(server, async (baseUrl) => {
    const wsBase = baseUrl.replace('http:', 'ws:');
    const token = authService.issueAccessToken(await repository.findUserByUsername('alice'));
    const sockets = [];
    for (let index = 0; index < 5; index += 1) {
      const socket = await openSocket(`${wsBase}/ws`);
      assert.equal((await authenticate(socket, token, `req_auth_${index}`, `rate socket ${index}`)).type, 'authenticated');
      sockets.push(socket);
    }
    const sixth = await openSocket(`${wsBase}/ws`);
    const sixthClose = closeInfo(sixth);
    sixth.send(JSON.stringify({ type: 'authenticate', requestId: 'req_auth_6', accessToken: token, replay: { limit: 100 } }));
    assert.deepEqual(await sixthClose, CLOSE.RATE_LIMITED);

    for (let index = 0; index < 60; index += 1) {
      sendMessageFrame(sockets[index % sockets.length], `req_send_${index}`, envelope({ messageId: `msg_${String(index).padStart(26, 'a')}` }));
    }
    for (let index = 0; index < 60; index += 1) {
      assert.equal((await readJson(sockets[index % sockets.length])).type, 'message.ack');
    }
    const limitedClose = closeInfo(sockets[0]);
    sendMessageFrame(sockets[0], 'req_send_61', envelope({ messageId: 'msg_zzzzzzzzzzzzzzzzzzzzzzzzzz' }));
    assert.deepEqual(await limitedClose, CLOSE.RATE_LIMITED);
    for (const socket of sockets.slice(1)) await closeSocket(socket);
  });
});

test('logout closes active sockets for the logged-out user', async () => {
  const { server } = makeHarness();
  await withHttpServer(server, async (baseUrl) => {
    const register = await fetch(`${baseUrl}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'alice',
        password: 'correct horse battery staple',
        displayName: 'Alice',
        publicKeyBundle: vectors.publicKeyBundle
      })
    });
    assert.equal(register.status, 201);
    const cookie = register.headers.get('set-cookie').split(';')[0];
    const token = (await register.json()).data.accessToken;
    const ws = await openSocket(`${baseUrl.replace('http:', 'ws:')}/ws`);
    await authenticate(ws, token);
    const closed = closeInfo(ws);
    const logout = await fetch(`${baseUrl}/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: '{}'
    });
    assert.equal(logout.status, 204);
    assert.deepEqual(await closed, { code: 1000, reason: 'normal_closure' });
  });
});

test('history option parser rejects malformed cursor and limit over 100', () => {
  assert.throws(() => parseHistoryOptions({ limit: 101 }), { status: 400, code: 'VALIDATION_FAILED' });
  assert.throws(() => parseHistoryOptions({ cursor: 'not-base64url-json' }), { status: 400, code: 'VALIDATION_FAILED' });
});
