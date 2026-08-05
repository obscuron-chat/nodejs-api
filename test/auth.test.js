const assert = require('node:assert/strict');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const test = require('node:test');
const vectors = require('./fixtures/protocol/vectors.json');
const { DUMMY_PASSWORD_HASH, createAuthService } = require('../src/auth');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/server');
const { createFakeRepository, fakeMongo, validEnv, withServer } = require('./helpers');

function makeHarness() {
  const config = loadConfig(validEnv());
  const repository = createFakeRepository();
  const authService = createAuthService({ config, repository });
  const app = createApp({
    config,
    mongo: fakeMongo(),
    wsState: { acceptingUpgrades: true },
    dbState: { indexesReady: true },
    authService
  });
  return { app, authService, config, repository };
}

function registerBody(username = 'alice', displayName = 'Alice') {
  return {
    username,
    password: 'correct horse battery staple',
    displayName,
    avatarUrl: 'https://example.com/alice.png',
    publicKeyBundle: { ...vectors.publicKeyBundle, userId: username }
  };
}

function resetBundle(username = 'alice') {
  return {
    ...vectors.publicKeyBundle,
    userId: username,
    signingKey: { ...vectors.publicKeyBundle.signingKey, keyId: 'k1_AAAAAAAAAAAAAAAAAAAAAA' },
    encryptionKey: { ...vectors.publicKeyBundle.encryptionKey, keyId: 'k1_BBBBBBBBBBBBBBBBBBBBBB' },
    fingerprint: 'sha3-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
  };
}

function jsonRequest(method, body, headers = {}) {
  return {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body)
  };
}

function cookieFrom(response) {
  return response.headers.get('set-cookie').split(';')[0];
}

test('register stores bcrypt cost 12 hash, returns public user, JWT TTL, and digest-only refresh cookie', async () => {
  const { app, config, repository } = makeHarness();
  await withServer(app, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody()));
    const body = await response.json();
    assert.equal(response.status, 201);
    assert.equal(body.ok, true);
    assert.equal(body.data.user.username, 'alice');
    assert.equal(body.data.user.identityVersion, 1);
    assert.equal(body.data.user.passwordHash, undefined);
    assert.equal(body.data.user._id, undefined);
    assert.equal(body.data.user.publicKeyBundle.userId, 'alice');
    const decoded = jwt.decode(body.data.accessToken);
    assert.equal(decoded.exp - decoded.iat, 900);

    const stored = repository.state.users.get('alice');
    assert.equal(Number(stored.passwordHash.split('$')[2]), 12);
    assert.equal(await bcrypt.compare('correct horse battery staple', stored.passwordHash), true);
    const refreshToken = cookieFrom(response).split('=')[1];
    assert.equal([...repository.state.sessions.values()].some((session) => session.tokenHash === refreshToken), false);
    assert.equal([...repository.state.sessions.values()][0].tokenHash, repository.state.sessions.keys().next().value);
    assert.equal(config.refreshCookieName, '__Host-obscuron_refresh');
  });
});

test('register rejects duplicate usernames, mismatched bundle users, and encrypted vault fields', async () => {
  const { app } = makeHarness();
  await withServer(app, async (baseUrl) => {
    assert.equal((await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody()))).status, 201);
    const duplicate = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody()));
    assert.equal(duplicate.status, 409);
    assert.equal((await duplicate.json()).error.code, 'CONFLICT');

    const mismatched = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', { ...registerBody('bob'), publicKeyBundle: { ...vectors.publicKeyBundle, userId: 'alice' } }));
    assert.equal(mismatched.status, 400);
    assert.equal((await mismatched.json()).error.code, 'VALIDATION_FAILED');

    const vault = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', { ...registerBody('carol'), encryptedKeyBundle: vectors.encryptedKeyBundle }));
    assert.equal(vault.status, 400);

    const missingDisplayName = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', { ...registerBody('dave'), displayName: undefined }));
    assert.equal(missingDisplayName.status, 400);
    const missingBody = await missingDisplayName.json();
    assert.equal(missingBody.error.code, 'VALIDATION_FAILED');
    assert.ok(missingBody.error.details.some((detail) => detail.field === 'displayName'));
  });
});

test('unknown-user login still performs a cost-12 dummy bcrypt compare', async () => {
  const { authService } = makeHarness();
  const originalCompare = bcrypt.compare;
  const calls = [];
  bcrypt.compare = async (password, hash) => {
    calls.push({ password, hash });
    return originalCompare(password, hash);
  };
  try {
    await assert.rejects(
      () => authService.login({ username: 'nobody', password: 'wrong password!' }, { ip: '203.0.113.10' }),
      { status: 401, code: 'UNAUTHENTICATED' }
    );
  } finally {
    bcrypt.compare = originalCompare;
  }
  assert.equal(calls.length, 1);
  assert.equal(calls[0].hash, DUMMY_PASSWORD_HASH);
  assert.equal(Number(calls[0].hash.split('$')[2]), 12);
});

test('login uses generic failures and username rate limit while successful login issues a fresh refresh cookie', async () => {
  const { app } = makeHarness();
  await withServer(app, async (baseUrl) => {
    await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody()));
    const wrong = await fetch(`${baseUrl}/auth/login`, jsonRequest('POST', { username: 'alice', password: 'wrong password!' }));
    const unknown = await fetch(`${baseUrl}/auth/login`, jsonRequest('POST', { username: 'nobody', password: 'wrong password!' }));
    assert.equal(wrong.status, 401);
    const wrongBody = await wrong.json();
    const unknownBody = await unknown.json();
    assert.equal(wrongBody.error.code, unknownBody.error.code);
    assert.equal(wrongBody.error.message, unknownBody.error.message);
    assert.deepEqual(wrongBody.error.details, unknownBody.error.details);

    for (let index = 0; index < 4; index += 1) {
      await fetch(`${baseUrl}/auth/login`, jsonRequest('POST', { username: 'alice', password: 'wrong password!' }));
    }
    const locked = await fetch(`${baseUrl}/auth/login`, jsonRequest('POST', { username: 'alice', password: 'correct horse battery staple' }));
    assert.equal(locked.status, 429);

    const bobRegister = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody('bob')));
    assert.equal(bobRegister.status, 201);
    const login = await fetch(`${baseUrl}/auth/login`, jsonRequest('POST', { username: 'bob', password: 'correct horse battery staple' }));
    assert.equal(login.status, 200);
    assert.match(login.headers.get('set-cookie'), /HttpOnly; Secure; SameSite=Strict/);
  });
});

test('refresh rotates tokens and old token reuse revokes the whole token family', async () => {
  const { app, repository } = makeHarness();
  await withServer(app, async (baseUrl) => {
    const registered = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody()));
    const firstCookie = cookieFrom(registered);
    const refreshed = await fetch(`${baseUrl}/auth/refresh`, jsonRequest('POST', {}, { Cookie: firstCookie }));
    assert.equal(refreshed.status, 200);
    const secondCookie = cookieFrom(refreshed);
    assert.notEqual(firstCookie, secondCookie);

    const replay = await fetch(`${baseUrl}/auth/refresh`, jsonRequest('POST', {}, { Cookie: firstCookie }));
    assert.equal(replay.status, 401);
    assert.equal((await replay.json()).error.code, 'UNAUTHENTICATED');
    assert.equal([...repository.state.sessions.values()].every((session) => session.revokedAt), true);

    const revokedCurrent = await fetch(`${baseUrl}/auth/refresh`, jsonRequest('POST', {}, { Cookie: secondCookie }));
    assert.equal(revokedCurrent.status, 401);
  });
});

test('malformed percent-encoded refresh cookie returns 401 instead of a server error', async () => {
  const { app, config } = makeHarness();
  await withServer(app, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/refresh`, jsonRequest('POST', {}, { Cookie: `${config.refreshCookieName}=%E0%A4%A` }));
    const body = await response.json();
    assert.equal(response.status, 401);
    assert.equal(body.error.code, 'UNAUTHENTICATED');
  });
});

test('logout is idempotent, clears cookie, and prevents refresh reuse', async () => {
  const { app } = makeHarness();
  await withServer(app, async (baseUrl) => {
    const registered = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody()));
    const cookie = cookieFrom(registered);
    const logout = await fetch(`${baseUrl}/auth/logout`, jsonRequest('POST', {}, { Cookie: cookie }));
    assert.equal(logout.status, 204);
    assert.match(logout.headers.get('set-cookie'), /Max-Age=0/);
    assert.equal(await logout.text(), '');
    const secondLogout = await fetch(`${baseUrl}/auth/logout`, jsonRequest('POST', {}, { Cookie: cookie }));
    assert.equal(secondLogout.status, 204);
    const missingCookieLogout = await fetch(`${baseUrl}/auth/logout`, jsonRequest('POST', {}));
    assert.equal(missingCookieLogout.status, 204);
    const refresh = await fetch(`${baseUrl}/auth/refresh`, jsonRequest('POST', {}, { Cookie: cookie }));
    assert.equal(refresh.status, 401);
  });
});

test('concurrent same-cookie refresh allows one rotation and treats the stale peer as family reuse', async () => {
  const { app, repository } = makeHarness();
  await withServer(app, async (baseUrl) => {
    const registered = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody()));
    const cookie = cookieFrom(registered);
    const [first, second] = await Promise.all([
      fetch(`${baseUrl}/auth/refresh`, jsonRequest('POST', {}, { Cookie: cookie })),
      fetch(`${baseUrl}/auth/refresh`, jsonRequest('POST', {}, { Cookie: cookie }))
    ]);
    const statuses = [first.status, second.status].sort();
    assert.deepEqual(statuses, [200, 401]);
    assert.equal([...repository.state.sessions.values()].every((session) => session.revokedAt), true);
  });
});

test('protected profile, users, and me endpoints serialize public fields and reject unsupported profile input', async () => {
  const { app } = makeHarness();
  await withServer(app, async (baseUrl) => {
    const alice = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody()));
    const aliceToken = (await alice.json()).data.accessToken;
    await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody('bob')));
    const noAuth = await fetch(`${baseUrl}/me`);
    assert.equal(noAuth.status, 401);

    const me = await fetch(`${baseUrl}/me`, { headers: { Authorization: `Bearer ${aliceToken}` } });
    assert.equal(me.status, 200);
    assert.equal((await me.json()).data.user.username, 'alice');

    const users = await fetch(`${baseUrl}/users`, { headers: { Authorization: `Bearer ${aliceToken}` } });
    const usersBody = await users.json();
    assert.deepEqual(usersBody.data.users.map((user) => user.username), ['bob']);
    assert.equal(usersBody.data.users[0].passwordHash, undefined);

    const unknown = await fetch(`${baseUrl}/me/profile`, jsonRequest('PATCH', { displayName: 'Alice 2', role: 'admin' }, { Authorization: `Bearer ${aliceToken}` }));
    assert.equal(unknown.status, 400);
    const empty = await fetch(`${baseUrl}/me/profile`, jsonRequest('PATCH', {}, { Authorization: `Bearer ${aliceToken}` }));
    assert.equal(empty.status, 400);
    assert.ok((await empty.json()).error.details.some((detail) => detail.field === 'body'));
    const unsafeAvatar = await fetch(`${baseUrl}/me/profile`, jsonRequest('PATCH', { avatarUrl: 'http://example.com/a.png' }, { Authorization: `Bearer ${aliceToken}` }));
    assert.equal(unsafeAvatar.status, 400);
    const updated = await fetch(`${baseUrl}/me/profile`, jsonRequest('PATCH', { displayName: 'Alice 2', avatarUrl: null }, { Authorization: `Bearer ${aliceToken}` }));
    assert.equal(updated.status, 200);
    assert.equal((await updated.json()).data.user.displayName, 'Alice 2');
  });
});

// Contact discovery paging.
test('user discovery applies q, limit, and opaque cursor paging while excluding the caller', async () => {
  const { app } = makeHarness();
  await withServer(app, async (baseUrl) => {
    const alice = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody('alice', 'Alice')));
    const token = (await alice.json()).data.accessToken;
    for (const [username, displayName] of [['bob', 'Bobby'], ['carol', 'Carol'], ['bobby_two', 'Bee']]) {
      await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody(username, displayName)));
    }
    const auth = { Authorization: `Bearer ${token}` };

    const firstPage = await (await fetch(`${baseUrl}/users?limit=2`, { headers: auth })).json();
    assert.deepEqual(firstPage.data.users.map((user) => user.username), ['bob', 'bobby_two']);
    assert.ok(firstPage.data.nextCursor);

    const secondPage = await (await fetch(`${baseUrl}/users?limit=2&cursor=${encodeURIComponent(firstPage.data.nextCursor)}`, { headers: auth })).json();
    assert.deepEqual(secondPage.data.users.map((user) => user.username), ['carol']);
    assert.equal(secondPage.data.nextCursor, null);

    const byUsername = await (await fetch(`${baseUrl}/users?q=bob`, { headers: auth })).json();
    assert.deepEqual(byUsername.data.users.map((user) => user.username), ['bob', 'bobby_two']);
    const byDisplayName = await (await fetch(`${baseUrl}/users?q=Car`, { headers: auth })).json();
    assert.deepEqual(byDisplayName.data.users.map((user) => user.username), ['carol']);

    for (const query of ['limit=0', 'limit=101', 'limit=abc', 'cursor=not-a-cursor', 'unknown=1']) {
      const rejected = await fetch(`${baseUrl}/users?${query}`, { headers: auth });
      assert.equal(rejected.status, 400, query);
      assert.equal((await rejected.json()).error.code, 'VALIDATION_FAILED');
    }
  });
});

test('identity reset verifies password, increments identity version, and retires old public bundle', async () => {
  const { app, repository } = makeHarness();
  await withServer(app, async (baseUrl) => {
    const alice = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody()));
    const token = (await alice.json()).data.accessToken;
    const wrong = await fetch(`${baseUrl}/identity/reset`, jsonRequest('POST', {
      currentPassword: 'wrong password!',
      publicKeyBundle: resetBundle()
    }, { Authorization: `Bearer ${token}` }));
    assert.equal(wrong.status, 401);

    const reset = await fetch(`${baseUrl}/identity/reset`, jsonRequest('POST', {
      currentPassword: 'correct horse battery staple',
      publicKeyBundle: resetBundle()
    }, { Authorization: `Bearer ${token}` }));
    assert.equal(reset.status, 200);
    const body = await reset.json();
    assert.equal(body.data.user.identityVersion, 2);
    assert.equal(body.data.user.publicKeyBundle.fingerprint, resetBundle().fingerprint);
    const stored = repository.state.users.get('alice');
    assert.equal(stored.retiredPublicKeyBundles.length, 1);
    assert.equal(stored.retiredPublicKeyBundles[0].fingerprint, vectors.publicKeyBundle.fingerprint);
    assert.deepEqual(repository.state.messages, []);
  });
});

test('concurrent identity reset appends the active bundle and increments each winning update', async () => {
  const { app, repository } = makeHarness();
  await withServer(app, async (baseUrl) => {
    const alice = await fetch(`${baseUrl}/auth/register`, jsonRequest('POST', registerBody()));
    const token = (await alice.json()).data.accessToken;
    const bundleA = resetBundle();
    const bundleB = {
      ...resetBundle(),
      signingKey: { ...resetBundle().signingKey, keyId: 'k1_CCCCCCCCCCCCCCCCCCCCCC' },
      encryptionKey: { ...resetBundle().encryptionKey, keyId: 'k1_DDDDDDDDDDDDDDDDDDDDDD' },
      fingerprint: 'sha3-256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
    };
    const [first, second] = await Promise.all([
      fetch(`${baseUrl}/identity/reset`, jsonRequest('POST', {
        currentPassword: 'correct horse battery staple',
        publicKeyBundle: bundleA
      }, { Authorization: `Bearer ${token}` })),
      fetch(`${baseUrl}/identity/reset`, jsonRequest('POST', {
        currentPassword: 'correct horse battery staple',
        publicKeyBundle: bundleB
      }, { Authorization: `Bearer ${token}` }))
    ]);
    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    const stored = repository.state.users.get('alice');
    assert.equal(stored.identityVersion, 3);
    assert.equal(stored.retiredPublicKeyBundles.length, 2);
    assert.equal(stored.retiredPublicKeyBundles[0].fingerprint, vectors.publicKeyBundle.fingerprint);
    assert.ok(stored.retiredPublicKeyBundles[1].fingerprint === bundleA.fingerprint || stored.retiredPublicKeyBundles[1].fingerprint === bundleB.fingerprint);
  });
});
