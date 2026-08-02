const http = require('node:http');

function validEnv(overrides = {}) {
  return {
    NODE_ENV: 'test',
    PORT: '18080',
    MONGODB_URI: 'mongodb://tester:secret@mongodb:27017/obscuron_test?authSource=admin',
    JWT_ACCESS_SECRET: 'test_access_secret_with_32_bytes_minimum',
    JWT_ACCESS_TTL: '15m',
    REFRESH_TOKEN_SECRET: 'test_refresh_secret_with_32_bytes_minimum',
    REFRESH_COOKIE_NAME: '__Host-obscuron_refresh',
    BCRYPT_COST: '12',
    CORS_ALLOWED_ORIGINS: 'http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173',
    WS_ALLOWED_ORIGINS: 'http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173',
    WS_MAX_PAYLOAD_BYTES: '65536',
    WS_PERMESSAGE_DEFLATE: 'false',
    WS_HEARTBEAT_INTERVAL_SECONDS: '30',
    WS_HEARTBEAT_MISSES_ALLOWED: '2',
    WS_MAX_CONNECTIONS_PER_USER: '5',
    WS_MESSAGES_PER_MINUTE: '60',
    AUTH_USERNAME_FAIL_LIMIT: '5',
    AUTH_USERNAME_WINDOW_SECONDS: '900',
    AUTH_USERNAME_LOCKOUT_SECONDS: '1800',
    AUTH_IP_FAIL_LIMIT: '20',
    AUTH_IP_WINDOW_SECONDS: '900',
    AUTH_IP_LOCKOUT_SECONDS: '900',
    REFRESH_USER_LIMIT: '10',
    REFRESH_IP_LIMIT: '60',
    REFRESH_WINDOW_SECONDS: '600',
    MESSAGE_RETENTION_DAYS: '90',
    LOG_LEVEL: 'info',
    DEBUG: 'false',
    ...overrides
  };
}

function fakeMongo({ ready = true, ping = true } = {}) {
  return {
    connection: {
      readyState: ready ? 1 : 0,
      db: {
        admin() {
          return {
            async command(command) {
              if (!ping) throw new Error(`mongodb://user:password@host/${command}`);
              return { ok: 1 };
            }
          };
        }
      }
    }
  };
}

async function withServer(app, fn) {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

module.exports = {
  createFakeRepository,
  fakeMongo,
  validEnv,
  withServer
};

function createFakeRepository() {
  const state = {
    users: new Map(),
    sessions: new Map(),
    messages: []
  };
  let nextUserId = 1;

  function clone(value) {
    return value ? JSON.parse(JSON.stringify(value)) : value;
  }

  function publicCloneUser(user) {
    return clone(user);
  }

  const repository = {
    state,

    async findUserByUsername(username) {
      return publicCloneUser(state.users.get(username));
    },

    async createUser(user) {
      if (state.users.has(user.usernameNormalized)) {
        const error = new Error('duplicate');
        error.code = 'DUPLICATE_USER';
        throw error;
      }
      const created = { ...clone(user), id: `user_${nextUserId++}` };
      state.users.set(created.usernameNormalized, created);
      return publicCloneUser(created);
    },

    async updateUserProfile(username, patch) {
      const user = state.users.get(username);
      if (patch.displayName !== undefined) user.displayName = patch.displayName;
      if (patch.avatarUrl !== undefined) user.avatarUrl = patch.avatarUrl;
      user.updatedAt = new Date().toISOString();
      return publicCloneUser(user);
    },

    async listPublicUsersExcept(username) {
      return [...state.users.values()].filter((user) => user.username !== username).map(publicCloneUser);
    },

    async resetIdentity(username, publicKeyBundle, now) {
      const user = state.users.get(username);
      user.retiredPublicKeyBundles.push(clone(user.publicKeyBundle));
      user.publicKeyBundle = clone(publicKeyBundle);
      user.identityVersion += 1;
      user.identityResetAt = now.toISOString();
      user.updatedAt = now.toISOString();
      return publicCloneUser(user);
    },

    async createRefreshSession(session) {
      const created = clone(session);
      state.sessions.set(created.tokenHash, created);
      return clone(created);
    },

    async findRefreshSessionByHash(tokenHash) {
      return clone(state.sessions.get(tokenHash));
    },

    async rotateRefreshSession({ tokenHash, replacedByTokenHash, nextSession, now }) {
      const current = state.sessions.get(tokenHash);
      if (!current || current.revokedAt || current.replacedByTokenHash || new Date(current.expiresAt) <= now) return null;
      current.replacedByTokenHash = replacedByTokenHash;
      current.lastUsedAt = now.toISOString();
      const next = clone(nextSession);
      state.sessions.set(next.tokenHash, next);
      return clone(next);
    },

    async revokeRefreshFamily(tokenFamilyId, now) {
      for (const session of state.sessions.values()) {
        if (session.tokenFamilyId === tokenFamilyId && !session.revokedAt) session.revokedAt = now.toISOString();
      }
    }
  };

  return repository;
}
