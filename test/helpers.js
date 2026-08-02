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
  fakeMongo,
  validEnv,
  withServer
};
