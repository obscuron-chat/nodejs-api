const LOCAL_CORS_ORIGINS = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:4173',
  'http://127.0.0.1:4173'
];

const PRODUCTION_ORIGIN = 'https://obscuron.faizath.com';
const LOCAL_MONGODB_EXAMPLE = 'mongodb://admin:password@mongodb:27017/obscuron?authSource=admin';
const LOCAL_ACCESS_EXAMPLE = 'local_access_secret_replace_me_32_bytes_minimum';
const LOCAL_REFRESH_EXAMPLE = 'local_refresh_secret_replace_me_32_bytes_minimum';

class ConfigError extends Error {
  constructor(details) {
    super('Invalid service configuration.');
    this.name = 'ConfigError';
    this.details = details;
  }
}

function parseInteger(env, key, details, { min, max, exact } = {}) {
  const raw = env[key];
  const value = Number(raw);
  if (!raw || !Number.isInteger(value)) {
    details.push({ field: key, reason: 'must be an integer' });
    return undefined;
  }
  if (min !== undefined && value < min) details.push({ field: key, reason: `must be at least ${min}` });
  if (max !== undefined && value > max) details.push({ field: key, reason: `must be at most ${max}` });
  if (exact !== undefined && value !== exact) details.push({ field: key, reason: `must be ${exact}` });
  return value;
}

function parseOrigins(env, key, details, nodeEnv) {
  const raw = env[key];
  if (!raw) {
    details.push({ field: key, reason: 'is required' });
    return [];
  }
  const origins = raw.split(',').map((origin) => origin.trim()).filter(Boolean);
  if (origins.length === 0) details.push({ field: key, reason: 'must contain at least one origin' });
  for (const origin of origins) {
    if (origin === 'null' || origin.includes('*')) details.push({ field: key, reason: 'must be an exact allowlist' });
    if (origin.endsWith('/')) details.push({ field: key, reason: 'must not include trailing slashes' });
    try {
      const parsed = new URL(origin);
      if (!['http:', 'https:'].includes(parsed.protocol)) details.push({ field: key, reason: 'must use http or https' });
      if (nodeEnv === 'production' && parsed.protocol !== 'https:') details.push({ field: key, reason: 'production origins must use https' });
    } catch {
      details.push({ field: key, reason: 'must be valid origins' });
    }
  }
  if (nodeEnv === 'production' && origins.join(',') !== PRODUCTION_ORIGIN) {
    details.push({ field: key, reason: 'must match the production origin allowlist' });
  }
  return origins;
}

function requireString(env, key, details) {
  const value = env[key];
  if (!value || value.trim() === '') {
    details.push({ field: key, reason: 'is required' });
    return '';
  }
  return value;
}

function validateSecret(env, key, details, example) {
  const value = requireString(env, key, details);
  if (Buffer.byteLength(value) < 32) details.push({ field: key, reason: 'must be at least 32 bytes' });
  if (value === example) details.push({ field: key, reason: 'must not use the documented example value' });
  return value;
}

function loadConfig(env = process.env) {
  const details = [];
  const nodeEnv = requireString(env, 'NODE_ENV', details);
  if (!['development', 'test', 'production'].includes(nodeEnv)) {
    details.push({ field: 'NODE_ENV', reason: 'must be development, test, or production' });
  }

  const port = parseInteger(env, 'PORT', details, { min: 1024, max: 65535 });
  const mongodbUri = requireString(env, 'MONGODB_URI', details);
  if (mongodbUri === LOCAL_MONGODB_EXAMPLE) details.push({ field: 'MONGODB_URI', reason: 'must not use the documented example value' });
  try {
    const parsedMongo = new URL(mongodbUri);
    if (!parsedMongo.username || !parsedMongo.password) details.push({ field: 'MONGODB_URI', reason: 'must include credentials' });
    if (nodeEnv === 'production' && ['localhost', '127.0.0.1'].includes(parsedMongo.hostname)) {
      details.push({ field: 'MONGODB_URI', reason: 'production must not point to localhost' });
    }
  } catch {
    details.push({ field: 'MONGODB_URI', reason: 'must be a valid MongoDB URI' });
  }

  const jwtAccessSecret = validateSecret(env, 'JWT_ACCESS_SECRET', details, LOCAL_ACCESS_EXAMPLE);
  const refreshTokenSecret = validateSecret(env, 'REFRESH_TOKEN_SECRET', details, LOCAL_REFRESH_EXAMPLE);
  if (jwtAccessSecret && refreshTokenSecret && jwtAccessSecret === refreshTokenSecret) {
    details.push({ field: 'REFRESH_TOKEN_SECRET', reason: 'must differ from JWT_ACCESS_SECRET' });
  }

  if (requireString(env, 'JWT_ACCESS_TTL', details) !== '15m') details.push({ field: 'JWT_ACCESS_TTL', reason: 'must be 15m' });
  const refreshCookieName = requireString(env, 'REFRESH_COOKIE_NAME', details);
  if (nodeEnv === 'production' && refreshCookieName !== '__Host-obscuron_refresh') {
    details.push({ field: 'REFRESH_COOKIE_NAME', reason: 'must be __Host-obscuron_refresh in production' });
  }
  if (refreshCookieName && !refreshCookieName.startsWith('__Host-')) {
    details.push({ field: 'REFRESH_COOKIE_NAME', reason: 'must use the __Host- prefix' });
  }

  const bcryptCost = parseInteger(env, 'BCRYPT_COST', details, { exact: 12 });
  const corsAllowedOrigins = parseOrigins(env, 'CORS_ALLOWED_ORIGINS', details, nodeEnv);
  const wsAllowedOrigins = parseOrigins(env, 'WS_ALLOWED_ORIGINS', details, nodeEnv);
  const wsMaxPayloadBytes = parseInteger(env, 'WS_MAX_PAYLOAD_BYTES', details, { exact: 65536 });
  const wsHeartbeatIntervalSeconds = parseInteger(env, 'WS_HEARTBEAT_INTERVAL_SECONDS', details, { exact: 30 });
  const wsHeartbeatMissesAllowed = parseInteger(env, 'WS_HEARTBEAT_MISSES_ALLOWED', details, { exact: 2 });
  const wsMaxConnectionsPerUser = parseInteger(env, 'WS_MAX_CONNECTIONS_PER_USER', details, { exact: 5 });
  const wsMessagesPerMinute = parseInteger(env, 'WS_MESSAGES_PER_MINUTE', details, { exact: 60 });
  const messageRetentionDays = parseInteger(env, 'MESSAGE_RETENTION_DAYS', details, { min: 1, max: 365 });

  if (requireString(env, 'WS_PERMESSAGE_DEFLATE', details) !== 'false') details.push({ field: 'WS_PERMESSAGE_DEFLATE', reason: 'must be false' });
  const authUsernameFailLimit = parseInteger(env, 'AUTH_USERNAME_FAIL_LIMIT', details, { exact: 5 });
  const authUsernameWindowSeconds = parseInteger(env, 'AUTH_USERNAME_WINDOW_SECONDS', details, { exact: 900 });
  const authUsernameLockoutSeconds = parseInteger(env, 'AUTH_USERNAME_LOCKOUT_SECONDS', details, { exact: 1800 });
  const authIpFailLimit = parseInteger(env, 'AUTH_IP_FAIL_LIMIT', details, { exact: 20 });
  const authIpWindowSeconds = parseInteger(env, 'AUTH_IP_WINDOW_SECONDS', details, { exact: 900 });
  const authIpLockoutSeconds = parseInteger(env, 'AUTH_IP_LOCKOUT_SECONDS', details, { exact: 900 });
  const refreshUserLimit = parseInteger(env, 'REFRESH_USER_LIMIT', details, { exact: 10 });
  const refreshIpLimit = parseInteger(env, 'REFRESH_IP_LIMIT', details, { exact: 60 });
  const refreshWindowSeconds = parseInteger(env, 'REFRESH_WINDOW_SECONDS', details, { exact: 600 });
  const logLevel = requireString(env, 'LOG_LEVEL', details);
  if (logLevel && !['info', 'warn', 'error'].includes(logLevel)) details.push({ field: 'LOG_LEVEL', reason: 'must be info, warn, or error' });
  const debug = requireString(env, 'DEBUG', details);
  if (nodeEnv === 'production' && debug === 'true') details.push({ field: 'DEBUG', reason: 'must be false in production' });

  if (details.length > 0) throw new ConfigError(details);
  return {
    nodeEnv,
    port,
    mongodbUri,
    jwtAccessSecret,
    jwtAccessTtl: '15m',
    refreshTokenSecret,
    refreshCookieName,
    bcryptCost,
    corsAllowedOrigins,
    wsAllowedOrigins,
    wsMaxPayloadBytes,
    wsPerMessageDeflate: false,
    wsHeartbeatIntervalSeconds,
    wsHeartbeatMissesAllowed,
    wsMaxConnectionsPerUser,
    wsMessagesPerMinute,
    authUsernameFailLimit,
    authUsernameWindowSeconds,
    authUsernameLockoutSeconds,
    authIpFailLimit,
    authIpWindowSeconds,
    authIpLockoutSeconds,
    refreshUserLimit,
    refreshIpLimit,
    refreshWindowSeconds,
    messageRetentionDays,
    logLevel,
    debug: debug === 'true'
  };
}

module.exports = {
  ConfigError,
  LOCAL_CORS_ORIGINS,
  PRODUCTION_ORIGIN,
  loadConfig
};
