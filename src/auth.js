const bcrypt = require('bcrypt');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const {
  findForbiddenFields,
  normalizeUsername,
  validateAvatarUrl,
  validateDisplayName,
  validatePassword,
  validatePublicKeyBundle,
  validateUsername
} = require('./validation');

const ACCESS_TOKEN_SECONDS = 15 * 60;
const REFRESH_TOKEN_BYTES = 32;
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_USER_LIMIT = 50;
const MAX_USER_LIMIT = 100;
const MAX_USER_QUERY_LENGTH = 32;
const DUMMY_PASSWORD_HASH = '$2b$12$wThDT6GJX/YAyB1u0vR3Jus3oI6JdWMndZM9aa00exAIhX3tySUIm';

class PublicError extends Error {
  constructor(status, code, details = []) {
    super(code);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

class RateLimiter {
  constructor({ limit, windowMs, lockoutMs, clock = () => new Date() }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.lockoutMs = lockoutMs;
    this.clock = clock;
    this.entries = new Map();
  }

  isLimited(key) {
    const now = this.clock().getTime();
    const entry = this.entries.get(key);
    if (!entry) return false;
    if (entry.lockedUntil && entry.lockedUntil > now) return true;
    if (entry.windowStart + this.windowMs <= now) {
      this.entries.delete(key);
      return false;
    }
    return false;
  }

  recordFailure(key) {
    const now = this.clock().getTime();
    const current = this.entries.get(key);
    const entry = current && current.windowStart + this.windowMs > now ? current : { count: 0, windowStart: now, lockedUntil: null };
    entry.count += 1;
    if (entry.count >= this.limit) entry.lockedUntil = now + this.lockoutMs;
    this.entries.set(key, entry);
    return Boolean(entry.lockedUntil && entry.lockedUntil > now);
  }

  recordAttempt(key) {
    const now = this.clock().getTime();
    const current = this.entries.get(key);
    const entry = current && current.windowStart + this.windowMs > now ? current : { count: 0, windowStart: now, lockedUntil: null };
    if (entry.lockedUntil && entry.lockedUntil > now) return true;
    entry.count += 1;
    if (entry.count > this.limit) entry.lockedUntil = now + this.lockoutMs;
    this.entries.set(key, entry);
    return Boolean(entry.lockedUntil && entry.lockedUntil > now);
  }

  clear(key) {
    this.entries.delete(key);
  }
}

function createAuthService({ config, repository, clock = () => new Date(), randomBytes = crypto.randomBytes }) {
  const usernameFailures = new RateLimiter({
    limit: config.authUsernameFailLimit || 5,
    windowMs: (config.authUsernameWindowSeconds || 900) * 1000,
    lockoutMs: (config.authUsernameLockoutSeconds || 1800) * 1000,
    clock
  });
  const ipFailures = new RateLimiter({
    limit: config.authIpFailLimit || 20,
    windowMs: (config.authIpWindowSeconds || 900) * 1000,
    lockoutMs: (config.authIpLockoutSeconds || 900) * 1000,
    clock
  });
  const refreshUserAttempts = new RateLimiter({
    limit: config.refreshUserLimit || 10,
    windowMs: (config.refreshWindowSeconds || 600) * 1000,
    lockoutMs: (config.refreshWindowSeconds || 600) * 1000,
    clock
  });
  const refreshIpAttempts = new RateLimiter({
    limit: config.refreshIpLimit || 60,
    windowMs: (config.refreshWindowSeconds || 600) * 1000,
    lockoutMs: (config.refreshWindowSeconds || 600) * 1000,
    clock
  });

  function issueAccessToken(user) {
    return jwt.sign(
      { sub: String(user.id || user._id || user.username), username: user.username },
      config.jwtAccessSecret,
      { expiresIn: config.jwtAccessTtl }
    );
  }

  function verifyAccessToken(token) {
    try {
      return jwt.verify(token, config.jwtAccessSecret);
    } catch {
      throw new PublicError(401, 'UNAUTHENTICATED');
    }
  }

  function rawRefreshToken() {
    return randomBytes(REFRESH_TOKEN_BYTES).toString('base64url');
  }

  function digestRefreshToken(token) {
    return crypto.createHmac('sha256', config.refreshTokenSecret).update(token).digest('base64url');
  }

  function newId(prefix) {
    return `${prefix}_${randomBytes(16).toString('base64url')}`;
  }

  async function createRefreshSession(user, meta = {}, familyId = newId('fam')) {
    const token = rawRefreshToken();
    const now = clock();
    const session = {
      userId: user.id || user._id,
      usernameNormalized: user.usernameNormalized || user.username,
      tokenHash: digestRefreshToken(token),
      tokenFamilyId: familyId,
      sessionId: newId('sess'),
      lastUsedAt: now,
      expiresAt: new Date(now.getTime() + REFRESH_TTL_MS),
      revokedAt: null,
      replacedByTokenHash: null,
      ipHash: meta.ip ? crypto.createHash('sha256').update(meta.ip).digest('base64url') : null,
      userAgentHash: meta.userAgent ? crypto.createHash('sha256').update(meta.userAgent).digest('base64url') : null
    };
    await repository.createRefreshSession(session);
    return { token, session };
  }

  function validateExactObject(body, allowed) {
    const details = [];
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return [{ field: 'body', reason: 'Must be an object.' }];
    }
    for (const key of Object.keys(body)) {
      if (!allowed.includes(key)) details.push({ field: key, reason: 'Unknown field.' });
    }
    return details.concat(findForbiddenFields(body).filter((detail) => {
      const topLevel = detail.field.split('.')[0];
      return !allowed.includes(topLevel) || detail.field.includes('.');
    }));
  }

  function validatePublicProfileInput(body, { requirePassword = false, requireDisplayName = false, requirePublicKeyBundle = false } = {}) {
    let details = validateExactObject(body, ['username', 'password', 'displayName', 'avatarUrl', 'publicKeyBundle']);
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new PublicError(400, 'VALIDATION_FAILED', details);
    const usernameResult = body.username === undefined ? { value: undefined, details: [] } : validateUsername(body.username);
    const displayNameResult = body.displayName === undefined ? { value: undefined, details: [] } : validateDisplayName(body.displayName);
    const avatarResult = body.avatarUrl === undefined ? { value: null, details: [] } : validateAvatarUrl(body.avatarUrl);
    details = details.concat(usernameResult.details, displayNameResult.details, avatarResult.details);
    if (requirePassword) details = details.concat(validatePassword(body.password).details);
    if (requireDisplayName && body.displayName === undefined) details.push({ field: 'displayName', reason: 'Is required.' });
    if (requirePublicKeyBundle) {
      details = details.concat(validatePublicKeyBundle(body.publicKeyBundle).details);
      if (usernameResult.value && body.publicKeyBundle?.userId !== usernameResult.value) {
        details.push({ field: 'publicKeyBundle.userId', reason: 'Must match canonical username.' });
      }
    } else if (body.publicKeyBundle !== undefined) {
      details = details.concat(validatePublicKeyBundle(body.publicKeyBundle).details);
    }
    if (details.length > 0) throw new PublicError(400, 'VALIDATION_FAILED', details);
    return {
      username: usernameResult.value,
      password: body.password,
      displayName: displayNameResult.value,
      avatarUrl: avatarResult.value,
      publicKeyBundle: body.publicKeyBundle
    };
  }

  async function register(body, meta = {}) {
    const input = validatePublicProfileInput(body, { requirePassword: true, requireDisplayName: true, requirePublicKeyBundle: true });
    const existing = await repository.findUserByUsername(input.username, { includePasswordHash: false });
    if (existing) throw new PublicError(409, 'CONFLICT');
    const passwordHash = await bcrypt.hash(input.password, config.bcryptCost);
    const now = clock();
    const user = await repository.createUser({
      username: input.username,
      usernameNormalized: input.username,
      passwordHash,
      displayName: input.displayName || input.username,
      avatarUrl: input.avatarUrl,
      publicKeyBundle: input.publicKeyBundle,
      retiredPublicKeyBundles: [],
      identityVersion: 1,
      identityResetAt: null,
      createdAt: now,
      updatedAt: now
    }).catch((error) => {
      if (error && error.code === 'DUPLICATE_USER') throw new PublicError(409, 'CONFLICT');
      throw error;
    });
    const refresh = await createRefreshSession(user, meta);
    return { user, accessToken: issueAccessToken(user), refreshToken: refresh.token };
  }

  async function login(body, meta = {}) {
    let details = validateExactObject(body, ['username', 'password']);
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new PublicError(400, 'VALIDATION_FAILED', details);
    details = details.concat(validateUsername(body.username).details, validatePassword(body.password).details);
    if (details.length > 0) throw new PublicError(400, 'VALIDATION_FAILED', details);
    const username = normalizeUsername(body.username);
    if (usernameFailures.isLimited(username) || ipFailures.isLimited(meta.ip || 'unknown')) throw new PublicError(429, 'RATE_LIMITED');
    const user = await repository.findUserByUsername(username, { includePasswordHash: true });
    const passwordHash = user?.passwordHash || DUMMY_PASSWORD_HASH;
    const passwordOk = await bcrypt.compare(body.password, passwordHash);
    if (!passwordOk) {
      usernameFailures.recordFailure(username);
      ipFailures.recordFailure(meta.ip || 'unknown');
      throw new PublicError(401, 'UNAUTHENTICATED');
    }
    usernameFailures.clear(username);
    const refresh = await createRefreshSession(user, meta);
    return { user, accessToken: issueAccessToken(user), refreshToken: refresh.token };
  }

  async function refresh(rawToken, meta = {}) {
    if (!rawToken) throw new PublicError(401, 'UNAUTHENTICATED');
    if (refreshIpAttempts.recordAttempt(meta.ip || 'unknown')) throw new PublicError(429, 'RATE_LIMITED');
    const now = clock();
    const tokenHash = digestRefreshToken(rawToken);
    const existing = await repository.findRefreshSessionByHash(tokenHash);
    if (!existing) throw new PublicError(401, 'UNAUTHENTICATED');
    if (refreshUserAttempts.recordAttempt(existing.usernameNormalized)) throw new PublicError(429, 'RATE_LIMITED');
    if (existing.revokedAt || existing.replacedByTokenHash || new Date(existing.expiresAt) <= now) {
      await repository.revokeRefreshFamily(existing.tokenFamilyId, now);
      throw new PublicError(401, 'UNAUTHENTICATED');
    }
    const user = await repository.findUserByUsername(existing.usernameNormalized, { includePasswordHash: false });
    if (!user) throw new PublicError(401, 'UNAUTHENTICATED');
    const nextToken = rawRefreshToken();
    const nextHash = digestRefreshToken(nextToken);
    const nextSession = {
      userId: user.id || user._id,
      usernameNormalized: user.usernameNormalized || user.username,
      tokenHash: nextHash,
      tokenFamilyId: existing.tokenFamilyId,
      sessionId: existing.sessionId,
      lastUsedAt: now,
      expiresAt: new Date(now.getTime() + REFRESH_TTL_MS),
      revokedAt: null,
      replacedByTokenHash: null,
      ipHash: meta.ip ? crypto.createHash('sha256').update(meta.ip).digest('base64url') : null,
      userAgentHash: meta.userAgent ? crypto.createHash('sha256').update(meta.userAgent).digest('base64url') : null
    };
    const rotated = await repository.rotateRefreshSession({ tokenHash, replacedByTokenHash: nextHash, nextSession, now });
    if (!rotated) {
      await repository.revokeRefreshFamily(existing.tokenFamilyId, now);
      throw new PublicError(401, 'UNAUTHENTICATED');
    }
    return { user, accessToken: issueAccessToken(user), refreshToken: nextToken };
  }

  async function logout(rawToken) {
    let username = null;
    if (rawToken) {
      const session = await repository.findRefreshSessionByHash(digestRefreshToken(rawToken));
      if (session) {
        username = session.usernameNormalized;
        await repository.revokeRefreshFamily(session.tokenFamilyId, clock());
      }
    }
    return { username };
  }

  async function currentUser(authorization) {
    const token = parseBearer(authorization);
    const decoded = verifyAccessToken(token);
    const user = await repository.findUserByUsername(decoded.username, { includePasswordHash: false });
    if (!user) throw new PublicError(401, 'UNAUTHENTICATED');
    return user;
  }

  async function updateProfile(authorization, body) {
    const user = await currentUser(authorization);
    let details = validateExactObject(body, ['displayName', 'avatarUrl']);
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new PublicError(400, 'VALIDATION_FAILED', details);
    if (!Object.hasOwn(body, 'displayName') && !Object.hasOwn(body, 'avatarUrl')) {
      details.push({ field: 'body', reason: 'At least one profile field is required.' });
    }
    if (body.displayName !== undefined) details = details.concat(validateDisplayName(body.displayName).details);
    if (body.avatarUrl !== undefined) details = details.concat(validateAvatarUrl(body.avatarUrl).details);
    if (details.length > 0) throw new PublicError(400, 'VALIDATION_FAILED', details);
    return repository.updateUserProfile(user.username, {
      displayName: body.displayName === undefined ? undefined : validateDisplayName(body.displayName).value,
      avatarUrl: body.avatarUrl === undefined ? undefined : validateAvatarUrl(body.avatarUrl).value
    });
  }

  async function listUsers(authorization, query = {}) {
    const user = await currentUser(authorization);
    const options = parseUserListOptions(query);
    const users = await repository.listPublicUsersExcept(user.username, options);
    // One extra row tells us whether another page exists without a second count query.
    const page = users.slice(0, options.limit);
    return {
      users: page,
      nextCursor: users.length > options.limit ? encodeUserCursor(page[page.length - 1]) : null
    };
  }

  async function resetIdentity(authorization, body) {
    const user = await currentUser(authorization);
    let details = validateExactObject(body, ['password', 'publicKeyBundle']);
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new PublicError(400, 'VALIDATION_FAILED', details);
    details = details.concat(validatePassword(body.password).details, validatePublicKeyBundle(body.publicKeyBundle).details);
    if (body.publicKeyBundle?.userId !== user.username) details.push({ field: 'publicKeyBundle.userId', reason: 'Must match canonical username.' });
    if (details.length > 0) throw new PublicError(400, 'VALIDATION_FAILED', details);
    const withHash = await repository.findUserByUsername(user.username, { includePasswordHash: true });
    const passwordOk = withHash ? await bcrypt.compare(body.password, withHash.passwordHash) : false;
    if (!passwordOk) throw new PublicError(401, 'UNAUTHENTICATED');
    return repository.resetIdentity(user.username, body.publicKeyBundle, clock());
  }

  return {
    digestRefreshToken,
    issueAccessToken,
    login,
    logout,
    refresh,
    register,
    resetIdentity,
    currentUser,
    updateProfile,
    listUsers,
    verifyAccessToken
  };
}

function parseUserListOptions(query) {
  const details = [];
  if (query && typeof query === 'object' && !Array.isArray(query)) {
    for (const key of Object.keys(query)) {
      if (!['q', 'cursor', 'limit'].includes(key)) details.push({ field: key, reason: 'Unknown query parameter.' });
    }
  }
  const rawLimit = query.limit === undefined ? DEFAULT_USER_LIMIT : Number(query.limit);
  if (!Number.isInteger(rawLimit) || rawLimit < 1 || rawLimit > MAX_USER_LIMIT) {
    details.push({ field: 'limit', reason: `Must be an integer from 1 to ${MAX_USER_LIMIT}.` });
  }
  if (query.q !== undefined && (typeof query.q !== 'string' || query.q.trim().length > MAX_USER_QUERY_LENGTH)) {
    details.push({ field: 'q', reason: `Must be a string of at most ${MAX_USER_QUERY_LENGTH} characters.` });
  }
  let cursor = null;
  if (query.cursor !== undefined && query.cursor !== '') {
    cursor = decodeUserCursor(query.cursor);
    if (!cursor) details.push({ field: 'cursor', reason: 'Is not a cursor issued by this server.' });
  }
  if (details.length > 0) throw new PublicError(400, 'VALIDATION_FAILED', details);
  return {
    q: typeof query.q === 'string' ? query.q.trim() : '',
    cursor,
    limit: rawLimit
  };
}

function encodeUserCursor(user) {
  return user ? Buffer.from(JSON.stringify({ after: user.username })).toString('base64url') : null;
}

function decodeUserCursor(raw) {
  try {
    const parsed = JSON.parse(Buffer.from(String(raw), 'base64url').toString('utf8'));
    const keys = Object.keys(parsed);
    if (keys.length !== 1 || keys[0] !== 'after') return null;
    return validateUsername(parsed.after).details.length === 0 ? { after: parsed.after } : null;
  } catch {
    return null;
  }
}

function parseBearer(authorization) {
  if (typeof authorization !== 'string') throw new PublicError(401, 'UNAUTHENTICATED');
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) throw new PublicError(401, 'UNAUTHENTICATED');
  return match[1];
}

module.exports = {
  ACCESS_TOKEN_SECONDS,
  DUMMY_PASSWORD_HASH,
  MAX_USER_LIMIT,
  PublicError,
  RateLimiter,
  createAuthService,
  parseBearer,
  parseUserListOptions
};
