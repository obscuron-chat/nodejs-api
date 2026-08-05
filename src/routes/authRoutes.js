const { clearRefreshCookie, parseCookies, refreshCookie } = require('../cookies');
const { failure, success } = require('../envelope');
const { PublicError } = require('../auth');
const { publicUser } = require('../models/user');

function registerAuthRoutes(app, { authService, config, realtimeService = null, audit = () => null }) {
  app.post('/auth/register', asyncHandler(async (req, res) => {
    const result = await authService.register(req.body, requestMeta(req));
    audit('auth.register.success', auditMeta(req, res, result.user.username));
    res.setHeader('Set-Cookie', refreshCookie(config, result.refreshToken));
    return success(res, 201, { user: publicUser(result.user), accessToken: result.accessToken });
  }, { audit, failureEvent: loginStyleFailure }));

  app.post('/auth/login', asyncHandler(async (req, res) => {
    const result = await authService.login(req.body, requestMeta(req));
    audit('auth.login.success', auditMeta(req, res, result.user.username));
    res.setHeader('Set-Cookie', refreshCookie(config, result.refreshToken));
    return success(res, 200, { user: publicUser(result.user), accessToken: result.accessToken });
  }, { audit, failureEvent: loginStyleFailure }));

  app.post('/auth/refresh', asyncHandler(async (req, res) => {
    const token = parseCookies(req.headers.cookie)[config.refreshCookieName];
    const result = await authService.refresh(token, requestMeta(req));
    audit('auth.refresh.success', auditMeta(req, res, result.user.username));
    res.setHeader('Set-Cookie', refreshCookie(config, result.refreshToken));
    return success(res, 200, { user: publicUser(result.user), accessToken: result.accessToken });
  }, { audit, failureEvent: refreshFailure }));

  app.post('/auth/logout', asyncHandler(async (req, res) => {
    const token = parseCookies(req.headers.cookie)[config.refreshCookieName];
    const result = await authService.logout(token);
    if (result.username && realtimeService) realtimeService.disconnectUser(result.username, 'normal_closure');
    audit('auth.logout', auditMeta(req, res, result.username));
    res.setHeader('Set-Cookie', clearRefreshCookie(config));
    return res.status(204).end();
  }));

  app.get('/me', asyncHandler(async (req, res) => {
    const user = await authService.currentUser(req.headers.authorization);
    return success(res, 200, { user: publicUser(user) });
  }));

  app.patch('/me/profile', asyncHandler(async (req, res) => {
    const user = await authService.updateProfile(req.headers.authorization, req.body);
    return success(res, 200, { user: publicUser(user) });
  }));

  app.get('/users', asyncHandler(async (req, res) => {
    const page = await authService.listUsers(req.headers.authorization, req.query);
    return success(res, 200, { users: page.users.map(publicUser), nextCursor: page.nextCursor });
  }));

  app.post('/identity/reset', asyncHandler(async (req, res) => {
    const user = await authService.resetIdentity(req.headers.authorization, req.body);
    return success(res, 200, identityEpochResult(user));
  }));
}

function asyncHandler(handler, { audit = null, failureEvent = null } = {}) {
  return async (req, res, next) => {
    try {
      return await handler(req, res, next);
    } catch (error) {
      if (error instanceof PublicError) {
        if (audit && failureEvent) {
          const event = failureEvent(error);
          if (event) audit(event, auditMeta(req, res, error.auditUsername ?? usernameHint(req), error.code));
        }
        return failure(res, error.status, error.code, { details: error.details });
      }
      return next(error);
    }
  };
}

function loginStyleFailure(error) {
  if (error.code === 'RATE_LIMITED') return 'auth.rate_limited';
  return error.status === 401 ? 'auth.login.failure' : null;
}

function refreshFailure(error) {
  if (error.code === 'RATE_LIMITED') return 'auth.rate_limited';
  return error.auditEvent ?? null;
}

function auditMeta(req, res, username = null, reason = null) {
  return {
    requestId: res.locals?.requestId ?? null,
    username: username ?? null,
    sourceIp: req.ip || req.socket?.remoteAddress || null,
    origin: req.headers.origin || null,
    reason
  };
}

// Login failures must stay generic to the client, but the audit trail needs the
// attempted username; it is only ever read from the already-validated body.
function usernameHint(req) {
  return typeof req.body?.username === 'string' ? req.body.username.trim() : null;
}

// Reset reports the new identity epoch and published bundle, not a whole profile.
function identityEpochResult(user) {
  const updatedAt = user.identityResetAt || user.updatedAt;
  return {
    identityEpoch: user.identityVersion,
    publicKeyBundle: user.publicKeyBundle,
    updatedAt: updatedAt instanceof Date ? updatedAt.toISOString() : updatedAt
  };
}

function requestMeta(req) {
  return {
    ip: req.ip || req.socket?.remoteAddress || 'unknown',
    userAgent: req.headers['user-agent'] || ''
  };
}

module.exports = {
  registerAuthRoutes,
  requestMeta
};
