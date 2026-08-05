const { clearRefreshCookie, parseCookies, refreshCookie } = require('../cookies');
const { failure, success } = require('../envelope');
const { PublicError } = require('../auth');
const { publicUser } = require('../models/user');

function registerAuthRoutes(app, { authService, config, realtimeService = null }) {
  app.post('/auth/register', asyncHandler(async (req, res) => {
    const result = await authService.register(req.body, requestMeta(req));
    res.setHeader('Set-Cookie', refreshCookie(config, result.refreshToken));
    return success(res, 201, { user: publicUser(result.user), accessToken: result.accessToken });
  }));

  app.post('/auth/login', asyncHandler(async (req, res) => {
    const result = await authService.login(req.body, requestMeta(req));
    res.setHeader('Set-Cookie', refreshCookie(config, result.refreshToken));
    return success(res, 200, { user: publicUser(result.user), accessToken: result.accessToken });
  }));

  app.post('/auth/refresh', asyncHandler(async (req, res) => {
    const token = parseCookies(req.headers.cookie)[config.refreshCookieName];
    const result = await authService.refresh(token, requestMeta(req));
    res.setHeader('Set-Cookie', refreshCookie(config, result.refreshToken));
    return success(res, 200, { user: publicUser(result.user), accessToken: result.accessToken });
  }));

  app.post('/auth/logout', asyncHandler(async (req, res) => {
    const token = parseCookies(req.headers.cookie)[config.refreshCookieName];
    const result = await authService.logout(token);
    if (result.username && realtimeService) realtimeService.disconnectUser(result.username, 'normal_closure');
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
    return success(res, 200, { user: publicUser(user) });
  }));
}

function asyncHandler(handler) {
  return async (req, res, next) => {
    try {
      return await handler(req, res, next);
    } catch (error) {
      if (error instanceof PublicError) return failure(res, error.status, error.code, { details: error.details });
      return next(error);
    }
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
