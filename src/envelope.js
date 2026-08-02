const crypto = require('node:crypto');

const ERROR_MESSAGES = {
  VALIDATION_FAILED: 'Request validation failed.',
  UNAUTHENTICATED: 'Authentication required.',
  FORBIDDEN: 'Permission denied.',
  NOT_FOUND: 'Resource not found.',
  CONFLICT: 'Request conflicts with existing state.',
  RATE_LIMITED: 'Too many requests.',
  INTERNAL_ERROR: 'Internal server error.',
  UNSUPPORTED_MEDIA_TYPE: 'Unsupported media type.'
};

function createRequestId() {
  return `req_${crypto.randomBytes(16).toString('base64url')}`;
}

function success(res, status, data = {}) {
  return res.status(status).json({ ok: true, data });
}

function failure(res, status, code, { details = [], requestId = res.locals.requestId } = {}) {
  return res.status(status).json({
    ok: false,
    error: {
      code,
      message: ERROR_MESSAGES[code] || ERROR_MESSAGES.INTERNAL_ERROR,
      details,
      requestId
    }
  });
}

function requestIdMiddleware(req, res, next) {
  res.locals.requestId = req.headers['x-request-id'] || createRequestId();
  res.setHeader('X-Request-Id', res.locals.requestId);
  next();
}

module.exports = {
  ERROR_MESSAGES,
  createRequestId,
  failure,
  requestIdMiddleware,
  success
};
