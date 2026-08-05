const { redact } = require('./redaction');

// The complete set of audit events the service is allowed to emit.
const AUDIT_EVENTS = Object.freeze([
  'auth.login.success',
  'auth.login.failure',
  'auth.register.success',
  'auth.logout',
  'auth.refresh.success',
  'auth.refresh.reuse_detected',
  'auth.rate_limited',
  'ws.connect.accepted',
  'ws.connect.rejected',
  'ws.message.rejected',
  'ws.rate_limited',
  'ws.connection_limit',
  'config.startup_failed',
  'backup.completed',
  'backup.failed',
  'restore.completed',
  'restore.failed',
  'deploy.started',
  'deploy.completed',
  'rollback.started',
  'rollback.completed'
]);

const LEVEL_ORDER = { info: 0, warn: 1, error: 2 };
const FAILURE_EVENTS = new Set([
  'auth.login.failure',
  'auth.refresh.reuse_detected',
  'auth.rate_limited',
  'ws.connect.rejected',
  'ws.message.rejected',
  'ws.rate_limited',
  'ws.connection_limit',
  'config.startup_failed',
  'backup.failed',
  'restore.failed'
]);

/**
 * Builds the audit record for one event. Every field passes through
 * `redact` so secrets, key material, and ciphertext can never reach a log sink,
 * and unknown event names are rejected rather than silently written.
 */
function createAuditLogger({ config, clock = () => new Date(), sink = console } = {}) {
  const threshold = LEVEL_ORDER[config?.logLevel] ?? LEVEL_ORDER.info;

  return function audit(event, fields = {}) {
    if (!AUDIT_EVENTS.includes(event)) throw new Error(`Unknown audit event: ${event}`);
    const level = FAILURE_EVENTS.has(event) ? 'warn' : 'info';
    if (LEVEL_ORDER[level] < threshold) return null;
    const record = redact({
      timestamp: clock().toISOString(),
      event,
      level,
      result: FAILURE_EVENTS.has(event) ? 'failure' : 'success',
      requestId: fields.requestId ?? null,
      connectionId: fields.connectionId ?? null,
      username: fields.username ?? null,
      sourceIp: fields.sourceIp ?? null,
      origin: fields.origin ?? null,
      reason: fields.reason ?? null
    });
    sink[level === 'warn' ? 'warn' : 'log'](JSON.stringify(record));
    return record;
  };
}

module.exports = { AUDIT_EVENTS, createAuditLogger };
