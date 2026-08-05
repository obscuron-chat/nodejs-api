#!/usr/bin/env node
// Emits one audit event from outside the request path so backup,
// restore, deploy, and rollback tooling writes the same redacted record shape
// the service uses. Usage: node scripts/audit-event.js <event> [reason]
require('dotenv').config();

const { AUDIT_EVENTS, createAuditLogger } = require('../src/audit');

function main(argv) {
  const [event, reason = null] = argv;
  if (!AUDIT_EVENTS.includes(event)) {
    console.error(`Unknown audit event. Expected one of: ${AUDIT_EVENTS.join(', ')}`);
    return 1;
  }
  createAuditLogger({ config: { logLevel: process.env.LOG_LEVEL || 'info' } })(event, { reason });
  return 0;
}

if (require.main === module) process.exit(main(process.argv.slice(2)));

module.exports = { main };
