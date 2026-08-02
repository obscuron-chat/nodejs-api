const SECRET_KEY_PATTERN = /(authorization|cookie|password|token|secret|privatekey|passwordhash|tokenhash|ciphertext|publickey|fingerprint|nonce|hkdfsalt|avatarurl|url|uri)/i;
const REDACTED = '[REDACTED]';

function redact(value) {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(redact);
  if (typeof value === 'string') return redactString(value);
  if (typeof value !== 'object') return value;
  const output = {};
  for (const [key, child] of Object.entries(value)) {
    output[key] = isSensitiveKey(key) ? REDACTED : redact(child);
  }
  return output;
}

function isSensitiveKey(key) {
  return SECRET_KEY_PATTERN.test(key.replace(/[^a-z0-9]/gi, ''));
}

function redactString(value) {
  return value
    .replace(/mongodb(?:\+srv)?:\/\/[^:@/\s]+:[^@/\s]+@/gi, 'mongodb://[REDACTED]@')
    .replace(/(authorization=)[^&\s]+/gi, '$1[REDACTED]')
    .replace(/(token=)[^&\s]+/gi, '$1[REDACTED]')
    .replace(/(password=)[^&\s]+/gi, '$1[REDACTED]');
}

function redactedJson(value) {
  return JSON.stringify(redact(value));
}

module.exports = { REDACTED, redact, redactedJson };
