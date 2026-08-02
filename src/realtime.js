const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const { PublicError } = require('./auth');
const { ERROR_MESSAGES, failure, success } = require('./envelope');
const { normalizeUsername, validateEncryptedMessageEnvelope, validateUsername } = require('./validation');

const AUTH_TIMEOUT_MS = 5000;
const CLOSE = {
  BAD_REQUEST: { code: 4400, reason: 'bad_request' },
  AUTH_REQUIRED: { code: 4401, reason: 'authentication_required' },
  INVALID_TOKEN: { code: 4401, reason: 'invalid_token' },
  EXPIRED: { code: 4401, reason: 'token_expired' },
  FORBIDDEN: { code: 4403, reason: 'forbidden' },
  TIMEOUT: { code: 4408, reason: 'authentication_timeout' },
  RATE_LIMITED: { code: 4429, reason: 'rate_limited' },
  INTERNAL: { code: 4500, reason: 'internal_error' }
};
const CLIENT_EVENTS = new Set(['authenticate', 'message.send', 'message.delivered']);
const DEFAULT_HISTORY_LIMIT = 50;
const MAX_HISTORY_LIMIT = 100;
const HIGH_WATER_CURSOR_DOMAIN = 'obscuron:ws:high_water_cursor:v1';

function createRealtimeService({ config, repository, authService, clock = () => new Date(), setTimer = setTimeout, clearTimer = clearTimeout }) {
  const socketsByUser = new Map();
  const messageLimiter = new WindowRateLimiter({
    limit: config.wsMessagesPerMinute,
    windowMs: 60 * 1000,
    clock
  });

  function registerRoutes(app) {
    app.get('/messages/:peer', asyncHandler(async (req, res) => {
      const user = await authService.currentUser(req.headers.authorization);
      const peer = validatePeer(req.params.peer);
      if (peer === user.username) throw new PublicError(400, 'VALIDATION_FAILED', [{ field: 'peer', reason: 'Must be another user.' }]);
      if (!await repository.findUserByUsername(peer, { includePasswordHash: false })) throw new PublicError(404, 'NOT_FOUND');
      const { limit, cursor } = parseHistoryOptions(req.query);
      if (cursor && !await repository.findHistoryCursorMessage(user.username, peer, cursor, clock())) throw new PublicError(400, 'VALIDATION_FAILED');
      const messages = await repository.listMessagesForParticipant(user.username, peer, { limit, cursor, now: clock(), order: 'desc' });
      return success(res, 200, { messages, nextCursor: nextCursor(messages) });
    }));
  }

  function handleConnection(ws) {
    const state = {
      authenticated: false,
      authenticating: false,
      username: null,
      connectionId: `conn_${crypto.randomBytes(16).toString('base64url')}`,
      badFrames: 0,
      misses: 0,
      authTimer: null,
      expiryTimer: null,
      heartbeatTimer: null
    };

    state.authTimer = armTimer(setTimer, () => close(ws, CLOSE.TIMEOUT), AUTH_TIMEOUT_MS);

    ws.on('message', async (data, isBinary) => {
      if (isBinary) return badRequest(ws, state, null, true);
      const frame = parseFrame(data);
      if (!frame) return badRequest(ws, state, null, true);
      const requestId = typeof frame.requestId === 'string' ? frame.requestId : null;
      if (!state.authenticated && frame.type !== 'authenticate') return close(ws, CLOSE.AUTH_REQUIRED);
      if (!CLIENT_EVENTS.has(frame.type)) return badRequest(ws, state, requestId, false);

      try {
        if (frame.type === 'authenticate') return await authenticate(ws, state, frame);
        if (frame.type === 'message.send') return await sendMessage(ws, state, frame);
        return await markDelivered(ws, state, frame);
      } catch (error) {
        if (error instanceof WsCloseError) return close(ws, error.close);
        if (error instanceof PublicError) return close(ws, CLOSE.BAD_REQUEST);
        return close(ws, CLOSE.INTERNAL);
      }
    });

    ws.on('pong', () => {
      state.misses = 0;
    });

    ws.on('error', () => {});

    ws.on('close', () => {
      clearTimer(state.authTimer);
      clearTimer(state.expiryTimer);
      clearTimer(state.heartbeatTimer);
      removeSocket(state.username, ws);
    });
  }

  function disconnectUser(username, reason = 'normal_closure') {
    for (const ws of socketsByUser.get(username) || []) {
      if (ws.readyState === 1 || ws.readyState === 0) ws.close(1000, reason);
    }
  }

  async function authenticate(ws, state, frame) {
    if (state.authenticated || state.authenticating || invalidKeys(frame, ['type', 'requestId', 'accessToken', 'replay']) || typeof frame.requestId !== 'string') {
      throw new WsCloseError(CLOSE.BAD_REQUEST);
    }
    if (typeof frame.accessToken !== 'string' || frame.accessToken.trim() === '') throw new WsCloseError(CLOSE.INVALID_TOKEN);
    state.authenticating = true;
    let decoded;
    try {
      decoded = authService.verifyAccessToken(frame.accessToken);
    } catch {
      const raw = jwt.decode(frame.accessToken);
      throw new WsCloseError(raw?.exp && raw.exp * 1000 <= clock().getTime() ? CLOSE.EXPIRED : CLOSE.INVALID_TOKEN);
    }
    const username = normalizeUsername(decoded.username);
    const user = username ? await repository.findUserByUsername(username, { includePasswordHash: false }) : null;
    if (!user) throw new WsCloseError(CLOSE.INVALID_TOKEN);
    if (socketCount(username) >= config.wsMaxConnectionsPerUser) throw new WsCloseError(CLOSE.RATE_LIMITED);

    state.authenticated = true;
    state.authenticating = false;
    state.username = user.username;
    clearTimer(state.authTimer);
    addSocket(user.username, ws);
    const tokenExpiresAt = new Date(decoded.exp * 1000);
    state.expiryTimer = armTimer(setTimer, () => close(ws, CLOSE.EXPIRED), Math.max(0, tokenExpiresAt.getTime() - clock().getTime()));
    state.heartbeatTimer = armTimer(setTimer, () => heartbeat(ws, state), config.wsHeartbeatIntervalSeconds * 1000);

    let replayOptions;
    try {
      replayOptions = parseReplayOptions(frame.replay, config);
    } catch {
      sendAuthenticated(ws, frame, state, user, nextReplayCursor([], clock(), config), clock());
      return sendError(ws, frame.requestId, 'VALIDATION_FAILED');
    }
    const cursorExpired = replayOptions.cursor && (
      replayOptions.cursorRejected
      || cursorOutsideReplayRetention(replayOptions.cursor, clock(), config)
      || !await repository.findReplayCursorMessage(user.username, replayOptions.cursor, clock())
    );
    const replayMessages = cursorExpired ? [] : await repository.listUndeliveredMessages(user.username, { ...replayOptions, now: clock(), order: 'asc' });
    const deliveryReceipts = cursorExpired ? [] : await repository.listDeliveryReceiptsForSender(user.username, { ...replayOptions, now: clock(), order: 'asc' });
    const replayEvents = replayMessages
      .map((message) => ({ event: 'message.new', message }))
      .concat(deliveryReceipts.map((message) => ({ event: 'message.delivered', message })))
      .sort(compareReplayEventsAsc)
      .slice(0, replayOptions.limit);
    sendAuthenticated(ws, frame, state, user, cursorExpired ? (frame.replay?.afterCursor || null) : nextReplayCursor(replayEvents, clock(), config), clock());
    if (cursorExpired) {
      return sendError(ws, frame.requestId, 'CURSOR_EXPIRED', [{ field: 'replay.afterCursor', reason: 'Use GET /messages/:peer to fetch fallback history.' }]);
    }
    for (const replay of replayEvents) {
      if (replay.event === 'message.new') {
        send(ws, { type: 'message.new', message: replay.message, cursor: encodeCursor(replay.message, 'message') });
      } else {
        send(ws, { type: 'message.delivered', messageId: replay.message.messageId, deliveredAt: replay.message.deliveredAt, cursor: encodeCursor(replay.message, 'delivery') });
      }
    }
  }

  async function sendMessage(ws, state, frame) {
    if (invalidKeys(frame, ['type', 'requestId', 'messageId', 'receiver', 'envelope']) || typeof frame.requestId !== 'string') throw new WsCloseError(CLOSE.BAD_REQUEST);
    if (typeof frame.messageId !== 'string' || typeof frame.receiver !== 'string') throw new WsCloseError(CLOSE.BAD_REQUEST);
    const envelope = frame.envelope;
    const validation = validateEncryptedMessageEnvelope(envelope, 'envelope');
    if (validation.details.length > 0) throw new WsCloseError(CLOSE.BAD_REQUEST);
    const sender = await repository.findUserByUsername(state.username, { includePasswordHash: false });
    const receiver = await repository.findUserByUsername(frame.receiver, { includePasswordHash: false });
    if (!sender || !receiver) throw new WsCloseError(CLOSE.FORBIDDEN);
    if (!messageLimiter.record(state.username)) throw new WsCloseError(CLOSE.RATE_LIMITED);
    if (!messageContractMatches({ envelope, frame, sender, receiver })) throw new WsCloseError(CLOSE.FORBIDDEN);

    const now = clock();
    const result = await repository.storeEncryptedMessage(envelope, {
      now,
      expiresAt: new Date(now.getTime() + config.messageRetentionDays * 24 * 60 * 60 * 1000)
    });
    if (result.status === 'conflict') {
      return sendError(ws, frame.requestId, 'MESSAGE_ID_CONFLICT', [{ field: 'messageId', reason: 'Conflicts with a stored encrypted envelope.' }]);
    }
    send(ws, {
      type: 'message.ack',
      requestId: frame.requestId,
      messageId: frame.messageId,
      deliveryState: result.message.deliveryState,
      serverReceivedAt: result.message.serverReceivedAt,
      cursor: encodeCursor(result.message, 'message')
    });
    for (const peerSocket of socketsByUser.get(envelope.receiver) || []) {
      if (peerSocket.readyState === 1) send(peerSocket, { type: 'message.new', message: result.message, cursor: encodeCursor(result.message, 'message') });
    }
  }

  async function markDelivered(ws, state, frame) {
    if (invalidKeys(frame, ['type', 'requestId', 'messageId']) || typeof frame.requestId !== 'string') throw new WsCloseError(CLOSE.BAD_REQUEST);
    if (typeof frame.messageId !== 'string' || !/^msg_[A-Za-z0-9_-]{26,64}$/.test(frame.messageId)) throw new WsCloseError(CLOSE.BAD_REQUEST);
    const message = await repository.markMessageDelivered(state.username, frame.messageId, clock());
    if (!message) throw new WsCloseError(CLOSE.FORBIDDEN);
    const event = { type: 'message.delivered', requestId: frame.requestId, messageId: frame.messageId, deliveredAt: message.deliveredAt, cursor: encodeCursor(message, 'delivery') };
    send(ws, event);
    for (const peerSocket of socketsByUser.get(message.sender) || []) {
      if (peerSocket.readyState === 1) send(peerSocket, event);
    }
  }

  function heartbeat(ws, state) {
    if (ws.readyState !== 1) return;
    state.misses += 1;
    if (state.misses > config.wsHeartbeatMissesAllowed) return ws.terminate();
    ws.ping();
    state.heartbeatTimer = armTimer(setTimer, () => heartbeat(ws, state), config.wsHeartbeatIntervalSeconds * 1000);
  }

  function addSocket(username, ws) {
    const sockets = socketsByUser.get(username) || new Set();
    sockets.add(ws);
    socketsByUser.set(username, sockets);
  }

  function removeSocket(username, ws) {
    if (!username) return;
    const sockets = socketsByUser.get(username);
    if (!sockets) return;
    sockets.delete(ws);
    if (sockets.size === 0) socketsByUser.delete(username);
  }

  function socketCount(username) {
    return (socketsByUser.get(username) || new Set()).size;
  }

  return { disconnectUser, handleConnection, registerRoutes, socketsByUser };
}

class WindowRateLimiter {
  constructor({ limit, windowMs, clock }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.clock = clock;
    this.entries = new Map();
  }

  record(key) {
    const now = this.clock().getTime();
    const current = this.entries.get(key);
    const entry = current && current.windowStart + this.windowMs > now ? current : { count: 0, windowStart: now };
    entry.count += 1;
    this.entries.set(key, entry);
    return entry.count <= this.limit;
  }
}

class WsCloseError extends Error {
  constructor(closeCode) {
    super(closeCode.reason);
    this.close = closeCode;
  }
}

function deriveConversationId(left, right) {
  const pair = [normalizeUsername(left), normalizeUsername(right)].sort().join(':');
  return `conv_${crypto.createHash('sha3-256').update(pair).digest('base64url')}`;
}

function sendAuthenticated(ws, frame, state, user, replayCursor, now) {
  send(ws, {
    type: 'authenticated',
    requestId: frame.requestId,
    connectionId: state.connectionId,
    serverTime: now.toISOString(),
    user: { username: user.username },
    replayCursor
  });
}

function messageContractMatches({ envelope, frame, sender, receiver }) {
  return frame.messageId === envelope.messageId
    && frame.receiver === envelope.receiver
    && envelope.sender === sender.username
    && envelope.receiver === receiver.username
    && envelope.conversationId === deriveConversationId(sender.username, receiver.username)
    && envelope.senderSigningKeyId === sender.publicKeyBundle?.signingKey?.keyId
    && envelope.senderEncryptionKeyId === sender.publicKeyBundle?.encryptionKey?.keyId
    && envelope.senderPublicKeyFingerprint === sender.publicKeyBundle?.fingerprint
    && envelope.receiverEncryptionKeyId === receiver.publicKeyBundle?.encryptionKey?.keyId;
}

function parseFrame(data) {
  try {
    const raw = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);
    const frame = JSON.parse(raw);
    return frame && typeof frame === 'object' && !Array.isArray(frame) ? frame : null;
  } catch {
    return null;
  }
}

function parseReplayOptions(replay = {}, config) {
  if (replay === undefined || replay === null) replay = {};
  if (!replay || typeof replay !== 'object' || Array.isArray(replay) || invalidKeys(replay, ['afterCursor', 'limit'])) throw new PublicError(400, 'VALIDATION_FAILED');
  const options = parseHistoryOptions({ cursor: replay.afterCursor, limit: replay.limit });
  if (!options.cursor || options.cursor.event !== 'high_water') return options;
  return { ...options, cursorRejected: !verifyHighWaterCursor(replay.afterCursor, config) };
}

function parseHistoryOptions(source = {}) {
  const rawLimit = source.limit === undefined ? DEFAULT_HISTORY_LIMIT : Number(source.limit);
  if (!Number.isInteger(rawLimit) || rawLimit < 1 || rawLimit > MAX_HISTORY_LIMIT) throw new PublicError(400, 'VALIDATION_FAILED');
  const cursor = source.cursor === undefined || source.cursor === null || source.cursor === '' ? null : parseCursor(source.cursor);
  return { limit: rawLimit, cursor };
}

function parseCursor(raw) {
  try {
    const parsed = JSON.parse(Buffer.from(String(raw), 'base64url').toString('utf8'));
    if (typeof parsed.messageId !== 'string' || Number.isNaN(Date.parse(parsed.serverReceivedAt))) throw new Error('bad cursor');
    return {
      messageId: parsed.messageId,
      serverReceivedAt: new Date(parsed.serverReceivedAt),
      sentAt: parsed.sentAt && !Number.isNaN(Date.parse(parsed.sentAt)) ? new Date(parsed.sentAt) : null,
      event: ['delivery', 'high_water'].includes(parsed.event) ? parsed.event : 'message'
    };
  } catch {
    throw new PublicError(400, 'VALIDATION_FAILED');
  }
}

function encodeCursor(message, event = 'message') {
  const time = event === 'delivery' ? message.deliveredAt : message.serverReceivedAt;
  return Buffer.from(JSON.stringify({
    event,
    serverReceivedAt: time,
    sentAt: event === 'delivery' ? time : message.sentAt,
    messageId: message.messageId
  })).toString('base64url');
}

function nextCursor(messages) {
  return messages.length > 0 ? encodeCursor(messages[messages.length - 1], 'message') : null;
}

function nextReplayCursor(events, now, config) {
  const event = events[events.length - 1];
  return event ? encodeCursor(event.message, event.event === 'message.delivered' ? 'delivery' : 'message') : encodeHighWaterCursor(now, config);
}

function encodeHighWaterCursor(now, config) {
  const payload = {
    event: 'high_water',
    serverReceivedAt: now.toISOString(),
    sentAt: now.toISOString(),
    messageId: 'msg_high_water_cursor'
  };
  return Buffer.from(JSON.stringify({
    ...payload,
    sig: signHighWaterPayload(payload, config)
  })).toString('base64url');
}

function verifyHighWaterCursor(raw, config) {
  try {
    const parsed = JSON.parse(Buffer.from(String(raw), 'base64url').toString('utf8'));
    const keys = Object.keys(parsed).sort();
    if (keys.join(',') !== 'event,messageId,sentAt,serverReceivedAt,sig') return false;
    if (parsed.event !== 'high_water' || parsed.messageId !== 'msg_high_water_cursor') return false;
    if (typeof parsed.serverReceivedAt !== 'string' || parsed.sentAt !== parsed.serverReceivedAt) return false;
    if (new Date(parsed.serverReceivedAt).toISOString() !== parsed.serverReceivedAt) return false;
    if (typeof parsed.sig !== 'string') return false;
    const expected = signHighWaterPayload({
      event: parsed.event,
      serverReceivedAt: parsed.serverReceivedAt,
      sentAt: parsed.sentAt,
      messageId: parsed.messageId
    }, config);
    return timingSafeEqualString(parsed.sig, expected);
  } catch {
    return false;
  }
}

function signHighWaterPayload(payload, config) {
  return crypto.createHmac('sha256', config.jwtAccessSecret)
    .update(HIGH_WATER_CURSOR_DOMAIN)
    .update('\0')
    .update(JSON.stringify(payload))
    .digest('base64url');
}

function timingSafeEqualString(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function compareReplayEventsAsc(left, right) {
  const leftAt = left.event === 'message.delivered' ? left.message.deliveredAt : left.message.serverReceivedAt;
  const rightAt = right.event === 'message.delivered' ? right.message.deliveredAt : right.message.serverReceivedAt;
  return new Date(leftAt) - new Date(rightAt) || left.message.messageId.localeCompare(right.message.messageId);
}

function validatePeer(value) {
  const result = validateUsername(value, 'peer');
  if (result.details.length > 0) throw new PublicError(400, 'VALIDATION_FAILED', result.details);
  return result.value;
}

function cursorOutsideReplayRetention(cursor, now, config) {
  const retentionStart = new Date(now.getTime() - config.messageRetentionDays * 24 * 60 * 60 * 1000);
  return cursor.serverReceivedAt < retentionStart || cursor.serverReceivedAt > now;
}

function badRequest(ws, state, requestId, closeNow) {
  state.badFrames += 1;
  if (!closeNow && state.badFrames === 1) return sendError(ws, requestId, 'VALIDATION_FAILED');
  return close(ws, CLOSE.BAD_REQUEST);
}

function invalidKeys(value, allowed) {
  return !value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some((key) => !allowed.includes(key));
}

function send(ws, payload) {
  if (ws.readyState !== 1) return;
  const body = Object.fromEntries(Object.entries(payload).filter(([, value]) => value !== undefined));
  ws.send(JSON.stringify(body));
}

function sendError(ws, requestId, code, details = []) {
  send(ws, {
    type: 'error',
    requestId,
    error: {
      code,
      message: ERROR_MESSAGES[code] || ERROR_MESSAGES.INTERNAL_ERROR,
      details
    }
  });
}

function close(ws, closeCode) {
  if (ws.readyState === 1 || ws.readyState === 0) ws.close(closeCode.code, closeCode.reason);
}

function armTimer(setTimer, fn, ms) {
  const timer = setTimer(fn, ms);
  if (timer && typeof timer.unref === 'function') timer.unref();
  return timer;
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

module.exports = {
  AUTH_TIMEOUT_MS,
  CLOSE,
  MAX_HISTORY_LIMIT,
  createRealtimeService,
  deriveConversationId,
  parseHistoryOptions
};
