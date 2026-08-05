const express = require('express');
const http = require('node:http');
const WebSocket = require('ws');
const { failure, requestIdMiddleware, success } = require('./envelope');
const { isMongoReady } = require('./db');
const { createRealtimeService } = require('./realtime');
const { registerAuthRoutes } = require('./routes/authRoutes');

function createCorsMiddleware(config) {
  const allowed = new Set(config.corsAllowedOrigins);
  return (req, res, next) => {
    const origin = req.headers.origin;
    if (origin && !allowed.has(origin)) {
      return failure(res, 403, 'FORBIDDEN');
    }
    if (origin && allowed.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Request-Id');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS');
    }
    if (req.method === 'OPTIONS') return res.status(204).end();
    return next();
  };
}

function requireJsonBody(req, res, next) {
  if (['POST', 'PUT', 'PATCH'].includes(req.method) && !req.is('application/json')) {
    return failure(res, 415, 'UNSUPPORTED_MEDIA_TYPE');
  }
  return next();
}

function createApp({ config, mongo, wsState, dbState = { indexesReady: true }, authService = null, realtimeService = null, audit = () => null }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(requestIdMiddleware);
  app.use(createCorsMiddleware(config));
  app.use(requireJsonBody);
  app.use(express.json({ limit: '64kb' }));

  app.get('/healthz', (req, res) => success(res, 200, { status: 'ok' }));
  app.get('/readyz', async (req, res) => {
    const ready = await isMongoReady(mongo);
    if (ready && wsState.acceptingUpgrades && dbState.indexesReady) {
      return success(res, 200, { status: 'ready' });
    }
    return failure(res, 503, 'INTERNAL_ERROR');
  });
  app.get('/', (req, res) => success(res, 200, { service: 'obscuron-api' }));
  if (authService) registerAuthRoutes(app, { authService, config, realtimeService, audit });
  if (realtimeService) realtimeService.registerRoutes(app);

  app.use((req, res) => failure(res, 404, 'NOT_FOUND'));
  app.use((err, req, res, next) => {
    if (err && err.type === 'entity.too.large') return failure(res, 400, 'VALIDATION_FAILED');
    if (err instanceof SyntaxError && 'body' in err) return failure(res, 400, 'VALIDATION_FAILED');
    return failure(res, 500, 'INTERNAL_ERROR');
  });

  return app;
}

function createServer({ config, mongo, dbState = { indexesReady: true }, authService = null, repository = null, audit = () => null, realtimeOptions = {} }) {
  const wsState = { acceptingUpgrades: true };
  const realtimeService = authService && repository ? createRealtimeService({ config, repository, authService, audit, ...realtimeOptions }) : null;
  const app = createApp({ config, mongo, wsState, dbState, authService, realtimeService, audit });
  const server = http.createServer(app);
  const wss = new WebSocket.Server({
    noServer: true,
    maxPayload: config.wsMaxPayloadBytes,
    perMessageDeflate: config.wsPerMessageDeflate
  });
  server.wss = wss;
  const allowedWsOrigins = new Set(config.wsAllowedOrigins);

  server.on('upgrade', (req, socket, head) => {
    const origin = req.headers.origin;
    if (req.url !== '/ws' || !origin || !allowedWsOrigins.has(origin) || !wsState.acceptingUpgrades) {
      audit('ws.connect.rejected', {
        origin: origin || null,
        sourceIp: socket.remoteAddress || null,
        reason: wsState.acceptingUpgrades ? 'origin_or_path_not_allowed' : 'server_draining'
      });
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      if (!realtimeService) return ws.close(4401, 'authentication_required');
      wss.emit('connection', ws, req);
    });
  });

  if (realtimeService) wss.on('connection', realtimeService.handleConnection);

  const closeHttpServer = server.close.bind(server);
  server.close = (callback) => {
    wsState.acceptingUpgrades = false;
    for (const client of wss.clients) client.terminate();
    wss.close();
    return closeHttpServer(callback);
  };

  return { app, realtimeService, server, wss, wsState };
}

module.exports = {
  createApp,
  createCorsMiddleware,
  createServer,
  requireJsonBody
};
