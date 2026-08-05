require('dotenv').config();

const { loadConfig } = require('./src/config');
const { connectMongo, initializeDatabase } = require('./src/db');
const { createAuditLogger } = require('./src/audit');
const { createAuthService } = require('./src/auth');
const { createMongoRepository } = require('./src/repositories/mongoRepository');
const { createServer } = require('./src/server');
const { redact } = require('./src/redaction');

async function main() {
  let audit = null;
  try {
    const config = loadConfig(process.env);
    audit = createAuditLogger({ config });
    const mongo = await connectMongo(config);
    await initializeDatabase();
    const repository = createMongoRepository(mongo);
    const authService = createAuthService({ config, repository });
    const { server } = createServer({ config, mongo, authService, repository, audit, dbState: { indexesReady: true } });

    server.listen(config.port, () => {
      console.log(`api.started port=${config.port} env=${config.nodeEnv}`);
    });
  } catch (error) {
    if (audit) audit('config.startup_failed', { reason: error.name || 'startup_error' });
    console.error('config.startup_failed', redact({
      message: error.message,
      details: error.details || []
    }));
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { main };
