require('dotenv').config();

const { loadConfig } = require('./src/config');
const { connectMongo, initializeDatabase } = require('./src/db');
const { createAuthService } = require('./src/auth');
const { createMongoRepository } = require('./src/repositories/mongoRepository');
const { createServer } = require('./src/server');
const { redact } = require('./src/redaction');

async function main() {
  try {
    const config = loadConfig(process.env);
    const mongo = await connectMongo(config);
    await initializeDatabase();
    const repository = createMongoRepository(mongo);
    const authService = createAuthService({ config, repository });
    const { server } = createServer({ config, mongo, authService, dbState: { indexesReady: true } });

    server.listen(config.port, () => {
      console.log(`api.started port=${config.port} env=${config.nodeEnv}`);
    });
  } catch (error) {
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
