const mongoose = require('mongoose');
const { models } = require('./models');

async function connectMongo(config) {
  await mongoose.connect(config.mongodbUri, {
    serverSelectionTimeoutMS: 5000,
    serverApi: { version: '1', strict: true, deprecationErrors: true }
  });
  await mongoose.connection.db.admin().command({ ping: 1 });
  return mongoose;
}

async function initializeDatabase() {
  for (const model of models) {
    await model.createCollection();
    await model.syncIndexes();
  }
}

async function isMongoReady(mongo = mongoose) {
  if (mongo.connection.readyState !== 1) return false;
  try {
    await mongo.connection.db.admin().command({ ping: 1 });
    return true;
  } catch {
    return false;
  }
}

module.exports = {
  connectMongo,
  initializeDatabase,
  isMongoReady,
  mongoose
};
