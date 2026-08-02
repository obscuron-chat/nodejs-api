const { EncryptedMessage } = require('./encryptedMessage');
const { RefreshSession } = require('./refreshSession');
const { User } = require('./user');

const models = [User, RefreshSession, EncryptedMessage];

module.exports = {
  EncryptedMessage,
  RefreshSession,
  User,
  models
};
