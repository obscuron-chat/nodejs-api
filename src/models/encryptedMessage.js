const mongoose = require('mongoose');

const encryptedMessageSchema = new mongoose.Schema({
  messageId: { type: String, required: true },
  conversationId: { type: String, required: true },
  version: { type: Number, required: true },
  sender: { type: String, required: true },
  receiver: { type: String, required: true },
  senderEncryptionKeyId: { type: String, required: true },
  receiverEncryptionKeyId: { type: String, required: true },
  senderSigningKeyId: { type: String, required: true },
  senderPublicKeyFingerprint: { type: String, required: true },
  hkdfSalt: { type: String, required: true },
  nonce: { type: String, required: true },
  ciphertext: { type: String, required: true },
  sentAt: { type: Date, required: true },
  serverReceivedAt: { type: Date, required: true },
  deliveredAt: { type: Date, default: null },
  deliveryState: { type: String, enum: ['stored', 'delivered', 'expired'], required: true, default: 'stored' },
  expiresAt: { type: Date, required: true }
}, { timestamps: true, collection: 'encrypted_messages' });

encryptedMessageSchema.index({ messageId: 1 }, { unique: true, name: 'uniq_encrypted_messages_message_id' });
encryptedMessageSchema.index({ conversationId: 1, serverReceivedAt: -1, messageId: 1 }, { name: 'idx_encrypted_messages_conversation_time' });
encryptedMessageSchema.index({ receiver: 1, deliveryState: 1, serverReceivedAt: 1 }, { name: 'idx_encrypted_messages_receiver_delivery' });
encryptedMessageSchema.index({ sender: 1, serverReceivedAt: -1 }, { name: 'idx_encrypted_messages_sender_time' });
encryptedMessageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, name: 'ttl_encrypted_messages_expires_at' });

function storedEnvelope(message) {
  const source = typeof message.toObject === 'function' ? message.toObject() : message;
  return {
    version: source.version,
    messageId: source.messageId,
    conversationId: source.conversationId,
    sender: source.sender,
    receiver: source.receiver,
    senderEncryptionKeyId: source.senderEncryptionKeyId,
    receiverEncryptionKeyId: source.receiverEncryptionKeyId,
    senderSigningKeyId: source.senderSigningKeyId,
    senderPublicKeyFingerprint: source.senderPublicKeyFingerprint,
    hkdfSalt: source.hkdfSalt,
    nonce: source.nonce,
    ciphertext: source.ciphertext,
    sentAt: source.sentAt instanceof Date ? source.sentAt.toISOString() : source.sentAt,
    serverReceivedAt: source.serverReceivedAt instanceof Date ? source.serverReceivedAt.toISOString() : source.serverReceivedAt,
    deliveredAt: source.deliveredAt instanceof Date ? source.deliveredAt.toISOString() : source.deliveredAt,
    deliveryState: source.deliveryState,
    expiresAt: source.expiresAt instanceof Date ? source.expiresAt.toISOString() : source.expiresAt
  };
}

module.exports = {
  EncryptedMessage: mongoose.models.EncryptedMessage || mongoose.model('EncryptedMessage', encryptedMessageSchema),
  encryptedMessageSchema,
  storedEnvelope
};
