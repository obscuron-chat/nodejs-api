const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { createMongoRepository } = require('../src/repositories/mongoRepository');

test('Mongo repository uses standalone-compatible atomic updates for refresh and identity reset', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'repositories', 'mongoRepository.js'), 'utf8');
  assert.doesNotMatch(source, /connection\.transaction/);
  assert.match(source, /findOneAndUpdate\(\s*\n\s*\{ tokenHash, revokedAt: null, replacedByTokenHash: null, expiresAt: \{ \$gt: now \} \}/);
  assert.match(source, /findOneAndUpdate\(\s*\n\s*\{ tokenFamilyId \}/);
  assert.match(source, /sort: \{ createdAt: 1 \}/);
  assert.match(source, /\$concatArrays/);
  assert.match(source, /\$add: \['\$identityVersion', 1\]/);
});

test('refresh rotation revokes replacement inserted after stale family marker race', async () => {
  const now = new Date('2026-08-02T00:00:00.000Z');
  const docs = [
    {
      tokenHash: 'old_hash',
      tokenFamilyId: 'fam_1',
      replacedByTokenHash: null,
      revokedAt: null,
      expiresAt: new Date('2026-08-03T00:00:00.000Z'),
      createdAt: new Date('2026-08-01T00:00:00.000Z')
    }
  ];
  let repository;
  let revokeDuringCreate = true;
  const RefreshSession = fakeRefreshSessionModel(docs, async () => {
    if (!revokeDuringCreate) return;
    revokeDuringCreate = false;
    await repository.revokeRefreshFamily('fam_1', now);
  });
  repository = createMongoRepository({}, { RefreshSession, User: {} });

  const rotated = await repository.rotateRefreshSession({
    tokenHash: 'old_hash',
    replacedByTokenHash: 'new_hash',
    now,
    nextSession: {
      tokenHash: 'new_hash',
      tokenFamilyId: 'fam_1',
      replacedByTokenHash: null,
      revokedAt: null,
      expiresAt: new Date('2026-09-01T00:00:00.000Z'),
      createdAt: new Date('2026-08-02T00:00:00.000Z')
    }
  });

  assert.equal(rotated, null);
  assert.equal(docs.length, 2);
  assert.equal(docs.every((doc) => doc.revokedAt?.toISOString() === now.toISOString()), true);
  assert.equal(docs.find((doc) => doc.tokenHash === 'old_hash').replacedByTokenHash, 'new_hash');
});

test('ordinary refresh rotation leaves replaced root unrevoked when no family marker exists', async () => {
  const now = new Date('2026-08-02T00:00:00.000Z');
  const docs = [
    {
      tokenHash: 'old_hash',
      tokenFamilyId: 'fam_1',
      replacedByTokenHash: null,
      revokedAt: null,
      expiresAt: new Date('2026-08-03T00:00:00.000Z'),
      createdAt: new Date('2026-08-01T00:00:00.000Z')
    }
  ];
  const repository = createMongoRepository({}, { RefreshSession: fakeRefreshSessionModel(docs), User: {} });

  const rotated = await repository.rotateRefreshSession({
    tokenHash: 'old_hash',
    replacedByTokenHash: 'new_hash',
    now,
    nextSession: {
      tokenHash: 'new_hash',
      tokenFamilyId: 'fam_1',
      replacedByTokenHash: null,
      revokedAt: null,
      expiresAt: new Date('2026-09-01T00:00:00.000Z'),
      createdAt: new Date('2026-08-02T00:00:00.000Z')
    }
  });

  assert.equal(rotated.tokenHash, 'new_hash');
  assert.equal(docs.find((doc) => doc.tokenHash === 'old_hash').revokedAt, null);
  assert.equal(docs.find((doc) => doc.tokenHash === 'old_hash').replacedByTokenHash, 'new_hash');
});

function fakeRefreshSessionModel(docs, beforeCreate = async () => {}) {
  return {
    findOne(filter) {
      return query(findOne(docs, filter));
    },
    findOneAndUpdate(filter, update, options = {}) {
      const doc = findOne(docs, filter, options);
      if (doc && update.$set) Object.assign(doc, update.$set);
      return query(doc);
    },
    async create(items) {
      await beforeCreate();
      const created = items.map((item) => {
        const doc = { ...item };
        docs.push(doc);
        return { toObject: () => ({ ...doc }) };
      });
      return created;
    },
    async updateMany(filter, update) {
      for (const doc of docs) {
        if (matches(doc, filter) && update.$set) Object.assign(doc, update.$set);
      }
    }
  };
}

function query(value) {
  return {
    async lean() {
      return value ? { ...value } : null;
    }
  };
}

function findOne(docs, filter, options = {}) {
  const found = docs.filter((doc) => matches(doc, filter));
  if (options.sort?.createdAt === 1) found.sort((left, right) => left.createdAt - right.createdAt);
  return found[0] || null;
}

function matches(doc, filter) {
  return Object.entries(filter).every(([key, expected]) => {
    if (expected && typeof expected === 'object' && !Array.isArray(expected)) {
      if (Object.hasOwn(expected, '$gt')) return doc[key] > expected.$gt;
      if (Object.hasOwn(expected, '$ne')) return doc[key] !== expected.$ne;
    }
    return doc[key] === expected;
  });
}
