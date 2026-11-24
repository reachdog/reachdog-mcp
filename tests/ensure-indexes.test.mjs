import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';

const script = fileURLToPath(new URL('../scripts/ensure-indexes.mjs', import.meta.url));
let mongod;
before(async () => { mongod = await MongoMemoryServer.create(); });
after(async () => { await mongod?.stop(); });

const run = (env) => spawnSync(process.execPath, [script], {
  env: { PATH: process.env.PATH, ...env }, encoding: 'utf8', timeout: 60000,
});

test('creates the connector indexes and says so', async () => {
  const r = run({ MONGO_URI: mongod.getUri(), MONGO_DB: 'idx_test' });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), 'indexes ready');
  const c = await MongoClient.connect(mongod.getUri());
  try {
    const db = c.db('idx_test');
    const ttl = async (name) => (await db.collection(name).indexes()).filter((i) => i.expireAfterSeconds !== undefined);
    assert.equal((await ttl('mcp_oauth_codes'))[0].key.expires, 1);
    assert.equal((await ttl('mcp_oauth_refresh'))[0].key.last_used, 1);
    assert.equal((await ttl('mcp_spend'))[0].key.created_at, 1);
    assert.equal((await ttl('mcp_quotes'))[0].key.created_at, 1);
    assert.equal((await ttl('mcp_oauth_clients'))[0].key.last_used, 1);
    assert.equal((await ttl('mcp_oauth_clients'))[0].expireAfterSeconds, 90 * 86400);
    assert.ok((await db.collection('mcp_oauth_refresh').indexes()).some((i) => i.key.grant_id === 1));
  } finally { await c.close(); }
  assert.equal(run({ MONGO_URI: mongod.getUri(), MONGO_DB: 'idx_test' }).status, 0, 'idempotent');
});

test('a bad connection string fails without echoing it', () => {
  const secret = 'hunter2-not-a-real-password';
  const r = run({ MONGO_URI: 'mongodb://user:' + secret + '@127.0.0.1:1/x', MONGO_DB: 'idx_test' });
  assert.notEqual(r.status, 0);
  assert.ok(r.stderr.includes('MONGO_URI'));
  assert.ok(!(r.stdout + r.stderr).includes(secret));
  assert.ok(!(r.stdout + r.stderr).includes('127.0.0.1'));
});

test('missing MONGO_URI fails with a message naming it', () => {
  const r = run({});
  assert.notEqual(r.status, 0);
  assert.ok(r.stderr.includes('MONGO_URI'));
});
