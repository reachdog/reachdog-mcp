import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { HostedStore, utcDay } from '../dist/hosted/store.js';
import { ApiError } from '../dist/client.js';

let mongod, client, db, n = 0;
before(async () => {
  mongod = await MongoMemoryServer.create();
  client = await MongoClient.connect(mongod.getUri());
});
after(async () => { await client?.close(); await mongod?.stop(); });
const fresh = () => { db = client.db('t' + (n++)); return new HostedStore(db); };
const codeDoc = (over = {}) => ({
  client_id: 'c1', grant_id: 'g1', sealed_secret: 'opaque-sealed', challenge: 'ch',
  redirect_uri: 'http://127.0.0.1:1/cb', resource: 'https://x/mcp',
  expires: new Date(Date.now() + 60_000), ...over,
});

test('clients round trip', async () => {
  const s = fresh();
  assert.equal(await s.getClient('a'), undefined);
  await s.putClient({ client_id: 'a', redirect_uris: ['http://localhost:1/x'] });
  assert.equal((await s.getClient('a')).client_id, 'a');
});

test('code is single use, kind-matched, and stored hashed', async () => {
  const s = fresh();
  await s.putCode('raw-code', 'code', codeDoc());
  const ids = (await db.collection('mcp_oauth_codes').find().toArray()).map(d => d._id);
  assert.ok(!ids.includes('raw-code'));
  assert.equal(await s.takeCode('raw-code', 'pending'), null);
  const got = await s.takeCode('raw-code', 'code');
  assert.equal(got.grant_id, 'g1');
  assert.equal(await s.takeCode('raw-code', 'code'), null);
});

test('expired code is not returned', async () => {
  const s = fresh();
  await s.putCode('old', 'pending', codeDoc({ expires: new Date(Date.now() - 1000) }));
  assert.equal(await s.takeCode('old', 'pending'), null);
});

test('refresh rotation: ok, then reused, unknown', async () => {
  const s = fresh();
  await s.putRefresh('j1', 'g1', 'c1');
  assert.equal(await s.rotateRefresh('j1', 'j2'), 'ok');
  assert.equal(await s.rotateRefresh('j1', 'j3'), 'reused');
  assert.equal(await s.rotateRefresh('nope', 'j4'), 'unknown');
  assert.equal(await s.rotateRefresh('j2', 'j5'), 'ok');
  const docs = await db.collection('mcp_oauth_refresh').find().toArray();
  assert.ok(docs.every(d => !['j1', 'j2', 'j5'].includes(d._id)));
  await s.dropGrant('g1');
  assert.equal(await db.collection('mcp_oauth_refresh').countDocuments(), 0);
});

test('10 concurrent reserves of 2000 against 10000 admit exactly 5', async () => {
  const s = fresh();
  const sp = s.spend('g', 10000, '2026-01-01');
  assert.equal(sp.limit, 10000);
  const r = await Promise.allSettled(Array.from({ length: 10 }, (_, i) =>
    sp.runPaidPost('op' + i, 2000, async () => { await new Promise(r => setTimeout(r, 20)); return i; })));
  assert.equal(r.filter(x => x.status === 'fulfilled').length, 5);
  const bad = r.find(x => x.status === 'rejected');
  assert.match(bad.reason.message, /^Daily limit reached: 0 of 10000 Reach Dog tokens left today$/);
  const doc = await db.collection('mcp_spend').findOne({ _id: 'g:2026-01-01' });
  assert.equal(doc.total, 10000);
});

test('settle lowers reservation; refused releases; same id busy', async () => {
  const s = fresh();
  const sp = s.spend('g', 10000, '2026-01-01');
  await sp.runPaidPost('a', 3000, async () => 1);
  await sp.settle('a', 1000);
  assert.equal((await db.collection('mcp_spend').findOne({ _id: 'g:2026-01-01' })).total, 1000);
  await sp.refused('a');
  assert.equal((await db.collection('mcp_spend').findOne({ _id: 'g:2026-01-01' })).total, 0);
  let release;
  const p = sp.runPaidPost('b', 10, () => new Promise(r => { release = r; }));
  await new Promise(r => setTimeout(r, 30));
  await assert.rejects(sp.runPaidPost('b', 10, async () => 1), /already in progress/);
  release(1); await p;
});

test('ApiError refusal releases a new reservation, ambiguous keeps it', async () => {
  const s = fresh();
  const sp = s.spend('g', 10000, '2026-01-01');
  const total = async () => (await db.collection('mcp_spend').findOne({ _id: 'g:2026-01-01' })).total;
  await assert.rejects(sp.runPaidPost('x', 500, async () => { throw new ApiError(402, 'no'); }));
  assert.equal(await total(), 0);
  await assert.rejects(sp.runPaidPost('y', 500, async () => { throw new Error('boom'); }));
  assert.equal(await total(), 500);
  await sp.runPaidPost('y', 800, async () => 1);
  assert.equal(await total(), 800);
});

test('quote set on one instance is read by another; namespaced by grant', async () => {
  const a = fresh();
  const b = new HostedStore(db);
  await a.quotes('g1').setQuote('q', 'bind');
  await a.quotes('g1').setAccepted('q', 'acc');
  assert.equal(await b.quotes('g1').getQuote('q'), 'bind');
  assert.equal(await b.quotes('g1').getAccepted('q'), 'acc');
  assert.equal(await b.quotes('g2').getQuote('q'), undefined);
});

test('day rollover starts fresh; utcDay format', async () => {
  const s = fresh();
  await s.spend('g', 100, '2026-01-01').runPaidPost('a', 100, async () => 1);
  await assert.rejects(s.spend('g', 100, '2026-01-01').runPaidPost('b', 1, async () => 1), /Daily limit reached/);
  await s.spend('g', 100, '2026-01-02').runPaidPost('b', 100, async () => 1);
  assert.match(utcDay(), /^\d{4}-\d{2}-\d{2}$/);
});

test('ensureIndexes creates TTL indexes', async () => {
  const s = fresh();
  await s.ensureIndexes();
  const idx = await db.collection('mcp_oauth_refresh').indexes();
  assert.ok(idx.some(i => i.expireAfterSeconds === 30 * 86400));
});

test('persisted code doc holds no grant secret value', async () => {
  const s = fresh();
  await s.putCode('c', 'code', codeDoc());
  const raw = JSON.stringify(await db.collection('mcp_oauth_codes').find().toArray());
  assert.ok(!raw.includes('grant_secret'));
  assert.ok(raw.includes('opaque-sealed'));
});

test('two Spend objects from one store cannot run the same id concurrently', async () => {
  const s = fresh();
  let release;
  const p = s.spend('g', 10000, '2026-01-01').runPaidPost('same', 10, () => new Promise(r => { release = r; }));
  await new Promise(r => setTimeout(r, 30));
  await assert.rejects(s.spend('g', 10000, '2026-01-01').runPaidPost('same', 10, async () => 1), /already in progress/);
  release(1); await p;
});

test('refusal reports remaining excluding own prior reservation', async () => {
  const s = fresh();
  const sp = s.spend('g', 10000, '2026-01-01');
  await sp.runPaidPost('big', 9000, async () => 1);
  await assert.rejects(sp.runPaidPost('other', 2000, async () => 1), /1000 of 10000/);
  await assert.rejects(sp.runPaidPost('big', 11000, async () => 1), /10000 of 10000/);
});
