import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AccountsClient, setupWallet, metadataIdToken,
  ReconnectError, WalletError, GrantLimitError, AccountsUnavailable,
} from '../dist/hosted/accounts.js';

const ORIGIN = 'https://accounts.example';
const json = (status, body) => new Response(body === undefined ? null : JSON.stringify(body),
  { status, headers: { 'Content-Type': 'application/json' } });
const recorder = (reply) => {
  const calls = [];
  const f = async (url, init) => { calls.push({ url: String(url), init }); return typeof reply === 'function' ? reply(url, init) : reply.clone(); };
  return { f, calls };
};
const tok = async (aud) => 'idtoken-for-' + aud;
const hdr = (c, k) => new Headers(c.init.headers).get(k);
const errBody = (code) => ({ error: { code, message: 'secret upstream text' } });
const created = { grant_id: 'g1', grant_secret: 's1', key_id: 'k1', daily_limit: 10000 };
const resolved = { account_id: 'a1', key: 'rd_key', key_id: 'k1', daily_limit: 10000 };

test('createGrant sends token audience, pass, and body', async () => {
  const r = recorder(json(201, created));
  const audiences = [];
  const c = new AccountsClient(ORIGIN, async (a) => { audiences.push(a); return 'T'; }, r.f);
  const out = await c.createGrant('PASS', { client_name: 'n', redirect_host: 'h', daily_limit: 5 });
  assert.deepEqual(out, created);
  assert.deepEqual(audiences, [ORIGIN]);
  const call = r.calls[0];
  assert.equal(call.url, ORIGIN + '/internal/connector-grants');
  assert.equal(call.init.method, 'POST');
  assert.equal(hdr(call, 'Authorization'), 'Bearer T');
  assert.equal(hdr(call, 'X-Accounts-Pass'), 'PASS');
  assert.deepEqual(JSON.parse(call.init.body), { client_name: 'n', redirect_host: 'h', daily_limit: 5 });
});

test('resolve and revoke send no pass header', async () => {
  const r = recorder((u, i) => i.method === 'DELETE' ? new Response(null, { status: 204 }) : json(200, resolved));
  const c = new AccountsClient(ORIGIN + '/', tok, r.f);
  assert.deepEqual(await c.resolve('g1', 's1'), resolved);
  await c.revoke('g/1');
  assert.equal(r.calls[0].url, ORIGIN + '/internal/connector-grants/resolve');
  assert.deepEqual(JSON.parse(r.calls[0].init.body), { grant_id: 'g1', grant_secret: 's1' });
  assert.equal(r.calls[1].url, ORIGIN + '/internal/connector-grants/g%2F1');
  assert.equal(r.calls[1].init.method, 'DELETE');
  for (const c2 of r.calls) {
    assert.equal(hdr(c2, 'X-Accounts-Pass'), null);
    assert.equal(hdr(c2, 'Authorization'), 'Bearer idtoken-for-' + ORIGIN);
  }
});

const mapping = [
  ['grant_invalid', 401, ReconnectError], ['grant_revoked', 401, ReconnectError],
  ['wallet_ineligible', 409, WalletError], ['grant_limit', 409, GrantLimitError],
  ['account_unavailable', 403, AccountsUnavailable], ['invalid_request', 422, AccountsUnavailable],
  ['caller_denied', 403, AccountsUnavailable], ['person_required', 403, AccountsUnavailable],
  ['mystery', 500, AccountsUnavailable],
];
for (const [code, status, Cls] of mapping) {
  test('error ' + code + ' maps to ' + Cls.name, async () => {
    const c = new AccountsClient(ORIGIN, tok, recorder(json(status, errBody(code))).f);
    await assert.rejects(c.resolve('g', 's'), (e) => {
      assert.ok(e instanceof Cls);
      assert.ok(!e.message.includes('secret upstream text'));
      return true;
    });
  });
}

test('network failure, bad JSON, bad shapes, and token failure are AccountsUnavailable', async () => {
  const cases = [
    () => { throw new Error('boom rd_key'); },
    () => new Response('<html>', { status: 200 }),
    () => json(200, { account_id: 'a', key: '', key_id: 'k', daily_limit: 1 }),
    () => json(200, { account_id: 'a', key: 'k', key_id: 'k', daily_limit: '1' }),
    () => json(200, null),
    () => json(500, 'nonsense'),
  ];
  for (const reply of cases) {
    const c = new AccountsClient(ORIGIN, tok, async () => reply());
    await assert.rejects(c.resolve('g', 's'), (e) => e instanceof AccountsUnavailable && !/boom|rd_key/.test(e.message));
  }
  const c = new AccountsClient(ORIGIN, async () => { throw new Error('meta'); }, recorder(json(200, resolved)).f);
  await assert.rejects(c.resolve('g', 's'), AccountsUnavailable);
  const c2 = new AccountsClient(ORIGIN, tok, recorder(json(201, { ...created, key_id: 5 })).f);
  await assert.rejects(c2.createGrant('p', { client_name: 'n', redirect_host: 'h', daily_limit: 1 }), AccountsUnavailable);
});

test('revoke maps errors and requires 204', async () => {
  const c = new AccountsClient(ORIGIN, tok, recorder(json(500, {})).f);
  await assert.rejects(c.revoke('g'), AccountsUnavailable);
  const c2 = new AccountsClient(ORIGIN, tok, recorder(json(200, {})).f);
  await assert.rejects(c2.revoke('g'), AccountsUnavailable);
});

test('requests carry a timeout signal', async () => {
  const r = recorder(json(200, resolved));
  await new AccountsClient(ORIGIN, tok, r.f).resolve('g', 's');
  assert.ok(r.calls[0].init.signal instanceof AbortSignal);
});

test('setupWallet posts {} with wallet-audience token and pass', async () => {
  const r = recorder(json(200, { state: 'active' }));
  const audiences = [];
  await setupWallet('https://api.example/', 'wallet-aud', 'PASS', async (a) => { audiences.push(a); return 'WT'; }, r.f);
  assert.deepEqual(audiences, ['wallet-aud']);
  const c = r.calls[0];
  assert.equal(c.url, 'https://api.example/internal/console-wallet');
  assert.equal(c.init.body, '{}');
  assert.equal(hdr(c, 'Authorization'), 'Bearer WT');
  assert.equal(hdr(c, 'X-Accounts-Pass'), 'PASS');
});

test('setupWallet errors', async () => {
  const run = (resp) => setupWallet('https://api.example', 'a', 'p', tok, recorder(resp).f);
  await assert.rejects(run(json(409, { detail: { code: 'wallet_ineligible' } })), WalletError);
  await assert.rejects(run(json(403, { detail: { code: 'service_unauthorized' } })), AccountsUnavailable);
  await assert.rejects(run(json(200, { state: 'weird' })), AccountsUnavailable);
  await assert.rejects(run(json(200, { state: 'pending' })), AccountsUnavailable);
  await assert.rejects(setupWallet('https://api.example', 'a', 'p', tok, async () => { throw new Error('x'); }), AccountsUnavailable);
});

test('metadataIdToken calls the metadata server', async () => {
  const r = recorder(new Response('jwt.value', { status: 200 }));
  assert.equal(await metadataIdToken('https://a b', r.f), 'jwt.value');
  assert.equal(r.calls[0].url,
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https%3A%2F%2Fa%20b&format=full');
  assert.equal(hdr(r.calls[0], 'Metadata-Flavor'), 'Google');
  await assert.rejects(metadataIdToken('a', recorder(new Response('', { status: 500 })).f), AccountsUnavailable);
});
