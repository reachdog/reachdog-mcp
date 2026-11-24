import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { spawnSync } from 'node:child_process';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { HostedStore } from '../dist/hosted/store.js';
import { AccountsClient } from '../dist/hosted/accounts.js';
import { ReachDogOAuthProvider } from '../dist/hosted/provider.js';
import { createApp } from '../dist/http.js';

const KEY = randomBytes(32);
const CB = 'http://127.0.0.1:4567/callback';
const SECRET = 'gs-very-secret-grant-value';
const RECONNECT = 'Reconnect Reach Dog in your assistant to continue.';
const title = { title: 'Tea', parameters: ['brand'] };
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const pass = () => `${b64({ alg: 'none' })}.${b64({ sid: 'sess1', kind: 'person', exp: Math.floor(Date.now() / 1000) + 600 })}.sig`;

let mongod, mclient, n = 0;
before(async () => {
  mongod = await MongoMemoryServer.create();
  mclient = await MongoClient.connect(mongod.getUri());
});
after(async () => { await mclient?.close(); await mongod?.stop(); });

const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${srv.address().port}`)));
const readBody = (req) => new Promise((r) => { let s = ''; req.on('data', (c) => { s += c; }); req.on('end', () => r(s)); });
const sendJson = (res, status, body, headers = {}) => {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(body === undefined ? undefined : JSON.stringify(body));
};

/** Fake Accounts + fake API + the connector app, all on ephemeral ports. */
async function setup(opts = {}) {
  const db = mclient.db('http' + (n++));
  const store = new HostedStore(db);
  const acc = { resolves: 0, revoked: false, key: 'rd_key_one', limit: 10000, resolveError: null, deletes: 0 };
  const api = { revokedKeys: new Set(), titleCalls: 0, titleStatus: 200, titleBody: null, usageStatus: 200, usageBody: null };
  const accountsSrv = createServer(async (req, res) => {
    const body = await readBody(req);
    if (req.method === 'POST' && req.url === '/internal/connector-grants') {
      acc.limit = JSON.parse(body).daily_limit;
      return sendJson(res, 201, { grant_id: 'g-1', grant_secret: SECRET, key_id: 'k1', daily_limit: acc.limit });
    }
    if (req.method === 'POST' && req.url === '/internal/connector-grants/resolve') {
      acc.resolves++;
      const b = JSON.parse(body);
      if (acc.resolveError) return sendJson(res, acc.resolveError[0], acc.resolveError[1]);
      if (acc.revoked || b.grant_secret !== SECRET) return sendJson(res, 401, { detail: { code: 'grant_revoked' } });
      return sendJson(res, 200, { account_id: 'a1', key: acc.key, key_id: 'k1', daily_limit: acc.limit });
    }
    if (req.method === 'DELETE') { acc.deletes++; acc.revoked = true; res.writeHead(204); return res.end(); }
    sendJson(res, 404, {});
  });
  const apiSrv = createServer(async (req, res) => {
    await readBody(req);
    const key = (req.headers.authorization ?? '').replace(/^Bearer /, '');
    if (api.revokedKeys.has(key)) return sendJson(res, 401, { detail: 'invalid key' });
    if (req.url === '/v1/usage' && api.usageStatus !== 200) return sendJson(res, api.usageStatus, api.usageBody);
    if (req.url === '/v1/usage') return sendJson(res, 200, { parameter_price: 25, billing: 'wallet' });
    if (req.method === 'POST' && req.url === '/v1/title-matches') {
      api.titleCalls++;
      if (api.titleStatus !== 200) return sendJson(res, api.titleStatus, api.titleBody);
      return sendJson(res, 200, { brand: 'secret result text' }, { 'x-charge-state': 'settled', 'x-charged-tokens': '25' });
    }
    sendJson(res, 404, {});
  });
  const accountsBase = await listen(accountsSrv);
  const apiBase = await listen(apiSrv);
  const appSrv = createServer();
  const base = await listen(appSrv);
  const accounts = new AccountsClient(accountsBase, async () => 'idtoken');
  const provider = new ReachDogOAuthProvider({
    store, accounts, sealKey: KEY, publicUrl: base, accountsOrigin: 'https://accounts.test',
  });
  const logs = [];
  let clock = Date.now();
  const app = createApp({
    store: opts.wrapStore ? opts.wrapStore(store) : store, provider, accounts, apiUrl: apiBase, sealKey: KEY, accountsOrigin: 'https://accounts.test',
    setupWallet: async () => {}, now: () => clock, log: (line) => logs.push(line),
  });
  appSrv.on('request', app);
  const close = async () => {
    for (const s of [appSrv, accountsSrv, apiSrv]) { s.closeAllConnections?.(); await new Promise((r) => s.close(r)); }
  };
  return { db, store, acc, api, base, logs, close, advance: (ms) => { clock += ms; } };
}

/** register -> authorize -> consent approve -> token. Returns the access token. */
async function connect(ctx, dailyLimit = '10000') {
  const reg = await fetch(ctx.base + '/register', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: [CB], token_endpoint_auth_method: 'none', client_name: 'Test App' }),
  });
  assert.equal(reg.status, 201);
  const { client_id } = await reg.json();
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const q = new URLSearchParams({
    response_type: 'code', client_id, redirect_uri: CB, code_challenge: challenge, code_challenge_method: 'S256',
    state: 'st', resource: ctx.base + '/mcp',
  });
  const auth = await fetch(ctx.base + '/authorize?' + q, { redirect: 'manual' });
  assert.equal(auth.status, 302);
  const back = new URL(new URL(auth.headers.get('location')).searchParams.get('return_to'));
  const request = back.searchParams.get('request');
  const cookie = `__Secure-rd_pass=${pass()}`;
  const page = await fetch(ctx.base + '/oauth/consent?request=' + request, { headers: { cookie } });
  assert.equal(page.status, 200);
  const csrf = (await page.text()).match(/name="csrf" value="([^"]+)"/)[1];
  const approve = await fetch(ctx.base + '/oauth/consent', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: new URLSearchParams({ request, csrf, action: 'approve', daily_limit: dailyLimit }).toString(),
  });
  assert.equal(approve.status, 302);
  const done = new URL(approve.headers.get('location'));
  assert.equal(done.searchParams.get('iss'), ctx.base + '/');
  const tok = await fetch(ctx.base + '/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code: done.searchParams.get('code'), code_verifier: verifier,
      client_id, redirect_uri: CB, resource: ctx.base + '/mcp',
    }).toString(),
  });
  assert.equal(tok.status, 200);
  const tokens = await tok.json();
  ctx.refreshToken = tokens.refresh_token;
  ctx.clientId = client_id;
  return tokens.access_token;
}

async function mcpClient(ctx, token, capabilities = {}) {
  const client = new Client({ name: 'test', version: '1' }, { capabilities });
  const transport = new StreamableHTTPClientTransport(new URL(ctx.base + '/mcp'),
    { requestInit: { headers: { Authorization: 'Bearer ' + token } } });
  await client.connect(transport);
  return client;
}

const text = (r) => r.content[0].text;

test('unauthenticated /mcp is 401 and names the protected resource metadata', async () => {
  const ctx = await setup();
  try {
    const res = await fetch(ctx.base + '/mcp', {
      method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    assert.equal(res.status, 401);
    assert.match(res.headers.get('www-authenticate'), /resource_metadata="[^"]*\/\.well-known\/oauth-protected-resource\/mcp"/);
    const h = await fetch(ctx.base + '/health');
    assert.equal(h.status, 200);
  } finally { await ctx.close(); }
});

test('metadata documents: issuer, RFC 9207 flag, protected resource', async () => {
  const ctx = await setup();
  try {
    const as = await (await fetch(ctx.base + '/.well-known/oauth-authorization-server')).json();
    assert.equal(as.issuer, ctx.base + '/');
    assert.equal(as.authorization_response_iss_parameter_supported, true);
    assert.equal(as.authorization_endpoint, ctx.base + '/authorize');
    assert.equal(as.token_endpoint, ctx.base + '/token');
    assert.equal(as.registration_endpoint, ctx.base + '/register');
    const prm = await (await fetch(ctx.base + '/.well-known/oauth-protected-resource/mcp')).json();
    assert.equal(prm.resource, ctx.base + '/mcp');
    assert.deepEqual(prm.authorization_servers, [ctx.base + '/']);
  } finally { await ctx.close(); }
});

test('an authorize error redirect carries iss', async () => {
  const ctx = await setup();
  try {
    const reg = await (await fetch(ctx.base + '/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [CB], token_endpoint_auth_method: 'none' }),
    })).json();
    // No resource: the provider refuses after the SDK has validated the redirect.
    const q = new URLSearchParams({ response_type: 'code', client_id: reg.client_id, redirect_uri: CB, state: 'zz',
      code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' });
    const res = await fetch(ctx.base + '/authorize?' + q, { redirect: 'manual' });
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get('location'));
    assert.equal(loc.origin + loc.pathname, CB);
    assert.equal(loc.searchParams.get('error'), 'invalid_request');
    assert.equal(loc.searchParams.get('state'), 'zz');
    assert.equal(loc.searchParams.get('iss'), ctx.base + '/');
  } finally { await ctx.close(); }
});

test('rate limiting keys on the client address from X-Forwarded-For and never errors on it', async () => {
  const ctx = await setup();
  const errors = [];
  const orig = console.error;
  console.error = (...a) => { errors.push(a.map(String).join(' ')); };
  try {
    const hit = (ip) => fetch(ctx.base + '/authorize?client_id=nope', { redirect: 'manual', headers: { 'x-forwarded-for': ip } });
    const a1 = await hit('203.0.113.5'), a2 = await hit('203.0.113.5'), b1 = await hit('198.51.100.7');
    for (const r of [a1, a2, b1]) assert.equal(r.status, 400);
    const left = (r) => Number(r.headers.get('ratelimit-remaining'));
    assert.equal(left(a2), left(a1) - 1);
    assert.equal(left(b1), left(a1));
    assert.deepEqual(errors.filter((e) => /ERR_ERL/.test(e)), []);
  } finally { console.error = orig; await ctx.close(); }
});

test('full flow: tools listed, paid call charges 25 and records spend, key cached 5 minutes', async () => {
  const ctx = await setup();
  let client;
  try {
    const token = await connect(ctx);
    let elicited = 0;
    client = await mcpClient(ctx, token, { elicitation: { form: {} } });
    client.setRequestHandler(ElicitRequestSchema, async () => { elicited++; return { action: 'accept', content: {} }; });
    assert.equal((await client.listTools()).tools.length, 9);
    const r = await client.callTool({ name: 'enrich_title', arguments: { body: title, confirm: true } });
    assert.equal(r.isError, false, text(r));
    const v = JSON.parse(text(r));
    assert.equal(v.charged_tokens, 25);
    assert.equal(v.charge_state, 'settled');
    // Stateless requests never see initialize, so the consent limit is the approval.
    assert.equal(v.approval, 'within pre-approved session cap');
    assert.equal(elicited, 0);
    const spend = await ctx.db.collection('mcp_spend').find().toArray();
    assert.equal(spend.length, 1);
    assert.equal(spend[0].total, 25);
    assert.match(spend[0]._id, /^g-1:/);
    assert.equal(ctx.acc.resolves, 1);
    await client.callTool({ name: 'get_usage', arguments: {} });
    assert.equal(ctx.acc.resolves, 1);
    ctx.advance(5 * 60_000 + 1);
    await client.callTool({ name: 'get_usage', arguments: {} });
    assert.equal(ctx.acc.resolves, 2);

    const line = ctx.logs.find((l) => l.tool === 'enrich_title');
    assert.deepEqual(line, { event: 'tool_call', grant_id: 'g-1', tool: 'enrich_title', status: 'ok', charged_tokens: 25 });
    const all = JSON.stringify(ctx.logs);
    for (const s of [SECRET, ctx.acc.key, token, 'Tea', 'secret result text']) assert.ok(!all.includes(s), s);
  } finally { await client?.close(); await ctx.close(); }
});

test('console revoke: the API 401 clears the cache, the tool says reconnect, the next call re-resolves', async () => {
  const ctx = await setup();
  let client;
  try {
    client = await mcpClient(ctx, await connect(ctx));
    assert.equal((await client.callTool({ name: 'get_usage', arguments: {} })).isError, false);
    assert.equal(ctx.acc.resolves, 1);
    ctx.api.revokedKeys.add(ctx.acc.key);
    const r = await client.callTool({ name: 'get_usage', arguments: {} });
    assert.equal(r.isError, true);
    assert.equal(text(r), RECONNECT);
    assert.equal(ctx.logs.at(-1).status, 'reconnect');
    // A fresh resolve happens on the next call (here Accounts has issued a new key).
    ctx.acc.key = 'rd_key_two';
    const ok = await client.callTool({ name: 'get_usage', arguments: {} });
    assert.equal(ok.isError, false, text(ok));
    assert.equal(ctx.acc.resolves, 2);
    // Accounts refusing the grant also reads as reconnect.
    ctx.acc.revoked = true;
    ctx.api.revokedKeys.add(ctx.acc.key);
    const again = await client.callTool({ name: 'get_usage', arguments: {} });
    assert.equal(text(again), RECONNECT);
    const after = await client.callTool({ name: 'get_usage', arguments: {} });
    assert.equal(text(after), RECONNECT);
    assert.equal(ctx.acc.resolves, 3);
  } finally { await client?.close(); await ctx.close(); }
});

test('a call over the daily limit is refused with the amount left', async () => {
  const ctx = await setup();
  let client;
  try {
    client = await mcpClient(ctx, await connect(ctx, '30'));
    const first = await client.callTool({ name: 'enrich_title', arguments: { body: title, confirm: true } });
    assert.equal(first.isError, false, text(first));
    const second = await client.callTool({ name: 'enrich_title', arguments: { body: title, confirm: true, run_label: 'b' } });
    assert.equal(second.isError, true);
    assert.match(text(second), /5 of 30 Reach Dog tokens left today/);
    assert.equal(ctx.api.titleCalls, 1);
  } finally { await client?.close(); await ctx.close(); }
});

test('GET /mcp is not offered in stateless mode', async () => {
  const ctx = await setup();
  try {
    const token = await connect(ctx);
    const res = await fetch(ctx.base + '/mcp', { headers: { Authorization: 'Bearer ' + token, accept: 'text/event-stream' } });
    assert.equal(res.status, 405);
  } finally { await ctx.close(); }
});

test('main refuses to start without required settings and never prints values', () => {
  const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot };
  const run = (extra) => spawnSync(process.execPath, ['dist/http.js'], { env: { ...env, ...extra }, encoding: 'utf8', timeout: 20000 });
  const missing = run({});
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /MONGO_URI/);
  const sentinel = 'sentinel-not-a-real-key';
  const bad = run({ MONGO_URI: 'mongodb://127.0.0.1:1/x', CONNECTOR_SEAL_KEY: sentinel, WALLET_URL: 'https://w.test', WALLET_AUDIENCE: 'aud' });
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /CONNECTOR_SEAL_KEY/);
  assert.ok(!bad.stderr.includes(sentinel) && !bad.stdout.includes(sentinel));
  const noWallet = run({ MONGO_URI: 'mongodb://127.0.0.1:1/x', CONNECTOR_SEAL_KEY: randomBytes(32).toString('base64') });
  assert.notEqual(noWallet.status, 0);
  assert.match(noWallet.stderr, /WALLET_URL/);
  const uriSentinel = 'sentinel-uri-host.example';
  const badUri = run({ MONGO_URI: 'not-mongo://' + uriSentinel, CONNECTOR_SEAL_KEY: randomBytes(32).toString('base64'),
    WALLET_URL: 'https://w.test', WALLET_AUDIENCE: 'aud' });
  assert.notEqual(badUri.status, 0);
  assert.match(badUri.stderr, /MONGO_URI/);
  assert.ok(!badUri.stderr.includes(uriSentinel) && !badUri.stdout.includes(uriSentinel));
});

test('/mcp refuses a garbage bearer and a refresh token used as a bearer', async () => {
  const ctx = await setup();
  try {
    await connect(ctx);
    const call = (tok) => fetch(ctx.base + '/mcp', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + tok, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    for (const tok of ['garbage', ctx.refreshToken]) {
      const res = await call(tok);
      assert.equal(res.status, 401, tok === 'garbage' ? 'garbage' : 'refresh token');
      assert.match(res.headers.get('www-authenticate'), /invalid_token/);
    }
  } finally { await ctx.close(); }
});

test('infrastructure failures never reach the assistant; API 4xx bodies do, 5xx bodies do not', async () => {
  const host = 'mongo-secret-host.internal:27017';
  const ctx = await setup({
    wrapStore: (store) => Object.assign(Object.create(store), {
      spend: (grantId, limit) => {
        if (ctx.failSpend) throw new Error('connect ECONNREFUSED ' + host + ' collection mcp_spend');
        return store.spend(grantId, limit);
      },
    }),
  });
  let client;
  try {
    client = await mcpClient(ctx, await connect(ctx));
    ctx.failSpend = true;
    const infra = await client.callTool({ name: 'get_usage', arguments: {} });
    assert.equal(infra.isError, true);
    assert.equal(text(infra), 'Reach Dog is having trouble right now. Try again in a few minutes.');
    assert.ok(!text(infra).includes('mongo') && !JSON.stringify(ctx.logs).includes(host));
    assert.equal(ctx.logs.at(-1).status, 'unavailable');
    ctx.failSpend = false;

    ctx.api.titleStatus = 501;
    ctx.api.titleBody = { detail: 'stack trace at db-internal-7' };
    const five = await client.callTool({ name: 'enrich_title', arguments: { body: title, confirm: true } });
    assert.equal(five.isError, true);
    assert.deepEqual(JSON.parse(text(five)),
      { status: 501, error: 'Reach Dog had a problem completing this request. Try again in a minute.' });

    ctx.api.titleStatus = 422;
    ctx.api.titleBody = { detail: [{ loc: ['body', 'title'], msg: 'too short' }] };
    const four = await client.callTool({ name: 'enrich_title', arguments: { body: title, confirm: true, run_label: 'c' } });
    assert.equal(four.isError, true);
    assert.deepEqual(JSON.parse(text(four)), { status: 422, error: ctx.api.titleBody });

    const bad = await client.callTool({ name: 'no_such_tool', arguments: {} });
    assert.equal(bad.isError, true);
    assert.match(text(bad), /^Invalid no_such_tool input/);
    assert.equal(ctx.logs.at(-1).tool, 'unknown');
  } finally { await client?.close(); await ctx.close(); }
});

test('an API 403 is a caller-facing refusal, not reconnect: the body passes through and the key stays cached', async () => {
  const ctx = await setup();
  let client;
  try {
    client = await mcpClient(ctx, await connect(ctx));
    assert.equal((await client.callTool({ name: 'get_usage', arguments: {} })).isError, false);
    assert.equal(ctx.acc.resolves, 1);
    ctx.api.usageStatus = 403;
    ctx.api.usageBody = { detail: { code: 'wallet_frozen', message: 'This wallet is frozen.' } };
    const r = await client.callTool({ name: 'get_usage', arguments: {} });
    assert.equal(r.isError, true);
    assert.notEqual(text(r), RECONNECT);
    assert.deepEqual(JSON.parse(text(r)), { status: 403, error: ctx.api.usageBody });
    assert.equal(ctx.logs.at(-1).status, 'error');
    ctx.api.usageStatus = 200;
    assert.equal((await client.callTool({ name: 'get_usage', arguments: {} })).isError, false);
    assert.equal(ctx.acc.resolves, 1, 'a 403 must not drop the cached key');
  } finally { await client?.close(); await ctx.close(); }
});

test('OAuth endpoints use the connector rate limits, not the SDK per-IP defaults', async () => {
  const ctx = await setup();
  try {
    const headers = { 'content-type': 'application/x-www-form-urlencoded', 'x-forwarded-for': '203.0.113.9' };
    const limit = (r) => r.headers.get('ratelimit-limit');
    let last;
    for (let i = 0; i < 55; i++) {
      last = await fetch(ctx.base + '/token', { method: 'POST', headers, body: 'grant_type=refresh_token' });
      assert.notEqual(last.status, 429, 'token request ' + (i + 1));
    }
    assert.equal(limit(last), '3000');
    const reg = await fetch(ctx.base + '/register', { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: '{}' });
    assert.equal(limit(reg), '300');
    const rev = await fetch(ctx.base + '/revoke', { method: 'POST', headers, body: 'token=x' });
    assert.equal(limit(rev), '600');
  } finally { await ctx.close(); }
});

test('a closed account and a wallet problem are terminal messages, not reconnect', async () => {
  const ctx = await setup();
  let client;
  try {
    client = await mcpClient(ctx, await connect(ctx));
    ctx.acc.resolveError = [403, { detail: { code: 'account_unavailable' } }];
    const closed = await client.callTool({ name: 'get_usage', arguments: {} });
    assert.equal(closed.isError, true);
    assert.equal(text(closed), 'This Reach Dog account is closed. Disconnect Reach Dog in your assistant.');
    ctx.acc.resolveError = [409, { detail: { code: 'wallet_ineligible' } }];
    const wallet = await client.callTool({ name: 'get_usage', arguments: {} });
    assert.equal(wallet.isError, true);
    assert.equal(text(wallet), "This Reach Dog account's wallet needs attention. Contact support.");
    assert.equal(ctx.logs.at(-1).status, 'error');
  } finally { await client?.close(); await ctx.close(); }
});

test('revoking the connection at /revoke drops the cached key at once', async () => {
  const ctx = await setup();
  let client;
  try {
    client = await mcpClient(ctx, await connect(ctx));
    assert.equal((await client.callTool({ name: 'get_usage', arguments: {} })).isError, false);
    assert.equal(ctx.acc.resolves, 1);
    const rev = await fetch(ctx.base + '/revoke', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: ctx.refreshToken, client_id: ctx.clientId }).toString(),
    });
    assert.equal(rev.status, 200);
    assert.equal(ctx.acc.deletes, 1);
    // The access token is still sealed-valid, but the cached key must be gone: Accounts now refuses.
    const r = await client.callTool({ name: 'get_usage', arguments: {} });
    assert.equal(text(r), RECONNECT);
    assert.equal(ctx.acc.resolves, 2);
  } finally { await client?.close(); await ctx.close(); }
});
