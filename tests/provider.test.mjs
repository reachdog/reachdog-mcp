import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import express from 'express';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { tokenHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/token.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import {
  InvalidGrantError, InvalidRequestError, InvalidTargetError, InvalidTokenError, OAuthError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { HostedStore } from '../dist/hosted/store.js';
import { AccountsClient } from '../dist/hosted/accounts.js';
import { seal } from '../dist/hosted/seal.js';
import { ReachDogOAuthProvider } from '../dist/hosted/provider.js';
import { allowedRedirect, CLIENT_CALLBACKS } from '../dist/hosted/redirects.js';

const KEY = randomBytes(32);
const RESOURCE = 'https://mcp.reach.dog/mcp';
const CB = 'http://127.0.0.1:4567/callback';
const GRANT = { grant_id: 'g-1', grant_secret: 'gs-very-secret-value', key_id: 'k1', daily_limit: 10000 };

let mongod, mclient, db, n = 0;
before(async () => {
  mongod = await MongoMemoryServer.create();
  mclient = await MongoClient.connect(mongod.getUri());
});
after(async () => { await mclient?.close(); await mongod?.stop(); });

/** Fake Accounts transport: records every call. */
function fakeAccounts() {
  const calls = [];
  const transport = async (url, init) => {
    calls.push({ url, method: init.method });
    return new Response(null, { status: 204 });
  };
  return { calls, client: new AccountsClient('https://accounts.test', async () => 'idtok', transport) };
}

function setup(opts = {}) {
  db = mclient.db('p' + (n++));
  const store = new HostedStore(db);
  const acc = fakeAccounts();
  let clock = Date.now();
  const fetches = [];
  const docs = opts.docs ?? {};
  const fetchImpl = async (url, init) => {
    fetches.push({ url: String(url), init });
    const d = docs[String(url)];
    if (!d) return new Response('nope', { status: 404 });
    if (typeof d === 'function') return d();
    return new Response(typeof d === 'string' ? d : JSON.stringify(d),
      { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const provider = new ReachDogOAuthProvider({
    store, accounts: acc.client, sealKey: KEY, fetch: fetchImpl, now: () => clock,
  });
  return { store, provider, acc, fetches, advance: ms => { clock += ms; }, now: () => clock };
}

const fakeRes = () => {
  const r = { redirects: [] };
  r.redirect = (status, url) => { r.redirects.push({ status, url }); };
  return r;
};

async function registered(provider, over = {}) {
  return provider.clientsStore.registerClient({
    client_id: 'dcr-' + randomBytes(4).toString('hex'), client_id_issued_at: 1,
    redirect_uris: [CB], token_endpoint_auth_method: 'none', client_name: 'Test App', ...over,
  });
}

const pkce = () => {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
};

/** authorize -> consent approve -> code. Returns { code, verifier, client, url }. */
async function getCode(ctx, client, state = 'st-1') {
  const { verifier, challenge } = pkce();
  const res = fakeRes();
  await ctx.provider.authorize(client, {
    state, scopes: [], codeChallenge: challenge, redirectUri: client.redirect_uris[0], resource: new URL(RESOURCE),
  }, res);
  const id = new URL(new URL(res.redirects[0].url).searchParams.get('return_to')).searchParams.get('request');
  const url = new URL(await ctx.provider.issueCode(id, GRANT));
  return { code: url.searchParams.get('code'), verifier, url, id };
}

async function tokens(ctx, client) {
  const { code } = await getCode(ctx, client);
  return ctx.provider.exchangeAuthorizationCode(client, code, undefined, client.redirect_uris[0], new URL(RESOURCE));
}

/** Real SDK token endpoint on an ephemeral port. */
async function tokenServer(provider) {
  const app = express();
  app.use('/token', tokenHandler({ provider, rateLimit: false }));
  const server = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}/token`;
  const post = async body => {
    const res = await fetch(base, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString() });
    return { status: res.status, body: await res.json() };
  };
  return { post, close: () => new Promise(r => server.close(r)) };
}

// ---------------- redirects ----------------

test('client callbacks match exactly, nothing near them', () => {
  for (const u of CLIENT_CALLBACKS) assert.equal(allowedRedirect(u), true, u);
  assert.ok(CLIENT_CALLBACKS.includes('https://claude.ai/api/mcp/auth_callback'));
  assert.ok(CLIENT_CALLBACKS.includes('https://chatgpt.com/connector_platform_oauth_redirect'));
  for (const u of [
    'https://claude.ai/api/mcp/auth_callback/', 'https://claude.ai/api/mcp/auth_callback?x=1',
    'http://claude.ai/api/mcp/auth_callback', 'https://claude.ai/api/mcp/auth_callback#f',
    'https://chatgpt.com/connector/oauth/abc123', 'https://CLAUDE.ai/api/mcp/auth_callback',
  ]) assert.equal(allowedRedirect(u), false, u);
});

test('loopback any port and any path allowed; everything else refused', () => {
  for (const u of ['http://127.0.0.1:1/cb', 'http://127.0.0.1:65535/a/b?x=1', 'http://localhost:3118/callback',
    'http://localhost/callback', 'http://127.0.0.1/callback', 'http://localhost:9/'])
    assert.equal(allowedRedirect(u), true, u);
  for (const u of ['http://evil.example', 'http://evil.example:80/cb', 'https://127.0.0.1:5/cb', 'https://localhost:5/cb',
    'http://user@127.0.0.1:5/cb', 'http://u:p@localhost:5/cb', 'http://127.0.0.1:5/cb#frag', 'http://127.0.0.1:5/cb#',
    'http://[::1]:5/cb', 'http://127.0.0.1.evil.example/cb', 'http://localhost.evil.example/cb', 'http://127.1:5/cb',
    'http://0x7f000001:5/cb', 'javascript:alert(1)', 'not a url', '', 'http://127.0.0.2:5/cb', 'ftp://127.0.0.1/cb'])
    assert.equal(allowedRedirect(u), false, u);
});

// ---------------- registration ----------------

test('registration refuses an unlisted redirect with invalid_redirect_uri', async () => {
  const ctx = setup();
  await assert.rejects(registered(ctx.provider, { redirect_uris: [CB, 'https://evil.example/cb'] }),
    e => e instanceof OAuthError && e.errorCode === 'invalid_redirect_uri');
  await assert.rejects(registered(ctx.provider, { redirect_uris: ['http://evil.example'] }),
    e => e instanceof OAuthError && e.errorCode === 'invalid_redirect_uri');
  const ok = await registered(ctx.provider, { redirect_uris: ['http://localhost:9999/cb'] });
  assert.equal((await ctx.provider.clientsStore.getClient(ok.client_id)).redirect_uris[0], 'http://localhost:9999/cb');
});

test('authorize refuses an unlisted redirect even for a stored client', async () => {
  const ctx = setup();
  await ctx.store.putClient({ client_id: 'legacy', redirect_uris: ['https://evil.example/cb', CB] });
  const c = await ctx.provider.clientsStore.getClient('legacy');
  assert.deepEqual(c.redirect_uris, [CB]); // the SDK then refuses the evil one before any redirect
  await assert.rejects(ctx.provider.authorize({ ...c, redirect_uris: ['https://evil.example/cb'] }, {
    scopes: [], codeChallenge: 'x', redirectUri: 'https://evil.example/cb', resource: new URL(RESOURCE),
  }, fakeRes()), InvalidRequestError);
  await ctx.store.putClient({ client_id: 'allbad', redirect_uris: ['https://evil.example/cb'] });
  assert.equal(await ctx.provider.clientsStore.getClient('allbad'), undefined);
});

// ---------------- authorize and consent hand-off ----------------

test('authorize requires the exact resource', async () => {
  const ctx = setup();
  const c = await registered(ctx.provider);
  const p = { scopes: [], codeChallenge: 'x', redirectUri: CB };
  await assert.rejects(ctx.provider.authorize(c, p, fakeRes()), InvalidRequestError);
  await assert.rejects(ctx.provider.authorize(c, { ...p, resource: new URL('https://mcp.reach.dog/other') }, fakeRes()),
    InvalidTargetError);
  await assert.rejects(ctx.provider.authorize(c, { ...p, resource: new URL('https://evil.example/mcp') }, fakeRes()),
    InvalidTargetError);
});

test('authorize stores a pending request and sends the browser to Accounts', async () => {
  const ctx = setup();
  const c = await registered(ctx.provider);
  const res = fakeRes();
  await ctx.provider.authorize(c, { state: 'abc', scopes: ['reachdog'], codeChallenge: 'chal', redirectUri: CB,
    resource: new URL(RESOURCE) }, res);
  assert.equal(res.redirects.length, 1);
  const { status, url } = res.redirects[0];
  assert.equal(status, 302);
  const m = /^https:\/\/accounts\.reach\.dog\/authorize\?return_to=(.+)$/.exec(url);
  assert.ok(m, url);
  const back = decodeURIComponent(m[1]);
  assert.equal(m[1], encodeURIComponent(back));
  const id = /^https:\/\/mcp\.reach\.dog\/oauth\/consent\?request=([A-Za-z0-9_-]{43})$/.exec(back)?.[1];
  assert.ok(id, back);
  const pend = await ctx.provider.peekPending(id);
  assert.deepEqual(pend, { client_id: c.client_id, client_name: 'Test App', redirect_uri: CB, state: 'abc',
    scopes: ['reachdog'], resource: RESOURCE });
  assert.deepEqual(await ctx.provider.peekPending(id), pend); // non-destructive
  assert.equal(await ctx.provider.peekPending('nope'), null);
  const raw = JSON.stringify(await db.collection('mcp_oauth_codes').find().toArray());
  assert.ok(!raw.includes(id)); // stored hashed
});

test('client name falls back to the redirect host and is truncated to 80', async () => {
  const ctx = setup();
  const anon = await registered(ctx.provider, { client_name: undefined, redirect_uris: ['http://localhost:8123/x'] });
  const long = await registered(ctx.provider, { client_name: 'A'.repeat(200) });
  for (const [c, want] of [[anon, 'localhost:8123'], [long, 'A'.repeat(80)]]) {
    const res = fakeRes();
    await ctx.provider.authorize(c, { scopes: [], codeChallenge: 'x', redirectUri: c.redirect_uris[0],
      resource: new URL(RESOURCE) }, res);
    const id = new URL(new URL(res.redirects[0].url).searchParams.get('return_to')).searchParams.get('request');
    const p = await ctx.provider.peekPending(id);
    assert.equal(p.client_name, want);
    assert.equal(p.state, undefined);
  }
});

test('issueCode returns the client redirect with code, state and iss; deny returns access_denied', async () => {
  const ctx = setup();
  const c = await registered(ctx.provider, { redirect_uris: ['http://127.0.0.1:5/cb?keep=1'] });
  const { url, id } = await getCode(ctx, c, 's&t=1');
  assert.equal(url.origin + url.pathname, 'http://127.0.0.1:5/cb');
  assert.equal(url.searchParams.get('keep'), '1');
  assert.equal(url.searchParams.get('state'), 's&t=1');
  assert.equal(url.searchParams.get('iss'), 'https://mcp.reach.dog/');
  assert.match(url.searchParams.get('code'), /^[A-Za-z0-9_-]{43}$/);
  assert.equal(await ctx.provider.peekPending(id), null); // consumed
  await assert.rejects(ctx.provider.issueCode(id, GRANT));
  const raw = JSON.stringify(await db.collection('mcp_oauth_codes').find().toArray());
  assert.ok(!raw.includes(GRANT.grant_secret));

  const res = fakeRes();
  await ctx.provider.authorize(c, { state: 'zz', scopes: [], codeChallenge: 'x', redirectUri: c.redirect_uris[0],
    resource: new URL(RESOURCE) }, res);
  const id2 = new URL(new URL(res.redirects[0].url).searchParams.get('return_to')).searchParams.get('request');
  const denied = new URL(await ctx.provider.denyRequest(id2));
  assert.equal(denied.searchParams.get('error'), 'access_denied');
  assert.equal(denied.searchParams.get('state'), 'zz');
  assert.equal(denied.searchParams.get('iss'), 'https://mcp.reach.dog/');
  assert.equal(await ctx.provider.denyRequest(id2), null);
});

// ---------------- token endpoint (through the SDK handler) ----------------

test('PKCE wrong verifier refused, right one works, code reuse refused (SDK token handler)', async () => {
  const ctx = setup();
  const c = await registered(ctx.provider);
  const srv = await tokenServer(ctx.provider);
  try {
    const { code, verifier } = await getCode(ctx, c);
    const base = { grant_type: 'authorization_code', client_id: c.client_id, code, redirect_uri: CB, resource: RESOURCE };
    const bad = await srv.post({ ...base, code_verifier: pkce().verifier });
    assert.equal(bad.status, 400);
    assert.equal(bad.body.error, 'invalid_grant');
    const ok = await srv.post({ ...base, code_verifier: verifier });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal(ok.body.token_type, 'bearer');
    assert.equal(ok.body.expires_in, 3600);
    assert.ok(ok.body.access_token && ok.body.refresh_token);
    const again = await srv.post({ ...base, code_verifier: verifier });
    assert.equal(again.status, 400);
    assert.equal(again.body.error, 'invalid_grant');
  } finally { await srv.close(); }
});

test('code is bound to its client, redirect and resource', async () => {
  const ctx = setup();
  const c = await registered(ctx.provider);
  const other = await registered(ctx.provider);
  let g = await getCode(ctx, c);
  await assert.rejects(ctx.provider.challengeForAuthorizationCode(other, g.code), InvalidGrantError);
  await assert.rejects(ctx.provider.exchangeAuthorizationCode(other, g.code, undefined, CB), InvalidGrantError);
  g = await getCode(ctx, c);
  await assert.rejects(ctx.provider.exchangeAuthorizationCode(c, g.code, undefined, 'http://127.0.0.1:9/other'),
    InvalidGrantError);
  g = await getCode(ctx, c);
  await assert.rejects(ctx.provider.exchangeAuthorizationCode(c, g.code, undefined, CB, new URL('https://x.example/mcp')),
    InvalidTargetError);
  g = await getCode(ctx, c);
  assert.equal(typeof await ctx.provider.challengeForAuthorizationCode(c, g.code), 'string');
  const t = await ctx.provider.exchangeAuthorizationCode(c, g.code, undefined, undefined, undefined);
  assert.ok(t.access_token);
  await assert.rejects(ctx.provider.challengeForAuthorizationCode(c, 'unknown-code'), InvalidGrantError);
});

// ---------------- refresh ----------------

test('refresh rotates with a new jti; the old one no longer works on its own', async () => {
  const ctx = setup();
  const c = await registered(ctx.provider);
  const t1 = await tokens(ctx, c);
  const t2 = await ctx.provider.exchangeRefreshToken(c, t1.refresh_token, undefined, new URL(RESOURCE));
  assert.notEqual(t2.refresh_token, t1.refresh_token);
  assert.equal(t2.expires_in, 3600);
  const info = await ctx.provider.verifyAccessToken(t2.access_token);
  assert.equal(info.extra.grant_id, GRANT.grant_id);
  const t3 = await ctx.provider.exchangeRefreshToken(c, t2.refresh_token);
  assert.ok(t3.access_token);
  await assert.rejects(ctx.provider.exchangeRefreshToken(c, 'garbage'), InvalidGrantError);
  const other = await registered(ctx.provider);
  await assert.rejects(ctx.provider.exchangeRefreshToken(other, t3.refresh_token), InvalidGrantError);
  await assert.rejects(ctx.provider.exchangeRefreshToken(c, t3.refresh_token, undefined, new URL('https://x.example/mcp')),
    InvalidTargetError);
  assert.equal(ctx.acc.calls.length, 0);
});

test('refresh replay revokes the whole grant in Accounts', async () => {
  const ctx = setup();
  const c = await registered(ctx.provider);
  const t1 = await tokens(ctx, c);
  const t2 = await ctx.provider.exchangeRefreshToken(c, t1.refresh_token);
  await assert.rejects(ctx.provider.exchangeRefreshToken(c, t1.refresh_token), InvalidGrantError);
  assert.deepEqual(ctx.acc.calls, [{ url: 'https://accounts.test/internal/connector-grants/g-1', method: 'DELETE' }]);
  assert.equal(await db.collection('mcp_oauth_refresh').countDocuments({ grant_id: 'g-1' }), 0);
  await assert.rejects(ctx.provider.exchangeRefreshToken(c, t2.refresh_token), InvalidGrantError);
});

test('refresh replay still fails closed when Accounts is down', async () => {
  const ctx = setup();
  const failing = new AccountsClient('https://accounts.test', async () => 'idtok', async () => { throw new Error('down'); });
  const provider = new ReachDogOAuthProvider({ store: ctx.store, accounts: failing, sealKey: KEY });
  const c = await registered(provider);
  const t1 = await tokens({ ...ctx, provider }, c);
  const t2 = await provider.exchangeRefreshToken(c, t1.refresh_token);
  await assert.rejects(provider.exchangeRefreshToken(c, t1.refresh_token), InvalidGrantError);
  await assert.rejects(provider.exchangeRefreshToken(c, t2.refresh_token), InvalidGrantError);
});

// ---------------- access tokens ----------------

test('verifyAccessToken returns AuthInfo for the MCP resource', async () => {
  const ctx = setup();
  const c = await registered(ctx.provider);
  const t = await tokens(ctx, c);
  const info = await ctx.provider.verifyAccessToken(t.access_token);
  assert.equal(info.token, t.access_token);
  assert.equal(info.clientId, c.client_id);
  assert.deepEqual(info.scopes, ['reachdog']);
  assert.equal(info.expiresAt, Math.floor(ctx.now() / 1000) + 3600);
  assert.equal(info.resource.href, RESOURCE);
  assert.deepEqual(info.extra, { grant_id: GRANT.grant_id, grant_secret: GRANT.grant_secret });
});

test('expired, foreign or wrong-kind access token -> InvalidTokenError and 401', async () => {
  const ctx = setup();
  const c = await registered(ctx.provider);
  const t = await tokens(ctx, c);
  const foreign = seal('access', { grant_id: 'g', grant_secret: 's', client_id: 'x', exp: Date.now() + 60_000, jti: 'j' },
    randomBytes(32));
  await assert.rejects(ctx.provider.verifyAccessToken(foreign), InvalidTokenError);
  await assert.rejects(ctx.provider.verifyAccessToken(t.refresh_token), InvalidTokenError);
  await assert.rejects(ctx.provider.verifyAccessToken('junk'), InvalidTokenError);

  const mw = requireBearerAuth({ verifier: ctx.provider, expectedResource: new URL(RESOURCE) });
  const call = async token => {
    const res = { headers: {}, code: 0, set(k, v) { this.headers[k] = v; return this; },
      status(s) { this.code = s; return this; }, json() { return this; } };
    let passed = false;
    await mw({ headers: { authorization: 'Bearer ' + token } }, res, () => { passed = true; });
    return passed ? 200 : res.code;
  };
  assert.equal(await call(t.access_token), 200);
  assert.equal(await call(foreign), 401);
  ctx.advance(3601 * 1000);
  await assert.rejects(ctx.provider.verifyAccessToken(t.access_token), InvalidTokenError);
  assert.equal(await call(t.access_token), 401);
});

// ---------------- revocation ----------------

test('revokeToken revokes the grant for refresh or access tokens; unknown tokens are ignored', async () => {
  const ctx = setup();
  const c = await registered(ctx.provider);
  const t = await tokens(ctx, c);
  await ctx.provider.revokeToken(c, { token: 'nonsense' });
  assert.equal(ctx.acc.calls.length, 0);
  await ctx.provider.revokeToken(c, { token: t.refresh_token, token_type_hint: 'refresh_token' });
  assert.deepEqual(ctx.acc.calls, [{ url: 'https://accounts.test/internal/connector-grants/g-1', method: 'DELETE' }]);
  assert.equal(await db.collection('mcp_oauth_refresh').countDocuments(), 0);
  await assert.rejects(ctx.provider.exchangeRefreshToken(c, t.refresh_token), InvalidGrantError);
  const t2 = await tokens(ctx, c);
  await ctx.provider.revokeToken(c, { token: t2.access_token });
  assert.equal(ctx.acc.calls.length, 2);
  const other = await registered(ctx.provider);
  await ctx.provider.revokeToken(other, { token: t2.refresh_token }); // not this client's token: ignored
  assert.equal(ctx.acc.calls.length, 2);
});

// ---------------- Client ID Metadata Documents ----------------

const CIMD = 'https://client.example/oauth/client.json';
const cimdDoc = (over = {}) => ({ client_id: CIMD, client_name: 'Meta App', redirect_uris: [CB],
  token_endpoint_auth_method: 'none', ...over });

test('CIMD document is fetched safely, validated and cached for a day', async () => {
  const ctx = setup({ docs: { [CIMD]: cimdDoc({ client_secret: 'should-not-stick' }) } });
  const c = await ctx.provider.clientsStore.getClient(CIMD);
  assert.equal(c.client_id, CIMD);
  assert.equal(c.client_name, 'Meta App');
  assert.equal(c.client_secret, undefined);
  assert.equal(ctx.fetches.length, 1);
  assert.equal(ctx.fetches[0].init.redirect, 'error');
  assert.ok(ctx.fetches[0].init.signal instanceof AbortSignal);
  await ctx.provider.clientsStore.getClient(CIMD);
  assert.equal(ctx.fetches.length, 1); // cached
  ctx.advance(86400 * 1000 + 1);
  await ctx.provider.clientsStore.getClient(CIMD);
  assert.equal(ctx.fetches.length, 2); // stale, refetched
});

test('CIMD with mismatched client_id or a disallowed redirect is refused', async () => {
  const a = 'https://a.example/client.json', b = 'https://b.example/client.json';
  const ctx = setup({ docs: {
    [a]: cimdDoc({ client_id: 'https://other.example/client.json' }),
    [b]: { ...cimdDoc({ redirect_uris: [CB, 'https://evil.example/cb'] }), client_id: b },
  } });
  assert.equal(await ctx.provider.clientsStore.getClient(a), undefined);
  assert.equal(await ctx.provider.clientsStore.getClient(b), undefined);
  assert.equal(await db.collection('mcp_oauth_clients').countDocuments(), 0);
});

test('CIMD refuses non-https, private hosts, oversize and non-JSON documents', async () => {
  const big = 'https://big.example/client.json', txt = 'https://txt.example/client.json';
  const ctx = setup({ docs: {
    [big]: JSON.stringify({ ...cimdDoc(), client_id: big, pad: 'x'.repeat(6000) }),
    [txt]: 'not json',
  } });
  for (const id of ['http://client.example/c.json', 'https://127.0.0.1/c.json', 'https://localhost/c.json',
    'https://10.1.2.3/c.json', 'https://192.168.0.1/c.json', 'https://169.254.169.254/c.json', 'https://[::1]/c.json',
    'https://metadata.google.internal/c.json', 'https://foo.localhost/c.json', 'https://intranet/c.json',
    'https://user@client.example/c.json', 'https://client.example/'])
    assert.equal(await ctx.provider.clientsStore.getClient(id), undefined, id);
  assert.equal(ctx.fetches.length, 0);
  assert.equal(await ctx.provider.clientsStore.getClient(big), undefined);
  assert.equal(await ctx.provider.clientsStore.getClient(txt), undefined);
  assert.equal(await ctx.provider.clientsStore.getClient('https://missing.example/c.json'), undefined);
});
