import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import express from 'express';
import { consentRouter } from '../dist/hosted/consent.js';
import { ReconnectError, WalletError, GrantLimitError, AccountsUnavailable } from '../dist/hosted/accounts.js';

const KEY = randomBytes(32);
const NOW = 1_800_000_000_000;
const PUBLIC = 'https://mcp.reach.dog';
const ACCOUNTS = 'https://accounts.reach.dog';
const PENDING = {
  client_id: 'c1', client_name: 'Claude <b>X</b>', redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
  state: 'st', scopes: ['reachdog'],
};
const GRANT = { grant_id: 'g-1', grant_secret: 'gs-secret', key_id: 'k1', daily_limit: 10000 };
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const pass = (over = {}) => `${b64({ alg: 'none' })}.${b64({ sid: 'sess1', exp: NOW / 1000 + 600, ...over })}.sig`;
const csrf = (id, sid = 'sess1') => createHmac('sha256', KEY).update(`consent:${id}:${sid}`).digest('base64url');

let server, base, h;
function reset(over = {}) {
  h = {
    calls: [], grantErrors: [], issueThrows: false, pending: { ...PENDING },
    deny: 'https://claude.ai/api/mcp/auth_callback?error=access_denied&state=st',
    ...over,
  };
}
before(async () => {
  reset();
  const provider = {
    peekPending: async (id) => (id === 'req1' ? h.pending : null),
    issueCode: async (id, grant) => {
      h.calls.push(['issueCode', id, grant.grant_id]);
      if (h.issueThrows) throw new Error('boom');
      return 'https://claude.ai/api/mcp/auth_callback?code=CODE&state=st&iss=x';
    },
    denyRequest: async (id) => { h.calls.push(['deny', id]); return id === 'req1' ? h.deny : null; },
  };
  const accounts = {
    createGrant: async (p, req) => {
      h.calls.push(['createGrant', p, req]);
      const e = h.grantErrors.shift();
      if (e) throw e;
      return GRANT;
    },
    revoke: async (id) => { h.calls.push(['revoke', id]); if (h.revokeThrows) throw new Error('x'); },
  };
  const app = express();
  app.use(consentRouter({
    provider, accounts, sealKey: KEY, publicUrl: PUBLIC, accountsOrigin: ACCOUNTS, now: () => NOW,
    setupWallet: async (p) => { h.calls.push(['setupWallet', p]); },
  }));
  await new Promise((r) => { server = app.listen(0, '127.0.0.1', r); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const get = (q, cookie) => fetch(`${base}/oauth/consent?request=${q}`, {
  redirect: 'manual', headers: cookie ? { cookie: `__Secure-rd_pass=${cookie}` } : {},
});
const post = (fields, cookie) => fetch(`${base}/oauth/consent`, {
  method: 'POST', redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded', ...(cookie ? { cookie: `__Secure-rd_pass=${cookie}` } : {}) },
  body: new URLSearchParams(fields).toString(),
});
const form = (over = {}) => ({ request: 'req1', csrf: csrf('req1'), action: 'approve', daily_limit: '10000', ...over });
const consentUrl = `${PUBLIC}/oauth/consent?request=req1`;
const authorize = `${ACCOUNTS}/authorize?return_to=${encodeURIComponent(consentUrl)}`;

test('GET without pass cookie goes to accounts with this exact consent URL', async () => {
  reset();
  const r = await get('req1');
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), authorize);
});

test('GET with expired or garbage pass goes to accounts', async () => {
  reset();
  assert.equal((await get('req1', pass({ exp: NOW / 1000 }))).headers.get('location'), authorize);
  assert.equal((await get('req1', 'not-a-jwt')).headers.get('location'), authorize);
});

test('GET unknown request is a plain 400 with no redirect', async () => {
  reset();
  const r = await get('nope', pass());
  assert.equal(r.status, 400);
  assert.equal(r.headers.get('location'), null);
  assert.match(await r.text(), /expired/);
});

test('GET renders the exact copy, escapes values, no scripts, hardened headers', async () => {
  reset();
  const r = await get('req1', pass());
  assert.equal(r.status, 200);
  const html = await r.text();
  assert.ok(html.includes('Connect Claude &lt;b&gt;X&lt;/b&gt; to Reach Dog'));
  assert.ok(html.includes('will be able to classify products, group catalogs, research markets and write content using your Reach Dog tokens.'));
  assert.ok(html.includes('Daily spending limit (Reach Dog tokens)'));
  assert.ok(html.includes("Every result shows its price. Calls over today's limit are refused. To change the limit, disconnect and connect again."));
  assert.ok(html.includes('It will send you back to claude.ai.'));
  assert.ok(html.includes('value="10000"') && html.includes('min="1"'));
  assert.ok(!html.includes('<b>X</b>'));
  assert.ok(!/<script/i.test(html));
  assert.ok(!/(src|href)=/i.test(html));
  assert.ok(!html.includes('—'));
  assert.ok(html.includes(csrf('req1')));
  assert.equal(r.headers.get('cache-control'), 'no-store');
  assert.equal(r.headers.get('content-security-policy'),
    `default-src 'none'; style-src 'unsafe-inline'; form-action ${PUBLIC}; frame-ancestors 'none'`);
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
});

test('POST bad CSRF is 403 and creates nothing', async () => {
  reset();
  assert.equal((await post(form({ csrf: 'bad' }), pass())).status, 403);
  assert.equal((await post(form({ csrf: csrf('req1', 'other') }), pass())).status, 403);
  assert.equal(h.calls.length, 0);
});

test('POST with expired pass returns to the same consent page, never 500', async () => {
  reset();
  const r = await post(form(), pass({ exp: NOW / 1000 - 1 }));
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), authorize);
  assert.equal((await post(form())).headers.get('location'), authorize);
  assert.equal(h.calls.length, 0);
});

test('Approve creates the grant and redirects to the client with the code', async () => {
  reset();
  const p = pass();
  const r = await post(form({ daily_limit: '2500' }), p);
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), 'https://claude.ai/api/mcp/auth_callback?code=CODE&state=st&iss=x');
  assert.deepEqual(h.calls[0], ['createGrant', p, { client_name: 'Claude <b>X</b>', redirect_host: 'claude.ai', daily_limit: 2500 }]);
  assert.deepEqual(h.calls[1], ['issueCode', 'req1', 'g-1']);
  assert.equal(r.headers.get('cache-control'), 'no-store');
});

test('Cancel redirects with access_denied; unknown request on cancel is 400', async () => {
  reset();
  const r = await post(form({ action: 'cancel' }), pass());
  assert.equal(r.status, 302);
  assert.match(r.headers.get('location'), /error=access_denied/);
  assert.equal(h.calls.some((c) => c[0] === 'createGrant'), false);
  const r2 = await post(form({ request: 'nope', csrf: csrf('nope'), action: 'cancel' }), pass());
  assert.equal(r2.status, 400);
});

test('new person with no wallet: setup once, then grant', async () => {
  reset({ grantErrors: [new WalletError()] });
  const p = pass();
  const r = await post(form(), p);
  assert.equal(r.status, 302);
  assert.deepEqual(h.calls.map((c) => c[0]), ['createGrant', 'setupWallet', 'createGrant', 'issueCode']);
  assert.equal(h.calls[1][1], p);
});

test('wallet still bad after setup: 409 support page', async () => {
  reset({ grantErrors: [new WalletError(), new WalletError()] });
  const r = await post(form(), pass());
  assert.equal(r.status, 409);
  assert.match(await r.text(), /wallet needs attention\. Contact support\./);
  assert.equal(h.calls.filter((c) => c[0] === 'setupWallet').length, 1);
});

test('limit validation: 422 and the form is shown again', async () => {
  for (const v of ['0', '-5', '1.5', '', 'abc', '010', '10000001', '+5', '1e3', ' 5']) {
    reset();
    const r = await post(form({ daily_limit: v }), pass());
    assert.equal(r.status, 422, `limit ${JSON.stringify(v)}`);
    const html = await r.text();
    assert.ok(html.includes('Daily spending limit (Reach Dog tokens)'));
    assert.ok(html.includes('whole number'));
    assert.equal(h.calls.length, 0);
  }
});

test('Accounts failures map to plain pages', async () => {
  reset({ grantErrors: [new GrantLimitError()] });
  let r = await post(form(), pass());
  assert.equal(r.status, 409);
  assert.match(await r.text(), /You have 10 connected apps\. Disconnect one in your Reach Dog console, then try again\./);
  reset({ grantErrors: [new AccountsUnavailable()] });
  r = await post(form(), pass());
  assert.equal(r.status, 503);
  assert.match(await r.text(), /Reach Dog is having trouble right now\. Try again in a few minutes\./);
  reset({ grantErrors: [new ReconnectError()] });
  r = await post(form(), pass());
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), authorize);
});

test('issueCode failure revokes the grant and shows a start-again page', async () => {
  reset({ issueThrows: true, revokeThrows: true });
  const r = await post(form(), pass());
  assert.equal(r.status, 409);
  assert.match(await r.text(), /start again/i);
  assert.deepEqual(h.calls.at(-1), ['revoke', 'g-1']);
});
