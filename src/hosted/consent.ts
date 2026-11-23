// Consent page for the hosted connector. After sign-in at accounts.reach.dog the
// person lands here, approves one MCP client with a daily spending limit, and is
// sent back to the client with an authorization code. The Accounts pass is only
// decoded here (for its session id and expiry); Accounts verifies it on createGrant.
// Nothing here logs: the pass, grant secret and codes must never reach a log line.

import { createHmac, timingSafeEqual } from 'node:crypto';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import type { ReachDogOAuthProvider } from './provider.ts';
import {
  AccountsUnavailable, GrantLimitError, ReconnectError, WalletError, type AccountsClient, type CreatedGrant,
} from './accounts.ts';

export interface ConsentDeps {
  provider: Pick<ReachDogOAuthProvider, 'peekPending' | 'issueCode' | 'denyRequest'>;
  accounts: Pick<AccountsClient, 'createGrant' | 'revoke'>;
  /** Pre-bound by the caller with the wallet URL, audience and ID token. */
  setupWallet: (pass: string) => Promise<void>;
  sealKey: Buffer;
  publicUrl: string;
  accountsOrigin: string;
  now?: () => number;
}

const PASS_COOKIE = '__Secure-rd_pass';
const DEFAULT_LIMIT = '10000';
const MAX_LIMIT = 10_000_000;
const MAX_ID = 512;

const esc = (s: string): string => s.replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
const trimSlash = (s: string): string => s.replace(/\/+$/, '');

interface Pass { raw: string; sid: string }

function readCookie(req: Request, name: string): string | null {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim() || null;
  }
  return null;
}

/** Decodes (does not verify) the pass. Null when missing, malformed or expired. */
function readPass(req: Request, nowMs: number): Pass | null {
  const raw = readCookie(req, PASS_COOKIE);
  if (!raw) return null;
  const parts = raw.split('.');
  if (parts.length !== 3) return null;
  try {
    const p = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>;
    if (typeof p.sid !== 'string' || p.sid.length === 0 || typeof p.exp !== 'number') return null;
    if (p.exp * 1000 <= nowMs) return null;
    return { raw, sid: p.sid };
  } catch {
    return null;
  }
}

const STYLE = 'body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a;background:#fff}'
  + 'h1{font-size:1.4rem}label{display:block;font-weight:600;margin-top:1.25rem}'
  + 'input[type=number]{font:inherit;padding:.4rem;width:10rem;margin-top:.25rem}'
  + '.note{color:#555;font-size:.9rem}.err{color:#a00;font-weight:600}'
  + 'button{font:inherit;padding:.6rem 1.2rem;margin:1.25rem .5rem 0 0;cursor:pointer}'
  + 'button.go{background:#1a1a1a;color:#fff;border:1px solid #1a1a1a}';

function document(title: string, body: string): string {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + `<title>${esc(title)}</title><style>${STYLE}</style></head><body>${body}</body></html>`;
}

export function consentRouter(deps: ConsentDeps): express.Router {
  const router = express.Router();
  const now = deps.now ?? Date.now;
  const publicUrl = trimSlash(deps.publicUrl);
  const accountsOrigin = trimSlash(deps.accountsOrigin);
  const csp = `default-src 'none'; style-src 'unsafe-inline'; form-action ${publicUrl}; frame-ancestors 'none'`;

  const headers = (res: Response): void => {
    res.set({
      'Cache-Control': 'no-store',
      'Content-Security-Policy': csp,
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    });
  };
  const page = (res: Response, status: number, title: string, body: string): void => {
    headers(res);
    res.status(status).type('html').send(document(title, body));
  };
  const message = (res: Response, status: number, text: string): void => {
    page(res, status, 'Reach Dog', `<h1>Reach Dog</h1><p>${esc(text)}</p>`);
  };
  const expired = (res: Response): void => message(res, 400,
    'This sign-in link expired. Start connecting again from your assistant.');
  const toAccounts = (res: Response, id: string): void => {
    const back = `${publicUrl}/oauth/consent?request=${encodeURIComponent(id)}`;
    headers(res);
    res.redirect(302, `${accountsOrigin}/authorize?return_to=${encodeURIComponent(back)}`);
  };

  const csrfFor = (id: string, sid: string): string => createHmac('sha256', deps.sealKey)
    .update(`consent:${id}:${sid}`).digest('base64url');
  const csrfOk = (id: string, sid: string, given: unknown): boolean => {
    if (typeof given !== 'string') return false;
    const a = Buffer.from(csrfFor(id, sid));
    const b = Buffer.from(given);
    return a.length === b.length && timingSafeEqual(a, b);
  };

  const form = (id: string, sid: string, name: string, host: string, limit: string, error?: string): string => (
    `<h1>Connect ${esc(name)} to Reach Dog</h1>`
    + `<p>${esc(name)} will be able to classify products, group catalogs, research markets and write content using your Reach Dog tokens.</p>`
    + `<p class="note">It will send you back to ${esc(host)}.</p>`
    + `<form method="post" action="${esc(publicUrl)}/oauth/consent">`
    + `<input type="hidden" name="request" value="${esc(id)}">`
    + `<input type="hidden" name="csrf" value="${esc(csrfFor(id, sid))}">`
    + '<label for="daily_limit">Daily spending limit (Reach Dog tokens)</label>'
    + (error ? `<p class="err" role="alert">${esc(error)}</p>` : '')
    + `<input id="daily_limit" type="number" name="daily_limit" min="1" max="${MAX_LIMIT}" step="1" required value="${esc(limit)}">`
    + '<p class="note">Every result shows its price. Calls over today\'s limit are refused. To change the limit, disconnect and connect again.</p>'
    + '<button class="go" type="submit" name="action" value="approve">Approve</button>'
    + '<button type="submit" name="action" value="cancel" formnovalidate>Cancel</button>'
    + '</form>'
  );

  const requestId = (v: unknown): string | null => (
    typeof v === 'string' && v.length > 0 && v.length <= MAX_ID ? v : null);
  const hostOf = (uri: string): string => { try { return new URL(uri).host; } catch { return ''; } };

  router.get('/oauth/consent', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = requestId(req.query.request);
      const pending = id ? await deps.provider.peekPending(id) : null;
      if (!id || !pending) return expired(res);
      const pass = readPass(req, now());
      if (!pass) return toAccounts(res, id);
      page(res, 200, 'Connect to Reach Dog',
        form(id, pass.sid, pending.client_name, hostOf(pending.redirect_uri), DEFAULT_LIMIT));
    } catch (e) { next(e); }
  });

  router.post('/oauth/consent', express.urlencoded({ extended: false, limit: '4kb' }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const body = (req.body ?? {}) as Record<string, unknown>;
        const id = requestId(body.request);
        if (!id) return expired(res);
        const pass = readPass(req, now());
        if (!pass) return toAccounts(res, id);
        if (!csrfOk(id, pass.sid, body.csrf)) return message(res, 403, 'This form is no longer valid. Start connecting again from your assistant.');
        const pending = await deps.provider.peekPending(id);
        if (!pending) return expired(res);

        if (body.action === 'cancel') {
          const url = await deps.provider.denyRequest(id);
          if (!url) return expired(res);
          headers(res);
          return res.redirect(302, url);
        }
        if (body.action !== 'approve') return message(res, 400, 'That request was not understood.');

        const limitRaw = typeof body.daily_limit === 'string' ? body.daily_limit : '';
        const limit = /^[1-9][0-9]{0,7}$/.test(limitRaw) ? Number(limitRaw) : 0;
        if (limit < 1 || limit > MAX_LIMIT) {
          return page(res, 422, 'Connect to Reach Dog', form(id, pass.sid, pending.client_name,
            hostOf(pending.redirect_uri), limitRaw.slice(0, 20),
            `Enter a whole number of tokens from 1 to ${MAX_LIMIT.toLocaleString('en-US')}.`));
        }

        const request = { client_name: pending.client_name, redirect_host: hostOf(pending.redirect_uri), daily_limit: limit };
        let grant: CreatedGrant;
        try {
          try {
            grant = await deps.accounts.createGrant(pass.raw, request);
          } catch (e) {
            if (!(e instanceof WalletError)) throw e;
            await deps.setupWallet(pass.raw);
            grant = await deps.accounts.createGrant(pass.raw, request);
          }
        } catch (e) {
          if (e instanceof ReconnectError) return toAccounts(res, id);
          if (e instanceof GrantLimitError) {
            return message(res, 409, 'You have 10 connected apps. Disconnect one in your Reach Dog console, then try again.');
          }
          if (e instanceof WalletError) return message(res, 409, "This account's wallet needs attention. Contact support.");
          if (e instanceof AccountsUnavailable) {
            return message(res, 503, 'Reach Dog is having trouble right now. Try again in a few minutes.');
          }
          throw e;
        }

        let url: string;
        try {
          url = await deps.provider.issueCode(id, grant);
        } catch {
          try { await deps.accounts.revoke(grant.grant_id); } catch { /* best effort */ }
          return message(res, 409, 'Something went wrong while connecting. Please start again from your assistant.');
        }
        headers(res);
        res.redirect(302, url);
      } catch (e) { next(e); }
    });

  router.use('/oauth/consent', (err: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) return next(err);
    message(res, 400, 'That request was not understood. Start connecting again from your assistant.');
  });

  return router;
}
