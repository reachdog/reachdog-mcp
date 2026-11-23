// Hosted connector entry point (mcp.reach.dog). Serves the OAuth authorization
// server, the consent page and a stateless Streamable HTTP MCP endpoint at /mcp
// that runs the same nine tools as the stdio package with the approving person's
// managed key. Logs are one JSON line per tool call and never carry tokens, keys,
// grant secrets, titles, bodies or results.

import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import express from 'express';
import type { Request, Response } from 'express';
import { MongoClient } from 'mongodb';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import {
  createOAuthMetadata, getOAuthProtectedResourceMetadataUrl, mcpAuthRouter,
} from '@modelcontextprotocol/sdk/server/auth/router.js';
import { metadataHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/metadata.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { OAuthMetadata } from '@modelcontextprotocol/sdk/shared/auth.js';
import { ApiError, ReachDogClient } from './client.ts';
import { Session, tools } from './tools.ts';
import { ToolError } from './errors.ts';
import { HostedStore } from './hosted/store.ts';
import { ReachDogOAuthProvider } from './hosted/provider.ts';
import { consentRouter } from './hosted/consent.ts';
import {
  AccountsClient, ReconnectError, metadataIdToken, setupWallet as walletSetup,
  type ResolvedGrant,
} from './hosted/accounts.ts';

export const RECONNECT = 'Reconnect Reach Dog in your assistant to continue.';
const UNAVAILABLE = 'Reach Dog is having trouble right now. Try again in a few minutes.';
const API_FAILED = 'Reach Dog had a problem completing this request. Try again in a minute.';
const KEY_TTL_MS = 5 * 60_000;
const KEY_CACHE_MAX = 5000;
const SCOPES = ['reachdog'];

export interface ToolLog {
  event: 'tool_call';
  grant_id: string;
  tool: string;
  status: 'ok' | 'error' | 'reconnect' | 'unavailable';
  charged_tokens: number | null;
}

export interface AppDeps {
  store: HostedStore;
  provider: ReachDogOAuthProvider;
  accounts: Pick<AccountsClient, 'createGrant' | 'revoke' | 'resolve'>;
  apiUrl: string;
  sealKey: Buffer;
  /** Pre-bound with the wallet URL, audience and ID token source. */
  setupWallet: (pass: string) => Promise<void>;
  accountsOrigin?: string;
  /** Proxy hops in front of the app. Cloud Run's front end adds exactly one. */
  trustProxyHops?: number;
  now?: () => number;
  log?: (line: ToolLog) => void;
}

const sha = (s: string): string => createHash('sha256').update(s).digest('hex');
const writeLog = (line: ToolLog): void => { process.stdout.write(JSON.stringify(line) + '\n'); };

/** Resolved managed keys, held at most five minutes and only for the secret that resolved them. */
class KeyCache {
  private readonly entries = new Map<string, { secret: string; grant: ResolvedGrant; expires: number }>();
  constructor(private readonly accounts: Pick<AccountsClient, 'resolve'>, private readonly now: () => number) {}

  async get(grantId: string, grantSecret: string): Promise<ResolvedGrant> {
    const hit = this.entries.get(grantId);
    if (hit && hit.expires > this.now() && hit.secret === sha(grantSecret)) return hit.grant;
    this.entries.delete(grantId);
    const grant = await this.accounts.resolve(grantId, grantSecret);
    if (this.entries.size >= KEY_CACHE_MAX) {
      for (const [k, v] of this.entries) if (v.expires <= this.now()) this.entries.delete(k);
      if (this.entries.size >= KEY_CACHE_MAX) this.entries.delete(this.entries.keys().next().value as string);
    }
    this.entries.set(grantId, { secret: sha(grantSecret), grant, expires: this.now() + KEY_TTL_MS });
    return grant;
  }

  drop(grantId: string): void { this.entries.delete(grantId); }
}

/** Adds RFC 9207 `iss` to the SDK's own authorize error redirects, which omit it. */
function issOnErrors(issuer: string): express.RequestHandler {
  const withIss = (url: string): string => {
    try {
      const u = new URL(url);
      if (u.searchParams.has('error') && !u.searchParams.has('iss')) {
        u.searchParams.set('iss', issuer);
        return u.href;
      }
    } catch { /* not an absolute URL: leave it */ }
    return url;
  };
  return (_req, res, next) => {
    const redirect = res.redirect.bind(res) as (status: number, url: string) => void;
    (res as { redirect: unknown }).redirect = (a: number | string, b?: string): void => {
      if (typeof a === 'number') redirect(a, withIss(String(b)));
      else redirect(302, withIss(a));
    };
    next();
  };
}

const text = (s: string, isError: boolean) => ({ isError, content: [{ type: 'text' as const, text: s }] });

export function createApp(deps: AppDeps): express.Express {
  const { provider, store } = deps;
  const now = deps.now ?? Date.now;
  const log = deps.log ?? writeLog;
  const apiHost = new URL(deps.apiUrl).host;
  const publicUrl = provider.issuer.replace(/\/+$/, '');
  const issuerUrl = new URL(provider.issuer);
  const keys = new KeyCache(deps.accounts, now);

  const app = express();
  app.disable('x-powered-by');
  // The SDK rate limiters key on req.ip. Trusting a fixed hop count takes the client
  // address the front end appended, which a caller cannot spoof, and keeps
  // express-rate-limit's trust-proxy validation quiet.
  app.set('trust proxy', deps.trustProxyHops ?? 1);

  app.get('/health', (_req, res) => { res.type('text').send('ok'); });

  const metadata = {
    ...createOAuthMetadata({ provider, issuerUrl, scopesSupported: SCOPES }),
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: true,
  } as OAuthMetadata;
  app.use('/.well-known/oauth-authorization-server', metadataHandler(metadata));
  app.use('/authorize', issOnErrors(provider.issuer));
  app.use(mcpAuthRouter({
    provider, issuerUrl, scopesSupported: SCOPES, resourceServerUrl: provider.resource, resourceName: 'Reach Dog',
  }));
  app.use(consentRouter({
    provider, accounts: deps.accounts, setupWallet: deps.setupWallet, sealKey: deps.sealKey, publicUrl,
    accountsOrigin: deps.accountsOrigin ?? 'https://accounts.reach.dog', now,
  }));

  const toolNames = new Set(tools.map((t) => t.name));

  /** Only caller-facing text leaves the service: infrastructure details stay inside. */
  const failure = (e: unknown, grantId: string, line: ToolLog) => {
    if (e instanceof ReconnectError || (e instanceof ApiError && (e.status === 401 || e.status === 403))) {
      keys.drop(grantId);
      line.status = 'reconnect';
      return text(RECONNECT, true);
    }
    if (e instanceof ApiError) {
      line.status = 'error';
      // The public API's own 4xx bodies help the assistant correct the call; 5xx bodies are not passed on.
      return text(JSON.stringify(e.status >= 400 && e.status < 500
        ? { status: e.status, error: e.body } : { status: e.status, error: API_FAILED }), true);
    }
    if (e instanceof ToolError) { line.status = 'error'; return text(e.message, true); }
    line.status = 'unavailable';
    return text(UNAVAILABLE, true);
  };

  const callTool = async (grantId: string, grantSecret: string, name: string, args: unknown) => {
    const line: ToolLog = {
      event: 'tool_call', grant_id: grantId, tool: toolNames.has(name) ? name : 'unknown', status: 'ok', charged_tokens: null,
    };
    try {
      const grant = await keys.get(grantId, grantSecret);
      // Stateless requests never carry the client's initialize capabilities, so elicitation
      // cannot be offered: 'unsupported' makes the consent page's daily limit the approval.
      const session = new Session(new ReachDogClient(deps.apiUrl, grant.key), apiHost, 'connector:' + grantId,
        store.spend(grantId, grant.daily_limit), async () => 'unsupported', 120000, store.quotes(grantId));
      const value = await session.call(name, args as never) as Record<string, unknown> | null;
      const isError = !!(value && typeof value === 'object' && 'error' in value && value.error);
      if (value && typeof value.charged_tokens === 'number') line.charged_tokens = value.charged_tokens;
      if (isError) line.status = 'error';
      return text(JSON.stringify(value), isError);
    } catch (e) {
      return failure(e, grantId, line);
    } finally {
      log(line);
    }
  };

  const bearer = requireBearerAuth({
    verifier: provider,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(provider.resource),
    expectedResource: provider.resource,
  });

  app.post('/mcp', bearer, async (req: Request, res: Response) => {
    const extra = req.auth?.extra ?? {};
    const grantId = extra.grant_id, grantSecret = extra.grant_secret;
    if (typeof grantId !== 'string' || typeof grantSecret !== 'string') {
      res.status(401).json({ error: 'invalid_token', error_description: 'Invalid access token' });
      return;
    }
    const server = new Server({ name: 'reachdog', version: '0.1.0' }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, () => ({ tools }));
    server.setRequestHandler(CallToolRequestSchema, ({ params }) => callTool(grantId, grantSecret, params.name, params.arguments));
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => { void transport.close(); void server.close(); });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res);
    } catch {
      if (!res.headersSent) res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null });
    }
  });
  app.all('/mcp', bearer, (_req: Request, res: Response) => {
    res.status(405).set('Allow', 'POST').json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed' }, id: null });
  });

  return app;
}

// ---- process entry ----

function fail(message: string): never {
  process.stderr.write('reachdog-mcp http: ' + message + '\n');
  process.exit(1);
}

function readUrl(env: NodeJS.ProcessEnv, name: string, fallback?: string): string {
  const v = env[name] || fallback;
  if (!v) fail(`Missing required setting ${name}`);
  try { new URL(v); } catch { fail(`${name} must be an absolute URL`); }
  return v;
}

async function main(): Promise<void> {
  const env = process.env;
  const missing = ['MONGO_URI', 'CONNECTOR_SEAL_KEY', 'WALLET_URL', 'WALLET_AUDIENCE'].filter((k) => !env[k]);
  if (missing.length) fail('Missing required settings: ' + missing.join(', '));
  const sealRaw = env.CONNECTOR_SEAL_KEY as string;
  const sealKey = Buffer.from(sealRaw, 'base64');
  if (!/^[A-Za-z0-9+/]{43}=$/.test(sealRaw) || sealKey.length !== 32) {
    fail('CONNECTOR_SEAL_KEY must be base64 of exactly 32 bytes');
  }
  const walletUrl = readUrl(env, 'WALLET_URL');
  const walletAudience = env.WALLET_AUDIENCE as string;
  const accountsOrigin = readUrl(env, 'ACCOUNTS_ORIGIN', 'https://accounts.reach.dog');
  const apiUrl = readUrl(env, 'REACHDOG_API_URL', 'https://api.reach.dog');
  const publicUrl = readUrl(env, 'PUBLIC_URL', 'https://mcp.reach.dog');
  const port = Number(env.PORT || '8080');
  if (!Number.isInteger(port) || port < 1 || port > 65535) fail('PORT must be a port number');
  const hops = Number(env.TRUST_PROXY_HOPS || '1');
  if (!Number.isInteger(hops) || hops < 0 || hops > 10) fail('TRUST_PROXY_HOPS must be a whole number from 0 to 10');

  let mongo: MongoClient;
  try {
    mongo = new MongoClient(env.MONGO_URI as string);
    await mongo.connect();
  } catch { fail('Could not connect to MongoDB. Check MONGO_URI'); }
  const store = new HostedStore(mongo.db(env.MONGO_DB || 'rlly_meloquent'));
  const idToken = (audience: string) => metadataIdToken(audience);
  const accounts = new AccountsClient(accountsOrigin, idToken);
  const provider = new ReachDogOAuthProvider({ store, accounts, sealKey, publicUrl, accountsOrigin });
  const app = createApp({
    store, provider, accounts, apiUrl, sealKey, accountsOrigin, trustProxyHops: hops,
    setupWallet: (pass) => walletSetup(walletUrl, walletAudience, pass, idToken),
  });
  const server = app.listen(port);
  process.on('SIGTERM', () => { server.close(() => { void mongo.close(); }); });
}

function isEntry(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try { return import.meta.url === pathToFileURL(realpathSync(entry)).href; } catch { return false; }
}

if (isEntry()) await main();
