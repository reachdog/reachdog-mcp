// OAuth 2.1 authorization server for the hosted connector (mcp.reach.dog).
// Sign-in and consent happen at accounts.reach.dog; this provider keeps the
// pending request, turns an approved grant into a single-use code, and issues
// sealed access and rotating refresh tokens. Nothing here logs: tokens, codes
// and grant secrets must never reach a log line.

import { randomBytes } from 'node:crypto';
import type { AuthorizationParams, OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import {
  CustomOAuthError, InvalidGrantError, InvalidRequestError, InvalidTargetError, InvalidTokenError, ServerError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import {
  OAuthClientMetadataSchema, type OAuthClientInformationFull, type OAuthTokenRevocationRequest, type OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HostedStore, PendingRecord } from './store.ts';
import { open, openValue, seal, sealValue, type SealKind, type SealPayload } from './seal.ts';
import { ReconnectError, type AccountsClient, type CreatedGrant } from './accounts.ts';
import { allowedRedirect } from './redirects.ts';
import {
  pinnedGet, publicHostName, systemResolver, vetHostAll, type DocumentGetter, type Resolver,
} from './cimd-fetch.ts';

type AuthorizeResponse = Parameters<OAuthServerProvider['authorize']>[2];

export interface PendingRequest {
  client_id: string;
  client_name: string;
  redirect_uri: string;
  state?: string;
  scopes: string[];
  resource?: string;
}

export interface ProviderOptions {
  store: HostedStore;
  accounts: Pick<AccountsClient, 'revoke'>;
  sealKey: Buffer;
  publicUrl?: string;
  accountsOrigin?: string;
  /** DNS resolver for metadata-document hosts (tests inject one). */
  resolve?: Resolver;
  /** Fetches a metadata document pinned to a vetted address (tests inject one). */
  getDocument?: DocumentGetter;
  now?: () => number;
}

const ACCESS_TTL_S = 3600;
const REFRESH_TTL_MS = 30 * 86400_000;
const CODE_TTL_MS = 10 * 60_000;
const CIMD_FRESH_MS = 86400_000;
const CIMD_TIMEOUT_MS = 2000;
const CIMD_MAX_ADDRS = 4;
const CIMD_MAX_BYTES = 5 * 1024;
const CIMD_NEGATIVE_MS = 5 * 60_000;
const CIMD_NEGATIVE_MAX = 1000;
const NAME_MAX = 80;
const SCOPES = ['reachdog'];

const randomId = (): string => randomBytes(32).toString('base64url');
const trimSlash = (s: string): string => s.replace(/\/+$/, '');

/** Parses a CIMD client_id. Null unless it is a plain https URL with a path on a public host. */
function cimdUrl(id: string): URL | null {
  if (!id.startsWith('https://') || id.length > 2048 || id.includes('#')) return null;
  let u: URL;
  try { u = new URL(id); } catch { return null; }
  if (u.protocol !== 'https:' || u.username || u.password || u.pathname === '/' || u.pathname === '') return null;
  return publicHostName(u.hostname) ? u : null;
}

function displayName(name: unknown, redirectUri: string): string {
  const clean = (s: string) => s.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  let out = typeof name === 'string' ? clean(name) : '';
  if (!out) { try { out = new URL(redirectUri).host; } catch { out = 'Unknown app'; } }
  return out.slice(0, NAME_MAX);
}

class ClientsStore implements OAuthRegisteredClientsStore {
  /** Metadata-document ids that recently failed, so they cannot trigger a fetch on every request. */
  private readonly failed = new Map<string, number>();

  constructor(
    private readonly store: HostedStore,
    private readonly resolve: Resolver,
    private readonly getDocument: DocumentGetter,
    private readonly now: () => number,
  ) {}

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    if (typeof clientId !== 'string' || clientId.length === 0) return undefined;
    if (clientId.startsWith('https://') || clientId.startsWith('http://')) return this.metadataClient(clientId);
    return onlyAllowed(await this.store.getClient(clientId));
  }

  async registerClient(
    client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>,
  ): Promise<OAuthClientInformationFull> {
    const full = client as OAuthClientInformationFull;
    const uris = full.redirect_uris ?? [];
    if (uris.length === 0 || !uris.every(allowedRedirect)) {
      throw new CustomOAuthError('invalid_redirect_uri', 'Redirect URI is not allowed');
    }
    if (typeof full.client_id !== 'string' || full.client_id.length === 0 || full.client_id.includes('://')) {
      throw new ServerError('Client id was not generated');
    }
    await this.store.putClient({ ...full });
    return full;
  }

  /** Client ID Metadata Document: fetch, validate, cache for a day. */
  private async metadataClient(id: string): Promise<OAuthClientInformationFull | undefined> {
    const url = cimdUrl(id);
    if (!url) return undefined;
    const cached = await this.store.getClient(id);
    if (cached && typeof cached.cached_at === 'number' && this.now() - cached.cached_at < CIMD_FRESH_MS) {
      return onlyAllowed(cached);
    }
    const until = this.failed.get(id);
    if (until !== undefined && until > this.now()) return undefined;
    const info = await this.fetchMetadata(url, id);
    if (info) { this.failed.delete(id); return info; }
    this.failed.delete(id);
    if (this.failed.size >= CIMD_NEGATIVE_MAX) this.failed.delete(this.failed.keys().next().value as string);
    this.failed.set(id, this.now() + CIMD_NEGATIVE_MS);
    return undefined;
  }

  private async fetchMetadata(url: URL, id: string): Promise<OAuthClientInformationFull | undefined> {
    const addrs = await vetHostAll(url.hostname, this.resolve);
    if (!addrs) return undefined;
    // IPv4 first (Cloud Run may lack IPv6 egress); later addresses only within the same budget.
    const deadline = this.now() + CIMD_TIMEOUT_MS;
    let text: string | null = null;
    for (const addr of addrs.slice(0, CIMD_MAX_ADDRS)) {
      const left = deadline - this.now();
      if (left <= 0) break;
      try { text = await this.getDocument(url, addr, left); } catch { text = null; }
      if (text !== null) break;
    }
    if (text === null || Buffer.byteLength(text) > CIMD_MAX_BYTES) return undefined;
    let doc: unknown;
    try { doc = JSON.parse(text); } catch { return undefined; }
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return undefined;
    if ((doc as Record<string, unknown>).client_id !== id) return undefined;
    const parsed = OAuthClientMetadataSchema.safeParse(doc);
    if (!parsed.success) return undefined;
    const uris = parsed.data.redirect_uris;
    if (uris.length === 0 || !uris.every(allowedRedirect)) return undefined;
    // The schema strips any client_secret: metadata-document clients are always public.
    const info = { ...parsed.data, client_id: id, cached_at: this.now() };
    await this.store.putClient(info);
    return info as OAuthClientInformationFull;
  }
}

/** Drops any stored redirect that is no longer allowed; a client with none left is unknown. */
function onlyAllowed(client: any): OAuthClientInformationFull | undefined {
  if (!client || !Array.isArray(client.redirect_uris)) return undefined;
  const uris = client.redirect_uris.filter((u: unknown) => typeof u === 'string' && allowedRedirect(u));
  return uris.length ? { ...client, redirect_uris: uris } : undefined;
}

export class ReachDogOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: ClientsStore;
  /** RFC 8414 issuer, also returned as RFC 9207 `iss` on every consent redirect. */
  readonly issuer: string;
  readonly resource: URL;
  readonly #store: HostedStore;
  readonly #accounts: Pick<AccountsClient, 'revoke'>;
  readonly #key: Buffer;
  readonly #publicUrl: string;
  readonly #accountsOrigin: string;
  readonly #now: () => number;

  constructor(opts: ProviderOptions) {
    if (!Buffer.isBuffer(opts.sealKey) || opts.sealKey.length !== 32) throw new Error('Invalid seal key');
    this.#store = opts.store;
    this.#accounts = opts.accounts;
    this.#key = opts.sealKey;
    this.#publicUrl = trimSlash(opts.publicUrl ?? 'https://mcp.reach.dog');
    this.#accountsOrigin = trimSlash(opts.accountsOrigin ?? 'https://accounts.reach.dog');
    this.#now = opts.now ?? Date.now;
    this.issuer = new URL(this.#publicUrl).href;
    this.resource = new URL(this.#publicUrl + '/mcp');
    const getDocument: DocumentGetter = opts.getDocument
      ?? ((url, addr, timeoutMs) => pinnedGet(url, addr,
        { timeoutMs: Math.min(CIMD_TIMEOUT_MS, timeoutMs ?? CIMD_TIMEOUT_MS), maxBytes: CIMD_MAX_BYTES }));
    this.clientsStore = new ClientsStore(this.#store, opts.resolve ?? systemResolver, getDocument, this.#now);
  }

  // ---- authorize and the consent hand-off (Task C6 uses peekPending/issueCode/denyRequest) ----

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: AuthorizeResponse): Promise<void> {
    if (!params.resource) throw new InvalidRequestError('The resource parameter is required');
    if (params.resource.href !== this.resource.href) throw new InvalidTargetError('Unknown resource');
    if (!allowedRedirect(params.redirectUri)) throw new InvalidRequestError('Redirect URI is not allowed');
    const id = randomId();
    const rec: PendingRecord = {
      client_id: client.client_id,
      client_name: displayName(client.client_name, params.redirectUri),
      challenge: params.codeChallenge,
      redirect_uri: params.redirectUri,
      scopes: params.scopes ?? [],
      resource: this.resource.href,
      expires: new Date(this.#now() + CODE_TTL_MS),
    };
    if (params.state !== undefined) rec.state = params.state;
    await this.#store.putCode(id, 'pending', rec);
    const back = this.#publicUrl + '/oauth/consent?request=' + id;
    res.redirect(302, this.#accountsOrigin + '/authorize?return_to=' + encodeURIComponent(back));
  }

  async peekPending(id: string): Promise<PendingRequest | null> {
    if (typeof id !== 'string' || id.length === 0) return null;
    const rec = await this.#store.peekCode(id, 'pending');
    return rec && rec.done !== true ? toPending(rec) : null;
  }

  /** Claims a pending request for one approval; a duplicate submit gets 'taken'. */
  async claimRequest(id: string): Promise<'claimed' | 'taken' | 'missing'> {
    if (typeof id !== 'string' || id.length === 0) return 'missing';
    return this.#store.claimPending(id);
  }

  /** Gives a claim back after a failed approval. */
  async releaseRequest(id: string): Promise<void> {
    if (typeof id === 'string' && id.length > 0) await this.#store.releasePending(id);
  }

  /** The client redirect an earlier approval of this request produced, if it has finished. */
  async finishedRedirect(id: string): Promise<string | null> {
    if (typeof id !== 'string' || id.length === 0) return null;
    const sealed = await this.#store.readRedirect(id);
    return sealed ? openValue('redirect', sealed, this.#key) : null;
  }

  /** Uses up the pending request once and returns the client redirect carrying the code. */
  async issueCode(id: string, grant: CreatedGrant): Promise<string> {
    const rec = typeof id === 'string' && id ? await this.#store.finishPending(id) : null;
    if (!rec) throw new InvalidRequestError('This sign-in request has expired. Start again from your assistant');
    const code = randomId();
    await this.#store.putCode(code, 'code', {
      client_id: rec.client_id,
      grant_id: grant.grant_id,
      sealed_secret: sealValue('code-secret', grant.grant_secret, this.#key),
      challenge: rec.challenge,
      redirect_uri: rec.redirect_uri,
      resource: this.resource.href,
      expires: new Date(this.#now() + CODE_TTL_MS),
    });
    const url = this.#clientRedirect(rec, { code });
    await this.#store.recordRedirect(id, sealValue('redirect', url, this.#key));
    return url;
  }

  /**
   * Consumes an open pending request and returns an access_denied redirect. A request
   * whose Approve already finished is left alone and its code redirect is returned;
   * null if it is unknown or expired.
   */
  async denyRequest(id: string): Promise<string | null> {
    if (typeof id !== 'string' || id.length === 0) return null;
    const rec = await this.#store.takeOpenPending(id);
    return rec ? this.#clientRedirect(rec, { error: 'access_denied' }) : this.finishedRedirect(id);
  }

  #clientRedirect(rec: PendingRecord, params: Record<string, string>): string {
    const url = new URL(rec.redirect_uri);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    if (typeof rec.state === 'string') url.searchParams.set('state', rec.state);
    url.searchParams.set('iss', this.issuer);
    return url.href;
  }

  // ---- token endpoint ----

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string): Promise<string> {
    const rec = await this.#store.peekCode(code, 'code');
    if (!rec || rec.client_id !== client.client_id) throw new InvalidGrantError('Invalid authorization code');
    return rec.challenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull, code: string, _verifier?: string, redirectUri?: string, resource?: URL,
  ): Promise<OAuthTokens> {
    const rec = await this.#store.takeCode(code, 'code');
    if (!rec || rec.client_id !== client.client_id) throw new InvalidGrantError('Invalid authorization code');
    if (redirectUri !== undefined && redirectUri !== rec.redirect_uri) throw new InvalidGrantError('Redirect URI mismatch');
    this.#checkResource(resource);
    const secret = openValue('code-secret', rec.sealed_secret, this.#key);
    if (secret === null) throw new InvalidGrantError('Invalid authorization code');
    const jti = randomId();
    await this.#store.putRefresh(jti, rec.grant_id, client.client_id);
    return this.#tokens(rec.grant_id, secret, client.client_id, jti);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull, refreshToken: string, _scopes?: string[], resource?: URL,
  ): Promise<OAuthTokens> {
    const p = this.#open('refresh', refreshToken);
    if (!p || p.client_id !== client.client_id) throw new InvalidGrantError('Invalid refresh token');
    this.#checkResource(resource);
    const next = randomId();
    const r = await this.#store.rotateRefresh(p.jti, next);
    if (r === 'reused') {
      await this.#killGrant(p.grant_id).catch(() => undefined); // fail closed: local tokens are gone either way
      throw new InvalidGrantError('Invalid refresh token');
    }
    if (r !== 'ok') throw new InvalidGrantError('Invalid refresh token');
    return this.#tokens(p.grant_id, p.grant_secret, client.client_id, next);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const p = this.#open('access', token);
    if (!p) throw new InvalidTokenError('Invalid or expired access token');
    return {
      token,
      clientId: p.client_id,
      scopes: [...SCOPES],
      expiresAt: Math.floor(p.exp / 1000),
      resource: new URL(this.resource.href),
      extra: { grant_id: p.grant_id, grant_secret: p.grant_secret },
    };
  }

  /** RFC 7009: unknown or foreign tokens are ignored; a known one revokes its whole grant. */
  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const kinds: SealKind[] = request.token_type_hint === 'access_token' ? ['access', 'refresh'] : ['refresh', 'access'];
    let p: SealPayload | null = null;
    for (const k of kinds) { p = this.#open(k, request.token); if (p) break; }
    if (!p || p.client_id !== client.client_id) return;
    try { await this.#killGrant(p.grant_id); }
    catch { throw new ServerError('Could not disconnect right now. Try again'); }
  }

  // ---- helpers ----

  #open(kind: SealKind, token: unknown): SealPayload | null {
    return typeof token === 'string' ? open(kind, token, this.#key, this.#now()) : null;
  }

  #checkResource(resource?: URL): void {
    if (resource !== undefined && resource.href !== this.resource.href) throw new InvalidTargetError('Unknown resource');
  }

  /** Drops local refresh tokens first, then revokes in Accounts (already revoked counts as done). */
  async #killGrant(grant_id: string): Promise<void> {
    await this.#store.dropGrant(grant_id);
    try { await this.#accounts.revoke(grant_id); }
    catch (e) { if (!(e instanceof ReconnectError)) throw e; }
  }

  #tokens(grant_id: string, grant_secret: string, client_id: string, refreshJti: string): OAuthTokens {
    const now = this.#now();
    const access_token = seal('access',
      { grant_id, grant_secret, client_id, exp: now + ACCESS_TTL_S * 1000, jti: randomId() }, this.#key);
    const refresh_token = seal('refresh',
      { grant_id, grant_secret, client_id, exp: now + REFRESH_TTL_MS, jti: refreshJti }, this.#key);
    return { access_token, token_type: 'bearer', expires_in: ACCESS_TTL_S, refresh_token };
  }
}

function toPending(rec: PendingRecord): PendingRequest {
  const out: PendingRequest = {
    client_id: rec.client_id,
    client_name: typeof rec.client_name === 'string' ? rec.client_name : '',
    redirect_uri: rec.redirect_uri,
    scopes: Array.isArray(rec.scopes) ? rec.scopes.filter((s): s is string => typeof s === 'string') : [],
  };
  if (typeof rec.state === 'string') out.state = rec.state;
  if (typeof rec.resource === 'string') out.resource = rec.resource;
  return out;
}
