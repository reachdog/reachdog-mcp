// Clients for the Accounts connector-grant API and the API wallet-setup route.
// Callers authenticate as the service's Google identity with an ID token.
// Nothing here logs; upstream text never reaches an error message.

export type IdTokenSource = (audience: string) => Promise<string>;

export class ReconnectError extends Error {
  constructor() { super('Reconnect Reach Dog in your assistant'); this.name = 'ReconnectError'; }
}
export class WalletError extends Error {
  constructor() { super('This account cannot use a Reach Dog wallet'); this.name = 'WalletError'; }
}
export class GrantLimitError extends Error {
  constructor() { super('Too many connected apps. Disconnect another app first'); this.name = 'GrantLimitError'; }
}
/** The pass is not a direct person session (a guest or delegated pass): signing in again with it cannot help. */
export class PersonRequiredError extends Error {
  constructor() { super('Sign in with a Reach Dog account to connect'); this.name = 'PersonRequiredError'; }
}
/** The account behind a grant is closed or unavailable. Terminal for that grant. */
export class AccountClosedError extends Error {
  constructor() { super('This Reach Dog account is closed'); this.name = 'AccountClosedError'; }
}
export class AccountsUnavailable extends Error {
  constructor() { super('Reach Dog accounts are unavailable right now'); this.name = 'AccountsUnavailable'; }
}

export interface GrantRequest { client_name: string; redirect_host: string; daily_limit: number }
export interface CreatedGrant { grant_id: string; grant_secret: string; key_id: string; daily_limit: number }
export interface ResolvedGrant { account_id: string; key: string; key_id: string; daily_limit: number }

const TIMEOUT_MS = 10_000;
type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const num = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);

async function readJson(res: Response): Promise<unknown> {
  try { return await res.json(); } catch { return undefined; }
}

function errorCode(body: unknown): string | undefined {
  if (!isObj(body)) return undefined;
  for (const k of ['error', 'detail']) {
    const inner = body[k];
    if (isObj(inner) && typeof inner.code === 'string') return inner.code;
  }
  return undefined;
}

function mapFailure(body: unknown): Error {
  const code = errorCode(body);
  if (code === 'grant_invalid' || code === 'grant_revoked') return new ReconnectError();
  if (code === 'wallet_ineligible') return new WalletError();
  if (code === 'grant_limit') return new GrantLimitError();
  return new AccountsUnavailable();
}

async function send(
  transport: typeof fetch, url: string, method: string, headers: Record<string, string>, body?: string,
): Promise<{ res: Response; body: unknown }> {
  let res: Response;
  try {
    res = await transport(url, { method, headers, body, signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch {
    throw new AccountsUnavailable();
  }
  const parsed = res.status === 204 ? undefined : await readJson(res);
  return { res, body: parsed };
}

async function bearer(idToken: IdTokenSource, audience: string): Promise<string> {
  try {
    const t = await idToken(audience);
    if (!str(t)) throw new Error('empty');
    return t;
  } catch {
    throw new AccountsUnavailable();
  }
}

export class AccountsClient {
  readonly #origin: string;
  readonly #idToken: IdTokenSource;
  readonly #fetch: typeof fetch;

  constructor(origin: string, idToken: IdTokenSource, transport: typeof fetch = fetch) {
    this.#origin = origin.replace(/\/+$/, '');
    this.#idToken = idToken;
    this.#fetch = transport;
  }

  async #call(method: string, path: string, body?: object, pass?: string) {
    const headers: Record<string, string> = {
      Authorization: 'Bearer ' + await bearer(this.#idToken, this.#origin),
      Accept: 'application/json',
    };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (pass !== undefined) headers['X-Accounts-Pass'] = pass;
    return send(this.#fetch, this.#origin + path, method, headers,
      body === undefined ? undefined : JSON.stringify(body));
  }

  async createGrant(pass: string, req: GrantRequest): Promise<CreatedGrant> {
    const { res, body } = await this.#call('POST', '/internal/connector-grants', req, pass);
    // Only here does a refused pass mean "sign in again": a bare 401. A guest or delegated
    // pass (person_required) cannot be fixed by signing in with the same session.
    if (res.status === 401) throw new ReconnectError();
    if (errorCode(body) === 'person_required') throw new PersonRequiredError();
    if (res.status !== 201) throw mapFailure(body);
    if (!isObj(body) || !str(body.grant_id) || !str(body.grant_secret) || !str(body.key_id) || !num(body.daily_limit)) {
      throw new AccountsUnavailable();
    }
    return { grant_id: body.grant_id, grant_secret: body.grant_secret, key_id: body.key_id, daily_limit: body.daily_limit };
  }

  async resolve(grantId: string, grantSecret: string): Promise<ResolvedGrant> {
    const { res, body } = await this.#call('POST', '/internal/connector-grants/resolve',
      { grant_id: grantId, grant_secret: grantSecret });
    if (res.status === 403 && errorCode(body) === 'account_unavailable') throw new AccountClosedError();
    if (res.status !== 200) throw mapFailure(body);
    if (!isObj(body) || !str(body.account_id) || !str(body.key) || !str(body.key_id) || !num(body.daily_limit)) {
      throw new AccountsUnavailable();
    }
    return { account_id: body.account_id, key: body.key, key_id: body.key_id, daily_limit: body.daily_limit };
  }

  async revoke(grantId: string): Promise<void> {
    const { res, body } = await this.#call('DELETE', '/internal/connector-grants/' + encodeURIComponent(grantId));
    if (res.status !== 204) throw mapFailure(body);
  }
}

export async function setupWallet(
  walletUrl: string, audience: string, pass: string, idToken: IdTokenSource, transport: typeof fetch = fetch,
): Promise<void> {
  const headers = {
    Authorization: 'Bearer ' + await bearer(idToken, audience),
    'X-Accounts-Pass': pass,
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  const { res, body } = await send(transport, walletUrl.replace(/\/+$/, '') + '/internal/console-wallet', 'POST', headers, '{}');
  // The API refused the pass as expired: the person signs in again. Every other refusal is not theirs to fix.
  if (res.status === 401 && errorCode(body) === 'session_expired') throw new ReconnectError();
  if (res.status !== 200) throw mapFailure(body);
  if (!isObj(body) || body.state !== 'active') throw new AccountsUnavailable();
}

export async function metadataIdToken(audience: string, transport: typeof fetch = fetch): Promise<string> {
  const url = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience='
    + encodeURIComponent(audience) + '&format=full';
  try {
    const res = await transport(url, { headers: { 'Metadata-Flavor': 'Google' }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    const text = (await res.text()).trim();
    if (res.status !== 200 || !text) throw new Error('bad');
    return text;
  } catch {
    throw new AccountsUnavailable();
  }
}
