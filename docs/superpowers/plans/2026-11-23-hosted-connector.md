# Hosted Reach Dog connector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a person add `https://mcp.reach.dog/mcp` to Claude or ChatGPT, sign in with Reach Dog, and run the nine existing tools on their own tokens.

**Architecture:** The connector (reachdog-mcp) becomes an OAuth 2.1 authorization server plus a Streamable HTTP MCP server. Sign-in reuses accounts.reach.dog/authorize; on approval Accounts creates a "connector grant" with its own managed API key, which the connector resolves per call and uses against the unchanged API.

**Tech Stack:** TypeScript on Node 24, @modelcontextprotocol/sdk 1.32 (auth router, bearer middleware, Streamable HTTP), express 5, mongodb driver; Accounts in Python/FastAPI with pymongo; Cloud Run.

**Spec:** `docs/superpowers/specs/2026-11-23-hosted-connector-design.md` (this repo). Read it first.

Three pull requests, in three repos, built in this order: Part A (reachdog/accounts), Part B (reachdog/API), Part C (reachdog-mcp). Each part is reviewable and testable alone. Part C uses fakes for Accounts and the API until A and B are deployed.

## Global Constraints

- No change to the API's key checks, billing, prices or scopes. Part B only widens who may call wallet setup.
- Key scopes for connector keys: exactly `developer_keys.SCOPES` = `['content', 'match', 'read', 'research']`.
- Daily spending limit default: 10,000 Reach Dog tokens per grant per UTC day; the person may pick another positive integer on the consent page.
- The limit counts settled charges plus open reservations. A call or quote larger than what is left today is refused and the remaining amount is shown.
- Access token lifetime: 1 hour. Auth code lifetime: 10 minutes, single use. Refresh tokens rotate; reuse of an old one revokes the grant; expire after 30 days unused.
- Resolved API keys cached in memory at most 5 minutes.
- At most 10 active connector grants per account.
- Redirect URIs: exact match against an allowlist of Claude and ChatGPT callback URLs, plus `http://127.0.0.1:<port>` and `http://localhost:<port>` with any port. Nothing else.
- Accounts: ASCII only, every file under 500 lines, build under 2,500 lines; PRs go to the Arbiter, then the Deploy session. Never modify wallets.
- Coding sessions never deploy, merge, or change Cloud Armor, DNS or IAM. Those go in the DEPLOY HANDOFF.
- Logs never contain tokens, keys, grant secrets, titles or results.
- User-facing copy: plain sentences, no em dashes, no trackers or analytics on the consent page.
- Existing stdio package behaviour and its tests stay unchanged.

## Review Focus

- The Accounts pass cookie expired between sign-in and clicking Approve: the person is sent back through accounts.reach.dog/authorize and returns to the same consent page, never a 500. (Test in Task C6.)
- Two tool calls race against the daily limit: total reserved never exceeds the limit. (Test in Task C3.)
- The person revokes the connector key from the console while the connector has it cached: the API's 401 clears the cache and the tool returns "Reconnect Reach Dog in your assistant", not a generic failure. (Test in Task C7.)
- A refresh token is replayed after rotation: the whole grant is revoked in Accounts and both tokens stop working. (Test in Task C5.)
- A catalog quote displayed on one Cloud Run instance is accepted on another: acceptance works because quotes live in Mongo. (Test in Task C3.)

---

## Part A: Accounts connector grants (reachdog/accounts, branch `feat/connector-grants`)

### Task A1: Settings for the connector

**Files:**
- Modify: `accounts/config.py` (fields block, `allowed_origins`, `from_env`)
- Test: `tests/test_connector_grants.py` (new)

**Interfaces:**
- Produces: `Settings.connector_identity: str` (env `CONNECTOR_SERVICE_ACCOUNT`, default `''`), `Settings.connector_grants_enabled: bool` (env `CONNECTOR_GRANTS_ENABLED == 'true'`, default False), `"https://mcp.reach.dog"` in `allowed_origins`.

- [ ] **Step 1: Write the failing test**

```python
def test_mcp_return_host_allowed(settings):
    url = 'https://mcp.reach.dog/oauth/consent?request=abc'
    assert settings.return_url(url) == url

def test_connector_disabled_by_default(settings):
    assert settings.connector_grants_enabled is False and settings.connector_identity == ''
```

- [ ] **Step 2: Run** `python -m pytest tests/test_connector_grants.py -v` (with `ACCOUNTS_TEST_URI` and `TEST_MONGOD` set as in the existing suite). Expected: FAIL.
- [ ] **Step 3: Add the two settings and the origin.**
- [ ] **Step 4: Run again.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(connector): settings and mcp.reach.dog return host`.

### Task A2: Grant store

**Files:**
- Create: `accounts/connector_grants.py`
- Modify: `accounts/developer_keys.py` (`schema()` creates `match_connector_grants`; nothing else)
- Test: `tests/test_connector_grants.py`

**Interfaces:**
- Consumes: `DeveloperKeys.tenant(account, session, create=True)`, `generate()`, `CredentialCipher.encrypt/decrypt`, `transaction(db, fn)`, `refuse(code, message, status)`, `SCOPES`.
- Produces: class `ConnectorGrants(db, keys: DeveloperKeys, cipher: CredentialCipher)` with
  - `create(account: str, client_name: str, redirect_host: str, daily_limit: int) -> dict` returning `{'grant_id': str(16 hex), 'grant_secret': str, 'key_id': str, 'daily_limit': int}`
  - `resolve(grant_id: str, grant_secret: str) -> dict` returning `{'account_id', 'key', 'key_id', 'daily_limit'}`; sets `last_used_at`
  - `revoke(grant_id: str, account: str | None = None) -> None` (idempotent; with `account`, ownership-checked, foreign = 404)
  - `list(account: str) -> list[dict]` metadata only (`grant_id, client_name, redirect_host, daily_limit, created_at, last_used_at`)

Grant row: `_id=grant_id, account_id, tenant_id, key_id, client_name, redirect_host, daily_limit, created_at, last_used_at, revoked_at, secret_salt, secret_hash, envelope`. Key row in `api_keys` has `managed: True, connector_grant: grant_id, scopes: SCOPES`. Key, grant and envelope commit in one transaction. The envelope binding is `json.dumps([account, tenant, key_id, grant_id])`.

- [ ] **Step 1: Write failing tests**

```python
def test_create_resolve_revoke(grants, db):
    g = grants.create('a', 'Claude', 'claude.ai', 10000)
    r = grants.resolve(g['grant_id'], g['grant_secret'])
    assert r['account_id'] == 'a' and r['key'].startswith('tca_' + g['key_id'])
    assert db.api_keys.find_one({'key_id': g['key_id']})['scopes'] == SCOPES
    assert 'grant_secret' not in str(db.match_connector_grants.find_one({}))
    grants.revoke(g['grant_id'])
    assert db.api_keys.find_one({'key_id': g['key_id']})['revoked_at'] is not None
    with pytest.raises(KeyErrorResponse) as e: grants.resolve(g['grant_id'], g['grant_secret'])
    assert e.value.code == 'grant_revoked'

def test_wrong_secret_and_unknown_grant_look_the_same(grants):
    g = grants.create('a', 'Claude', 'claude.ai', 10000)
    for gid, sec in [(g['grant_id'], 'x' * 43), ('0' * 16, g['grant_secret'])]:
        with pytest.raises(KeyErrorResponse) as e: grants.resolve(gid, sec)
        assert (e.value.code, e.value.status) == ('grant_invalid', 401)

def test_key_revoked_elsewhere_blocks_resolve(grants, db):  # console revoke path
    g = grants.create('a', 'Claude', 'claude.ai', 10000)
    db.api_keys.update_one({'key_id': g['key_id']}, {'$set': {'revoked_at': now()}})
    with pytest.raises(KeyErrorResponse) as e: grants.resolve(g['grant_id'], g['grant_secret'])
    assert e.value.code == 'grant_revoked'

def test_closed_account_and_frozen_wallet(grants, db): ...  # each -> account_unavailable / wallet_ineligible on create AND resolve
def test_grant_limit_ten(grants): ...                       # 11th create -> ('grant_limit', 409)
def test_console_credential_untouched(grants, service, db): ...  # create+revoke a grant leaves match_console_credentials and the console key active
def test_wallet_never_written(grants, db): ...             # balance unchanged after create/resolve/revoke
```

- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement `ConnectorGrants`.** Secret: `secrets.token_urlsafe(32)`, stored as salted SHA-256; compare with `hmac.compare_digest`. Resolve re-checks account active, wallet unfrozen (same query as `tenant(create=True)` but read-only) and key not revoked.
- [ ] **Step 4: Run, expect PASS; run the full suite, expect no regressions.**
- [ ] **Step 5: Commit** `feat(connector): grant store with dedicated managed keys`.

### Task A3: Internal routes

**Files:**
- Create: `accounts/connector_routes.py`
- Modify: `accounts/app.py` (install only when `settings.connector_grants_enabled`)
- Test: `tests/test_connector_grants.py`

**Interfaces:**
- Consumes: `ConnectorGrants` (A2), `sessions.live(token)`.
- Produces (all JSON, `Cache-Control: no-store`, caller must present a Google ID token with audience `settings.origin` and email `settings.connector_identity`):
  - `POST /internal/connector-grants` + header `X-Accounts-Pass`, body `{"client_name": str<=80, "redirect_host": str<=253, "daily_limit": int 1..10000000}` -> 201 `{grant_id, grant_secret, key_id, daily_limit}`
  - `POST /internal/connector-grants/resolve` body `{"grant_id", "grant_secret"}` -> 200 `{account_id, key, key_id, daily_limit}`
  - `DELETE /internal/connector-grants/{grant_id}` -> 204 (service only; used on OAuth revoke and refresh reuse)
  - `GET /internal/connector-grants` + `X-Accounts-Pass` -> `{"grants": [...]}`
  - `DELETE /internal/connector-grants/{grant_id}` + `X-Accounts-Pass` -> 204 ownership-checked (for the console later)

- [ ] **Step 1: Failing tests** reusing the fake Google verifier pattern from `tests/test_developer_keys.py`: console identity refused (403 `caller_denied`); guest or `acting_for` pass refused on create (403 `person_required`); resolve needs no person pass; routes absent (404) when the flag is off; responses carry `no-store`; audit log line has `grant_id` and `account_id` but no secret or key.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement**, mirroring `key_routes.identity()` with `connector_identity`.
- [ ] **Step 4: Run full suite with `TEST_MONGOD` and `TITLE_API_SOURCE`, expect all pass.**
- [ ] **Step 5: Update `docs/INTERFACES.md`, `docs/LINE_COUNTS.md` (build must stay under 2,500), add `docs/CONNECTOR_GRANTS.md` (settings, schema step `python -m accounts.key_schema --apply`, Mongo role additions: read/insert/update on `match_connector_grants`). Commit and open the PR with a DEPLOY HANDOFF block; request Arbiter review.**

## Part B: Wallet setup accepts the connector (reachdog/API, branch `feat/connector-wallet-caller`)

### Task B1: Second allowed caller

**Files:**
- Modify: `app/internal/console_wallet.py` (`CONSOLE_IDENTITY` check)
- Test: the existing console wallet test module (find with `grep -rl console_wallet tests`)

**Interfaces:**
- Produces: the route accepts a verified email equal to `CONSOLE_IDENTITY` or to env `CONNECTOR_WALLET_IDENTITY` (unset = console only). Behaviour otherwise identical.

- [ ] **Step 1: Failing tests**: connector identity accepted when env set; refused when unset; any other identity refused; `acting_for` pass still refused.
- [ ] **Step 2: Run, expect FAIL. Step 3: implement. Step 4: run the full API suite (Python 3.13, local mongod 8.0.17), expect all pass.**
- [ ] **Step 5: Commit, PR with DEPLOY HANDOFF (env var value is the connector service account email).**

## Part C: Hosted connector (reachdog-mcp, branch `feat/hosted-connector`)

New code lives in `src/hosted/`. `src/server.ts` (stdio) keeps working unchanged.

### Task C1: Make Session state and budget pluggable

**Files:**
- Modify: `src/tools.ts`, `src/budget.ts`
- Test: `tests/tools.test.mjs` (existing must pass unchanged), `tests/stores.test.mjs` (new)

**Interfaces:**
- Produces:
  - `interface QuoteStore { getQuote(id:string):Promise<string|undefined>; setQuote(id:string,binding:string):Promise<void>; getAccepted(id:string):Promise<string|undefined>; setAccepted(id:string,binding:string):Promise<void> }` and `class MemoryQuoteStore implements QuoteStore`
  - `interface Spend { readonly limit?:number; runPaidPost<T>(id:string,estimate:number,post:()=>Promise<T>):Promise<T>; settle(id:string,x:unknown):Promise<void>; refused(id:string):Promise<void> }`; existing `Budget` implements it.
  - `Session` constructor takes `(client, host, account, spend: Spend, approve, waitMs=120000, quotes: QuoteStore = new MemoryQuoteStore())`.
- `Budget` errors keep the text `Session budget exceeded`.

- [ ] **Step 1: Write `tests/stores.test.mjs`**: MemoryQuoteStore round-trip; a Session built with the default store behaves exactly as before (reuse one existing catalog scenario).
- [ ] **Step 2: Run `npm test`, expect the new test to FAIL.**
- [ ] **Step 3: Refactor** `quotes`/`accepted` maps into the store and await `settle`/`refused`.
- [ ] **Step 4: `npm test`, expect all old and new tests PASS.**
- [ ] **Step 5: Commit** `refactor: pluggable quote store and spend`.

### Task C2: Sealed tokens

**Files:**
- Create: `src/hosted/seal.ts`
- Test: `tests/seal.test.mjs`

**Interfaces:**
- Produces: `seal(kind:'access'|'refresh', payload:{grant_id:string; grant_secret:string; client_id:string; exp:number; jti:string}, key:Buffer): string` and `open(kind, token:string, key:Buffer, now=Date.now()): payload | null`. AES-256-GCM, random 12-byte IV, `kind` as additional authenticated data, base64url. Key: 32 bytes from env `CONNECTOR_SEAL_KEY` (base64), loaded by Task C7.

- [ ] **Step 1: Failing tests**: round-trip; access token rejected as refresh and vice versa; tampered byte -> null; expired -> null; wrong key -> null; output never contains the grant secret in clear.
- [ ] **Step 2-4: Run FAIL, implement with `node:crypto`, run PASS.**
- [ ] **Step 5: Commit.**

### Task C3: Mongo store

**Files:**
- Create: `src/hosted/store.ts`
- Modify: `package.json` (dependency `mongodb@6`, devDependency `mongodb-memory-server@10`)
- Test: `tests/store.test.mjs` (uses mongodb-memory-server)

**Interfaces:**
- Produces: `class HostedStore(db: Db)` with
  - `ensureIndexes()` (called by an operator script, Task C8, never on a request)
  - clients: `getClient(id)`, `putClient(info)`
  - codes: `putCode(code, {client_id, grant_id, grant_secret, challenge, redirect_uri, resource, expires})`, `takeCode(code)` (atomic find-and-delete, null if missing or expired)
  - refresh: `putRefresh(jti, grant_id, client_id)`, `rotateRefresh(oldJti, newJti): 'ok'|'reused'|'unknown'`, `dropGrant(grant_id)`
  - `quotes(grant_id): QuoteStore`
  - `spend(grant_id, daily_limit, day=utcDay()): Spend`
- Collections: `mcp_oauth_clients`, `mcp_oauth_codes` (TTL on `expires`), `mcp_oauth_refresh` (TTL 30 days on `last_used`), `mcp_spend` (`_id: grant_id + ':' + day`, `total`, `ops.{id}`; TTL 7 days), `mcp_quotes` (TTL 2 days).
- Spend algorithm: reserve with one conditional `updateOne` that requires `total - (ops[id] ?? 0) + reserve <= limit` (use `$expr` with an aggregation-pipeline update so check and increment are atomic); refusal throws `Daily limit reached: <left> of <limit> Reach Dog tokens left today`.

- [ ] **Step 1: Failing tests**: code is single use and expires; refresh rotation returns `reused` for the old jti; **10 concurrent reserves of 2,000 against a 10,000 limit admit exactly 5**; settle lowers the reservation to the charged amount; a refused call releases its reservation; **a quote set via one `HostedStore` instance is read by a second instance on the same db**; day rollover starts a fresh total.
- [ ] **Step 2-4: Run FAIL, implement, run PASS.**
- [ ] **Step 5: Commit.**

### Task C4: Accounts and wallet clients

**Files:**
- Create: `src/hosted/accounts.ts`
- Test: `tests/accounts-client.test.mjs` (fake fetch)

**Interfaces:**
- Produces: `class AccountsClient(origin:string, idToken:(audience:string)=>Promise<string>, transport=fetch)` with `createGrant(pass, {client_name, redirect_host, daily_limit})`, `resolve(grant_id, grant_secret)`, `revoke(grant_id)`; and `setupWallet(walletUrl, pass, idToken)` calling `POST <walletUrl>/internal/console-wallet` with `{}`.
- `metadataIdToken(audience)` fetches `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=<aud>&format=full` with `Metadata-Flavor: Google`.
- Errors: Accounts `grant_invalid`/`grant_revoked` -> `ReconnectError`; `wallet_ineligible` -> `WalletError`; anything else -> generic `AccountsUnavailable` (no upstream text passed through).

- [ ] **Steps 1-5**: tests for each mapping, the headers sent (Bearer ID token, `X-Accounts-Pass` only on create), and that the response key is never logged; implement; commit.

### Task C5: OAuth provider

**Files:**
- Create: `src/hosted/provider.ts`, `src/hosted/redirects.ts`
- Test: `tests/provider.test.mjs`

**Interfaces:**
- Consumes: `HostedStore` (C3), `seal/open` (C2), `AccountsClient` (C4).
- Produces: `class ReachDogOAuthProvider implements OAuthServerProvider` (SDK `server/auth/provider.js`), and `allowedRedirect(uri:string): boolean` in `redirects.ts` with the constant `CLIENT_CALLBACKS` (Claude and ChatGPT callback URLs, confirmed from their current docs at build time) plus loopback rules.
  - `clientsStore.registerClient` refuses any redirect URI where `allowedRedirect` is false (`invalid_redirect_uri`).
  - `clientsStore.getClient(id)`: if `id` is an https URL, treat it as a Client ID Metadata Document: fetch it (2 s timeout, 5 KB cap, no redirects), require `client_id === id` and every redirect allowed; cache in `mcp_oauth_clients` for 1 day.
  - `authorize` stores the request (client, challenge, redirect, state, resource) under a random id in `mcp_oauth_codes` with kind `pending`, then 302s to `https://accounts.reach.dog/authorize?return_to=` + encoded `https://mcp.reach.dog/oauth/consent?request=<id>`.
  - `exchangeAuthorizationCode` -> `{access_token, token_type:'bearer', expires_in:3600, refresh_token}`; refresh carries a new `jti`.
  - `exchangeRefreshToken`: `rotateRefresh` result `reused` -> `AccountsClient.revoke(grant_id)` + `dropGrant` + `invalid_grant`.
  - `verifyAccessToken` -> `AuthInfo{token, clientId, scopes:['reachdog'], expiresAt, extra:{grant_id, grant_secret}}`; `resource` must equal `https://mcp.reach.dog/mcp`.
  - `revokeToken` revokes the grant in Accounts.

- [ ] **Step 1: Failing tests**: unlisted redirect refused at registration and at authorize; loopback any port allowed, `http://evil.example` refused; CIMD document with mismatched `client_id` refused; PKCE wrong verifier refused (SDK handles; assert it); code reuse refused; **refresh replay revokes the grant (fake Accounts records the DELETE)**; expired or foreign access token -> 401.
- [ ] **Steps 2-5: run FAIL, implement, run PASS, commit.**

### Task C6: Consent page

**Files:**
- Create: `src/hosted/consent.ts`
- Test: `tests/consent.test.mjs`

**Interfaces:**
- Consumes: pending request (C5), `AccountsClient.createGrant`, `setupWallet` (C4).
- Produces: express handlers `GET /oauth/consent?request=<id>` and `POST /oauth/consent`.
  - GET reads cookie `__Secure-rd_pass`; missing -> 302 to `https://accounts.reach.dog/authorize?return_to=<this exact consent URL>`. Renders a self-contained HTML page (inline CSS, no scripts from other hosts, no trackers): app name and redirect host, what it can do, a number input for the daily limit (default 10000, min 1), Approve and Cancel. CSRF: hidden field equal to HMAC(seal key, request id + pass session id).
  - POST: verifies CSRF; calls `createGrant`; on `wallet_ineligible` with state missing, calls `setupWallet` once then retries `createGrant`; stores the code (`putCode`) and 302s to the client redirect with `code` and `state`. Cancel 302s with `error=access_denied`.
  - Copy (exact): heading `Connect <client name> to Reach Dog`; body `<client name> will be able to classify products, group catalogs, research markets and write content using your Reach Dog tokens.`; label `Daily spending limit (Reach Dog tokens)`; note `Every result shows its price. Calls over today's limit are refused. To change the limit, disconnect and connect again.`

- [ ] **Step 1: Failing tests**: **no pass cookie -> 302 to accounts with the same consent URL encoded in `return_to`**; bad CSRF -> 403; Approve -> 302 to redirect with `code` and the original `state`; Cancel -> `access_denied`; new person with no wallet -> setup called once then grant created; limit 0 or non-integer -> 422; page HTML contains no `<script src=`.
- [ ] **Steps 2-5: run FAIL, implement, run PASS, commit.**

### Task C7: HTTP entry point

**Files:**
- Create: `src/http.ts`
- Modify: `package.json` (`bin` unchanged; add script `start:http`), `Dockerfile` (keep stdio default; `ENTRYPOINT` overridable, document `node dist/http.js`)
- Test: `tests/http.test.mjs` (SDK `Client` + `StreamableHTTPClientTransport` against the app on a random port, fake Accounts and fake API via `node:http`)

**Interfaces:**
- Consumes: everything above; `Session`, `tools` from `src/tools.ts`.
- Produces: `createApp(deps:{store, provider, accounts, apiUrl, sealKey, now?}): express.Express`; `http.ts` main reads env `MONGO_URI`, `CONNECTOR_SEAL_KEY`, `ACCOUNTS_ORIGIN` (default `https://accounts.reach.dog`), `WALLET_URL`, `REACHDOG_API_URL` (default `https://api.reach.dog`), `PUBLIC_URL` (default `https://mcp.reach.dog`), `PORT`.
  - Routes: `mcpAuthRouter` (issuer `PUBLIC_URL`, resource `PUBLIC_URL + '/mcp'`), consent handlers, `GET /healthz`, `POST /mcp` behind `requireBearerAuth` (stateless: new `Server` and `StreamableHTTPServerTransport({sessionIdGenerator: undefined})` per request).
  - Per request: resolve key via an in-memory cache (5 min, keyed by grant_id); build `ReachDogClient(apiUrl, key)`, `Session(client, apiHost, 'connector:'+grant_id, store.spend(grant_id, daily_limit), approve, 120000, store.quotes(grant_id))`. `approve` uses elicitation when the client supports form elicitation, else `'unsupported'` (so the daily limit applies, matching `mode()`).
  - API 401/403 from a resolved key, or `ReconnectError`: drop the cache entry and return tool error text `Reconnect Reach Dog in your assistant to continue.`

- [ ] **Step 1: Failing tests**: unauthenticated `/mcp` -> 401 with `WWW-Authenticate` naming `/.well-known/oauth-protected-resource/mcp`; metadata documents served; full flow with fakes: register -> authorize -> consent approve -> token -> `listTools` returns the 9 tools -> `enrich_title` with `confirm:true` charges 25 and records spend; **fake API returns 401 after console revoke -> tool error says reconnect and the next call re-resolves**; over-limit call refused with remaining amount.
- [ ] **Steps 2-5: run FAIL, implement, run PASS (`npm test`), commit.**

### Task C8: Operator script, docs and handoff

**Files:**
- Create: `scripts/ensure-indexes.mjs` (calls `HostedStore.ensureIndexes()`), `docs/HOSTED.md`
- Modify: `README.md` (short "Hosted connector" section, marked "coming soon" until live)

- [ ] **Step 1: Write `docs/HOSTED.md`**: env vars and secret references (never values), Mongo role (read/write on the five `mcp_*` collections only), service account `rd-mcp-connector-sa`, Cloud Run service `rd-mcp-connector` us-east1, health check.
- [ ] **Step 2: Run `npm test`; expect all pass. Run `npm pack --dry-run`; expect the file list to include `dist/http.js` and `dist/hosted/` and no `.env` or key files.**
  Note: the SDK auth router serves `/authorize`, `/token`, `/register` and `/revoke` at the root, not under `/oauth/` as the spec sketched; the consent page stays at `/oauth/consent`.
- [ ] **Step 3: Commit, push the branch, open the PR with this DEPLOY HANDOFF:**
  - Sysadmin: Mongo user for the connector; `CONNECTOR_SEAL_KEY` secret (32 random bytes); Accounts env `CONNECTOR_SERVICE_ACCOUNT`, `CONNECTOR_GRANTS_ENABLED=true`, schema apply; API env `CONNECTOR_WALLET_IDENTITY`.
  - Operator: DNS and load balancer for mcp.reach.dog; Cloud Armor rule 2003 exemptions for mcp.reach.dog paths `/authorize`, `/register`, `/oauth/consent`, `/token`; run `scripts/ensure-indexes.mjs`.
  - Deploy order: Part A, Part B, then Part C with no traffic; end-to-end check on the tagged revision with a fresh test account (operator OK for its free-token spend); then traffic.
  - Rollback: route traffic off `rd-mcp-connector`; set `CONNECTOR_GRANTS_ENABLED=false` in Accounts (all grants stop resolving).

## After this plan

Site and llms.txt updates ("Add to Claude / ChatGPT") and directory submissions are separate work, started once the connector is live.
