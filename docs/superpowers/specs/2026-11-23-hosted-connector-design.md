# Hosted Reach Dog connector with sign-in (design)

Status: for approval, 2026-11-23. Repos touched: reachdog-mcp (most of the
work), reachdog/accounts (small internal routes), reachdog/API (one caller
allowlist line in the wallet setup route, no change to paid calls), infra (Cloud
Run, DNS, Cloud Armor).

## Why

Developers ask an AI assistant (Claude, ChatGPT, Cursor) what to use instead of
searching Google. The operator wants the assistant to be able to say "this works,
here is how, I have your catalog, want me to run it now?" and then actually run it.

Today that cannot happen. Before the first call the person must sign up, create a
key, install Node 24 and edit a JSON config, because @reachdog/mcp only runs as a
local stdio process. Claude and ChatGPT connectors expect a hosted URL with sign-in.

## Goal

A person adds `https://mcp.reach.dog/mcp` as a connector, signs in with Google,
GitHub or email on a Reach Dog page, approves, and the assistant can call the same
nine tools on their account straight away, spending their free daily tokens.

Success:
- Works as a custom connector in Claude (web and desktop) and ChatGPT, and with
  Claude Code, Cursor and VS Code through their remote MCP support.
- First paid call possible within about a minute of pasting the URL, with no key
  shown, copied or stored by the person.
- Eligible to submit to Claude's connector directory and ChatGPT's app directory.

## Non-goals

- No change to the Reach Dog API, its key checks, billing, prices or scopes.
- No new tools. Same nine tools and behaviour as @reachdog/mcp 0.1.0.
- Not reading a person's Shopify store or other systems. "Your catalog" means the
  titles the person gives the assistant (pasted, uploaded file, up to 500 per call).
- The local npx package stays supported and unchanged.
- No ads pixels or tracking in the sign-in pages (site promise: no trackers).

## Anti-goals (a failure even if it works)

- The connector service able to fetch the key of an account that never approved it.
- Money spent without the person seeing a price first.
- A wildcard redirect: Accounts' rule is explicit return hosts only.
- Revoking the connector breaking the person's console playground, or the reverse.

## Approaches considered

- A. Accounts issues OAuth tokens and the API accepts them next to API keys.
  Most standard, but it changes the code that authorizes every paid call. Rejected.
- B. (chosen by the user) The connector holds the key. Sign-in proves the person;
  the connector then gets a dedicated managed API key for that person from
  Accounts, the way the console does, and calls the API exactly as today.
- C. Paste an API key into the connector settings. Claude and ChatGPT connectors
  are built around OAuth sign-in, so this fails the no-setup goal. Rejected.
- Third-party auth vendor: splits account ownership; Accounts already signs
  people in. Rejected.

Refinement inside B (my call): the OAuth protocol itself (metadata, client
registration, authorize, token, refresh, revoke) lives in the connector service,
not in Accounts. Accounts is near its 2,500-line build cap (about 2,070 today) and
has a narrow approved scope, so it only gets a small "connector grant" feature.

## How it works

```
Claude/ChatGPT --(MCP over HTTP, Bearer access token)--> mcp.reach.dog (Cloud Run)
     |                                                     |   tools.ts (unchanged logic)
     | OAuth 2.1 + PKCE                                    |-- resolve key --> Accounts /internal/connector-grants/resolve
     v                                                     |-- API calls  --> api.reach.dog (unchanged, managed key)
mcp.reach.dog/oauth/* --sign-in--> accounts.reach.dog/authorize (existing Google/GitHub/email)
```

### Sign-in and approval (first connect)

1. The client calls `/mcp` without a token and gets 401 with
   `WWW-Authenticate` pointing at `/.well-known/oauth-protected-resource`
   (RFC 9728). That names mcp.reach.dog as its own authorization server
   (`/.well-known/oauth-authorization-server`, RFC 8414).
2. Client registration: support Client ID Metadata Documents and Dynamic Client
   Registration (RFC 7591), because current clients differ. Every redirect URI
   must match an allowlist: the published callback URLs of Claude and ChatGPT,
   plus loopback `http://127.0.0.1:<any port>` and `http://localhost:<any port>`
   for desktop and editor clients (RFC 8252). Anything else is refused.
   The builder confirms each client's exact callback URLs at build time.
3. `/oauth/authorize` (PKCE S256 required, `resource` parameter required) sends
   the browser to `accounts.reach.dog/authorize?return_to=https://mcp.reach.dog/oauth/consent?...`.
   Accounts adds mcp.reach.dog to its permitted return hosts; nothing else changes.
4. `/oauth/consent` reads the shared ten-minute Accounts pass cookie, shows one
   page: which app is asking (client name and redirect host), what it can do
   (classify products, group catalogs, research markets, write content, spend
   tokens from your balance), the daily spending limit (below), and Approve /
   Cancel. Plain copy, no em dashes, no trackers.
5. On Approve, the connector calls Accounts
   `POST /internal/connector-grants` with its Google service identity plus the
   person pass. Accounts checks the live session, an active account and an eligible
   wallet, then creates a grant and a dedicated managed API key for it, and returns
   `grant_id` and a `grant_secret` once. If the wallet is missing, the connector
   first runs the existing wallet setup the console uses
   (`/internal/console-wallet`, POST, in the API repo), so a brand-new person can
   finish in one go. That route hardcodes the console's service account today
   (`CONSOLE_IDENTITY` in app/internal/console_wallet.py); it must also accept the
   connector's. Who may connect: anyone the console would issue a customer API
   key to (active account, one eligible wallet). The playground rule in
   `demo_access.py` does not apply: the connector is an API-key client, and API
   keys already work for Google and email sign-ins with free tokens.
6. The connector returns an authorization code to the client, then exchanges it
   at `/oauth/token` for a one-hour access token and a rotating refresh token.

### Each tool call

The access token maps to a grant. The connector resolves the grant's managed key
from Accounts (`POST /internal/connector-grants/resolve`, service identity plus
grant_id and grant_secret; cached in memory for at most five minutes), then runs
the existing `Session` logic from `src/tools.ts` with that key. API behaviour,
idempotency keys, quotes and catalog acceptance are exactly as in the npx package.

### Spending approval

The npx package asks before spending through MCP elicitation, and without it only
spends within a configured session cap. Hosted clients do not all support
elicitation, so each grant has a daily spending limit set on the consent page.
Decided by the user 2026-11-23: the limit chosen on the consent page is the
approval; no extra per-call step. Default 10,000 Reach Dog tokens per day (the
free top-up amount), with the option to pick a different number. The limit counts
settled charges plus open reservations (estimates and accepted quotes not yet
settled); a call or catalog quote larger than what is left today is refused with
the remaining amount shown. To change the limit, the person reconnects. Tool results always show the estimate or
quote before a paid call; paid tools still need `confirm: true`, and catalog jobs
still need the exact displayed quote accepted. When the client supports
elicitation it is used as well.

### Revocation

- Client revoke (`/oauth/revoke`) or the person disconnecting deletes the grant
  in Accounts, which revokes its managed key immediately.
- Accounts rejects resolve for closed accounts, revoked grants or frozen wallets.
- The console API keys page lists connector grants (name, app, created, last used)
  with a Disconnect button. That is a follow-up in the API repo; until it ships,
  disconnect from the client side or by support.
- Connector grants and keys are separate from the console's managed credential.

## Accounts changes (small, needs operator scope approval)

AGENTS.md limits Accounts to an approved scope; this is an extension the operator
must approve, then Arbiter review and the Deploy session, as usual.

- Add `mcp.reach.dog` to permitted return hosts.
- New `match_connector_grants` collection: grant_id, account_id, tenant_id,
  key_id, client name and redirect host, daily limit, created_at, last_used_at,
  revoked_at, salted hash of grant_secret. Written in the same transaction as the
  key, like console credential provisioning.
- Routes, all requiring the connector's exact Google service identity:
  `POST /internal/connector-grants` (also a live person pass),
  `POST /internal/connector-grants/resolve`, `DELETE /internal/connector-grants/{id}`,
  `GET /internal/connector-grants` (person pass; for the console list later).
- Key scopes: the customer key set, content, match, read, research
  (`developer_keys.SCOPES`); catalog jobs already run with these.
- Limit: 10 active grants per account.
- Budget: about 200 lines including tests' helpers outside the build count.

## Connector service (reachdog-mcp)

- Same package, new entry point `src/http.ts` using the SDK's Streamable HTTP
  transport. `src/server.ts` (stdio) stays as is.
- OAuth endpoints as above. Use a maintained OAuth library or the SDK's auth
  helpers rather than hand-rolled crypto where one fits; builder's call.
- Token secrecy (my call): grant_secret is never stored by the connector. Access
  and refresh tokens are opaque AES-GCM blobs, sealed with a connector key from
  Secret Manager, carrying grant_id and grant_secret. Mongo keeps only hashes, so
  a copy of the database plus the service identity still cannot resolve keys.
- State in MongoDB (rlly_meloquent, its own collections, its own scoped user
  from the Sysadmin): OAuth clients, auth codes (TTL 10 min), refresh token
  hashes (rotating, reuse revokes the grant, TTL 30 days of inactivity), per-grant
  daily spend, and the
  per-grant session state that `Session` keeps in memory today (displayed quotes,
  accepted quotes) so any Cloud Run instance can serve the next call.
- Access tokens: one hour, bound to the resource `https://mcp.reach.dog/mcp`.
- Cloud Run service `rd-mcp-connector`, us-east1, behind the existing load
  balancer at mcp.reach.dog. No public key material in the image.
- Logs: grant_id, tool name, status, tokens charged. Never tokens, keys, titles
  or results.

## Infra and operator steps

- DNS and load balancer route for mcp.reach.dog.
- Cloud Armor: `/oauth/authorize` and `/oauth/register` carry https URLs in
  their parameters, which trips rule 2003 (RFI 931130), the same rule that broke
  sign-in on 2026-11-18. The operator adds exemptions for those paths. I do not
  change security settings.
- Service account for the connector, registered in Accounts config like the
  console's. Secrets via Secret Manager references only.

## Testing

- Unit tests for every OAuth endpoint: PKCE, redirect allowlist, code reuse,
  refresh rotation and reuse detection, revoke, expired and foreign tokens.
- Accounts tests for grants: no person pass, wrong service, closed account,
  frozen wallet, revoked grant, grant limit, transaction rollback.
- End-to-end (my call, no staging Accounts exists): a second Cloud Run revision
  with no traffic, tagged URL, against production Accounts and API with a fresh
  test account spending only its free tokens, with the operator's OK for the run:
  add the connector in Claude and in ChatGPT, run one `enrich_title` with `product_type` (25 tokens)
  and one small catalog quote, then disconnect and confirm the next call fails.
- Existing npx tests keep passing unchanged.

## After it is live (separate work)

- reach.dog/developers and both llms.txt files lead with "Add to Claude /
  ChatGPT: https://mcp.reach.dog/mcp", with the npx package second.
- Submit to Claude's connector directory, ChatGPT's app directory, the official
  MCP registry (remote entry), Smithery, Glama and PulseMCP. Each submission
  publishes under the company name and gets the operator's OK first.

## Left to the builder

Library choices, file layout inside reachdog-mcp, exact Mongo indexes, cache
details, consent page markup (plain, matching the Accounts sign-in look), and the
exact client callback URLs (confirm from each client's current docs).
