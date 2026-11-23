# Hosted connector (mcp.reach.dog)

The hosted connector lets a person add Reach Dog to Claude or ChatGPT by URL, without handling an API key. It is the same nine tools as the stdio package. It is served by `dist/http.js`.

Status: built and tested, not yet deployed. Nothing here is live until the Deploy handoff below is done.

## What it does

- Runs an OAuth authorization server for assistants (authorization code with PKCE, refresh tokens that rotate, client metadata documents and dynamic registration).
- Sends the person to accounts.reach.dog to sign in, then shows its own consent page where they approve and set a daily limit in Reach Dog tokens (default 10,000 per UTC day).
- Serves a stateless MCP endpoint at `POST /mcp`. Each call resolves the person's managed API key through Accounts, runs the tool, and counts spending against the daily limit.
- Never logs tokens, keys, grant secrets, titles or results. The only log line is one JSON object per tool call: grant id, tool name, status, charged tokens.

## Routes

| Route | Purpose |
|---|---|
| `GET /health` | Returns `ok`. Use it for the Cloud Run health check. |
| `GET /.well-known/oauth-authorization-server` | Authorization server metadata. |
| `GET /.well-known/oauth-protected-resource/mcp` | Protected resource metadata for `/mcp`. |
| `GET /authorize`, `POST /token`, `POST /register`, `POST /revoke` | OAuth endpoints at the root, not under `/oauth/`. |
| `GET/POST /oauth/consent` | The consent page. |
| `POST /mcp` | MCP over Streamable HTTP, stateless, Bearer token required. Other methods return 405. |

## Environment variables

Values are never committed. Secret Manager entries are given as references to the secret name only.

| Variable | Required | Default | Notes |
|---|---|---|---|
| `MONGO_URI` | yes | none | Secret Manager reference. Connection string for the connector's Mongo user. |
| `CONNECTOR_SEAL_KEY` | yes | none | Secret Manager reference. Base64 of exactly 32 random bytes. Startup refuses anything else. |
| `WALLET_URL` | yes | none | Absolute URL of the API's wallet setup endpoint. |
| `WALLET_AUDIENCE` | yes | none | Audience of the ID token sent to the wallet endpoint. Must equal the API's `CONSOLE_WALLET_AUDIENCE`. |
| `MONGO_DB` | no | `rlly_meloquent` | Database that holds the `mcp_*` collections. |
| `ACCOUNTS_ORIGIN` | no | `https://accounts.reach.dog` | Accounts service origin. |
| `REACHDOG_API_URL` | no | `https://api.reach.dog` | Public API the tools call. |
| `PUBLIC_URL` | no | `https://mcp.reach.dog` | Issuer and resource base. The MCP resource is `PUBLIC_URL/mcp`. |
| `PORT` | no | `8080` | Listen port. |
| `TRUST_PROXY_HOPS` | no | `1` | Proxy hops in front of the app, 0 to 10. Use `2` behind the external load balancer with Cloud Armor in front of Cloud Run. |

Create the seal key with `openssl rand -base64 32` and store it straight into Secret Manager. Do not paste it anywhere else.

## Infrastructure names

- Cloud Run service: `rd-mcp-connector`, region `us-east1`, project `reachdog-308818`.
- Service account: `rd-mcp-connector-sa`. It needs `secretmanager.secretAccessor` on the two secrets. It calls Accounts and the API wallet endpoint with ID tokens from the metadata server, so those two services must accept its identity.
- Command: the image default is the stdio server. Override the Cloud Run command to `node dist/http.js`.
- Node: the image uses Node 24. Local runs need Node 24 or newer.
- Health check: `GET /health`.

## Mongo

The connector's Mongo user gets read and write on these five collections in `MONGO_DB` and nothing else:

| Collection | Holds | Expiry |
|---|---|---|
| `mcp_oauth_clients` | Registered and cached client metadata | none |
| `mcp_oauth_codes` | Pending authorize requests and authorization codes, stored hashed | `expires` field (10 minutes) |
| `mcp_oauth_refresh` | Refresh token records | 30 days after `last_used` |
| `mcp_spend` | Daily spend counters and reservations | 7 days after creation |
| `mcp_quotes` | Catalog quotes so any instance can accept them | 2 days after creation |

The user also needs permission to create indexes on these collections for the one-time script below.

Run the index script once per database, and again after any change to expiry rules. It is safe to repeat.

```
npm ci && npm run build
MONGO_URI=... MONGO_DB=rlly_meloquent node scripts/ensure-indexes.mjs
```

It prints `indexes ready` on success. On failure it prints a short message naming the setting to check and exits non-zero. It never prints the connection string.

## Client callbacks

The server accepts redirect URIs only from this exact list, plus loopback addresses (`http://127.0.0.1` and `http://localhost`, any port or none).

| Callback | Used by | Status |
|---|---|---|
| `https://claude.ai/api/mcp/auth_callback` | Claude web, Desktop, mobile | Confirmed in Anthropic's connector docs. Live check still wanted. |
| `https://claude.com/api/mcp/auth_callback` | Claude, announced future home | Not confirmed live. Kept so a move does not break sign-in. Needs a live check. |
| `https://chatgpt.com/connector_platform_oauth_redirect` | ChatGPT | Confirmed in OpenAI's docs. Needs a live check. |

ChatGPT only uses that stable callback when the server supports RFC 9207 issuer identification. The server does: its metadata sets `authorization_response_iss_parameter_supported` to true, and every authorize redirect, including errors, carries `iss`. Without that, ChatGPT would use per-connector callback URLs that an exact list cannot hold.

If a client cannot connect, check its callback against this list first.

## Deploy handoff

Coding sessions do not deploy, merge, or change Cloud Armor, DNS or IAM. These steps are for the sysadmin, the operator and the Deploy session.

### Sysadmin

- Create a Mongo user for the connector with read and write on the five `mcp_*` collections only, plus index creation on them.
- Create the `CONNECTOR_SEAL_KEY` secret (32 random bytes, base64) and the `MONGO_URI` secret. Grant `rd-mcp-connector-sa` access to both.
- Create the service account `rd-mcp-connector-sa` and the Cloud Run service `rd-mcp-connector` in us-east1 with the env vars above and the command override `node dist/http.js`. Set `TRUST_PROXY_HOPS=2`.
- Accounts env: set `CONNECTOR_SERVICE_ACCOUNT` to the connector service account email and `CONNECTOR_GRANTS_ENABLED=true`. This requires `DEVELOPER_KEYS_ENABLED=true`. Accounts refuses to start if the connector and console identities are the same.
- Accounts schema: run `python -m accounts.key_schema --apply`. Give the Accounts Mongo role read, insert and update on `match_connector_grants`.
- API env: set `CONNECTOR_WALLET_IDENTITY` to the connector service account email. The connector's `WALLET_AUDIENCE` must equal the API's `CONSOLE_WALLET_AUDIENCE`.

### Operator

- DNS and the external load balancer for mcp.reach.dog, in front of Cloud Run.
- Cloud Armor rule 2003 exemptions for mcp.reach.dog paths `/authorize`, `/register`, `/token`, `/revoke` and `/oauth/consent`. Confirm the `/.well-known` paths and `/mcp` are not blocked.
- Run `scripts/ensure-indexes.mjs` against the production database.
- Live-check the three client callbacks above.

### Deploy order

1. Part A (Accounts), then Part B (API), then Part C (this connector) deployed with no traffic.
2. End-to-end check on the tagged revision with a fresh test account. The operator approves the free-token spend for that test.
3. Then shift traffic.

### Rollback

- Route traffic off `rd-mcp-connector`.
- Set `CONNECTOR_GRANTS_ENABLED=false` in Accounts. All grants stop resolving.
