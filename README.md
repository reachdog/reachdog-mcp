# Reach Dog MCP server

Classify products, group catalogs, research markets and create content from an MCP client.

## Install and connect

Use Node.js 24 or newer. Sign in to the [Reach Dog developer console](https://platform.reach.dog/keys), create your account's API key, and use your existing tokens. The console documents the scopes enabled on your key.

Add this to the MCP configuration in Claude Desktop or Cursor, replacing the API key and account label with your own values.

```json
{
  "mcpServers": {
    "reachdog": {
      "command": "npx",
      "args": ["--yes", "@reachdog/mcp@0.1.0"],
      "env": {
        "REACHDOG_API_URL": "https://api.reach.dog",
        "REACHDOG_API_KEY": "YOUR_API_KEY",
        "REACHDOG_ACCOUNT_LABEL": "my-application"
      }
    }
  }
}
```

For VS Code, put the `reachdog` object under `servers` in `.vscode/mcp.json` and add `"type": "stdio"` to that object.

The tools are `get_usage`, `list_parameters`, `estimate_cost`, `enrich_title`, `research_market`, `generate_content`, `enrich_catalog`, `get_catalog_status`, and `retry_payment`.

## First request

Ask your client to enrich one of your product titles with `product_type`. Review the estimate and approve the request through the client's approval dialog. Catalog enrichment first returns a quote, then requires acceptance of that exact quote. Each request uses your Reach Dog account's tokens.

The session budget counts Reach Dog billing tokens. Set REACHDOG_MAX_TOKENS_PER_SESSION to a whole number to limit estimated spending across the process. A client with elicitation prompts for each payment. In a client without elicitation, configuring a cap authorizes spending up to the cap when the model confirms. With neither approval mechanism only previews are available.

## Build from source

Run `npm ci`, `npm run build`, and `npm pack` from this repository. To use a source build, configure the MCP command as `node` with the absolute path to `dist/server.js` as its argument. `npm test` runs the offline client and tool checks.

## Support

Use [GitHub issues](https://github.com/reachdog/reachdog-mcp/issues) for bugs. Include the version and error code, keeping API keys and private product records out of the report. See the [API reference](https://platform.reach.dog/docs/api-reference) for request fields, scopes and errors.

MIT licensed. API usage uses your Reach Dog account and its available tokens.
