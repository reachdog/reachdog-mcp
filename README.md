# Reach Dog MCP server

Run `npm ci && npm run build` with Node 24 or newer. Build an installable archive with `npm pack`. For an offline install, first cache all dependencies using `npm ci`, then install the archive with npm in offline mode. The executable is `reachdog-mcp`.

For Claude Desktop or Cursor, put this entry in the client's MCP configuration. Replace the path and environment values locally. Keep credentials out of version control.

```json
{
  "mcpServers": {
    "reachdog": {
      "command": "node",
      "args": [
        "C:/reachdog-mcp/dist/server.js"
      ],
      "env": {
        "REACHDOG_API_URL": "<HTTPS API origin>",
        "REACHDOG_API_KEY": "<your bearer key>",
        "REACHDOG_ACCOUNT_LABEL": "<non-secret billing account label>"
      }
    }
  }
}
```

For VS Code, use the same entry under the `servers` key in `.vscode/mcp.json`:

```json
{
  "servers": {
    "reachdog": {
      "type": "stdio",
      "command": "node",
      "args": [
        "C:/reachdog-mcp/dist/server.js"
      ],
      "env": {
        "REACHDOG_API_URL": "<HTTPS API origin>",
        "REACHDOG_API_KEY": "<your bearer key>",
        "REACHDOG_ACCOUNT_LABEL": "<non-secret billing account label>"
      }
    }
  }
}
```

The session budget counts Reach Dog billing tokens. Set REACHDOG_MAX_TOKENS_PER_SESSION to a whole number to limit estimated spending across the process. A client with elicitation prompts for each payment. In a client without elicitation, configuring a cap authorizes spending up to the cap when the model confirms. With neither approval mechanism only previews are available.

### Operator live check

Use an approved account and key. Call get_usage and list_parameters. Preview enrich_title with a title and one supported parameter, then confirm and inspect charge_state and charged_tokens. Submit a small catalog_local_v1 body with enrich_catalog. Confirm using the returned batch_id and acceptance. Compare the settled result with the approved quote. Repeat confirmation and verify the batch_id remains the same. Resume a timeout with get_catalog_status. retry_payment requires fresh approval and a recoverable refusal for the original accepted quote. Change run_label only when a fresh operation is intended.
