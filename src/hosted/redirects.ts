// Redirect URI allowlist for the hosted connector's OAuth server.
// Exact published callbacks of the hosted assistants, plus RFC 8252 loopback
// redirects for desktop and editor clients. Nothing else is accepted.

/**
 * Hosted assistant callbacks, matched exactly.
 * - claude.ai: Claude web, Desktop, mobile and Cowork (claude.com/docs/connectors/building/authentication).
 * - claude.com: announced future home of the same callback; kept so a move does not break sign-in.
 * - chatgpt.com stable callback: used when the server returns RFC 9207 `iss`
 *   (developers.openai.com/apps-sdk/build/auth). Per-connector `/connector/oauth/{id}` URIs are not listed.
 */
export const CLIENT_CALLBACKS: readonly string[] = Object.freeze([
  'https://claude.ai/api/mcp/auth_callback',
  'https://claude.com/api/mcp/auth_callback',
  'https://chatgpt.com/connector_platform_oauth_redirect',
]);

const LOOPBACK_PREFIX = /^http:\/\/(127\.0\.0\.1|localhost)(:\d{1,5})?(\/|\?|$)/;

/** Loopback redirect: http, host 127.0.0.1 or localhost written literally, any port, any path. */
function isLoopback(uri: string): boolean {
  if (!LOOPBACK_PREFIX.test(uri) || uri.includes('#')) return false;
  let u: URL;
  try { u = new URL(uri); } catch { return false; }
  return u.protocol === 'http:'
    && (u.hostname === '127.0.0.1' || u.hostname === 'localhost')
    && u.username === '' && u.password === '' && u.hash === '';
}

export function allowedRedirect(uri: string): boolean {
  if (typeof uri !== 'string' || uri.length === 0 || uri.length > 2048) return false;
  return CLIENT_CALLBACKS.includes(uri) || isLoopback(uri);
}
