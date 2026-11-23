// Safe outbound fetch for Client ID Metadata Documents.
// The hostname is resolved once, every address is vetted, and the TLS
// connection is pinned to a vetted address, so DNS rebinding cannot race the
// check. Certificate and SNI validation still use the original hostname.

import { lookup as dnsLookup } from 'node:dns/promises';
import { request } from 'node:https';
import { BlockList, isIP } from 'node:net';

export interface Address { address: string; family: 4 | 6 }
export type Resolver = (host: string) => Promise<Address[]>;
export type DocumentGetter = (url: URL, addr: Address) => Promise<string | null>;

// Separate lists: a v6 list holding ::ffff:0:0/96 would also match every plain IPv4 address.
const blocked4 = new BlockList();
const blocked6 = new BlockList();
for (const [net, bits] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
] as const) blocked4.addSubnet(net, bits, 'ipv4');
for (const [net, bits] of [
  ['::', 128], ['::1', 128], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['100::', 64], ['2001:db8::', 32],
  ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
] as const) blocked6.addSubnet(net, bits, 'ipv6');

/** True only for a globally routable unicast address. IPv4-mapped and NAT64 forms count as blocked. */
export function isPublicAddress(address: string): boolean {
  const v = isIP(address);
  if (v === 0) return false;
  try { return v === 4 ? !blocked4.check(address, 'ipv4') : !blocked6.check(address, 'ipv6'); } catch { return false; }
}

/** Lowercase, without brackets or trailing dots. */
export function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
}

/** Hostnames a metadata document may never live on: IP literals and internal names. */
export function publicHostName(host: string): boolean {
  const h = normalizeHost(host);
  if (!h || isIP(h) !== 0) return false;
  if (!h.includes('.') || h === 'localhost') return false;
  return !['.localhost', '.internal', '.local', '.home.arpa', '.arpa'].some(s => h.endsWith(s));
}

export const systemResolver: Resolver = async host => {
  const rows = await dnsLookup(host, { all: true, verbatim: true });
  return rows.map(r => ({ address: r.address, family: r.family === 6 ? 6 : 4 }));
};

/** Resolves and vets a hostname. Returns the address to pin, or null if any result is not public. */
export async function vetHost(host: string, resolve: Resolver): Promise<Address | null> {
  if (!publicHostName(host)) return null;
  let rows: Address[];
  try { rows = await resolve(normalizeHost(host)); } catch { return null; }
  if (!Array.isArray(rows) || rows.length === 0) return null;
  if (!rows.every(r => r && typeof r.address === 'string' && isPublicAddress(r.address))) return null;
  const a = rows[0];
  return { address: a.address, family: isIP(a.address) === 6 ? 6 : 4 };
}

export interface PinnedGetOptions { timeoutMs: number; maxBytes: number; ca?: string | Buffer }

/** HTTPS GET pinned to `addr`. 200 only, no redirects, body capped. Null on any failure. */
export function pinnedGet(url: URL, addr: Address, opts: PinnedGetOptions): Promise<string | null> {
  return new Promise(resolve => {
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const host = normalizeHost(url.hostname);
    const finish = (v: string | null) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(v);
    };
    const req = request({
      protocol: 'https:', hostname: host, servername: host, port: url.port ? Number(url.port) : 443,
      path: url.pathname + url.search, method: 'GET', agent: false, ca: opts.ca,
      headers: { Accept: 'application/json', Host: url.port ? `${host}:${url.port}` : host },
      lookup: ((_h: string, o: { all?: boolean } | undefined, cb: (...a: unknown[]) => void) => {
        if (o?.all) cb(null, [{ address: addr.address, family: addr.family }]);
        else cb(null, addr.address, addr.family);
      }) as any,
    }, res => {
      const declared = Number(res.headers['content-length']);
      if (res.statusCode !== 200 || (Number.isFinite(declared) && declared > opts.maxBytes)) {
        req.destroy();
        return finish(null);
      }
      const chunks: Buffer[] = [];
      let total = 0;
      res.on('data', (c: Buffer) => {
        total += c.length;
        if (total > opts.maxBytes) { req.destroy(); finish(null); } else chunks.push(c);
      });
      res.on('end', () => finish(Buffer.concat(chunks).toString('utf8')));
      res.on('error', () => finish(null));
    });
    timer = setTimeout(() => { req.destroy(); finish(null); }, opts.timeoutMs);
    req.on('error', () => finish(null));
    req.end();
  });
}
