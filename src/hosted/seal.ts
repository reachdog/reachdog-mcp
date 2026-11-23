import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export type SealKind = 'access' | 'refresh';

export interface SealPayload {
  grant_id: string;
  grant_secret: string;
  client_id: string;
  /** Unix time in milliseconds. */
  exp: number;
  jti: string;
}

const IV_LEN = 12;
const TAG_LEN = 16;
const AAD_PREFIX = 'rdmcp1:';

function checkKey(key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('Invalid seal key');
}

function aad(kind: SealKind): Buffer {
  return Buffer.from(AAD_PREFIX + kind, 'utf8');
}

/** Encrypt a payload into an opaque base64url token: iv || ciphertext || tag. */
export function seal(kind: SealKind, payload: SealPayload, key: Buffer): string {
  checkKey(key);
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad(kind));
  const ct = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, ct, cipher.getAuthTag()]).toString('base64url');
}

function isPayload(v: unknown): v is SealPayload {
  if (typeof v !== 'object' || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.grant_id === 'string' &&
    typeof o.grant_secret === 'string' &&
    typeof o.client_id === 'string' &&
    typeof o.jti === 'string' &&
    typeof o.exp === 'number' &&
    Number.isFinite(o.exp)
  );
}

/** Decrypt a token. Returns null for anything invalid or expired; throws only on a bad key. */
export function open(
  kind: SealKind,
  token: string,
  key: Buffer,
  now: number = Date.now(),
): SealPayload | null {
  checkKey(key);
  try {
    if (typeof token !== 'string' || token.length === 0 || token.length > 4096) return null;
    if (!/^[A-Za-z0-9_-]+$/.test(token)) return null;
    const raw = Buffer.from(token, 'base64url');
    if (raw.length <= IV_LEN + TAG_LEN) return null;
    const iv = raw.subarray(0, IV_LEN);
    const tag = raw.subarray(raw.length - TAG_LEN);
    const ct = raw.subarray(IV_LEN, raw.length - TAG_LEN);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(aad(kind));
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
    const data: unknown = JSON.parse(plain);
    if (!isPayload(data)) return null;
    if (data.exp <= now) return null;
    return {
      grant_id: data.grant_id,
      grant_secret: data.grant_secret,
      client_id: data.client_id,
      exp: data.exp,
      jti: data.jti,
    };
  } catch {
    return null;
  }
}
