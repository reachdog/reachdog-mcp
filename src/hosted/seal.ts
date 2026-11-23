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

function aad(label: string): Buffer {
  return Buffer.from(AAD_PREFIX + label, 'utf8');
}

/** Encrypt a string into an opaque base64url token: iv || ciphertext || tag. AAD binds the label. */
export function sealValue(label: string, value: string, key: Buffer): string {
  checkKey(key);
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad(label));
  const ct = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, ct, cipher.getAuthTag()]).toString('base64url');
}

/** Decrypt a sealValue token. Null for anything invalid; throws only on a bad key. */
export function openValue(label: string, token: string, key: Buffer): string | null {
  checkKey(key);
  try {
    if (typeof token !== 'string' || token.length === 0 || token.length > 4096) return null;
    if (!/^[A-Za-z0-9_-]+$/.test(token)) return null;
    const raw = Buffer.from(token, 'base64url');
    if (raw.toString('base64url') !== token) return null; // canonical encoding only
    if (raw.length < IV_LEN + TAG_LEN) return null;
    const iv = raw.subarray(0, IV_LEN);
    const tag = raw.subarray(raw.length - TAG_LEN);
    const ct = raw.subarray(IV_LEN, raw.length - TAG_LEN);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(aad(label));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}

/** Encrypt a payload into an opaque base64url token. */
export function seal(kind: SealKind, payload: SealPayload, key: Buffer): string {
  return sealValue(kind, JSON.stringify(payload), key);
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
    const plain = openValue(kind, token, key);
    if (plain === null) return null;
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
