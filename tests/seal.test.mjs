import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { seal, open } from '../dist/hosted/seal.js';

const key = randomBytes(32);
const now = 1_700_000_000_000;
const payload = {
  grant_id: 'g_123',
  grant_secret: 'SECRET-VALUE-abcdefghijklmnop',
  client_id: 'client_1',
  exp: now + 3_600_000,
  jti: 'jti_1',
};

test('round trip', () => {
  const t = seal('access', payload, key);
  assert.deepEqual(open('access', t, key, now), payload);
  const r = seal('refresh', payload, key);
  assert.deepEqual(open('refresh', r, key, now), payload);
});

test('kind is bound: access is not refresh and vice versa', () => {
  assert.equal(open('refresh', seal('access', payload, key), key, now), null);
  assert.equal(open('access', seal('refresh', payload, key), key, now), null);
});

test('tampering any byte returns null', () => {
  const t = seal('access', payload, key);
  const buf = Buffer.from(t, 'base64url');
  for (let i = 0; i < buf.length; i++) {
    const c = Buffer.from(buf);
    c[i] ^= 1;
    assert.equal(open('access', c.toString('base64url'), key, now), null, `byte ${i}`);
  }
});

test('expired returns null (exp <= now)', () => {
  const t = seal('access', payload, key);
  assert.equal(open('access', t, key, payload.exp), null);
  assert.equal(open('access', t, key, payload.exp + 1), null);
  assert.notEqual(open('access', t, key, payload.exp - 1), null);
});

test('wrong key returns null', () => {
  assert.equal(open('access', seal('access', payload, key), randomBytes(32), now), null);
});

test('token never contains the secret in clear', () => {
  const t = seal('access', payload, key);
  assert.ok(!t.includes(payload.grant_secret));
  assert.ok(!Buffer.from(t, 'base64url').toString('latin1').includes(payload.grant_secret));
});

test('same payload seals to different tokens', () => {
  assert.notEqual(seal('access', payload, key), seal('access', payload, key));
});

test('malformed input returns null, never throws', () => {
  for (const bad of ['', 'a', '!!!', 'AAAA', 'x'.repeat(10), 'x'.repeat(5000), '%%%%']) {
    assert.equal(open('access', bad, key, now), null);
  }
  assert.equal(open('access', undefined, key, now), null);
  assert.equal(open('access', 42, key, now), null);
});

test('wrong payload shape returns null', () => {
  // seal() with a bad shape must not produce a token open() accepts
  const bad = { ...payload, exp: 'soon' };
  const t = seal('access', bad, key);
  assert.equal(open('access', t, key, now), null);
});

test('bad key length throws Invalid seal key', () => {
  assert.throws(() => seal('access', payload, Buffer.alloc(16)), /Invalid seal key/);
  assert.throws(() => open('access', 'abc', Buffer.alloc(31), now), /Invalid seal key/);
});

test('non-canonical encodings return null', () => {
  const t = seal('access', payload, key);
  assert.notEqual(open('access', t, key, now), null);
  assert.equal(open('access', t + 'A', key, now), null);
  // swap the last char for another that decodes to the same bytes (unused low bits)
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const raw = Buffer.from(t, 'base64url');
  let variants = 0;
  for (const c of alphabet) {
    const v = t.slice(0, -1) + c;
    if (v === t) continue;
    if (Buffer.from(v, 'base64url').equals(raw)) {
      variants++;
      assert.equal(open('access', v, key, now), null);
    }
  }
});

test('truncated tokens return null', () => {
  const raw = Buffer.from(seal('access', payload, key), 'base64url');
  assert.equal(open('access', raw.subarray(0, raw.length - 1).toString('base64url'), key, now), null);
  assert.equal(open('access', raw.subarray(0, raw.length - 16).toString('base64url'), key, now), null);
});
