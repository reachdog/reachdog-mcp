import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReachDogClient, ApiError } from '../src/client.ts';

function setup(...steps) {
  const calls = [], delays = [];
  const client = new ReachDogClient('https://mock.invalid', 'test', async (url, options) => {
    calls.push({ url, options });
    const step = steps.shift();
    if (step instanceof Error) throw step;
    assert.ok(step, 'unexpected extra request');
    return step;
  }, async ms => { delays.push(ms); });
  return { client, calls, delays };
}

test('503 and a dropped response reuse the same creation key and body', async () => {
  const { client, calls, delays } = setup(new TypeError('lost response'),
    new Response(null, { status: 503, headers: { 'Retry-After': '3' } }),
    Response.json({}, { headers: { 'X-Charge-State': 'settled', 'X-Charged-Tokens': '2' } }));
  const reply = await client.title({ title: 'test', parameters: ['product_type'] }, 'same-key');
  assert.equal(reply.headers.get('x-charged-tokens'), '2');
  assert.deepEqual(delays, [2000, 3000]);
  assert.equal(calls.length, 3);
  for (const { options } of calls) {
    assert.equal(options.headers.get('Idempotency-Key'), 'same-key');
    assert.equal(options.body, calls[0].options.body);
  }
});

test('reports quota error without retrying', async () => {
  const { client, calls } = setup(Response.json({ code: 'quota_exceeded' }, { status: 429 }));
  await assert.rejects(client.usage(), e => e instanceof ApiError && e.status === 429 && e.body.code === 'quota_exceeded');
  assert.equal(calls.length, 1);
});

test('acceptance and payment retry use the original binding without a creation key', async () => {
  const { client, calls } = setup(Response.json({}), Response.json({}));
  await client.accept('id', 'binding');
  await client.retryPayment('id', 'binding');
  assert.deepEqual(calls.map(c => c.url.pathname), ['/v1/batches/id/accept', '/v1/batches/id/retry-payment']);
  for (const { options } of calls) {
    assert.equal(options.headers.has('Idempotency-Key'), false);
    assert.deepEqual(JSON.parse(options.body), { acceptance: 'binding' });
  }
});

test('merge result lists, preserve first scalar and follow opaque cursors', async () => {
  const page = { workflow: 'catalog_local_v1', processing: {}, expires_at: 'expiry' };
  const { client, calls } = setup(
    Response.json({ ...page, outputs: { items: [1], count: 3 }, has_more: true, next_cursor: 'a+b' }),
    Response.json({ ...page, outputs: { items: [2, 3], count: 3 }, has_more: false }));
  const reply = await client.results('id');
  assert.equal(calls[1].url.searchParams.get('cursor'), 'a+b');
  assert.deepEqual(reply.outputs.items, [1, 2, 3]);
  assert.equal(reply.outputs.count, 3);
  assert.equal(reply.page_count, 2);
});

test('reject missing key before issuing a creation request', () => {
  const { client, calls } = setup();
  assert.throws(() => client.submit({}, undefined), /Idempotency-Key/);
  assert.equal(calls.length, 0);
});
