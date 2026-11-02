import type {
  CatalogRequest, CatalogPage, CatalogStatus, TitleRequest, ContentRequest, ResearchRequest,
} from './api-types.ts';

export interface UsageResponse {
  day_utc: string;
  admitted_titles: number;
  daily_title_limit: number;
  active_job_limit: number;
  billing: string;
  billing_mode?: string;
  wallet_balance?: number;
  parameter_price?: number;
  api_limit_resets_at?: string;
  wallet_refill_eligible_at?: string | null;
  wallet_refill_evaluated_on_use?: boolean;
}

type Reply<T> = { body: T; headers: Headers };
const transient = new Set([500, 502, 503, 504]);
const wait = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));

export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  readonly ambiguous: boolean;
  constructor(status: number, body: unknown, ambiguous=false) {
    super(`Reach Dog returned HTTP ${status}`);
    this.ambiguous = ambiguous;
    this.status = status;
    this.body = body;
  }
}

function retryDelay(header: string | null, attempt: number) {
  if (header !== null && header.trim()) {
    if (/^\d+(\.\d+)?$/.test(header)) return Number(header) * 1000;
    const date = Date.parse(header);
    if (Number.isFinite(date)) return Math.max(0, date - Date.now());
  }
  return Math.min(10000, 2000 * 2 ** attempt);
}

function batchPath(id: string) {
  if (!id || id === '.' || id === '..') throw new Error('Invalid batch ID');
  return '/v1/batches/' + encodeURIComponent(id);
}

export class ReachDogClient {
  readonly #base: URL;
  readonly #headers: Headers;
  readonly #fetch: typeof fetch;
  readonly #sleep: typeof wait;

  constructor(base: string, key: string, transport = fetch, sleep = wait) {
    this.#base = new URL(base);
    if (!key || /[^\x21-\x7e]/.test(key)) throw new Error('Invalid Reach Dog API key');
    if (this.#base.username || this.#base.password) throw new Error('Invalid API configuration');
    if (this.#base.protocol !== 'https:' && !(this.#base.protocol === 'http:' &&
      ['127.0.0.1', 'localhost', '[::1]'].includes(this.#base.hostname))) {
      throw new Error('Use HTTPS or a loopback test server');
    }
    this.#headers = new Headers({ Authorization: 'Bearer ' + key, Accept: 'application/json' });
    this.#fetch = transport;
    this.#sleep = sleep;
  }

  async #request<T>(path: string, body?: object, key?: string, stopAt=Infinity): Promise<Reply<T>> {
    const headers = new Headers(this.#headers);
    if (body !== undefined) headers.set('Content-Type', 'application/json');
    if (key !== undefined) {
      if (!key.trim() || key.length > 200 || /[^\x20-\x7e]/.test(key)) throw new Error('Invalid Idempotency-Key');
      headers.set('Idempotency-Key', key);
    }
    const json = JSON.stringify(body);
    const deadline = Math.min(stopAt, Date.now() + 90000);
    for (let attempt = 0; ; attempt++) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error('API request retry deadline exceeded');
      let response: Response;
      let raw: string;
      try {
        response = await this.#fetch(new URL(path, this.#base), {
          headers, method: body === undefined ? 'GET' : 'POST', body: json,
          redirect: 'error', signal: AbortSignal.timeout(Math.min(60000, remaining)),
        });
        raw = await response.text();
      } catch (cause) {
        const delay = retryDelay(null, attempt);
        if (attempt >= 3 || Date.now() + delay >= deadline) throw new Error('API transport failed', { cause });
        await this.#sleep(delay);
        continue;
      }
      if (transient.has(response.status) && attempt < 3) {
        const delay = retryDelay(response.headers.get('Retry-After'), attempt);
        if (Date.now() + delay < deadline) {
          await this.#sleep(delay);
          continue;
        }
      }
      if (!response.ok) {
        let detail: unknown = raw;
        try { detail = JSON.parse(raw); } catch { /* Preserve a non-JSON error body. */ }
        throw new ApiError(response.status, detail, attempt > 0);
      }
      return { body: JSON.parse(raw) as T, headers: response.headers };
    }
  }

  usage() { return this.#request<UsageResponse>('/v1/usage'); }
  title(body: TitleRequest, key: string) { return this.#create('/v1/title-matches', body, key); }
  research(body: ResearchRequest, key: string) { return this.#create('/v1/market-research', body, key); }
  content(body: ContentRequest, key: string) { return this.#create('/v1/content-generations', body, key); }
  submit(body: CatalogRequest, key: string) { return this.#create<CatalogStatus>('/v1/batches', body, key); }

  #create<T = unknown>(path: string, body: object, key: string) {
    if (typeof key !== 'string' || !key.trim()) throw new Error('Creation requires an Idempotency-Key');
    return this.#request<T>(path, body, key);
  }

  status(id: string, stopAt=Infinity) { return this.#request<CatalogStatus>(batchPath(id), undefined, undefined, stopAt); }
  accept(id: string, acceptance: string) {
    return this.#request<CatalogStatus>(batchPath(id) + '/accept', { acceptance });
  }
  retryPayment(id: string, acceptance: string) {
    return this.#request<CatalogStatus>(batchPath(id) + '/retry-payment', { acceptance });
  }

  async results(id: string) {
    const outputs: Record<string, unknown> = Object.create(null);
    const seen = new Set<string>();
    let cursor: string | null = null;
    let first: CatalogPage | undefined;
    let pageCount = 0;
    do {
      const query = new URLSearchParams({ page_size: '100' });
      if (cursor !== null) query.set('cursor', cursor);
      const { body: page }: Reply<CatalogPage> = await this.#request(batchPath(id) + '/results?' + query);
      first ??= page;
      pageCount++;
      for (const [name, value] of Object.entries(page.outputs)) {
        if (!(name in outputs)) outputs[name] = value;
        else if (Array.isArray(value)) {
          const existing = outputs[name];
          if (!Array.isArray(existing)) throw new Error('Catalog output changed type');
          outputs[name] = existing.concat(value);
        }
      }
      if (typeof page.has_more !== 'boolean') throw new Error('Missing catalog pagination flag');
      if (!page.has_more) break;
      cursor = page.next_cursor;
      if (!cursor || seen.has(cursor)) throw new Error('Invalid catalog pagination cursor');
      seen.add(cursor);
    } while (true);
    return { workflow: first.workflow, processing: first.processing, expires_at: first.expires_at,
      outputs, page_count: pageCount };
  }
}
