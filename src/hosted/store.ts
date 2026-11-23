import { ToolError } from '../errors.ts';
import { createHash } from 'node:crypto';
import type { Db, Document } from 'mongodb';
import { ApiError } from '../client.ts';
import { amount } from '../budget.ts';
import type { QuoteStore, Spend } from '../state.ts';

export type CodeKind = 'pending' | 'code';

/** A pending authorize request: no grant exists yet. */
export interface PendingRecord {
  client_id: string;
  challenge: string;
  redirect_uri: string;
  resource?: string;
  expires: Date;
  [extra: string]: unknown;
}

/** An issued authorization code: always bound to a grant. */
export interface CodeRecord extends PendingRecord {
  grant_id: string;
  /** Opaque value sealed by the caller. The store never sees a raw grant secret. */
  sealed_secret: string;
}

type RecordFor<K extends CodeKind> = K extends 'code' ? CodeRecord : PendingRecord;

export type RotateResult = 'ok' | 'reused' | 'unknown';

const DAY = 86400;
/** A client's last_used is rewritten at most this often, so busy clients do not write on every request. */
const CLIENT_TOUCH_MS = 3600_000;
const sha = (s: string): string => createHash('sha256').update(s).digest('hex');

/** Current UTC day as YYYY-MM-DD. */
export function utcDay(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

function strip<K extends CodeKind>(d: Document): RecordFor<K> {
  const { _id, kind: _k, ...rec } = d;
  return rec as unknown as RecordFor<K>;
}

/** MongoDB-backed state shared by every Cloud Run instance of the hosted connector. */
export class HostedStore {
  private readonly busy = new Set<string>();
  constructor(private readonly db: Db) {}

  private col(name: string) { return this.db.collection<Document>(name); }

  /** Operator-only (Task C8). Never call on a request path. */
  async ensureIndexes(): Promise<void> {
    await this.col('mcp_oauth_codes').createIndex({ expires: 1 }, { expireAfterSeconds: 0 });
    await this.col('mcp_oauth_refresh').createIndex({ last_used: 1 }, { expireAfterSeconds: 30 * DAY });
    await this.col('mcp_oauth_refresh').createIndex({ grant_id: 1 });
    await this.col('mcp_spend').createIndex({ created_at: 1 }, { expireAfterSeconds: 7 * DAY });
    await this.col('mcp_quotes').createIndex({ created_at: 1 }, { expireAfterSeconds: 2 * DAY });
    // Registration is open, so unused clients must not pile up forever.
    await this.col('mcp_oauth_clients').createIndex({ last_used: 1 }, { expireAfterSeconds: 90 * DAY });
  }

  // ---- OAuth clients ----
  async getClient(id: string): Promise<any | undefined> {
    const col = this.col('mcp_oauth_clients');
    const d = await col.findOne({ _id: id as any });
    if (!d) return undefined;
    const { _id, last_used, ...info } = d;
    const stale = new Date(Date.now() - CLIENT_TOUCH_MS);
    if (!(last_used instanceof Date) || last_used < stale) {
      // Conditional, so concurrent reads on many instances still write once an hour at most.
      await col.updateOne({ _id: id as any, $or: [{ last_used: { $exists: false } }, { last_used: { $lt: stale } }] },
        { $set: { last_used: new Date() } });
    }
    return info;
  }
  async putClient(info: { client_id: string; [k: string]: unknown }): Promise<void> {
    const { last_used: _ignored, ...rest } = info;
    await this.col('mcp_oauth_clients').replaceOne({ _id: info.client_id as any }, { ...rest, last_used: new Date() }, { upsert: true });
  }

  // ---- Authorization codes and pending authorize requests ----
  async putCode<K extends CodeKind>(code: string, kind: K, rec: RecordFor<K>): Promise<void> {
    await this.col('mcp_oauth_codes').replaceOne({ _id: sha(code) as any }, { ...rec, kind }, { upsert: true });
  }
  /** Atomic find-and-delete. Null if missing, wrong kind or expired. */
  async takeCode<K extends CodeKind>(code: string, kind: K): Promise<RecordFor<K> | null> {
    const d = await this.col('mcp_oauth_codes').findOneAndDelete(
      { _id: sha(code) as any, kind, expires: { $gt: new Date() } });
    return d ? strip<K>(d) : null;
  }
  /** Non-destructive read. Null if missing, wrong kind or expired. */
  async peekCode<K extends CodeKind>(code: string, kind: K): Promise<RecordFor<K> | null> {
    const d = await this.col('mcp_oauth_codes').findOne(
      { _id: sha(code) as any, kind, expires: { $gt: new Date() } });
    return d ? strip<K>(d) : null;
  }

  // ---- Claiming a pending request (single approval per request) ----
  /** Atomically claims a pending request for one approval. 'taken' when another approval holds it. */
  async claimPending(id: string): Promise<'claimed' | 'taken' | 'missing'> {
    const col = this.col('mcp_oauth_codes');
    const live = { _id: sha(id) as any, kind: 'pending', expires: { $gt: new Date() } };
    const won = await col.findOneAndUpdate({ ...live, claimed: { $ne: true } }, { $set: { claimed: true } });
    if (won) return 'claimed';
    return (await col.findOne(live)) ? 'taken' : 'missing';
  }
  /** Atomically deletes a pending request nobody is approving. Null if missing, expired, claimed or done. */
  async takeOpenPending(id: string): Promise<PendingRecord | null> {
    const d = await this.col('mcp_oauth_codes').findOneAndDelete(
      { _id: sha(id) as any, kind: 'pending', expires: { $gt: new Date() }, done: { $ne: true }, claimed: { $ne: true } });
    return d ? strip<'pending'>(d) : null;
  }
  /** Gives the claim back so the person can retry. A request that already issued a code stays done. */
  async releasePending(id: string): Promise<void> {
    await this.col('mcp_oauth_codes').updateOne(
      { _id: sha(id) as any, kind: 'pending', redirect: { $exists: false } },
      { $unset: { claimed: '', done: '' } });
  }
  /** Atomically marks the request used and returns it. Null if missing, expired or already used. */
  async finishPending(id: string): Promise<PendingRecord | null> {
    const d = await this.col('mcp_oauth_codes').findOneAndUpdate(
      { _id: sha(id) as any, kind: 'pending', expires: { $gt: new Date() }, done: { $ne: true } },
      { $set: { done: true, claimed: true } });
    return d ? strip<'pending'>(d) : null;
  }
  /** Stores the (sealed) client redirect so a duplicate submit can follow it. */
  async recordRedirect(id: string, sealed: string): Promise<void> {
    await this.col('mcp_oauth_codes').updateOne({ _id: sha(id) as any, kind: 'pending' }, { $set: { redirect: sealed } });
  }
  async readRedirect(id: string): Promise<string | null> {
    const d = await this.col('mcp_oauth_codes').findOne(
      { _id: sha(id) as any, kind: 'pending', expires: { $gt: new Date() } });
    return d && typeof d.redirect === 'string' ? d.redirect : null;
  }

  // ---- Refresh tokens ----
  async putRefresh(jti: string, grant_id: string, client_id: string): Promise<void> {
    await this.col('mcp_oauth_refresh').insertOne(
      { _id: sha(jti) as any, grant_id, client_id, used: false, last_used: new Date() });
  }
  async rotateRefresh(oldJti: string, newJti: string): Promise<RotateResult> {
    const refresh = this.col('mcp_oauth_refresh');
    const old = await refresh.findOneAndUpdate(
      { _id: sha(oldJti) as any, used: false }, { $set: { used: true, last_used: new Date() } });
    if (!old) return (await refresh.findOne({ _id: sha(oldJti) as any })) ? 'reused' : 'unknown';
    await this.putRefresh(newJti, old.grant_id, old.client_id);
    return 'ok';
  }
  async dropGrant(grant_id: string): Promise<void> {
    await this.col('mcp_oauth_refresh').deleteMany({ grant_id });
  }

  // ---- Per-grant views ----
  quotes(grant_id: string): QuoteStore {
    const col = this.col('mcp_quotes');
    const key = (kind: string, id: string) => `${grant_id}:${kind}:${sha(id)}`;
    const get = async (k: string) => (await col.findOne({ _id: k as any }))?.binding as string | undefined;
    const set = async (k: string, binding: string) => {
      await col.replaceOne({ _id: k as any }, { binding, created_at: new Date() }, { upsert: true });
    };
    return {
      getQuote: id => get(key('q', id)),
      setQuote: (id, b) => set(key('q', id), b),
      getAccepted: id => get(key('a', id)),
      setAccepted: (id, b) => set(key('a', id), b),
    };
  }

  spend(grant_id: string, daily_limit: number, day: string = utcDay()): Spend {
    return new MongoSpend(this.col('mcp_spend'), `${grant_id}:${day}`, amount(daily_limit), this.busy);
  }
}

class MongoSpend implements Spend {
  constructor(
    private readonly col: ReturnType<Db['collection']>,
    private readonly docId: string,
    readonly limit: number,
    private readonly busy: Set<string>,
  ) {}

  private async refuse(k?: string): Promise<never> {
    const d = await this.col.findOne({ _id: this.docId as any });
    const own = k ? ((d?.ops as Record<string, number> | undefined)?.[k] ?? 0) : 0;
    const left = Math.max(0, this.limit - (((d?.total as number | undefined) ?? 0) - own));
    throw new ToolError(`Daily limit reached: ${left} of ${this.limit} Reach Dog tokens left today`);
  }

  /** Returns the prior reservation (undefined if none). Throws when over the limit. */
  private async reserve(k: string, estimate: number): Promise<number | undefined> {
    if (estimate > this.limit) return this.refuse(k);
    const prior = { $ifNull: [`$ops.${k}`, 0] };
    const next = { $max: [prior, estimate] };
    const newTotal = { $add: [{ $subtract: [{ $ifNull: ['$total', 0] }, prior] }, next] };
    await this.ensureDoc();
    // One atomic statement: the $expr filter is the check, the pipeline is the increment.
    const before = await this.col.findOneAndUpdate(
      { _id: this.docId as any, $expr: { $lte: [newTotal, this.limit] } },
      [{ $set: { total: newTotal, [`ops.${k}`]: next } }],
      { returnDocument: 'before' });
    if (!before) return this.refuse(k);
    return (before.ops as Record<string, number> | undefined)?.[k];
  }

  /** $expr filters cannot upsert, so the day document is created first (idempotent). */
  private async ensureDoc(): Promise<void> {
    try {
      await this.col.updateOne({ _id: this.docId as any },
        { $setOnInsert: { total: 0, ops: {}, created_at: new Date() } }, { upsert: true });
    } catch (e: any) {
      if (e?.code !== 11000) throw e; // lost an insert race: the doc exists
    }
  }

  private async release(k: string): Promise<void> {
    await this.col.updateOne({ _id: this.docId as any, [`ops.${k}`]: { $exists: true } },
      [{ $set: { total: { $subtract: ['$total', `$ops.${k}`] } } }, { $unset: `ops.${k}` }]);
  }

  async runPaidPost<T>(id: string, estimate: number, post: () => Promise<T>): Promise<T> {
    const bk = `${this.docId}:${id}`;
    if (this.busy.has(bk)) throw new ToolError('Operation already in progress');
    const k = sha(id).slice(0, 32);
    this.busy.add(bk);
    try {
      const prior = await this.reserve(k, amount(estimate));
      try { return await post(); }
      catch (e) {
        if (prior === undefined && e instanceof ApiError && !e.ambiguous && [400, 401, 402, 403, 422, 429].includes(e.status))
          await this.release(k);
        throw e;
      }
    } finally { this.busy.delete(bk); }
  }

  async settle(id: string, x: unknown): Promise<void> {
    const k = sha(id).slice(0, 32);
    const v = amount(x);
    await this.col.updateOne({ _id: this.docId as any, [`ops.${k}`]: { $exists: true } },
      [{ $set: { total: { $add: [{ $subtract: ['$total', `$ops.${k}`] }, v] }, [`ops.${k}`]: v } }]);
  }

  async refused(id: string): Promise<void> { await this.release(sha(id).slice(0, 32)); }
}
