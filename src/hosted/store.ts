import { createHash } from 'node:crypto';
import type { Db, Document } from 'mongodb';
import { ApiError } from '../client.ts';
import { amount } from '../budget.ts';
import type { QuoteStore, Spend } from '../state.ts';

export type CodeKind = 'pending' | 'code';

export interface CodeRecord {
  client_id: string;
  grant_id: string;
  grant_secret: string;
  challenge: string;
  redirect_uri: string;
  resource?: string;
  expires: Date;
  [extra: string]: unknown;
}

export type RotateResult = 'ok' | 'reused' | 'unknown';

const DAY = 86400;
const sha = (s: string): string => createHash('sha256').update(s).digest('hex');

/** Current UTC day as YYYY-MM-DD. */
export function utcDay(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

/** MongoDB-backed state shared by every Cloud Run instance of the hosted connector. */
export class HostedStore {
  constructor(private readonly db: Db) {}

  private col(name: string) { return this.db.collection<Document>(name); }

  /** Operator-only (Task C8). Never call on a request path. */
  async ensureIndexes(): Promise<void> {
    await this.col('mcp_oauth_codes').createIndex({ expires: 1 }, { expireAfterSeconds: 0 });
    await this.col('mcp_oauth_refresh').createIndex({ last_used: 1 }, { expireAfterSeconds: 30 * DAY });
    await this.col('mcp_oauth_refresh').createIndex({ grant_id: 1 });
    await this.col('mcp_spend').createIndex({ created_at: 1 }, { expireAfterSeconds: 7 * DAY });
    await this.col('mcp_quotes').createIndex({ created_at: 1 }, { expireAfterSeconds: 2 * DAY });
  }

  // ---- OAuth clients ----
  async getClient(id: string): Promise<any | undefined> {
    const d = await this.col('mcp_oauth_clients').findOne({ _id: id as any });
    if (!d) return undefined;
    const { _id, ...info } = d;
    return info;
  }
  async putClient(info: { client_id: string; [k: string]: unknown }): Promise<void> {
    await this.col('mcp_oauth_clients').replaceOne({ _id: info.client_id as any }, { ...info }, { upsert: true });
  }

  // ---- Authorization codes and pending authorize requests ----
  async putCode(code: string, kind: CodeKind, rec: CodeRecord): Promise<void> {
    await this.col('mcp_oauth_codes').replaceOne({ _id: sha(code) as any }, { ...rec, kind }, { upsert: true });
  }
  /** Atomic find-and-delete. Null if missing, wrong kind or expired. */
  async takeCode(code: string, kind: CodeKind): Promise<CodeRecord | null> {
    const d = await this.col('mcp_oauth_codes').findOneAndDelete(
      { _id: sha(code) as any, kind, expires: { $gt: new Date() } });
    if (!d) return null;
    const { _id, kind: _k, ...rec } = d;
    return rec as unknown as CodeRecord;
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
    return new MongoSpend(this.col('mcp_spend'), `${grant_id}:${day}`, amount(daily_limit));
  }
}

class MongoSpend implements Spend {
  private busy = new Set<string>();
  constructor(
    private readonly col: ReturnType<Db['collection']>,
    private readonly docId: string,
    readonly limit: number,
  ) {}

  private async refuse(): Promise<never> {
    const d = await this.col.findOne({ _id: this.docId as any });
    const left = Math.max(0, this.limit - ((d?.total as number | undefined) ?? 0));
    throw new Error(`Daily limit reached: ${left} of ${this.limit} Reach Dog tokens left today`);
  }

  /** Returns the prior reservation (undefined if none). Throws when over the limit. */
  private async reserve(k: string, estimate: number): Promise<number | undefined> {
    if (estimate > this.limit) return this.refuse();
    const prior = { $ifNull: [`$ops.${k}`, 0] };
    const next = { $max: [prior, estimate] };
    const newTotal = { $add: [{ $subtract: [{ $ifNull: ['$total', 0] }, prior] }, next] };
    await this.ensureDoc();
    // One atomic statement: the $expr filter is the check, the pipeline is the increment.
    const before = await this.col.findOneAndUpdate(
      { _id: this.docId as any, $expr: { $lte: [newTotal, this.limit] } },
      [{ $set: { total: newTotal, [`ops.${k}`]: next } }],
      { returnDocument: 'before' });
    if (!before) return this.refuse();
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
    if (this.busy.has(id)) throw new Error('Operation already in progress');
    const k = sha(id).slice(0, 32);
    this.busy.add(id);
    try {
      const prior = await this.reserve(k, amount(estimate));
      try { return await post(); }
      catch (e) {
        if (prior === undefined && e instanceof ApiError && !e.ambiguous && [400, 401, 402, 403, 422, 429].includes(e.status))
          await this.release(k);
        throw e;
      }
    } finally { this.busy.delete(id); }
  }

  async settle(id: string, x: unknown): Promise<void> {
    const k = sha(id).slice(0, 32);
    const v = amount(x);
    await this.col.updateOne({ _id: this.docId as any, [`ops.${k}`]: { $exists: true } },
      [{ $set: { total: { $add: [{ $subtract: ['$total', `$ops.${k}`] }, v] }, [`ops.${k}`]: v } }]);
  }

  async refused(id: string): Promise<void> { await this.release(sha(id).slice(0, 32)); }
}
