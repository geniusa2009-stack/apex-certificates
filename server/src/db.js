import pg from 'pg';

export function createPool(url) {
  return new pg.Pool({ connectionString: url, max: 3, statement_timeout: 15000, connectionTimeoutMillis: 10000, idleTimeoutMillis: 30000, keepAlive: true });
}
// Real finding from concurrent-write testing: under SERIALIZABLE
// isolation, Postgres can and does abort one side of two genuinely
// concurrent transactions on the same row with a `serialization_failure`
// (SQLSTATE 40001) -- that's the isolation level working as intended, not
// data corruption, and the standard, safe response is to retry the whole
// transaction from scratch a few times. Before this, that error just
// propagated as an opaque, unhandled 500 to whichever admin lost the
// race, even though nothing was actually wrong. Every other error still
// rolls back and rethrows exactly as before -- only 40001 gets retried.
const SERIALIZATION_FAILURE = '40001';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export async function tx(pool, fn, attempts = 6) {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const c = await pool.connect();
    try {
      await c.query('begin isolation level serializable');
      const r = await fn(c);
      await c.query('commit');
      return r;
    } catch (e) {
      await c.query('rollback').catch(() => {});
      if (e?.code === SERIALIZATION_FAILURE && attempt < attempts) {
        // Small randomized backoff so competing retries don't collide
        // again in lockstep -- standard jitter for a retry-on-conflict loop.
        await sleep(5 + Math.random() * 20 * attempt);
        continue;
      }
      throw e;
    } finally { c.release(); }
  }
}
export class HttpError extends Error {
  constructor(status, message) { super(message); this.statusCode = status; this.expose = true; }
}
