import { createHash } from 'node:crypto';
import { canonicalize } from '../../shared/apex-verify.js';

export const GENESIS = 'GENESIS';
export const eventHash = (prev, ev) =>
  createHash('sha256').update(prev + '\n' + canonicalize({ at: ev.at, actor: ev.actor ?? null, action: ev.action, cert_id: ev.cert_id ?? null, details: ev.details ?? {} })).digest('hex');

// Must run inside a transaction. The table lock serialises appends so the chain has no forks.
export async function appendAudit(client, { actor = null, action, certId = null, details = {} }) {
  await client.query('lock table audit_events in share row exclusive mode');
  const { rows } = await client.query('select hash from audit_events order by seq desc limit 1');
  const prev = rows[0]?.hash || GENESIS;
  const ev = { at: new Date().toISOString(), actor, action, cert_id: certId, details };
  const hash = eventHash(prev, ev);
  await client.query('insert into audit_events(at, actor, action, cert_id, details, prev_hash, hash) values ($1,$2,$3,$4,$5,$6,$7)',
    [ev.at, actor, action, certId, details, prev, hash]);
  return hash;
}

export function verifyChain(rows) {
  let prev = GENESIS;
  for (const r of rows) {
    const at = r.at instanceof Date ? r.at.toISOString() : r.at;
    if (r.prev_hash !== prev) return { ok: false, brokenAt: Number(r.seq), why: 'prev_hash mismatch' };
    if (eventHash(prev, { ...r, at }) !== r.hash) return { ok: false, brokenAt: Number(r.seq), why: 'hash mismatch' };
    prev = r.hash;
  }
  return { ok: true, head: prev, count: rows.length };
}
