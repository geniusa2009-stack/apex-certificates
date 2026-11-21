// Admin-configurable certificate signers (cert_signers table, migration
// 003). Two fixed slots -- this does NOT introduce a template system,
// it only moves the two printed signature name/title pairs out of
// static config/markup into the database so an authorized admin can
// change them without a deploy. Every change is audited through the
// same real, hash-chained `audit_events` table every other certificate
// action already goes through (see audit.js) -- no second, parallel
// history mechanism.
import { HttpError, tx } from './db.js';
import { appendAudit } from './audit.js';

const SLOTS = ['signer1', 'signer2'];
const TEXT = /^[\p{L}\p{M}\p{N} .,'’&()\/-]{2,120}$/u;

// Only an 'admin' role may change who is printed on an official,
// cryptographically signed document -- deliberately distinct from
// 'issuer' (drafts/submits a specific volunteer's certificate) and
// 'approver' (independently approves/revokes one), since editing the
// signers affects EVERY future certificate, not one record. The
// `roles` column's check constraint already allows 'admin' (see
// 001_init.sql) -- it was reserved but never wired to anything until
// now.
const need = (cond, status, msg) => { if (!cond) throw new HttpError(status, msg); };
const isAdmin = (user) => !!user && Array.isArray(user.roles) && user.roles.includes('admin');

export function createSigners({ pool, cfg }) {
  // Config's own existing fallback strings (config.js's `signers`
  // default), used only if the table is ever empty (e.g. a DB that
  // hasn't run migration 003 yet) -- so a missing row never breaks
  // certificate rendering, it just means nothing has been
  // customized yet.
  const fallback = () => {
    const [s1, s2] = cfg.signers.map(s => { const [name, title] = s.split('|'); return { name, title }; });
    return { signer1: s1, signer2: s2 };
  };

  return {
    async get() {
      const { rows } = await pool.query('select slot, name, title, updated_at from cert_signers order by slot');
      if (rows.length === 0) return fallback();
      const out = fallback();
      for (const r of rows) out[r.slot] = { name: r.name, title: r.title, updated_at: r.updated_at };
      return out;
    },
    async update(user, slot, input) {
      need(isAdmin(user), 403, 'Admin role required');
      need(SLOTS.includes(slot), 404, 'Unknown signer slot');
      const name = typeof input?.name === 'string' ? input.name.normalize('NFC').trim().replace(/\s+/g, ' ') : '';
      const title = typeof input?.title === 'string' ? input.title.normalize('NFC').trim().replace(/\s+/g, ' ') : '';
      need(TEXT.test(name), 400, 'Invalid name');
      need(TEXT.test(title), 400, 'Invalid title');

      await tx(pool, async (c) => {
        const before = (await c.query('select name, title from cert_signers where slot=$1 for update', [slot])).rows[0] || null;
        await c.query(
          `insert into cert_signers(slot, name, title, updated_by, updated_at) values ($1,$2,$3,$4, now())
           on conflict (slot) do update set name=$2, title=$3, updated_by=$4, updated_at=now()`,
          [slot, name, title, user.id]
        );
        await appendAudit(c, {
          actor: user.id, action: 'signer.update', certId: null,
          details: { slot, before, after: { name, title } }
        });
      });
      return { slot, name, title };
    }
  };
}
