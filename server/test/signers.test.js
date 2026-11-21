import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSigners } from '../src/signers.js';

// Fake pool: enough `query`/`connect` surface for createSigners + the
// shared `tx()` helper (begin/commit/rollback), no real Postgres. Keeps
// this test real-logic (role check, validation, what gets written) and
// dependency-free, matching this codebase's own existing test style
// (rules.test.js does the same for assertAllowed with plain objects).
function fakePool(seedRow) {
  const state = { row: seedRow, audits: [] };
  const client = {
    async query(sql, params) {
      if (sql.startsWith('select name, title from cert_signers')) return { rows: state.row ? [state.row] : [] };
      if (sql.startsWith('insert into cert_signers')) { state.row = { name: params[1], title: params[2] }; return {}; }
      if (sql.includes('audit_events') && sql.startsWith('select hash')) return { rows: [] };
      if (sql.startsWith('insert into audit_events')) { state.audits.push({ action: params[2], details: params[4] }); return {}; }
      if (sql.startsWith('lock table')) return {};
      if (sql === 'begin isolation level serializable' || sql === 'commit' || sql === 'rollback') return {};
      throw new Error('unexpected query: ' + sql);
    },
    release() {}
  };
  return {
    state,
    async connect() { return client; },
    async query(sql) {
      if (sql.startsWith('select slot, name, title')) return { rows: state.row ? [{ slot: 'signer1', ...state.row }] : [] };
      throw new Error('unexpected pool.query: ' + sql);
    }
  };
}

const cfg = { signers: ['G. Ahmed I. Ragab|Founder', 'Asmaa Hassan|Volunteer Program Coordinator'] };
const admin = { id: 'u-admin', roles: ['admin'] };
const issuer = { id: 'u-issuer', roles: ['issuer'] };

test('get() falls back to config defaults when table is empty', async () => {
  const pool = fakePool(null);
  const svc = createSigners({ pool, cfg });
  const s = await svc.get();
  assert.equal(s.signer1.name, 'G. Ahmed I. Ragab');
  assert.equal(s.signer2.title, 'Volunteer Program Coordinator');
});

test('update() rejects a non-admin with 403', async () => {
  const pool = fakePool(null);
  const svc = createSigners({ pool, cfg });
  await assert.rejects(() => svc.update(issuer, 'signer1', { name: 'X Y', title: 'Lead' }), (e) => e.statusCode === 403);
});

test('update() rejects an unknown slot with 404', async () => {
  const pool = fakePool(null);
  const svc = createSigners({ pool, cfg });
  await assert.rejects(() => svc.update(admin, 'signer3', { name: 'X Y', title: 'Lead' }), (e) => e.statusCode === 404);
});

test('update() rejects an empty/invalid name or title with 400', async () => {
  const pool = fakePool(null);
  const svc = createSigners({ pool, cfg });
  await assert.rejects(() => svc.update(admin, 'signer1', { name: '', title: 'Lead' }), (e) => e.statusCode === 400);
  await assert.rejects(() => svc.update(admin, 'signer1', { name: 'A B', title: '' }), (e) => e.statusCode === 400);
});

test('update() by an admin writes the new row and a real audit event', async () => {
  const pool = fakePool({ name: 'Old Name', title: 'Old Title' });
  const svc = createSigners({ pool, cfg });
  const out = await svc.update(admin, 'signer2', { name: 'New Person', title: 'New Title' });
  assert.deepEqual(out, { slot: 'signer2', name: 'New Person', title: 'New Title' });
  assert.equal(pool.state.row.name, 'New Person');
  assert.equal(pool.state.audits.length, 1);
  assert.equal(pool.state.audits[0].action, 'signer.update');
  assert.equal(pool.state.audits[0].details.after.name, 'New Person');
  assert.equal(pool.state.audits[0].details.before.name, 'Old Name');
});
