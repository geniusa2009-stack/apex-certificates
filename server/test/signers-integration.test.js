// Real-Postgres, real-HTTP verification of signer management: the unit
// tests in signers.test.js use a hand-rolled fake pool and never exercise
// a real transaction, real locking, or the actual admin HTTP routes.
// Skips (reported as skipped, not passed) when DATABASE_URL is absent,
// matching integration.test.js / passport.test.js.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { loadConfig } from '../src/config.js';
import { createPool } from '../src/db.js';
import { loadSigner, registerKey } from '../src/keys.js';
import { createSigners } from '../src/signers.js';
import { buildApp } from '../src/app.js';
import { hashPassword } from '../src/auth.js';
import { verifyChain } from '../src/audit.js';

const DB = process.env.DATABASE_URL;
const opts = { skip: !DB && 'DATABASE_URL not set' };
const pw = 'correct-horse-battery-staple';
const H = { 'content-type': 'application/json', 'x-apex-csrf': '1' };
let app, pool, base, signersSvc;

async function as(email) {
  const r = await fetch(base + '/api/v1/admin/login', { method: 'POST', headers: H, body: JSON.stringify({ email, password: pw }) });
  assert.equal(r.status, 200, 'login ' + email);
  const cookie = r.headers.get('set-cookie').split(';')[0];
  return (method, path, body) => fetch(base + path, { method, headers: { ...H, cookie }, body: body ? JSON.stringify(body) : undefined });
}

before(async () => {
  if (!DB) return;
  const { privateKey } = generateKeyPairSync('ed25519');
  process.env.APEX_SIGNING_KEY_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const cfg = loadConfig({ ...process.env, APEX_ENV: 'test', APEX_SIGNING_KID: 'sgtest-' + Date.now(), APEX_REQUIRE_TOTP: 'false', PORT: '0' });
  pool = createPool(DB);
  const signer = await loadSigner(cfg);
  await registerKey(pool, signer, 'test');
  signersSvc = createSigners({ pool, cfg });
  app = await buildApp({ cfg, pool, signer, signers: signersSvc, logger: false, renderPdf: async (p) => Buffer.from(`%PDF-1.7\n% TEST STUB ${p.id}\n%%EOF`) });
  await app.listen({ port: 0, host: '127.0.0.1' });
  base = `http://127.0.0.1:${app.server.address().port}`;
  const h = await hashPassword(pw);
  for (const [e, r] of [['sg-admin@test.apex', ['admin']], ['sg-issuer@test.apex', ['issuer']]])
    await pool.query(`insert into users(email, display_name, password_hash, roles) values ($1,$1,$2,$3) on conflict (email) do update set password_hash=$2, roles=$3, failed_logins=0, locked_until=null`, [e, h, r]);
});
after(async () => { if (app) await app.close(); if (pool) await pool.end(); });

test('non-admin cannot edit signers over the real HTTP route', opts, async () => {
  const issuer = await as('sg-issuer@test.apex');
  const r = await issuer('PUT', '/api/v1/admin/signers/signer1', { name: 'Someone Else', title: 'Nobody' });
  assert.equal(r.status, 403);
});

test('admin update is a real transaction: visible via GET, FK-stamped, hash-chained', opts, async () => {
  const admin = await as('sg-admin@test.apex');
  const newName = 'Real DB Test Signer ' + randomUUID().slice(0, 8);
  const putR = await admin('PUT', '/api/v1/admin/signers/signer2', { name: newName, title: 'Real Transaction Title' });
  assert.equal(putR.status, 200);

  const row = (await pool.query('select name, title, updated_by from cert_signers where slot=$1', ['signer2'])).rows[0];
  assert.equal(row.name, newName);
  assert.equal(row.title, 'Real Transaction Title');
  assert.ok(row.updated_by, 'updated_by FK should be stamped with the acting admin');

  const getR = await admin('GET', '/api/v1/admin/signers');
  const { signers } = await getR.json();
  assert.equal(signers.signer2.name, newName);

  const chain = await pool.query('select * from audit_events order by seq');
  assert.ok(verifyChain(chain.rows).ok, 'audit hash chain must still verify after a real signer update');
  const last = chain.rows[chain.rows.length - 1];
  assert.equal(last.action, 'signer.update');
  assert.equal(last.details.after.name, newName);
});

test('concurrent signer updates serialize correctly: last writer wins, no lost audit events, chain intact', opts, async () => {
  const admin = await as('sg-admin@test.apex');
  const before = (await pool.query('select seq from audit_events order by seq desc limit 1')).rows[0].seq;

  const names = Array.from({ length: 6 }, (_, i) => 'Concurrent Signer ' + i);
  const results = await Promise.all(
    names.map((name) => admin('PUT', '/api/v1/admin/signers/signer1', { name, title: 'Concurrent Title' }))
  );
  for (const r of results) assert.equal(r.status, 200, 'every concurrent request should succeed, none should be dropped or corrupted');

  const after = (await pool.query('select seq from audit_events order by seq desc limit 1')).rows[0].seq;
  assert.equal(after - before, names.length, 'every concurrent update must produce exactly one audit event -- none lost, none duplicated');

  const finalRow = (await pool.query('select name from cert_signers where slot=$1', ['signer1'])).rows[0];
  assert.ok(names.includes(finalRow.name), 'final stored value must be one of the actually-submitted names, not a torn/mixed write');

  const chain = await pool.query('select * from audit_events order by seq');
  assert.ok(verifyChain(chain.rows).ok, 'audit hash chain must verify even after concurrent writers');
});

test('a rejected update (invalid name) never touches the row or appends an audit event', opts, async () => {
  const admin = await as('sg-admin@test.apex');
  const beforeRow = (await pool.query('select name, title, updated_at from cert_signers where slot=$1', ['signer2'])).rows[0];
  const beforeCount = (await pool.query('select count(*) from audit_events')).rows[0].count;

  const r = await admin('PUT', '/api/v1/admin/signers/signer2', { name: 'x', title: 'also too short? no, this title is fine actually long enough' });
  assert.equal(r.status, 400, 'a one-character name must be rejected by the same TEXT length rule the DB enforces');

  const afterRow = (await pool.query('select name, title, updated_at from cert_signers where slot=$1', ['signer2'])).rows[0];
  const afterCount = (await pool.query('select count(*) from audit_events')).rows[0].count;
  assert.deepEqual(afterRow, beforeRow, 'a rejected update must leave the row completely untouched');
  assert.equal(afterCount, beforeCount, 'a rejected update must never append an audit event');
});
