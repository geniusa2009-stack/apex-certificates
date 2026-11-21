// End-to-end: real Postgres, real Ed25519, real HTTP; real Chromium PDF when RUN_PDF=1 (CI sets it).
// Skips (reported as skipped, not passed) when DATABASE_URL is absent.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { PDFDocument } from 'pdf-lib';
import { loadConfig } from '../src/config.js';
import { createPool } from '../src/db.js';
import { loadSigner, registerKey } from '../src/keys.js';
import { buildApp } from '../src/app.js';
import { hashPassword } from '../src/auth.js';
import { renderCertificatePdf, closeRenderer } from '../src/pdf.js';
import { evaluate } from '../../shared/apex-verify.js';

const DB = process.env.DATABASE_URL;
const opts = { skip: !DB && 'DATABASE_URL not set' };
let app, pool, cfg, base;
const pw = 'correct-horse-battery-staple';
const H = { 'content-type': 'application/json', 'x-apex-csrf': '1' };

async function as(email) {
  const r = await fetch(base + '/api/v1/admin/login', { method: 'POST', headers: H, body: JSON.stringify({ email, password: pw }) });
  assert.equal(r.status, 200, 'login ' + email);
  const cookie = r.headers.get('set-cookie').split(';')[0];
  return (method, path, body) => fetch(base + path, { method, headers: { ...H, cookie }, body: body ? JSON.stringify(body) : undefined });
}
const publicVerify = async (id) => {
  const [rec, keys] = await Promise.all([fetch(`${base}/api/v1/certificates/${id}.json`), fetch(`${base}/api/v1/keys.json`)]);
  if (rec.status === 404) return { state: 'NOT_FOUND' };
  return evaluate(id, await rec.json(), await keys.json(), { expectEnv: 'test' });
};

before(async () => {
  if (!DB) return;
  const { privateKey } = generateKeyPairSync('ed25519');
  process.env.APEX_SIGNING_KEY_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' });
  cfg = loadConfig({ ...process.env, APEX_ENV: 'test', APEX_SIGNING_KID: 'test-' + Date.now(), APEX_REQUIRE_TOTP: 'false', PORT: '0' });
  pool = createPool(DB);
  await pool.query(`delete from sessions; delete from users where email like '%@test.apex'`).catch(() => {});
  const signer = await loadSigner(cfg);
  await registerKey(pool, signer, 'test');
  const render = process.env.RUN_PDF === '1' ? (p, h) => renderCertificatePdf(cfg, p, h) : null;
  app = await buildApp({ cfg, pool, signer, logger: false, renderPdf: render || (async (p) => Buffer.from(`%PDF-1.7\n% NON-PRODUCTION TEST STUB for ${p.id}\n%%EOF`)) });
  await app.listen({ port: 0, host: '127.0.0.1' });
  base = `http://127.0.0.1:${app.server.address().port}`;
  cfg.renderOrigin = base;
  const h = await hashPassword(pw);
  for (const [e, n, r] of [['issuer@test.apex', 'Issuer', ['issuer']], ['approver@test.apex', 'Approver', ['approver']], ['both@test.apex', 'Both', ['issuer', 'approver']], ['viewer@test.apex', 'Viewer', []]])
    await pool.query(`insert into users(email, display_name, password_hash, roles) values ($1,$2,$3,$4) on conflict (email) do update set password_hash=$3, roles=$4, failed_logins=0, locked_until=null`, [e, n, h, r]);
});
after(async () => { if (app) await app.close(); await closeRenderer(); if (pool) await pool.end(); });

const draft = { name: 'TEST SAMPLE Volunteer', department: 'Youth Mentorship Initiative', role: 'Lead Program Mentor', period_start: '2026-02', period_end: '2026-10', hours: 186 };

test('full workflow, verification, tamper, revoke, reissue, audit', opts, async () => {
  const issuer = await as('issuer@test.apex'), approver = await as('approver@test.apex'), both = await as('both@test.apex'), viewer = await as('viewer@test.apex');
  assert.equal((await fetch(base + '/api/v1/admin/certificates', { method: 'POST', headers: H, body: '{}' })).status, 401, 'anonymous cannot issue');
  assert.equal((await viewer('POST', '/api/v1/admin/certificates', draft)).status, 403, 'viewer cannot issue');

  const { id } = await (await both('POST', '/api/v1/admin/certificates', draft)).json();
  assert.equal((await both('POST', `/api/v1/admin/certificates/${id}/submit`)).status, 200);
  assert.equal((await both('POST', `/api/v1/admin/certificates/${id}/approve`)).status, 403, 'self-approval blocked');
  assert.equal((await both('POST', `/api/v1/admin/certificates/${id}/sign`)).status, 409, 'cannot sign unapproved');
  assert.equal((await approver('POST', `/api/v1/admin/certificates/${id}/approve`)).status, 200);
  assert.equal((await (await publicVerify(id))).state, 'NOT_FOUND', 'unpublished is not public');
  const signed = await (await issuer('POST', `/api/v1/admin/certificates/${id}/sign`)).json();
  assert.match(signed.pdf_sha256, /^[0-9a-f]{64}$/);
  assert.equal((await issuer('POST', `/api/v1/admin/certificates/${id}/publish`)).status, 200);

  const v = await publicVerify(id);
  assert.equal(v.state, 'VERIFIED');
  const pdf = Buffer.from(await (await fetch(`${base}/api/v1/certificates/${id}.pdf`)).arrayBuffer());
  assert.equal(createHash('sha256').update(pdf).digest('hex'), v.pdf.sha256, 'served PDF = attested hash');
  const edited = Buffer.from(pdf); edited[edited.length - 10] ^= 1;
  assert.notEqual(createHash('sha256').update(edited).digest('hex'), v.pdf.sha256, 'edited PDF hash differs');
  if (process.env.RUN_PDF === '1') {
    const doc = await PDFDocument.load(pdf);
    const { width, height } = doc.getPage(0).getSize();
    assert.equal(doc.getPageCount(), 1); assert.ok(Math.abs(width - 841.89) < 1 && Math.abs(height - 595.28) < 1, 'A4 landscape');
  }

  await assert.rejects(pool.query(`update certificates set hours = 999 where id = $1`, [id]), /immutable/, 'DB refuses edits to signed data');
  await assert.rejects(pool.query(`delete from audit_events`), /append-only/);
  // Simulate an attacker serving altered data: signature must fail.
  const rec = await (await fetch(`${base}/api/v1/certificates/${id}.json`)).json();
  rec.certificate.payload.hours = 999;
  assert.equal((await evaluate(id, rec, await (await fetch(`${base}/api/v1/keys.json`)).json(), { expectEnv: 'test' })).state, 'INVALID_SIGNATURE');

  const { id: nid } = await (await issuer('POST', `/api/v1/admin/certificates/${id}/reissue`, { ...draft, hours: 190 })).json();
  await issuer('POST', `/api/v1/admin/certificates/${nid}/submit`);
  await approver('POST', `/api/v1/admin/certificates/${nid}/approve`);
  await issuer('POST', `/api/v1/admin/certificates/${nid}/sign`);
  await issuer('POST', `/api/v1/admin/certificates/${nid}/publish`);
  const old = await publicVerify(id);
  assert.equal(old.state, 'SUPERSEDED'); assert.equal(old.status.superseded_by, nid);
  assert.equal((await publicVerify(nid)).state, 'VERIFIED');

  assert.equal((await issuer('POST', `/api/v1/admin/certificates/${nid}/revoke`, { reason: 'Test revocation' })).status, 403, 'issuer cannot revoke');
  assert.equal((await approver('POST', `/api/v1/admin/certificates/${nid}/revoke`, { reason: 'Test revocation' })).status, 200);
  assert.equal((await publicVerify(nid)).state, 'REVOKED');

  const chain = await (await approver('GET', '/api/v1/admin/audit/verify')).json();
  assert.equal(chain.ok, true);
  const hist = (await (await approver('GET', `/api/v1/admin/audit?cert=${id}`)).json()).events.map(e => e.action);
  assert.deepEqual(hist, ['draft.create', 'review.submit', 'review.approve', 'certificate.sign', 'certificate.publish', 'certificate.supersede']);
  assert.equal((await publicVerify('APX-2026-VR-ZZZZZ999')).state, 'NOT_FOUND');
});
test('CSRF header required on admin mutations', opts, async () => {
  const r = await fetch(base + '/api/v1/admin/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'issuer@test.apex', password: pw }) });
  assert.equal(r.status, 403);
});
