// Passport, contributions, badges, bulk issuance — real Postgres over HTTP. Skips (not passes) without DATABASE_URL.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { loadConfig } from '../src/config.js';
import { createPool } from '../src/db.js';
import { loadSigner, registerKey } from '../src/keys.js';
import { buildApp } from '../src/app.js';
import { hashPassword } from '../src/auth.js';
import { validateContribution } from '../src/passport.js';
import { verifyChain } from '../src/audit.js';

const DB = process.env.DATABASE_URL;
const opts = { skip: !DB && 'DATABASE_URL not set' };
const pw = 'correct-horse-battery-staple';
const H = { 'content-type': 'application/json', 'x-apex-csrf': '1' };
let app, pool, base;

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
  const cfg = loadConfig({ ...process.env, APEX_ENV: 'test', APEX_SIGNING_KID: 'ptest-' + Date.now(), APEX_REQUIRE_TOTP: 'false', PORT: '0' });
  pool = createPool(DB);
  const signer = await loadSigner(cfg);
  await registerKey(pool, signer, 'test');
  app = await buildApp({ cfg, pool, signer, logger: false, renderPdf: async p => Buffer.from(`%PDF-1.7\n% TEST STUB ${p.id}\n%%EOF`) });
  await app.listen({ port: 0, host: '127.0.0.1' });
  base = `http://127.0.0.1:${app.server.address().port}`;
  const h = await hashPassword(pw);
  for (const [e, r] of [['p-issuer@test.apex', ['issuer']], ['p-approver@test.apex', ['approver']], ['p-vol@test.apex', ['volunteer']], ['p-vol2@test.apex', ['volunteer']]])
    await pool.query(`insert into users(email, display_name, password_hash, roles) values ($1,$1,$2,$3) on conflict (email) do update set password_hash=$2, roles=$3, failed_logins=0, locked_until=null`, [e, h, r]);
});
after(async () => { if (app) await app.close(); if (pool) await pool.end(); });

test('contribution validation (no DB)', () => {
  assert.throws(() => validateContribution({ project: 'P', role: 'Mentor' }), /Invalid project/);
  assert.throws(() => validateContribution({ project: 'Youth Mentorship', role: 'Mentor', period_start: '2026-02', period_end: '2026-05', hours: 10, summary: 'Mentored a cohort weekly.', evidence: [{ label: 'Doc', url: 'http://x.y' }] }), /https only/);
  assert.equal(validateContribution({ project: 'Youth Mentorship', role: 'Mentor', period_start: '2026-02', period_end: '2026-05', hours: 10, summary: 'Mentored a cohort weekly.' }).hours, 10);
});

test('passport privacy, independent review, hours, badges, bulk idempotency, audit', opts, async () => {
  const issuer = await as('p-issuer@test.apex'), approver = await as('p-approver@test.apex'), vol = await as('p-vol@test.apex'), vol2 = await as('p-vol2@test.apex');
  const { public_id } = await (await issuer('POST', '/api/v1/admin/volunteers', { display_name: 'TEST SAMPLE Passport', email: 'private@test.apex' })).json();
  await pool.query(`update volunteers set user_id=(select id from users where email='p-vol@test.apex'), phone='000', birth_date='2000-01-01', internal_notes='staff only' where public_id=$1`, [public_id]);
  assert.equal((await vol('POST', '/api/v1/admin/volunteers', { display_name: 'Nope' })).status, 403, 'volunteer cannot create volunteers');

  assert.equal((await fetch(`${base}/api/v1/volunteers/${public_id}`)).status, 404, 'private by default');
  assert.equal((await fetch(`${base}/api/v1/volunteers/v-0000000000`)).status, 404, 'unknown looks identical');

  const c = { project: 'Youth Mentorship Initiative', role: 'Mentor', period_start: '2026-02', period_end: '2026-05', hours: 80, summary: 'Weekly mentoring of a ten-person cohort.', evidence: [{ label: 'Cohort report', url: 'https://example.test/r', public: true }] };
  const a = await (await vol('POST', '/api/v1/me/contributions', c)).json();
  const b = await (await vol('POST', '/api/v1/me/contributions', { ...c, hours: 500, period_start: '2026-06', period_end: '2026-09' })).json();
  const self = await (await issuer('POST', `/api/v1/admin/volunteers/${public_id}/contributions`, { ...c, hours: 40 })).json();
  assert.equal((await vol('POST', `/api/v1/admin/contributions/${a.id}/review`, { decision: 'verified' })).status, 403, 'volunteer cannot self-verify');
  assert.equal((await issuer('POST', `/api/v1/admin/contributions/${self.id}/review`, { decision: 'verified' })).status, 403, 'issuer lacks approver role');
  assert.equal((await approver('POST', `/api/v1/admin/contributions/${a.id}/review`, { decision: 'verified' })).status, 200);
  assert.equal((await approver('POST', `/api/v1/admin/contributions/${a.id}/review`, { decision: 'verified' })).status, 409, 'no double review');
  assert.equal((await approver('POST', `/api/v1/admin/contributions/${b.id}/review`, { decision: 'rejected' })).status, 400, 'rejection needs note');
  assert.equal((await approver('POST', `/api/v1/admin/contributions/${b.id}/review`, { decision: 'rejected', note: 'Hours not supported by evidence' })).status, 200);
  await assert.rejects(pool.query('update contributions set hours=999 where id=$1', [a.id]), /immutable/);
  await assert.rejects(pool.query('delete from contributions where id=$1', [a.id]), /cannot be deleted/);

  assert.equal((await vol2('PUT', '/api/v1/me/privacy', { profile_public: true })).status, 404, 'other volunteer has no access to this profile');
  assert.equal((await vol('PUT', '/api/v1/me/privacy', { profile_public: true, is_admin: true })).status, 400, 'unknown privacy keys refused');
  assert.equal((await vol('PUT', '/api/v1/me/privacy', { profile_public: true })).status, 200);
  const pub = await (await fetch(`${base}/api/v1/volunteers/${public_id}`)).json();
  assert.equal(pub.verified_hours, 80, 'only verified hours');
  assert.deepEqual(pub.contributions.map(x => x.id), [a.id]);
  assert.deepEqual(pub.contributions[0].evidence, [], 'evidence links off by default');
  const s = JSON.stringify(pub);
  for (const leak of ['private@test.apex', '000', '2000-01-01', 'staff only', 'Hours not supported']) assert.ok(!s.includes(leak), 'leaked ' + leak);

  assert.equal((await approver('POST', '/api/v1/admin/badges', { volunteer: public_id, badge_class_id: 'mentorship', evidence: [b.id] })).status, 400, 'rejected evidence refused');
  assert.equal((await approver('POST', '/api/v1/admin/badges', { volunteer: public_id, badge_class_id: 'mentorship', evidence: [] })).status, 400, 'no basis refused');
  assert.equal((await issuer('POST', '/api/v1/admin/badges', { volunteer: public_id, badge_class_id: 'mentorship', evidence: [a.id] })).status, 403);
  const badge = await (await approver('POST', '/api/v1/admin/badges', { volunteer: public_id, badge_class_id: 'mentorship', evidence: [a.id] })).json();
  assert.match(badge.id, /^BDG-/);
  const ob = await (await fetch(`${base}/api/v1/badges/${badge.id}`)).json();
  assert.ok(ob.type.includes('OpenBadgeCredential'));
  assert.equal((await approver('POST', `/api/v1/admin/badges/${badge.id}/revoke`, { reason: 'Test revocation' })).status, 200);
  assert.equal((await (await fetch(`${base}/api/v1/volunteers/${public_id}`)).json()).badges.length, 0, 'revoked badge hidden');

  await vol('PUT', '/api/v1/me/privacy', { profile_public: false });
  assert.equal((await fetch(`${base}/api/v1/volunteers/${public_id}`)).status, 404, 'sharing disabled');
  assert.equal((await pool.query('select count(*)::int n from contributions where id=$1', [a.id])).rows[0].n, 1, 'record retained');

  const nm = 'TEST SAMPLE ' + public_id;
  const csv = `Name,Dept,Role,From,To,Hours,Ref\n${nm},Youth Mentorship Initiative,Mentor,2026-02,2026-05,80,${a.id}\n${nm},Youth Mentorship Initiative,Mentor,2026-02,2026-05,80,${a.id}\nOther Person,Outreach,Helper,2026-01,2026-02,5,${b.id}\n`;
  const mapping = { Name: 'name', Dept: 'department', Role: 'role', From: 'period_start', To: 'period_end', Hours: 'hours', Ref: 'contribution_ref' };
  const key = 'test-' + randomUUID();
  const v1 = await (await issuer('POST', '/api/v1/admin/bulk/validate', { csv, mapping, idempotencyKey: key })).json();
  assert.deepEqual(v1.report.rows.map(r => r.ok), [true, false, false], 'duplicate + unapproved held');
  const v2 = await (await issuer('POST', '/api/v1/admin/bulk/validate', { csv, mapping, idempotencyKey: key })).json();
  assert.equal(v2.batch, v1.batch); assert.ok(v2.replay);
  assert.equal((await issuer('POST', '/api/v1/admin/bulk/validate', { csv: csv + 'x', mapping, idempotencyKey: key })).status, 409);
  const d1 = await (await issuer('POST', `/api/v1/admin/bulk/${v1.batch}/draft`)).json();
  const d2 = await (await issuer('POST', `/api/v1/admin/bulk/${v1.batch}/draft`)).json();
  assert.equal(d1.created.length, 1); assert.deepEqual(d2.created, d1.created, 'retry creates no duplicates');
  const st = (await pool.query('select state, approved_by from certificates where id=$1', [d1.created[0]])).rows[0];
  assert.equal(st.state, 'draft'); assert.equal(st.approved_by, null, 'bulk never bypasses approval');
  const report = await (await issuer('GET', `/api/v1/admin/bulk/${v1.batch}/report.csv`)).text();
  assert.match(report, /accepted/); assert.match(report, /held/);

  assert.ok(verifyChain((await pool.query('select * from audit_events order by seq')).rows).ok, 'audit chain intact');
});
