import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createIssuance } from '../src/issuance.js';

test('parallel sign requests fail fast with 409 and the lock is released on failure', async () => {
  let resume, fail;
  const pendingSign = new Promise((resolve, reject) => { resume = resolve; fail = reject; });
  let queries = 0;
  const stored = {
    id: 'APX-2026-VR-TEST1234',
    state: 'approved',
    name: 'Test Volunteer',
    department: 'Community',
    role: 'Mentor',
    period_start: '2026-01',
    period_end: '2026-06',
    hours: 100,
    updated_at: new Date()
  };
  const pool = { async query() { queries++; return { rows: [stored] }; } };
  const signer = { kid: 'test-key', sign: () => pendingSign };
  const service = createIssuance({
    pool, cfg: { env: 'test' }, signer, getSigners: async () => ({}),
    renderPdf: async () => Buffer.from('%PDF-1.7')
  });
  const issuer = { id: 'issuer', roles: ['issuer'] };
  const first = service.sign(issuer, stored.id);
  await assert.rejects(
    service.sign(issuer, stored.id),
    (err) => err.statusCode === 409 && /already in progress/.test(err.message)
  );
  assert.equal(queries, 1, 'the duplicate never opens another DB query');
  fail(new Error('simulated signer failure'));
  await assert.rejects(first, /simulated signer failure/);
  await assert.rejects(service.sign(issuer, stored.id), /simulated signer failure/);
  assert.equal(queries, 2, 'the failed attempt releases the lock for retry');
});
