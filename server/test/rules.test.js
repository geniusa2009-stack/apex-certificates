import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertAllowed, validateDraft, newCertificateId, buildPayload } from '../src/rules.js';
import { ID_RE } from '../../shared/apex-verify.js';

const issuer = { id: 'u1', roles: ['issuer'] }, issuer2 = { id: 'u3', roles: ['issuer', 'approver'] };
const approver = { id: 'u2', roles: ['approver'] }, nobody = { id: 'u9', roles: [] };
const cert = (state, o = {}) => ({ state, created_by: 'u1', submitted_by: 'u1', ...o });
const denied = (fn, code) => assert.throws(fn, e => e.statusCode === code);

test('unauthenticated / unprivileged users cannot issue', () => {
  denied(() => assertAllowed('create', null), 401);
  denied(() => assertAllowed('create', nobody), 403);
  denied(() => assertAllowed('sign', nobody, cert('approved')), 403);
  denied(() => assertAllowed('approve', issuer, cert('in_review', { created_by: 'x', submitted_by: 'x' })), 403);
});
test('no self-approval, even with both roles', () => {
  denied(() => assertAllowed('approve', { id: 'u1', roles: ['issuer', 'approver'] }, cert('in_review')), 403);
  denied(() => assertAllowed('approve', issuer2, cert('in_review', { submitted_by: 'u3' })), 403);
  assert.doesNotThrow(() => assertAllowed('approve', approver, cert('in_review')));
});
test('state machine order enforced', () => {
  denied(() => assertAllowed('sign', approver, cert('in_review')), 409);
  denied(() => assertAllowed('sign', approver, cert('draft')), 409);
  denied(() => assertAllowed('publish', approver, cert('approved')), 409);
  denied(() => assertAllowed('revoke', approver, cert('signed')), 409);
  denied(() => assertAllowed('update', issuer, cert('approved')), 409);
  assert.doesNotThrow(() => assertAllowed('sign', issuer, cert('approved')));
  assert.doesNotThrow(() => assertAllowed('publish', issuer, cert('signed')));
  assert.doesNotThrow(() => assertAllowed('revoke', approver, cert('published')));
});
test('draft validation is strict', () => {
  const ok = { name: 'Amira Al-Rashid', department: 'Youth Mentorship', role: 'Mentor', period_start: '2026-02', period_end: '2026-10', hours: 186 };
  assert.equal(validateDraft(ok).name, 'Amira Al-Rashid');
  for (const bad of [{ ...ok, hours: 1.5 }, { ...ok, hours: '186' }, { ...ok, name: '<script>' }, { ...ok, period_end: '2025-01' }, { ...ok, period_start: '2026-13' }, { ...ok, admin: true }])
    assert.throws(() => validateDraft(bad));
});
test('IDs are well-formed and random', () => {
  const ids = new Set(Array.from({ length: 2000 }, () => newCertificateId(2026)));
  assert.equal(ids.size, 2000);
  for (const id of ids) assert.match(id, ID_RE);
});
test('payload contains no private data', () => {
  const p = buildPayload({ id: 'APX-2026-VR-ABCDE234', name: 'n', department: 'd', role: 'r', period_start: '2026-01', period_end: '2026-02', hours: 1, volunteer_email: 'a@b.co', created_by: 'u1' }, { env: 'test', kid: 'k', issuedAt: '2026-03-01' });
  assert.deepEqual(Object.keys(p).sort(), ['department', 'env', 'hours', 'id', 'issued_at', 'kid', 'name', 'period_end', 'period_start', 'role', 'v']);
});
