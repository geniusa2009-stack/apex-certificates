import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalize, signingInput, evaluate, recordHash, b64uEncode, b64uDecode, fetchAndVerify, sha256Hex } from '../../shared/apex-verify.js';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const kid = 'test-1';
const keyset = { keys: [{ kid, alg: 'Ed25519', public_key: publicKey.export({ format: 'jwk' }).x, status: 'active', env: 'test' }] };
const s = (kind, o) => b64uEncode(new Uint8Array(sign(null, signingInput(kind, o), privateKey)));
const payload = { v: 1, env: 'test', id: 'APX-2026-VR-ABCDE234', kid, name: 'Test Volunteer', department: 'Dept', role: 'Role', period_start: '2026-01', period_end: '2026-02', hours: 10, issued_at: '2026-03-01' };
const valid = () => ({ state: 'valid', certificate: { payload: structuredClone(payload), signature: s('cert', payload) }, status: null, pdf: null });

test('JCS canonical form', () => assert.equal(canonicalize({ b: 1, a: ['x', null, true] }), '{"a":["x",null,true],"b":1}'));
test('base64url round-trip', () => assert.deepEqual(b64uDecode(b64uEncode(new Uint8Array([0, 255, 7]))), new Uint8Array([0, 255, 7])));
test('node-signed record verifies with shared verifier', async () => assert.equal((await evaluate(payload.id, valid(), keyset)).state, 'VERIFIED'));
test('any field change invalidates', async () => {
  for (const k of ['name', 'department', 'role', 'hours', 'issued_at', 'period_end']) {
    const r = valid(); r.certificate.payload[k] = k === 'hours' ? 11 : 'X' + r.certificate.payload[k];
    assert.equal((await evaluate(payload.id, r, keyset)).state, 'INVALID_SIGNATURE', k);
  }
});
test('env mismatch rejected', async () => assert.equal((await evaluate(payload.id, valid(), keyset, { expectEnv: 'production' })).state, 'INVALID_SIGNATURE'));
test('revoked / superseded statements', async () => {
  for (const status of ['revoked', 'superseded']) {
    const st = { v: 1, type: 'status', id: payload.id, kid, status, superseded_by: status === 'superseded' ? 'APX-2026-VR-ZZZZZ234' : null, reason: 'r', at: '2026-01-01T00:00:00Z' };
    const r = { ...valid(), state: status, status: { statement: st, signature: s('status', st) } };
    assert.equal((await evaluate(payload.id, r, keyset)).state, status.toUpperCase());
  }
});
test('pdf attestation bound to record', async () => {
  const st = { v: 1, type: 'pdf', id: payload.id, kid, sha256: await sha256Hex(new Uint8Array([1, 2, 3])), bytes: 3, record_hash: await recordHash(payload) };
  const r = { ...valid(), pdf: { statement: st, signature: s('pdf', st) } };
  assert.equal((await evaluate(payload.id, r, keyset)).state, 'VERIFIED');
  r.pdf.statement = { ...st, record_hash: '0'.repeat(64) };
  assert.equal((await evaluate(payload.id, r, keyset)).state, 'INVALID_SIGNATURE');
});
test('network failures never verify', async () => {
  for (const f of [() => Promise.reject(new Error('ECONNRESET')), async () => ({ ok: false, status: 503 }), async () => ({ ok: true, status: 200, json: async () => ({}) })])
    assert.notEqual((await fetchAndVerify('http://x', payload.id, { fetchImpl: f })).state, 'VERIFIED');
});
