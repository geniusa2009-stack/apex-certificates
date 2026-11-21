import { test } from 'node:test';
import assert from 'node:assert/strict';
import { eventHash, verifyChain, GENESIS } from '../src/audit.js';
import { hotp, verifyTotp, base32Encode } from '../src/totp.js';

test('audit chain verifies and detects edits, deletions and reordering', () => {
  const rows = []; let prev = GENESIS;
  for (let i = 1; i <= 5; i++) {
    const ev = { seq: i, at: `2026-11-1${i}T00:00:00.000Z`, actor: 'u' + i, action: 'a' + i, cert_id: 'APX-2026-VR-ABCDE234', details: { n: i } };
    const hash = eventHash(prev, ev); rows.push({ ...ev, prev_hash: prev, hash }); prev = hash;
  }
  assert.equal(verifyChain(rows).ok, true);
  assert.equal(verifyChain(rows.map((r, i) => i === 2 ? { ...r, details: { n: 99 } } : r)).ok, false);
  assert.equal(verifyChain(rows.filter((_, i) => i !== 1)).ok, false);
  assert.equal(verifyChain([rows[1], rows[0], ...rows.slice(2)]).ok, false);
});
test('TOTP matches RFC 6238 vectors (SHA-1)', () => {
  const key = Buffer.from('12345678901234567890');
  assert.equal(hotp(key, Math.floor(59 / 30), 8), '94287082');
  assert.equal(hotp(key, Math.floor(1111111109 / 30), 8), '07081804');
  const b32 = base32Encode(key);
  assert.equal(verifyTotp(b32, hotp(key, Math.floor(1234567890 / 30)), 1234567890 * 1000), true);
  assert.equal(verifyTotp(b32, '000000', 1234567890 * 1000), false);
});
