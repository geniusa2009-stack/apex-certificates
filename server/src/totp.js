// RFC 6238 TOTP (SHA-1, 30 s, 6 digits) — no third-party dependency.
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const base32Encode = (buf) => { let bits = '', out = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; };
export const base32Decode = (s) => { let bits = ''; for (const c of s.replace(/=+$/, '').toUpperCase()) { const v = A.indexOf(c); if (v < 0) throw new Error('bad base32'); bits += v.toString(2).padStart(5, '0'); } const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
export function hotp(key, counter, digits = 6) {
  const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', key).update(c).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 10 ** digits).padStart(digits, '0');
}
export function verifyTotp(secretB32, code, now = Date.now(), window = 1) {
  if (!/^\d{6}$/.test(String(code || ''))) return false;
  const key = base32Decode(secretB32), t = Math.floor(now / 30000);
  for (let w = -window; w <= window; w++) {
    const exp = Buffer.from(hotp(key, t + w)), got = Buffer.from(String(code));
    if (timingSafeEqual(exp, got)) return true;
  }
  return false;
}
export const newTotpSecret = () => base32Encode(randomBytes(20));
