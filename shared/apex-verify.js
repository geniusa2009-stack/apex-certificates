// APEX certificate format v1 — shared by browser verifier and server. Public verification only; no private-key code here.
export const CONTEXT = { cert: 'apex-cert-v1:', status: 'apex-status-v1:', pdf: 'apex-pdf-v1:' };
export const ID_RE = /^APX-\d{4}-[A-Z]{2}-[0-9A-HJKMNP-TV-Z]{5,12}$/;
export const STATES = ['VERIFIED', 'REVOKED', 'SUPERSEDED', 'INVALID_SIGNATURE', 'NOT_FOUND', 'UNAVAILABLE'];
const enc = new TextEncoder();
const subtle = () => globalThis.crypto && globalThis.crypto.subtle;

// RFC 8785 (JCS) for the value types APEX uses: objects, arrays, strings, safe integers, booleans, null.
export function canonicalize(v) {
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new TypeError('Only safe integers are allowed in signed payloads');
    return String(v);
  }
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  if (typeof v === 'object') {
    const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return '{' + keys.map(k => {
      if (v[k] === undefined) throw new TypeError('undefined value at ' + k);
      return JSON.stringify(k) + ':' + canonicalize(v[k]);
    }).join(',') + '}';
  }
  throw new TypeError('Unsupported type ' + typeof v);
}
export const signingInput = (kind, obj) => enc.encode(CONTEXT[kind] + canonicalize(obj));

export const toHex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
export function b64uEncode(u8) {
  let s = ''; for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function b64uDecode(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) throw new TypeError('bad base64url');
  const s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4));
  return Uint8Array.from(s, c => c.charCodeAt(0));
}
export async function sha256Hex(data) {
  const u8 = typeof data === 'string' ? enc.encode(data) : data;
  return toHex(new Uint8Array(await subtle().digest('SHA-256', u8)));
}
export const recordHash = payload => sha256Hex(signingInput('cert', payload));

async function importKey(k) {
  return subtle().importKey('raw', b64uDecode(k.public_key), { name: 'Ed25519' }, false, ['verify']);
}
async function verifySig(kind, obj, sigB64u, keyMap) {
  const k = obj && keyMap.get(obj.kid);
  if (!k) return { ok: false, why: 'unknown or untrusted key ' + (obj && obj.kid) };
  if (k.alg !== 'Ed25519' || k.status === 'compromised') return { ok: false, why: 'key ' + k.kid + ' is not trusted' };
  let sig; try { sig = b64uDecode(sigB64u); } catch { return { ok: false, why: 'malformed signature' }; }
  if (sig.length !== 64) return { ok: false, why: 'malformed signature' };
  const ok = await subtle().verify({ name: 'Ed25519' }, await importKey(k), sig, signingInput(kind, obj));
  return { ok, why: ok ? '' : kind + ' signature does not match the data' };
}

// Pure decision function: given the registry response + trusted keyset, decide the state. Any doubt => not VERIFIED.
export async function evaluate(id, resp, keyset, { expectEnv } = {}) {
  const fail = (state, reason, extra) => ({ state, reason, ...extra });
  if (!resp || typeof resp !== 'object' || !resp.certificate) return fail('UNAVAILABLE', 'Malformed registry response');
  if (!keyset || !Array.isArray(keyset.keys)) return fail('UNAVAILABLE', 'Trusted key list unavailable');
  const keyMap = new Map(keyset.keys.map(k => [k.kid, k]));
  const { payload, signature } = resp.certificate;
  if (!payload || payload.v !== 1 || payload.id !== id) return fail('INVALID_SIGNATURE', 'Record does not match the requested certificate ID');
  const c = await verifySig('cert', payload, signature, keyMap);
  const base = { payload, signature, kid: payload.kid, env: payload.env, recordHash: await recordHash(payload) };
  if (!c.ok) return fail('INVALID_SIGNATURE', c.why, base);
  if (expectEnv && payload.env !== expectEnv) return fail('INVALID_SIGNATURE', `Record was signed for environment "${payload.env}", not "${expectEnv}"`, base);

  let pdf = null;
  if (resp.pdf) {
    const st = resp.pdf.statement;
    if (!st || st.type !== 'pdf' || st.id !== id || st.record_hash !== base.recordHash || !/^[0-9a-f]{64}$/.test(st.sha256 || ''))
      return fail('INVALID_SIGNATURE', 'PDF attestation does not belong to this record', base);
    const p = await verifySig('pdf', st, resp.pdf.signature, keyMap);
    if (!p.ok) return fail('INVALID_SIGNATURE', p.why, base);
    pdf = { sha256: st.sha256, bytes: st.bytes, url: resp.pdf.url || null };
  }
  base.pdf = pdf;

  if (resp.status) {
    const st = resp.status.statement;
    if (!st || st.type !== 'status' || st.id !== id) return fail('INVALID_SIGNATURE', 'Status statement does not belong to this record', base);
    const s = await verifySig('status', st, resp.status.signature, keyMap);
    if (!s.ok) return fail('INVALID_SIGNATURE', s.why, base);
    if (st.status === 'revoked') return fail('REVOKED', st.reason || 'Revoked by APEX', { ...base, status: st });
    if (st.status === 'superseded') return fail('SUPERSEDED', st.reason || 'Superseded', { ...base, status: st });
    return fail('UNAVAILABLE', 'Unknown status ' + st.status, base);
  }
  if (resp.state !== 'valid') return fail('UNAVAILABLE', 'Registry did not confirm current status', base);
  return { state: 'VERIFIED', reason: '', ...base };
}

export async function fetchAndVerify(apiBase, id, { fetchImpl = globalThis.fetch, timeoutMs = 8000, expectEnv } = {}) {
  id = String(id || '').trim().toUpperCase();
  if (!ID_RE.test(id)) return { state: 'NOT_FOUND', reason: 'Not a valid APEX certificate ID format' };
  if (!subtle() || !subtle().verify) return { state: 'UNAVAILABLE', reason: 'This browser cannot perform signature verification' };
  try { await subtle().importKey('raw', new Uint8Array(32), { name: 'Ed25519' }, false, ['verify']); }
  catch (e) { if (e && e.name === 'NotSupportedError') return { state: 'UNAVAILABLE', reason: 'This browser does not support Ed25519 verification. Update it or try another browser.' }; }
  const ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = ctl && setTimeout(() => ctl.abort(), timeoutMs);
  const get = async url => {
    const r = await fetchImpl(url, { signal: ctl && ctl.signal, cache: 'no-store', credentials: 'omit' });
    if (r.status === 404) return { notFound: true };
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return { json: await r.json() };
  };
  try {
    const base = apiBase.replace(/\/$/, '');
    const [rec, keys] = await Promise.all([get(`${base}/certificates/${encodeURIComponent(id)}.json`), get(`${base}/keys.json`)]);
    if (rec.notFound) return { state: 'NOT_FOUND', reason: 'No record with this ID in the APEX registry' };
    if (keys.notFound) return { state: 'UNAVAILABLE', reason: 'Trusted key list not found' };
    return await evaluate(id, rec.json, keys.json, { expectEnv });
  } catch (e) {
    return { state: 'UNAVAILABLE', reason: 'Registry unreachable (' + (e && e.name === 'AbortError' ? 'timeout' : (e && e.message) || 'network error') + '). Nothing was verified.' };
  } finally { if (timer) clearTimeout(timer); }
}
