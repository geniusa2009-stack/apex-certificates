import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { buildApp } from '../src/app.js';

const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const appFor = async (env) => buildApp({
  cfg: { env, webRoot, trustProxy: false, secureCookies: false,
    signers: ['Test Issuer|Founder', 'Test Approver|Coordinator'] },
  pool: { query: async () => ({ rows: [] }) },
  signer: { kid: 'test' },
  renderPdf: async () => Buffer.from('%PDF-1.7'),
  logger: false
});

test('the verifier receives the server environment, never a QR/query override', async () => {
  for (const env of ['staging', 'production', 'test']) {
    const app = await appFor(env);
    try {
      const res = await app.inject({ method: 'GET', url: '/APEX%20Verify.dc.html?id=APX-2026-VR-ABCDE234&env=production' });
      assert.equal(res.statusCode, 200);
      assert.match(res.headers['content-type'], /text\/html/);
      assert.equal(res.headers['cache-control'], 'no-store');
      assert.ok(res.body.includes(`<meta name="apex-verification-env" content="${env}">`), 'server environment must control trust');
      assert.match(res.body, /expectEnv: this\.verificationEnv\(base\)/, 'browser must enforce server environment');
      assert.match(res.body, /STAGING \/ TEST ENVIRONMENT/, 'staging must be labeled');
      assert.match(res.body, /STAGING VERIFIED/, 'staging success must be distinct from production success');
      const qrRoute = await app.inject({ method: 'GET', url: '/c/APX-2026-VR-ABCDE234' });
      assert.equal(qrRoute.statusCode, 302);
      assert.ok(qrRoute.headers.location.includes('APX-2026-VR-ABCDE234'));
    } finally { await app.close(); }
  }
});

test('non-verifier page never receives verifier environment metadata', async () => {
  const app = await appFor('staging');
  try {
    const res = await app.inject({ method: 'GET', url: '/APEX%20Volunteer%20Passport.dc.html' });
    assert.equal(res.statusCode, 200);
    assert.doesNotMatch(res.body, /apex-verification-env/);
  } finally { await app.close(); }
});
