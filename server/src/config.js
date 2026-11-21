import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const req = (k) => { const v = process.env[k]; if (!v) throw new Error(`Missing required env ${k}`); return v; };

export function loadConfig(env = process.env) {
  const appEnv = env.APEX_ENV || 'production';
  if (!['production', 'staging', 'test'].includes(appEnv)) throw new Error('APEX_ENV must be production|staging|test');
  const port = Number(env.PORT || 8080);
  return {
    env: appEnv,
    port,
    databaseUrl: env.DATABASE_URL || req('DATABASE_URL'),
    verifyHost: env.APEX_VERIFY_HOST || 'verify.apex.org',          // printed on certificate + QR target
    publicBaseUrl: env.APEX_PUBLIC_BASE_URL || `https://${env.APEX_VERIFY_HOST || 'verify.apex.org'}`,
    renderOrigin: env.APEX_RENDER_ORIGIN || `http://127.0.0.1:${port}`, // where headless Chromium loads the template
    webRoot: path.resolve(env.APEX_WEB_ROOT || path.join(here, '..', '..')),
    fontDir: path.resolve(env.APEX_FONT_DIR || path.join(here, '..', 'fonts')),
    keyProvider: env.APEX_KEY_PROVIDER || 'env',                    // env | gcp-kms
    kid: env.APEX_SIGNING_KID || req('APEX_SIGNING_KID'),
    kmsKeyVersion: env.APEX_KMS_KEY_VERSION,
    requireTotp: (env.APEX_REQUIRE_TOTP ?? 'true') !== 'false',
    secureCookies: appEnv !== 'test',
    sessionHours: Number(env.APEX_SESSION_HOURS || 8),
    signers: [env.APEX_SIGNER1 || 'G. Ahmed I. Ragab|Founder', env.APEX_SIGNER2 || 'Asmaa Hassan|Volunteer Program Coordinator'],
    trustProxy: env.APEX_TRUST_PROXY === 'true'
  };
}
