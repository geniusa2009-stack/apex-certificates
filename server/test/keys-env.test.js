import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { loadSigner } from '../src/keys.js';

const { privateKey } = generateKeyPairSync('ed25519');
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const cfg = { keyProvider: 'env', kid: 'staging-test-key' };

test('signing accepts a single-line base64 PEM, even with stale PEM set', async () => {
  const env = {
    APEX_SIGNING_KEY_B64: Buffer.from(pem, 'utf8').toString('base64'),
    APEX_SIGNING_KEY_PEM: 'invalid old value'
  };
  const signer = await loadSigner(cfg, env);
  assert.equal(signer.kid, 'staging-test-key');
  assert.equal(typeof signer.publicKey, 'string');
  assert.equal(typeof (await signer.sign(Buffer.from('test credential'))), 'string');
  assert.equal(env.APEX_SIGNING_KEY_B64, undefined);
  assert.equal(env.APEX_SIGNING_KEY_PEM, undefined);
});

test('signing keeps backward compatibility with escaped multiline PEM', async () => {
  const env = { APEX_SIGNING_KEY_PEM: pem.replace(/\n/g, '\\n') };
  const signer = await loadSigner(cfg, env);
  assert.equal(typeof (await signer.sign(Buffer.from('legacy'))), 'string');
});

test('signing rejects malformed base64 without logging its contents', async () => {
  const env = { APEX_SIGNING_KEY_B64: 'not-base64' };
  await assert.rejects(() => loadSigner(cfg, env), /APEX_SIGNING_KEY_B64 must be standard base64/);
});

test('signing rejects base64 that is not an Ed25519 PEM', async () => {
  const env = { APEX_SIGNING_KEY_B64: Buffer.from('not a key').toString('base64') };
  await assert.rejects(() => loadSigner(cfg, env), /Invalid Ed25519 signing key configuration/);
});

test('signing fails closed if neither key variable is set', async () => {
  await assert.rejects(() => loadSigner(cfg, {}), /not set/);
});
