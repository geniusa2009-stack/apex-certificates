// Server-only Ed25519 signing. The private key never leaves this process (env provider) or the KMS (gcp-kms provider).
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto';
import { b64uEncode, b64uDecode } from '../../shared/apex-verify.js';

const rawPublicFromKeyObject = (pub) => b64uDecode(pub.export({ format: 'jwk' }).x);

export async function loadSigner(cfg, env = process.env) {
  let publicRaw, signRaw;
  if (cfg.keyProvider === 'env') {
    // APEX_SIGNING_KEY_PEM must be injected by a secret manager (GCP Secret Manager, AWS Secrets Manager, Vault, k8s secret).
    const pem = env.APEX_SIGNING_KEY_PEM;
    if (!pem) throw new Error('APEX_SIGNING_KEY_PEM not set');
    const key = createPrivateKey(pem.replace(/\\n/g, '\n'));
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('Signing key must be Ed25519');
    publicRaw = rawPublicFromKeyObject(createPublicKey(key));
    signRaw = async (bytes) => new Uint8Array(edSign(null, bytes, key));
    delete env.APEX_SIGNING_KEY_PEM; // reduce exposure (child processes, debug dumps)
  } else if (cfg.keyProvider === 'gcp-kms') {
    // Cloud KMS key with algorithm EC_SIGN_ED25519. UNVERIFIED in this repo's CI (needs a GCP project).
    if (!cfg.kmsKeyVersion) throw new Error('APEX_KMS_KEY_VERSION required for gcp-kms');
    const { KeyManagementServiceClient } = await import('@google-cloud/kms');
    const client = new KeyManagementServiceClient();
    const [pk] = await client.getPublicKey({ name: cfg.kmsKeyVersion });
    if (pk.algorithm !== 'EC_SIGN_ED25519') throw new Error('KMS key must be EC_SIGN_ED25519, got ' + pk.algorithm);
    publicRaw = rawPublicFromKeyObject(createPublicKey(pk.pem));
    signRaw = async (bytes) => { const [res] = await client.asymmetricSign({ name: cfg.kmsKeyVersion, data: bytes }); return new Uint8Array(res.signature); };
  } else throw new Error('Unknown APEX_KEY_PROVIDER ' + cfg.keyProvider);

  const pubKeyObj = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64uEncode(publicRaw) }, format: 'jwk' });
  return {
    kid: cfg.kid,
    publicKey: b64uEncode(publicRaw),
    async sign(bytes) {
      const sig = await signRaw(bytes);
      if (sig.length !== 64 || !edVerify(null, bytes, pubKeyObj, sig)) throw new Error('Signer self-check failed');
      return b64uEncode(sig);
    }
  };
}

// Registers the signer's key; rotation = deploy a new kid+key, the previous active key for this env becomes 'retired'
// (still trusted for existing certificates). Refuses to start if a kid is reused with a different key.
export async function registerKey(pool, signer, env) {
  const c = await pool.connect();
  try {
    await c.query('begin');
    const { rows } = await c.query('select * from signing_keys where kid = $1 for update', [signer.kid]);
    if (rows[0]) {
      if (rows[0].public_key !== signer.publicKey) throw new Error(`kid ${signer.kid} already registered with a different public key`);
      if (rows[0].status !== 'active') throw new Error(`kid ${signer.kid} is ${rows[0].status}; deploy a new kid`);
      if (rows[0].env !== env) throw new Error(`kid ${signer.kid} belongs to env ${rows[0].env}`);
    } else {
      await c.query(`update signing_keys set status='retired', retired_at=now() where env=$1 and status='active'`, [env]);
      await c.query(`insert into signing_keys(kid, public_key, env, status) values ($1,$2,$3,'active')`, [signer.kid, signer.publicKey, env]);
    }
    await c.query('commit');
  } catch (e) { await c.query('rollback'); throw e; } finally { c.release(); }
}
