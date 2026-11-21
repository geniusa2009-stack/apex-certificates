// Generates an Ed25519 key for the env provider. Store the PEM in your secret manager; do not commit it.
import { generateKeyPairSync } from 'node:crypto';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
console.log('# APEX_SIGNING_KEY_PEM (store in secret manager):');
console.log(privateKey.export({ type: 'pkcs8', format: 'pem' }));
console.log('# public key (base64url raw):', publicKey.export({ format: 'jwk' }).x);
