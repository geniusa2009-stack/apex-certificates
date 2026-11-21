import { loadConfig } from './config.js';
import { createPool } from './db.js';
import { loadSigner, registerKey } from './keys.js';
import { buildApp } from './app.js';
import { renderCertificatePdf, assertFonts, closeRenderer } from './pdf.js';
import { createSigners } from './signers.js';

const cfg = loadConfig();
assertFonts(cfg.fontDir);
const pool = createPool(cfg.databaseUrl);
const signer = await loadSigner(cfg);
await registerKey(pool, signer, cfg.env);
const signers = createSigners({ pool, cfg });
const app = await buildApp({ cfg, pool, signer, signers, renderPdf: (p, h, s) => renderCertificatePdf(cfg, p, h, s) });
await app.listen({ port: cfg.port, host: '0.0.0.0' });
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, async () => { await app.close(); await closeRenderer(); await pool.end(); process.exit(0); });
