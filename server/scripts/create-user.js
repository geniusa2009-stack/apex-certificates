// Usage: DATABASE_URL=… APEX_NEW_PASSWORD=… node scripts/create-user.js email "Display Name" issuer,approver [--totp]
// Password is read from env (never argv) so it does not land in shell history / process lists.
import pg from 'pg';
import { hashPassword } from '../src/auth.js';
import { newTotpSecret } from '../src/totp.js';

const [email, name, roles = '', flag] = process.argv.slice(2);
const pw = process.env.APEX_NEW_PASSWORD;
if (!email || !name || !pw || pw.length < 14) { console.error('email, name and APEX_NEW_PASSWORD (≥14 chars) required'); process.exit(1); }
const totp = flag === '--totp' ? newTotpSecret() : null;
const c = new pg.Client({ connectionString: process.env.DATABASE_URL }); await c.connect();
await c.query('insert into users(email, display_name, password_hash, roles, totp_secret) values ($1,$2,$3,$4,$5)',
  [email.toLowerCase(), name, await hashPassword(pw), roles.split(',').filter(Boolean), totp]);
await c.end();
console.log('created', email, roles);
if (totp) console.log(`TOTP secret (enrol in an authenticator app, then discard): ${totp}\notpauth://totp/APEX:${encodeURIComponent(email)}?secret=${totp}&issuer=APEX`);
