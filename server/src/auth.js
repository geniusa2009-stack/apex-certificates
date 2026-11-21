import argon2 from 'argon2';
import { createHash, randomBytes } from 'node:crypto';
import { HttpError } from './db.js';
import { verifyTotp } from './totp.js';

const sha = (s) => createHash('sha256').update(s).digest('hex');
export const COOKIE = '__Host-apex_session';
export const hashPassword = (pw) => argon2.hash(pw, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
const DUMMY = '$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHRzb21lc2FsdA$4n7bC8m5bq3Q7m0p1xKk3cJq2r1o0rM9T0x8b3c6Wk0';

export async function login(pool, cfg, { email, password, totp }, ip) {
  if (typeof email !== 'string' || typeof password !== 'string' || password.length > 1024) throw new HttpError(400, 'Invalid credentials');
  const { rows } = await pool.query('select * from users where email = $1', [email.toLowerCase().trim()]);
  const u = rows[0];
  const ok = await argon2.verify(u ? u.password_hash : DUMMY, password).catch(() => false); // constant-ish time for unknown users
  if (!u || u.disabled || (u.locked_until && u.locked_until > new Date())) throw new HttpError(401, 'Invalid credentials');
  const needsTotp = !!u.totp_secret || (cfg.requireTotp && (u.roles.includes('approver') || u.roles.includes('admin')));
  const totpOk = !needsTotp || (u.totp_secret && verifyTotp(u.totp_secret, totp));
  if (!ok || !totpOk) {
    await pool.query(`update users set failed_logins = failed_logins + 1,
      locked_until = case when failed_logins + 1 >= 5 then now() + interval '15 minutes' else locked_until end where id = $1`, [u.id]);
    throw new HttpError(401, needsTotp && !u.totp_secret ? 'Two-factor enrolment required — contact an administrator' : 'Invalid credentials');
  }
  await pool.query('update users set failed_logins = 0, locked_until = null where id = $1', [u.id]);
  const token = randomBytes(32).toString('base64url');
  await pool.query(`insert into sessions(token_hash, user_id, expires_at, ip) values ($1,$2, now() + make_interval(hours => $3), $4)`,
    [sha(token), u.id, cfg.sessionHours, ip || null]);
  return { token, user: publicUser(u) };
}
export const publicUser = (u) => ({ id: u.id, email: u.email, display_name: u.display_name, roles: u.roles });

export async function userFromRequest(pool, req) {
  const token = req.cookies?.[COOKIE];
  if (!token) return null;
  const { rows } = await pool.query(`select u.* from sessions s join users u on u.id = s.user_id
    where s.token_hash = $1 and s.expires_at > now() and not u.disabled`, [sha(token)]);
  return rows[0] || null;
}
export async function logout(pool, req) {
  const token = req.cookies?.[COOKIE];
  if (token) await pool.query('delete from sessions where token_hash = $1', [sha(token)]);
}
