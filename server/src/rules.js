// Pure workflow rules: Draft → Review → Independent Approval → Sign → Publish (→ Revoke / Supersede).
import { randomBytes } from 'node:crypto';
import { HttpError } from './db.js';

const has = (u, r) => !!u && Array.isArray(u.roles) && u.roles.includes(r);
const need = (cond, status, msg) => { if (!cond) throw new HttpError(status, msg); };

export function assertAllowed(action, user, cert) {
  need(user && !user.disabled, 401, 'Authentication required');
  const st = cert && cert.state;
  switch (action) {
    case 'create': need(has(user, 'issuer'), 403, 'Issuer role required'); return;
    case 'update':
      need(has(user, 'issuer'), 403, 'Issuer role required');
      need(st === 'draft' || st === 'rejected', 409, `Cannot edit a certificate in state ${st}`);
      need(cert.created_by === user.id, 403, 'Only the creator can edit a draft'); return;
    case 'submit':
      need(has(user, 'issuer'), 403, 'Issuer role required');
      need(st === 'draft' || st === 'rejected', 409, `Cannot submit from state ${st}`);
      need(cert.created_by === user.id, 403, 'Only the creator can submit'); return;
    case 'approve': case 'reject':
      need(has(user, 'approver'), 403, 'Approver role required');
      need(st === 'in_review', 409, `Cannot ${action} from state ${st}`);
      need(cert.created_by !== user.id && cert.submitted_by !== user.id, 403, 'Independent approval required: you cannot approve or reject your own certificate'); return;
    case 'sign':
      need(has(user, 'issuer') || has(user, 'approver'), 403, 'Issuer or approver role required');
      need(st === 'approved', 409, `Only approved certificates can be signed (state ${st})`); return;
    case 'publish':
      need(has(user, 'issuer') || has(user, 'approver'), 403, 'Issuer or approver role required');
      need(st === 'signed', 409, `Only signed certificates can be published (state ${st})`); return;
    case 'revoke':
      need(has(user, 'approver'), 403, 'Approver role required');
      need(st === 'published', 409, `Only published certificates can be revoked (state ${st})`); return;
    case 'reissue':
      need(has(user, 'issuer'), 403, 'Issuer role required');
      need(st === 'published', 409, `Only published certificates can be reissued (state ${st})`); return;
    default: throw new HttpError(400, 'Unknown action');
  }
}

const TEXT = /^[\p{L}\p{M}\p{N} .,'’&()\/-]{2,120}$/u;
const MONTH = /^\d{4}-(0[1-9]|1[0-2])$/;
export const CERTIFICATE_TEMPLATES = Object.freeze(['classic_v1', 'hybrid_v4']);
export function validateDraft(input, { defaultTemplateId = 'classic_v1' } = {}) {
  const o = input || {};
  const clean = (k) => { const v = typeof o[k] === 'string' ? o[k].normalize('NFC').trim().replace(/\s+/g, ' ') : ''; need(TEXT.test(v), 400, `Invalid ${k}`); return v; };
  const out = { name: clean('name'), department: clean('department'), role: clean('role') };
  for (const k of ['period_start', 'period_end']) { need(typeof o[k] === 'string' && MONTH.test(o[k]), 400, `Invalid ${k} (YYYY-MM)`); out[k] = o[k]; }
  need(out.period_end >= out.period_start, 400, 'period_end before period_start');
  need(Number.isInteger(o.hours) && o.hours >= 1 && o.hours <= 10000, 400, 'Invalid hours');
  out.hours = o.hours;
  out.template_id = o.template_id === undefined ? defaultTemplateId : o.template_id;
  need(CERTIFICATE_TEMPLATES.includes(out.template_id), 400, 'Invalid certificate template');
  if (o.volunteer_email != null && o.volunteer_email !== '') {
    need(typeof o.volunteer_email === 'string' && /^[^\s@]{1,64}@[^\s@]{1,190}\.[a-z]{2,}$/i.test(o.volunteer_email), 400, 'Invalid volunteer_email');
    out.volunteer_email = o.volunteer_email.toLowerCase();
  } else out.volunteer_email = null;
  const extra = Object.keys(o).filter(k => !['name', 'department', 'role', 'period_start', 'period_end', 'hours', 'volunteer_email', 'template_id'].includes(k));
  need(extra.length === 0, 400, 'Unexpected fields: ' + extra.join(', '));
  return out;
}

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export function newCertificateId(year = new Date().getUTCFullYear()) {
  const b = randomBytes(8); let s = '';
  for (let i = 0; i < 8; i++) s += CROCKFORD[b[i] & 31];
  return `APX-${year}-VR-${s}`;
}

// Only fields printed on the certificate are signed and public. No email or internal IDs.
export function buildPayload(cert, { env, kid, issuedAt }) {
  return { v: 1, env, id: cert.id, kid, name: cert.name, department: cert.department, role: cert.role,
    period_start: cert.period_start, period_end: cert.period_end, hours: cert.hours, issued_at: issuedAt };
}
