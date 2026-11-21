// Volunteer Passport, contributions, badges and bulk issuance. Every write is transactional and audited.
import { createHash, randomBytes } from 'node:crypto';
import { tx, HttpError } from './db.js';
import { appendAudit } from './audit.js';
import { newCertificateId } from './rules.js';
import { publicProfile, normalizePrivacy, bucketContributions, validateBadgeAward, validateBulk, rowKey, toOpenBadge,
  PUBLIC_ID_RE, PRIVACY_KEYS } from '../../shared/passport-rules.js';

const has = (u, r) => !!u && Array.isArray(u.roles) && u.roles.includes(r);
const need = (c, s, m) => { if (!c) throw new HttpError(s, m); };
const CROCK = '0123456789abcdefghjkmnpqrstvwxyz';
const rand = (n, alpha = CROCK) => { const b = randomBytes(n); let s = ''; for (let i = 0; i < n; i++) s += alpha[b[i] & 31]; return s; };
export const newPublicId = () => 'v-' + rand(12);
export const newBadgeId = (y = new Date().getUTCFullYear()) => `BDG-${y}-${rand(8, CROCK.toUpperCase())}`;
const TEXT = /^[\p{L}\p{M}\p{N} .,'’&()\/:-]{2,160}$/u;
const MONTH = /^\d{4}-(0[1-9]|1[0-2])$/;
const URL_RE = /^https:\/\/[^\s<>"]{3,500}$/;

const CONTRIB_COLS = `id, volunteer_id, project, role, period_start as start, period_end as "end", hours, summary, evidence, status, submitted_by, reviewed_by, reviewed_at`;

export function validateContribution(o = {}) {
  const t = k => { const v = typeof o[k] === 'string' ? o[k].normalize('NFC').trim().replace(/\s+/g, ' ') : ''; need(TEXT.test(v), 400, `Invalid ${k}`); return v; };
  const out = { project: t('project'), role: t('role') };
  for (const k of ['period_start', 'period_end']) { need(typeof o[k] === 'string' && MONTH.test(o[k]), 400, `Invalid ${k}`); out[k] = o[k]; }
  need(out.period_end >= out.period_start, 400, 'period_end before period_start');
  need(Number.isInteger(o.hours) && o.hours >= 1 && o.hours <= 5000, 400, 'Invalid hours'); out.hours = o.hours;
  need(typeof o.summary === 'string' && o.summary.trim().length >= 10 && o.summary.length <= 2000, 400, 'Summary must be 10–2000 characters'); out.summary = o.summary.trim();
  const ev = Array.isArray(o.evidence) ? o.evidence : [];
  need(ev.length <= 10, 400, 'Too many evidence links');
  out.evidence = ev.map(e => { need(e && URL_RE.test(e.url) && TEXT.test(String(e.label || '')), 400, 'Invalid evidence link (https only)'); return { label: e.label, url: e.url, public: e.public === true }; });
  return out;
}

export function createPassport({ pool, cfg }) {
  const loadVolunteer = async (q, where, arg) => (await q.query(`select * from volunteers where ${where} = $1`, [arg])).rows[0];
  const bundle = async (q, v) => {
    const [c, certs, awards, classes] = await Promise.all([
      q.query(`select ${CONTRIB_COLS} from contributions where volunteer_id=$1`, [v.id]),
      q.query(`select id, state, department, role, period_start, period_end, hours, issued_at from certificates where volunteer_id=$1`, [v.id]),
      q.query(`select id, badge_class_id, status, issued_at, evidence from badge_awards where volunteer_id=$1`, [v.id]),
      q.query(`select * from badge_classes`)]);
    return { volunteer: v, privacy: v.privacy, contributions: c.rows, certificates: certs.rows, awards: awards.rows, badgeClasses: classes.rows };
  };

  return {
    // ---------- public ----------
    async publicPassport(publicId) {
      if (!PUBLIC_ID_RE.test(publicId)) return null;
      const v = await loadVolunteer(pool, 'public_id', publicId);
      return v ? publicProfile(await bundle(pool, v)) : null;
    },
    async publicBadge(id) {
      if (!/^BDG-\d{4}-[0-9A-HJKMNP-TV-Z]{8}$/.test(id)) return null;
      const { rows } = await pool.query(`select a.*, v.public_id as recipient_public_id, v.privacy, v.disabled from badge_awards a join volunteers v on v.id=a.volunteer_id where a.id=$1`, [id]);
      const a = rows[0]; if (!a || a.disabled) return null;
      const cls = (await pool.query('select * from badge_classes where id=$1', [a.badge_class_id])).rows[0];
      const p = normalizePrivacy(a.privacy);
      const ob = toOpenBadge(a, cls, { issuerUrl: cfg.publicBaseUrl, verifyBase: cfg.publicBaseUrl });
      if (!p.profile_public) ob.credentialSubject.id = null; // badge stays verifiable without exposing the profile link
      return ob;
    },

    // ---------- volunteer (own account) ----------
    async me(user) {
      need(has(user, 'volunteer'), 403, 'Volunteer account required');
      const v = await loadVolunteer(pool, 'user_id', user.id); need(v, 404, 'No volunteer profile linked');
      const b = await bundle(pool, v);
      const buckets = bucketContributions(b.contributions);
      return { public_id: v.public_id, display_name: v.display_name, privacy: normalizePrivacy(v.privacy), buckets,
        certificates: b.certificates.filter(c => ['published', 'revoked', 'superseded'].includes(c.state)),
        badges: b.awards, public_preview: publicProfile({ ...b, privacy: { ...normalizePrivacy(v.privacy), profile_public: true } }) };
    },
    async setPrivacy(user, input) {
      need(has(user, 'volunteer'), 403, 'Volunteer account required');
      const extra = Object.keys(input || {}).filter(k => !PRIVACY_KEYS.includes(k)); need(!extra.length, 400, 'Unknown privacy keys');
      return tx(pool, async c => {
        const v = await loadVolunteer(c, 'user_id', user.id); need(v, 404, 'No volunteer profile linked');
        const next = normalizePrivacy({ ...normalizePrivacy(v.privacy), ...input });
        await c.query('update volunteers set privacy=$2 where id=$1', [v.id, next]);
        await appendAudit(c, { actor: user.id, action: 'passport.privacy', details: { volunteer: v.public_id, privacy: next } });
        return next;
      });
    },
    async submitContribution(user, input, volunteerPublicId) {
      const d = validateContribution(input);
      return tx(pool, async c => {
        let v;
        if (has(user, 'volunteer') && !volunteerPublicId) v = await loadVolunteer(c, 'user_id', user.id);
        else { need(has(user, 'issuer'), 403, 'Issuer role required'); v = await loadVolunteer(c, 'public_id', volunteerPublicId); }
        need(v && !v.disabled, 404, 'Volunteer not found');
        const { rows } = await c.query(`insert into contributions(volunteer_id, project, role, period_start, period_end, hours, summary, evidence, submitted_by)
          values ($1,$2,$3,$4,$5,$6,$7,$8,$9) returning id`, [v.id, d.project, d.role, d.period_start, d.period_end, d.hours, d.summary, JSON.stringify(d.evidence), user.id]);
        await appendAudit(c, { actor: user.id, action: 'contribution.submit', details: { id: rows[0].id, volunteer: v.public_id, hours: d.hours } });
        return { id: rows[0].id };
      });
    },
    async withdrawContribution(user, id) {
      return tx(pool, async c => {
        const r = (await c.query('select c.*, v.user_id from contributions c join volunteers v on v.id=c.volunteer_id where c.id=$1 for update', [id])).rows[0];
        need(r, 404, 'Not found'); need(r.user_id === user.id || r.submitted_by === user.id, 403, 'Not your contribution');
        need(r.status === 'pending', 409, 'Only pending contributions can be withdrawn');
        await c.query(`update contributions set status='withdrawn' where id=$1`, [id]);
        await appendAudit(c, { actor: user.id, action: 'contribution.withdraw', details: { id } });
      });
    },

    // ---------- staff ----------
    async createVolunteer(user, o = {}) {
      need(has(user, 'issuer') || has(user, 'admin'), 403, 'Issuer or admin role required');
      need(typeof o.display_name === 'string' && TEXT.test(o.display_name.trim()), 400, 'Invalid display_name');
      return tx(pool, async c => {
        const pid = newPublicId();
        const { rows } = await c.query(`insert into volunteers(public_id, display_name, email, created_by) values ($1,$2,$3,$4) returning id`,
          [pid, o.display_name.trim(), typeof o.email === 'string' ? o.email.toLowerCase().trim() : null, user.id]);
        await appendAudit(c, { actor: user.id, action: 'volunteer.create', details: { public_id: pid } });
        return { id: rows[0].id, public_id: pid };
      });
    },
    async listVolunteers(user) {
      need(has(user, 'issuer') || has(user, 'approver') || has(user, 'admin'), 403, 'Staff role required');
      return (await pool.query(`select v.public_id, v.display_name, v.disabled, v.privacy->>'profile_public' as public,
        coalesce(sum(c.hours) filter (where c.status='verified'),0)::int as verified_hours,
        count(c.*) filter (where c.status='pending')::int as pending
        from volunteers v left join contributions c on c.volunteer_id=v.id group by v.id order by v.display_name limit 1000`)).rows;
    },
    async reviewQueue(user) {
      need(has(user, 'approver'), 403, 'Approver role required');
      return (await pool.query(`select ${CONTRIB_COLS}, v.public_id, v.display_name from contributions c join volunteers v on v.id=c.volunteer_id
        where c.status='pending' order by c.created_at limit 500`)).rows;
    },
    async reviewContribution(user, id, decision, note) {
      need(has(user, 'approver'), 403, 'Approver role required');
      need(decision === 'verified' || decision === 'rejected', 400, 'decision must be verified or rejected');
      if (decision === 'rejected') need(typeof note === 'string' && note.trim().length >= 3 && note.length <= 500, 400, 'A rejection note is required');
      return tx(pool, async c => {
        const r = (await c.query('select c.*, v.user_id from contributions c join volunteers v on v.id=c.volunteer_id where c.id=$1 for update', [id])).rows[0];
        need(r, 404, 'Not found'); need(r.status === 'pending', 409, `Contribution is ${r.status}`);
        need(r.submitted_by !== user.id && r.user_id !== user.id, 403, 'Independent review required');
        await c.query(`update contributions set status=$2, reviewed_by=$3, reviewed_at=now(), review_note=$4 where id=$1`, [id, decision, user.id, note || null]);
        await appendAudit(c, { actor: user.id, action: 'contribution.' + decision, details: { id, hours: r.hours } });
      });
    },
    async awardBadge(user, o = {}) {
      need(has(user, 'approver'), 403, 'Approver role required');
      return tx(pool, async c => {
        const v = await loadVolunteer(c, 'public_id', o.volunteer); need(v && !v.disabled, 404, 'Volunteer not found');
        need(v.user_id !== user.id, 403, 'Cannot award badges to yourself');
        const cls = (await c.query('select * from badge_classes where id=$1', [o.badge_class_id])).rows[0]; need(cls, 400, 'Unknown badge class');
        const contribs = (await c.query(`select ${CONTRIB_COLS} from contributions where volunteer_id=$1`, [v.id])).rows;
        const assessment = o.assessment && typeof o.assessment.note === 'string' ? { note: o.assessment.note.trim(), assessor: user.id } : null;
        const errs = validateBadgeAward({ recipientId: v.id, badgeClass: cls, evidenceIds: o.evidence, assessment, awardedBy: user.id },
          contribs.map(x => ({ ...x, volunteer_id: v.id })));
        need(!errs.length, 400, errs.join('; '));
        const id = newBadgeId();
        await c.query(`insert into badge_awards(id, badge_class_id, volunteer_id, evidence, assessment, awarded_by) values ($1,$2,$3,$4,$5,$6)`,
          [id, cls.id, v.id, [...new Set(o.evidence || [])], assessment, user.id]);
        await appendAudit(c, { actor: user.id, action: 'badge.award', details: { id, badge: cls.id, volunteer: v.public_id } });
        return { id };
      });
    },
    async revokeBadge(user, id, reason) {
      need(has(user, 'approver'), 403, 'Approver role required');
      need(typeof reason === 'string' && reason.trim().length >= 3, 400, 'A reason is required');
      return tx(pool, async c => {
        const r = await c.query(`update badge_awards set status='revoked', revoked_reason=$2 where id=$1 and status='active'`, [id, reason.trim()]);
        need(r.rowCount === 1, 404, 'Active badge not found');
        await appendAudit(c, { actor: user.id, action: 'badge.revoke', details: { id, reason: reason.trim() } });
      });
    },

    // ---------- bulk issuance: validate → create drafts. Drafts still go through submit → independent approve → sign → publish. ----------
    async bulkValidate(user, { csv, mapping, idempotencyKey } = {}) {
      need(has(user, 'issuer'), 403, 'Issuer role required');
      need(typeof csv === 'string' && csv.length <= 512 * 1024, 400, 'CSV required (max 512 KB)');
      need(typeof idempotencyKey === 'string' && /^[A-Za-z0-9_-]{16,80}$/.test(idempotencyKey), 400, 'idempotencyKey required');
      const sha = createHash('sha256').update(csv).digest('hex');
      return tx(pool, async c => {
        const prior = (await c.query('select * from bulk_batches where idempotency_key=$1', [idempotencyKey])).rows[0];
        if (prior) { need(prior.csv_sha256 === sha, 409, 'Idempotency key reused with a different file'); return { batch: prior.id, state: prior.state, report: prior.report, replay: true }; }
        const existing = (await c.query(`select name, department, role, period_start, period_end from certificates where state not in ('rejected')`)).rows.map(rowKey);
        const approved = (await c.query(`select id::text from contributions where status='verified' and reviewed_by is not null and reviewed_by <> submitted_by`)).rows.map(r => r.id);
        const report = validateBulk(csv, mapping, { existingKeys: existing, approvedRefs: approved });
        need(!report.errors.length, 400, report.errors.join('; '));
        const { rows } = await c.query(`insert into bulk_batches(idempotency_key, csv_sha256, report, created_by) values ($1,$2,$3,$4) returning id`,
          [idempotencyKey, sha, JSON.stringify(report), user.id]);
        await appendAudit(c, { actor: user.id, action: 'bulk.validate', details: { batch: rows[0].id, rows: report.rows.length, ok: report.rows.filter(r => r.ok).length } });
        return { batch: rows[0].id, state: 'validated', report };
      });
    },
    async bulkDraft(user, batchId) {
      need(has(user, 'issuer'), 403, 'Issuer role required');
      return tx(pool, async c => {
        const b = (await c.query('select * from bulk_batches where id=$1 for update', [batchId])).rows[0]; need(b, 404, 'Batch not found');
        need(b.created_by === user.id, 403, 'Only the batch creator can draft it');
        if (b.state === 'drafted') return { batch: b.id, created: (await c.query('select id from certificates where batch_id=$1 order by id', [b.id])).rows.map(r => r.id), replay: true };
        const created = [];
        for (const r of b.report.rows.filter(r => r.ok)) {
          const d = r.data;
          const contrib = (await c.query(`select volunteer_id from contributions where id=$1 and status='verified'`, [d.contribution_ref])).rows[0];
          need(contrib, 409, `Line ${r.line}: contribution no longer verified`);
          const id = newCertificateId();
          await c.query(`insert into certificates(id, state, name, department, role, period_start, period_end, hours, volunteer_email, created_by, volunteer_id, contribution_id, batch_id)
            values ($1,'draft',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
            [id, d.name, d.department, d.role, d.period_start, d.period_end, d.hours, d.volunteer_email || null, user.id, contrib.volunteer_id, d.contribution_ref, b.id]);
          await appendAudit(c, { actor: user.id, action: 'draft.create', certId: id, details: { batch: b.id, line: r.line } });
          created.push(id);
        }
        await c.query(`update bulk_batches set state='drafted', drafted_at=now() where id=$1`, [b.id]);
        await appendAudit(c, { actor: user.id, action: 'bulk.draft', details: { batch: b.id, created: created.length } });
        return { batch: b.id, created };
      });
    },
    async bulkReport(user, batchId) {
      need(has(user, 'issuer') || has(user, 'approver'), 403, 'Staff role required');
      const b = (await pool.query('select * from bulk_batches where id=$1', [batchId])).rows[0]; need(b, 404, 'Batch not found');
      const certs = (await pool.query('select id, state, name, contribution_id from certificates where batch_id=$1 order by id', [b.id])).rows;
      const esc = v => /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v ?? '');
      const lines = [['line', 'name', 'status', 'errors', 'flags', 'certificate_id', 'certificate_state'].join(',')];
      for (const r of b.report.rows) {
        const cert = certs.find(x => x.contribution_id === r.data.contribution_ref && x.name === r.data.name);
        lines.push([r.line, r.data.name, r.ok ? 'accepted' : 'held', r.errors.join('; '), r.flags.join('; '), cert?.id || '', cert?.state || ''].map(esc).join(','));
      }
      return lines.join('\n') + '\n';
    },
  };
}
