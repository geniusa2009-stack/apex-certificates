// APEX Volunteer Passport — pure rules shared by server and browser. No I/O, no secrets.
// Only VERIFIED contributions, PUBLISHED (or historically valid) certificates and ACTIVE badge awards may ever be public.

export const BADGE_CATEGORIES = ['leadership', 'research', 'community-management', 'event-organization', 'communication',
  'teamwork', 'mentorship', 'project-coordination', 'innovation', 'outstanding-contribution'];
export const CONTRIBUTION_STATES = ['pending', 'verified', 'rejected', 'withdrawn'];
export const PRIVACY_KEYS = ['profile_public', 'show_photo', 'show_hours', 'show_certificates', 'show_badges', 'show_contributions', 'show_evidence_links'];
export const DEFAULT_PRIVACY = Object.freeze({ profile_public: false, show_photo: false, show_hours: true, show_certificates: true,
  show_badges: true, show_contributions: true, show_evidence_links: false });
// Fields that must never leave the server on a public route, whatever the privacy settings say.
export const NEVER_PUBLIC = ['email', 'phone', 'birth_date', 'address', 'internal_notes', 'user_id', 'review_note'];
export const PUBLIC_ID_RE = /^v-[0-9a-hjkmnp-tv-z]{10,16}$/;

export function normalizePrivacy(p) {
  const out = { ...DEFAULT_PRIVACY };
  for (const k of PRIVACY_KEYS) if (p && typeof p[k] === 'boolean') out[k] = p[k];
  return out;
}

export function bucketContributions(list) {
  const b = { verified: [], pending: [], closed: [] };
  for (const c of list || []) {
    if (c.status === 'verified' && c.reviewed_by && c.reviewed_by !== c.submitted_by) b.verified.push(c);
    else if (c.status === 'pending') b.pending.push(c);
    else b.closed.push(c);
  }
  const byDate = (a, z) => String(z.end || z.start).localeCompare(String(a.end || a.start));
  b.verified.sort(byDate); b.pending.sort(byDate); b.closed.sort(byDate);
  return b;
}

// Hours count only from contributions that passed independent review.
export const verifiedHours = list => bucketContributions(list).verified.reduce((s, c) => s + (Number.isInteger(c.hours) && c.hours > 0 ? c.hours : 0), 0);

const CERT_PUBLIC = new Set(['published', 'revoked', 'superseded']);
const pick = (o, keys) => Object.fromEntries(keys.filter(k => o[k] !== undefined).map(k => [k, o[k]]));

// The only function that may build a public passport response.
export function publicProfile({ volunteer, privacy, contributions, certificates, awards, badgeClasses }) {
  const p = normalizePrivacy(privacy);
  if (!volunteer || volunteer.disabled || !p.profile_public) return null;
  const verified = bucketContributions(contributions).verified;
  const out = {
    v: 1, public_id: volunteer.public_id, display_name: volunteer.display_name,
    photo_url: p.show_photo && volunteer.photo_approved ? volunteer.photo_url || null : null,
    roles: [...new Set(verified.map(c => c.role))],
    projects: [...new Set(verified.map(c => c.project))],
  };
  if (p.show_hours) out.verified_hours = verifiedHours(contributions);
  if (p.show_contributions) out.contributions = verified.map(c => ({
    ...pick(c, ['id', 'project', 'role', 'start', 'end', 'hours', 'summary']),
    evidence: p.show_evidence_links ? (c.evidence || []).filter(e => e && e.public === true).map(e => pick(e, ['label', 'url'])) : [],
  }));
  if (p.show_certificates) out.certificates = (certificates || []).filter(c => CERT_PUBLIC.has(c.state))
    .map(c => ({ ...pick(c, ['id', 'department', 'role', 'period_start', 'period_end', 'hours', 'issued_at']), state: c.state }));
  if (p.show_badges) {
    const cls = new Map((badgeClasses || []).map(b => [b.id, b]));
    out.badges = (awards || []).filter(a => a.status === 'active' && cls.has(a.badge_class_id))
      .map(a => ({ id: a.id, badge: cls.get(a.badge_class_id).name, category: cls.get(a.badge_class_id).category, issued_at: a.issued_at }));
  }
  for (const k of NEVER_PUBLIC) if (k in out) delete out[k];
  return out;
}

// A badge may only be awarded with verified evidence belonging to the recipient, or an authorised assessment.
export function validateBadgeAward({ recipientId, badgeClass, evidenceIds, assessment, awardedBy }, contributions) {
  const errs = [];
  if (!badgeClass || !BADGE_CATEGORIES.includes(badgeClass.category)) errs.push('Unknown badge category');
  if (badgeClass && badgeClass.active === false) errs.push('Badge class is retired');
  const ids = Array.isArray(evidenceIds) ? [...new Set(evidenceIds)] : [];
  const byId = new Map((contributions || []).map(c => [c.id, c]));
  const verifiedIds = new Set(bucketContributions(contributions).verified.map(c => c.id));
  for (const id of ids) {
    const c = byId.get(id);
    if (!c) errs.push(`Evidence ${id} not found`);
    else if (c.volunteer_id !== recipientId) errs.push(`Evidence ${id} belongs to another volunteer`);
    else if (!verifiedIds.has(id)) errs.push(`Evidence ${id} is not a verified contribution`);
  }
  const hasAssessment = assessment && typeof assessment.note === 'string' && assessment.note.trim().length >= 20 && assessment.assessor && assessment.assessor !== recipientId;
  if (ids.length === 0 && !hasAssessment) errs.push('Verified evidence or an authorised assessment is required');
  if (awardedBy === recipientId) errs.push('Volunteers cannot award badges to themselves');
  return errs;
}

// Open Badges 3.0-shaped JSON (unsigned). Aligned structurally; not a certified OB 3.0 / W3C VC implementation.
export function toOpenBadge(award, badgeClass, { issuerName = 'APEX', issuerUrl, verifyBase }) {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'],
    id: `${verifyBase}/badges/${award.id}`,
    type: ['VerifiableCredential', 'OpenBadgeCredential'],
    issuer: { id: issuerUrl, type: ['Profile'], name: issuerName },
    validFrom: award.issued_at,
    name: badgeClass.name,
    credentialSubject: {
      type: ['AchievementSubject'],
      id: `${verifyBase}/volunteers/${award.recipient_public_id}`,
      achievement: { id: `${verifyBase}/badge-classes/${badgeClass.id}`, type: ['Achievement'], name: badgeClass.name,
        description: badgeClass.description, criteria: { narrative: badgeClass.criteria }, achievementType: 'Competency' },
    },
    evidence: (award.evidence || []).map(e => ({ type: ['Evidence'], id: `${verifyBase}/contributions/${e}` })),
    credentialStatus: { type: 'APEXRegistryStatus', status: award.status },
  };
}

// ---------- bulk issuance ----------
export const BULK_COLUMNS = ['name', 'department', 'role', 'period_start', 'period_end', 'hours', 'volunteer_email', 'contribution_ref'];
const TEXT = /^[\p{L}\p{M}\p{N} .,'’&()\/-]{2,120}$/u;
const MONTH = /^\d{4}-(0[1-9]|1[0-2])$/;

export function parseCsv(text) {
  const rows = []; let row = [], f = '', q = false;
  const s = String(text).replace(/^\uFEFF/, '');
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (q) { if (ch === '"') { if (s[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += ch; continue; }
    if (ch === '"' && f === '') q = true;
    else if (ch === ',') { row.push(f); f = ''; }
    else if (ch === '\n' || ch === '\r') { if (ch === '\r' && s[i + 1] === '\n') i++; row.push(f); f = ''; if (row.some(x => x !== '')) rows.push(row); row = []; }
    else f += ch;
  }
  if (q) throw new Error('Unterminated quoted field');
  row.push(f); if (row.some(x => x !== '')) rows.push(row);
  return rows;
}

const clean = v => String(v ?? '').normalize('NFC').trim().replace(/\s+/g, ' ');
export const rowKey = r => [r.name.toLowerCase(), r.department.toLowerCase(), r.role.toLowerCase(), r.period_start, r.period_end].join('|');

// mapping: { csvHeader: BULK_COLUMN }. existingKeys: rowKeys of certificates already drafted/issued.
// approvedRefs: ids of verified contributions; every row must reference one.
export function validateBulk(text, mapping, { existingKeys = [], approvedRefs = [], maxRows = 500 } = {}) {
  const grid = parseCsv(text);
  if (grid.length < 2) return { rows: [], errors: ['CSV has no data rows'] };
  const header = grid[0].map(clean);
  const idx = {};
  for (const [h, col] of Object.entries(mapping || {})) { const i = header.indexOf(h); if (i >= 0 && BULK_COLUMNS.includes(col)) idx[col] = i; }
  const missing = ['name', 'department', 'role', 'period_start', 'period_end', 'hours', 'contribution_ref'].filter(c => !(c in idx));
  if (missing.length) return { rows: [], errors: ['Unmapped required columns: ' + missing.join(', ')] };
  if (grid.length - 1 > maxRows) return { rows: [], errors: [`Too many rows (max ${maxRows})`] };
  const seen = new Map(), existing = new Set(existingKeys), refs = new Set(approvedRefs);
  const rows = grid.slice(1).map((cells, n) => {
    const r = {}; for (const c of BULK_COLUMNS) r[c] = c in idx ? clean(cells[idx[c]]) : '';
    const errors = [], flags = [];
    for (const k of ['name', 'department', 'role']) if (!TEXT.test(r[k])) errors.push(`Invalid ${k}`);
    for (const k of ['period_start', 'period_end']) if (!MONTH.test(r[k])) errors.push(`Invalid ${k} (YYYY-MM)`);
    if (MONTH.test(r.period_start) && MONTH.test(r.period_end) && r.period_end < r.period_start) errors.push('period_end before period_start');
    const h = /^\d+$/.test(r.hours) ? Number(r.hours) : NaN;
    if (!(h >= 1 && h <= 10000)) errors.push('Invalid hours'); else r.hours = h;
    if (r.volunteer_email && !/^[^\s@]{1,64}@[^\s@]{1,190}\.[a-z]{2,}$/i.test(r.volunteer_email)) errors.push('Invalid volunteer_email');
    if (!r.contribution_ref) errors.push('Missing contribution_ref');
    else if (!refs.has(r.contribution_ref)) flags.push('missing_approval');
    if (!errors.length) {
      const k = rowKey(r);
      if (seen.has(k)) flags.push(`duplicate_of_row_${seen.get(k)}`); else seen.set(k, n + 2);
      if (existing.has(k)) flags.push('already_issued');
    }
    return { line: n + 2, data: r, errors, flags, ok: errors.length === 0 && flags.length === 0 };
  });
  return { rows, errors: [] };
}

// ---------- sharing ----------
export function linkedInAddUrl(cert, verifyBase) {
  const [y, m] = String(cert.issued_at || '').split('-');
  const q = new URLSearchParams({ startTask: 'CERTIFICATION_NAME', name: `Volunteer Recognition — ${cert.role}`, organizationName: 'APEX',
    issueYear: y || '', issueMonth: m ? String(Number(m)) : '', certUrl: `${verifyBase}/c/${cert.id}`, certId: cert.id });
  return 'https://www.linkedin.com/profile/add?' + q.toString();
}
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
export const fmtMonth = ym => { const [y, m] = String(ym).split('-'); return m ? `${MON[Number(m) - 1]} ${y}` : String(ym); };
export function cvLine(cert, verifyBase) {
  return `${cert.role}, ${cert.department} — APEX (${fmtMonth(cert.period_start)}–${fmtMonth(cert.period_end)}). ${cert.hours} verified volunteer hours. Credential ${cert.id}, verify at ${verifyBase}/c/${cert.id}`;
}
