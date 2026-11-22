import { createHash } from 'node:crypto';
import { tx, HttpError } from './db.js';
import { appendAudit } from './audit.js';
import { assertAllowed, validateDraft, newCertificateId, buildPayload } from './rules.js';
import { signingInput, recordHash as computeRecordHash } from '../../shared/apex-verify.js';

const LIST_COLS = `id, state, name, department, role, period_start, period_end, hours, issued_at, supersedes, review_note,
  created_by, submitted_by, approved_by, signed_by, published_by, kid, record_hash, pdf_sha256, created_at, updated_at`;

export function createIssuance({ pool, cfg, signer, renderPdf, getSigners }) {
  // One PDF render at a time per server instance: Render Free has limited RAM.
  // Prevents duplicate sign requests from racing or spawning many Chromium contexts.
  let signInProgress = false;
  const lockCert = async (c, id) => {
    const { rows } = await c.query('select * from certificates where id = $1 for update', [id]);
    if (!rows[0]) throw new HttpError(404, 'Certificate not found');
    return rows[0];
  };
  const statusStatement = async (id, status, extra) => {
    const st = { v: 1, type: 'status', id, kid: signer.kid, status, superseded_by: null, reason: '', at: new Date().toISOString(), ...extra };
    return { st, sig: await signer.sign(signingInput('status', st)) };
  };

  return {
    async list() { return (await pool.query(`select ${LIST_COLS} from certificates order by updated_at desc limit 500`)).rows; },
    async get(id) { return (await pool.query(`select ${LIST_COLS}, volunteer_email from certificates where id = $1`, [id])).rows[0]; },

    async create(user, input) {
      assertAllowed('create', user);
      const d = validateDraft(input);
      return tx(pool, async c => {
        const id = newCertificateId();
        await c.query(`insert into certificates(id, state, name, department, role, period_start, period_end, hours, volunteer_email, created_by)
          values ($1,'draft',$2,$3,$4,$5,$6,$7,$8,$9)`, [id, d.name, d.department, d.role, d.period_start, d.period_end, d.hours, d.volunteer_email, user.id]);
        await appendAudit(c, { actor: user.id, action: 'draft.create', certId: id });
        return { id };
      });
    },
    async update(user, id, input) {
      const d = validateDraft(input);
      return tx(pool, async c => {
        const cert = await lockCert(c, id); assertAllowed('update', user, cert);
        await c.query(`update certificates set name=$2, department=$3, role=$4, period_start=$5, period_end=$6, hours=$7, volunteer_email=$8, state='draft' where id=$1`,
          [id, d.name, d.department, d.role, d.period_start, d.period_end, d.hours, d.volunteer_email]);
        await appendAudit(c, { actor: user.id, action: 'draft.update', certId: id });
      });
    },
    async submit(user, id) {
      return tx(pool, async c => {
        const cert = await lockCert(c, id); assertAllowed('submit', user, cert);
        await c.query(`update certificates set state='in_review', submitted_by=$2, review_note=null where id=$1`, [id, user.id]);
        await appendAudit(c, { actor: user.id, action: 'review.submit', certId: id });
      });
    },
    async approve(user, id) {
      return tx(pool, async c => {
        const cert = await lockCert(c, id); assertAllowed('approve', user, cert);
        await c.query(`update certificates set state='approved', approved_by=$2 where id=$1`, [id, user.id]);
        await appendAudit(c, { actor: user.id, action: 'review.approve', certId: id });
      });
    },
    async reject(user, id, note) {
      if (typeof note !== 'string' || note.trim().length < 3 || note.length > 500) throw new HttpError(400, 'A rejection note is required');
      return tx(pool, async c => {
        const cert = await lockCert(c, id); assertAllowed('reject', user, cert);
        await c.query(`update certificates set state='rejected', approved_by=null, review_note=$2 where id=$1`, [id, note.trim()]);
        await appendAudit(c, { actor: user.id, action: 'review.reject', certId: id, details: { note: note.trim() } });
      });
    },
    // Sign: canonical payload → Ed25519 → render PDF → SHA-256 of exact bytes → signed PDF attestation. All built from the stored approved row.
    async sign(user, id) {
      if (signInProgress) throw new HttpError(409, 'A certificate signing operation is already in progress; please retry after it finishes');
      signInProgress = true;
      try {
      const pre = (await pool.query('select * from certificates where id=$1', [id])).rows[0];
      if (!pre) throw new HttpError(404, 'Certificate not found');
      assertAllowed('sign', user, pre);
      const issuedAt = new Date().toISOString().slice(0, 10);
      const payload = buildPayload(pre, { env: cfg.env, kid: signer.kid, issuedAt });
      const signature = await signer.sign(signingInput('cert', payload));
      const rHash = await computeRecordHash(payload);
      // Admin-configurable signer name/title (cert_signers table, migration
      // 003) -- read fresh at sign time so a later edit to the signers
      // never changes what an already-signed certificate says (the PDF
      // bytes are hashed and Ed25519-signed right after this call), while
      // every NEW signature always uses whatever is current.
      const signers = await getSigners();
      const pdf = await renderPdf(payload, rHash, signers);
      const pdfSha = createHash('sha256').update(pdf).digest('hex');
      const pdfSt = { v: 1, type: 'pdf', id, kid: signer.kid, sha256: pdfSha, bytes: pdf.length, record_hash: rHash };
      const pdfSig = await signer.sign(signingInput('pdf', pdfSt));
      return tx(pool, async c => {
        const cert = await lockCert(c, id); assertAllowed('sign', user, cert);
        if (cert.updated_at.getTime() !== pre.updated_at.getTime()) throw new HttpError(409, 'Certificate changed during signing; retry');
        await c.query(`update certificates set state='signed', signed_by=$2, issued_at=$3, payload=$4, signature=$5, record_hash=$6, kid=$7,
          pdf=$8, pdf_sha256=$9, pdf_statement=$10, pdf_signature=$11 where id=$1`,
          [id, user.id, issuedAt, payload, signature, rHash, signer.kid, pdf, pdfSha, pdfSt, pdfSig]);
        await appendAudit(c, { actor: user.id, action: 'certificate.sign', certId: id, details: { kid: signer.kid, record_hash: rHash, pdf_sha256: pdfSha } });
        return { record_hash: rHash, pdf_sha256: pdfSha };
      });
      } finally {
        signInProgress = false;
      }
    },
    async publish(user, id) {
      const pre = (await pool.query('select * from certificates where id=$1', [id])).rows[0];
      if (!pre) throw new HttpError(404, 'Certificate not found');
      assertAllowed('publish', user, pre);
      const sup = pre.supersedes ? await statusStatement(pre.supersedes, 'superseded', { superseded_by: id, reason: `Replaced by ${id}.` }) : null;
      return tx(pool, async c => {
        const cert = await lockCert(c, id); assertAllowed('publish', user, cert);
        await c.query(`update certificates set state='published', published_by=$2 where id=$1`, [id, user.id]);
        if (sup) {
          const old = await lockCert(c, cert.supersedes);
          if (old.state !== 'published') throw new HttpError(409, `Superseded certificate ${old.id} is ${old.state}`);
          await c.query(`update certificates set state='superseded', status_statement=$2, status_signature=$3 where id=$1`, [old.id, sup.st, sup.sig]);
          await appendAudit(c, { actor: user.id, action: 'certificate.supersede', certId: old.id, details: { superseded_by: id } });
        }
        await appendAudit(c, { actor: user.id, action: 'certificate.publish', certId: id });
      });
    },
    async revoke(user, id, reason) {
      if (typeof reason !== 'string' || reason.trim().length < 5 || reason.length > 300) throw new HttpError(400, 'A revocation reason is required');
      const pre = (await pool.query('select * from certificates where id=$1', [id])).rows[0];
      if (!pre) throw new HttpError(404, 'Certificate not found');
      assertAllowed('revoke', user, pre);
      const s = await statusStatement(id, 'revoked', { reason: reason.trim() });
      return tx(pool, async c => {
        const cert = await lockCert(c, id); assertAllowed('revoke', user, cert);
        await c.query(`update certificates set state='revoked', status_statement=$2, status_signature=$3 where id=$1`, [id, s.st, s.sig]);
        await appendAudit(c, { actor: user.id, action: 'certificate.revoke', certId: id, details: { reason: reason.trim() } });
      });
    },
    async reissue(user, id, input) {
      return tx(pool, async c => {
        const old = await lockCert(c, id); assertAllowed('reissue', user, old);
        const d = validateDraft(input || { name: old.name, department: old.department, role: old.role, period_start: old.period_start, period_end: old.period_end, hours: old.hours, volunteer_email: old.volunteer_email });
        const nid = newCertificateId();
        await c.query(`insert into certificates(id, state, name, department, role, period_start, period_end, hours, volunteer_email, created_by, supersedes)
          values ($1,'draft',$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [nid, d.name, d.department, d.role, d.period_start, d.period_end, d.hours, d.volunteer_email, user.id, id]);
        await appendAudit(c, { actor: user.id, action: 'draft.reissue', certId: nid, details: { supersedes: id } });
        return { id: nid };
      });
    },

    // Public view: only published/revoked/superseded rows, only signed fields.
    async publicRecord(id) {
      const { rows } = await pool.query(`select state, payload, signature, pdf_statement, pdf_signature, status_statement, status_signature
        from certificates where id = $1 and state in ('published','revoked','superseded')`, [id]);
      const r = rows[0]; if (!r) return null;
      return {
        state: r.state === 'published' ? 'valid' : r.state,
        certificate: { payload: r.payload, signature: r.signature },
        status: r.status_statement ? { statement: r.status_statement, signature: r.status_signature } : null,
        pdf: { statement: r.pdf_statement, signature: r.pdf_signature, url: `/api/v1/certificates/${id}.pdf` }
      };
    },
    async publicPdf(id) {
      const { rows } = await pool.query(`select pdf from certificates where id = $1 and state in ('published','revoked','superseded')`, [id]);
      return rows[0]?.pdf || null;
    },
    async keys() {
      const { rows } = await pool.query(`select kid, alg, public_key, status, env, created_at as not_before, retired_at from signing_keys where env = $1 order by created_at`, [cfg.env]);
      return { keys: rows };
    }
  };
}
