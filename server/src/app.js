import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';
import fs from 'node:fs';
import path from 'node:path';
import { ID_RE } from '../../shared/apex-verify.js';
import { HttpError } from './db.js';
import { COOKIE, login, logout, userFromRequest, publicUser } from './auth.js';
import { createIssuance } from './issuance.js';
import { verifyChain } from './audit.js';
import { createPassport } from './passport.js';
import { PUBLIC_ID_RE } from '../../shared/passport-rules.js';

const PUBLIC_FILES = new Set(['APEX Verify.dc.html', 'APEX Certificate.dc.html', 'APEX Certificate V4 - Hybrid Clean.dc.html', 'APEX Issuance & Security.dc.html', 'APEX Volunteer Passport.dc.html', 'APEX Certificates Admin.dc.html', 'support.js']);
const PUBLIC_DIRS = ['shared/', '_ds/'];

export async function buildApp({ cfg, pool, signer, signers, renderPdf, logger = true }) {
  const app = Fastify({ logger, trustProxy: cfg.trustProxy, bodyLimit: 64 * 1024 });
  // Pre-existing bug, found by real integration testing (not previously run
  // against a live server): Fastify 5's default JSON parser rejects an
  // EMPTY body sent with `content-type: application/json` -- a 400 before
  // any route or auth code ever runs. Several admin actions (submit,
  // approve, sign, publish, revoke with no reason, reissue with no
  // overrides, logout) are legitimately bodyless POSTs, so a bodyless
  // JSON-typed request must be treated as `{}`, not rejected. This changes
  // no validation, authorization, or signing logic -- only what an empty
  // request body parses to.
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (req, body, done) => {
    if (body === '') { done(null, {}); return; }
    try { done(null, JSON.parse(body)); } catch (err) { err.statusCode = 400; done(err); }
  });
  // `signers` is optional here -- callers that never touch certificate
  // issuance/signing (e.g. passport.test.js, which predates the signer
  // feature and exercises an unrelated subsystem) shouldn't be forced to
  // construct one. Fall back to the same config-derived default shape
  // signers.js itself returns when its own DB table is empty, so a real
  // deploy (index.js always passes a real `signers`) is unaffected.
  const defaultSigners = () => {
    const [s1, s2] = (cfg.signers || []).map((s) => { const [name, title] = s.split('|'); return { name, title }; });
    return { signer1: s1, signer2: s2 };
  };
  const getSigners = signers?.get ?? defaultSigners;
  const svc = createIssuance({ pool, cfg, signer, renderPdf, getSigners });
  const pp = createPassport({ pool, cfg });
  await app.register(cookie);
  await app.register(rateLimit, { max: 300, timeWindow: '1 minute' });

  app.addHook('onSend', async (req, reply) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Referrer-Policy', 'no-referrer');
    // This authenticated PDF is embedded in our own Admin page via an iframe.
    // Keep all other pages unframeable, but allow this route on the same origin.
    const adminPdfPreview = req.method === 'GET' &&
      /^\/api\/v1\/admin\/certificates\/[^/?]+\/pdf(?:\?.*)?$/.test(req.url);
    reply.header('X-Frame-Options', adminPdfPreview ? 'SAMEORIGIN' : 'DENY');
    if (cfg.secureCookies) reply.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  });
  app.setErrorHandler((err, req, reply) => {
    const status = err.statusCode && err.statusCode < 500 ? err.statusCode : 500;
    if (status === 500) req.log.error(err);
    reply.code(status).send({ error: status === 500 ? 'Internal error' : err.message });
  });

  // ---------- static web (allow-list only) ----------
  await app.register(fastifyStatic, {
    root: cfg.webRoot, serve: false
  });
  const serveWeb = async (rel, reply) => {
    const ok = PUBLIC_FILES.has(rel) || PUBLIC_DIRS.some(d => rel.startsWith(d) && !rel.includes('..'));
    if (!ok) throw new HttpError(404, 'Not found');
    if (rel === 'APEX Verify.dc.html' || rel === 'APEX Volunteer Passport.dc.html') {
      // Trust is determined by this server's configured environment, not by
      // the certificate QR, record payload, URL params or browser inputs.
      const verifierEnvMeta = rel === 'APEX Verify.dc.html'
        ? '\n<meta name="apex-verification-env" content="' + cfg.env + '">'
        : '';
      const html = fs.readFileSync(path.join(cfg.webRoot, rel), 'utf8')
        .replace('<head>', '<head>\n<meta name="apex-api-base" content="/api/v1">' + verifierEnvMeta);
      return reply.type('text/html; charset=utf-8').header('Cache-Control', 'no-store').send(html);
    }
    return reply.sendFile(rel);
  };
  app.get('/', (req, reply) => reply.redirect('/APEX%20Verify.dc.html'));
  app.get('/c/:id', (req, reply) => {
    const id = String(req.params.id).toUpperCase();
    if (!ID_RE.test(id)) throw new HttpError(404, 'Not found');
    return reply.redirect(`/APEX%20Verify.dc.html?id=${encodeURIComponent(id)}`);
  });
  app.get('/volunteers/:pid', (req, reply) => {
    const pid = String(req.params.pid).toLowerCase();
    if (!PUBLIC_ID_RE.test(pid)) throw new HttpError(404, 'Not found');
    return reply.redirect(`/APEX%20Volunteer%20Passport.dc.html?v=${encodeURIComponent(pid)}`);
  });
  app.get('/_fonts/:f', (req, reply) => {
    if (!/^SourceSerif4-[A-Za-z]+\.woff2$/.test(req.params.f)) throw new HttpError(404, 'Not found');
    return reply.sendFile(req.params.f, cfg.fontDir, { maxAge: '365d', immutable: true });
  });
  app.get('/*', (req, reply) => serveWeb(decodeURIComponent(req.params['*']), reply));

  // ---------- public API ----------
  const publicLimit = { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } };
  app.get('/api/v1/keys.json', publicLimit, async (req, reply) => { reply.header('Cache-Control', 'public, max-age=300'); return svc.keys(); });
  app.get('/api/v1/certificates/:file', publicLimit, async (req, reply) => {
    const m = /^(.+)\.(json|pdf)$/.exec(req.params.file || '');
    if (!m || !ID_RE.test(m[1])) throw new HttpError(404, 'Not found');
    reply.header('Cache-Control', 'no-store');
    if (m[2] === 'json') {
      const rec = await svc.publicRecord(m[1]);
      if (!rec) throw new HttpError(404, 'Not found');
      return rec;
    }
    const pdf = await svc.publicPdf(m[1]);
    if (!pdf) throw new HttpError(404, 'Not found');
    return reply.type('application/pdf').header('Content-Disposition', `attachment; filename="${m[1]}.pdf"`).send(pdf);
  });

  app.get('/api/v1/volunteers/:pid', publicLimit, async (req, reply) => {
    const pid = String(req.params.pid).replace(/\.json$/, '');
    reply.header('Cache-Control', 'no-store');
    const p = await pp.publicPassport(pid);
    if (!p) throw new HttpError(404, 'Not found'); // same response for private, disabled and unknown profiles
    return p;
  });
  app.get('/api/v1/badges/:id', publicLimit, async (req) => {
    const b = await pp.publicBadge(String(req.params.id).replace(/\.json$/, ''));
    if (!b) throw new HttpError(404, 'Not found');
    return b;
  });

  // ---------- admin API ----------
  const authed = async (req) => {
    if (req.method !== 'GET' && req.headers['x-apex-csrf'] !== '1') throw new HttpError(403, 'Missing CSRF header');
    const u = await userFromRequest(pool, req);
    if (!u) throw new HttpError(401, 'Authentication required');
    req.user = u;
  };
  app.post('/api/v1/admin/login', { config: { rateLimit: { max: 10, timeWindow: '15 minutes' } } }, async (req, reply) => {
    if (req.headers['x-apex-csrf'] !== '1') throw new HttpError(403, 'Missing CSRF header');
    const { token, user } = await login(pool, cfg, req.body || {}, req.ip);
    reply.setCookie(COOKIE, token, { path: '/', httpOnly: true, secure: cfg.secureCookies, sameSite: 'strict', maxAge: cfg.sessionHours * 3600 });
    return { user };
  });
  app.register(async (r) => {
    r.addHook('preHandler', authed);
    r.post('/logout', async (req, reply) => { await logout(pool, req); reply.clearCookie(COOKIE, { path: '/' }); return { ok: true }; });
    r.get('/session', async (req) => ({ user: publicUser(req.user) }));
    r.get('/certificates', async () => ({ certificates: await svc.list() }));
    r.get('/certificates/:id', async (req) => { const c = await svc.get(req.params.id); if (!c) throw new HttpError(404, 'Not found'); return c; });
    // Admin-only PDF preview/download -- deliberately separate from the
    // PUBLIC `/api/v1/certificates/:id.pdf` route in the section above,
    // which only ever serves published/revoked/superseded states (by
    // design: an unpublished certificate must never be reachable by its
    // predictable id before an admin chooses to publish it). This one
    // serves the SAME stored `pdf` bytes for ANY state once `sign()` has
    // produced them, so an authorized admin can actually see/test the
    // real rendered output before publishing -- never a second render,
    // never mock bytes.
    r.get('/certificates/:id/pdf', async (req, reply) => {
      const { rows } = await pool.query('select pdf from certificates where id=$1', [req.params.id]);
      if (!rows[0]?.pdf) throw new HttpError(404, 'Not signed yet -- no PDF to preview');
      reply.type('application/pdf').header('Content-Disposition', `inline; filename="${req.params.id}.pdf"`);
      return rows[0].pdf;
    });
    r.post('/certificates', async (req) => svc.create(req.user, req.body));
    r.put('/certificates/:id', async (req) => { await svc.update(req.user, req.params.id, req.body); return { ok: true }; });
    for (const a of ['submit', 'approve', 'sign', 'publish'])
      r.post(`/certificates/:id/${a}`, async (req) => (await svc[a](req.user, req.params.id)) || { ok: true });
    r.post('/certificates/:id/reject', async (req) => { await svc.reject(req.user, req.params.id, req.body?.note); return { ok: true }; });
    r.post('/certificates/:id/revoke', async (req) => { await svc.revoke(req.user, req.params.id, req.body?.reason); return { ok: true }; });
    r.post('/certificates/:id/reissue', async (req) => svc.reissue(req.user, req.params.id, req.body && Object.keys(req.body).length ? req.body : null));
    r.get('/audit', async (req) => {
      const { rows } = req.query.cert
        ? await pool.query(`select a.*, u.display_name as actor_name from audit_events a left join users u on u.id=a.actor where cert_id=$1 order by seq`, [req.query.cert])
        : await pool.query(`select a.*, u.display_name as actor_name from audit_events a left join users u on u.id=a.actor order by seq desc limit 200`);
      return { events: rows };
    });
    r.get('/volunteers', async (req) => ({ volunteers: await pp.listVolunteers(req.user) }));
    r.post('/volunteers', async (req) => pp.createVolunteer(req.user, req.body));
    r.post('/volunteers/:pid/contributions', async (req) => pp.submitContribution(req.user, req.body, req.params.pid));
    r.get('/contributions/queue', async (req) => ({ contributions: await pp.reviewQueue(req.user) }));
    r.post('/contributions/:id/review', async (req) => { await pp.reviewContribution(req.user, req.params.id, req.body?.decision, req.body?.note); return { ok: true }; });
    r.post('/badges', async (req) => pp.awardBadge(req.user, req.body));
    r.post('/badges/:id/revoke', async (req) => { await pp.revokeBadge(req.user, req.params.id, req.body?.reason); return { ok: true }; });
    r.post('/bulk/validate', { bodyLimit: 600 * 1024 }, async (req) => pp.bulkValidate(req.user, req.body));
    r.post('/bulk/:id/draft', async (req) => pp.bulkDraft(req.user, req.params.id));
    r.get('/bulk/:id/report.csv', async (req, reply) => reply.type('text/csv; charset=utf-8').send(await pp.bulkReport(req.user, req.params.id)));
    r.get('/audit/verify', async () => verifyChain((await pool.query('select * from audit_events order by seq')).rows));
    // Admin-configurable signer name/title printed on the certificate
    // (see signers.js / migration 003). Not a template system -- just
    // the two fixed signature slots the existing design already has,
    // made editable without a deploy. `update` itself enforces the
    // 'admin' role and writes a real audit_events row; GET is open to
    // any authenticated admin-area user (same as every other read in
    // this block) since it's non-sensitive, already-public-on-the-PDF
    // information.
    r.get('/signers', async () => ({ signers: await signers.get() }));
    r.put('/signers/:slot', async (req) => signers.update(req.user, req.params.slot, req.body));
  }, { prefix: '/api/v1/admin' });

  // ---------- volunteer self-service ----------
  app.register(async (r) => {
    r.addHook('preHandler', authed);
    r.get('/', async (req) => pp.me(req.user));
    r.put('/privacy', async (req) => ({ privacy: await pp.setPrivacy(req.user, req.body) }));
    r.post('/contributions', async (req) => pp.submitContribution(req.user, req.body));
    r.post('/contributions/:id/withdraw', async (req) => { await pp.withdrawContribution(req.user, req.params.id); return { ok: true }; });
  }, { prefix: '/api/v1/me' });

  return app;
}
