// Server-side PDF: renders the existing "APEX Certificate.dc.html" design in headless Chromium with the approved record
// injected, then normalises metadata so output is stable. Fails closed on missing fonts, drift, overflow or wrong size.
import { chromium } from 'playwright';
import { PDFDocument } from 'pdf-lib';
import QRCode from 'qrcode';
import fs from 'node:fs';
import path from 'node:path';

export const FONT_FILES = {
  'SourceSerif4-Regular.woff2': '400 normal', 'SourceSerif4-Semibold.woff2': '600 normal', 'SourceSerif4-It.woff2': '400 italic'
};
const A4 = { w: 841.89, h: 595.28 };
const PDF_TEMPLATES = Object.freeze({
  classic_v1: { file: 'APEX Certificate.dc.html', screenLabel: 'Certificate' },
  hybrid_v4: { file: 'APEX Certificate V4 - Hybrid Clean.dc.html', screenLabel: 'APEX Hybrid Certificate V4' }
});
export function selectPdfTemplate(templateId = 'classic_v1') {
  if (!Object.prototype.hasOwnProperty.call(PDF_TEMPLATES, templateId)) {
    throw new Error('Unsupported certificate PDF template');
  }
  return PDF_TEMPLATES[templateId];
}
const fmtMonth = s => { const [y, m] = s.split('-'); return new Date(Date.UTC(+y, +m - 1, 1)).toLocaleString('en-GB', { month: 'short', year: 'numeric', timeZone: 'UTC' }); };
const fmtDate = s => new Date(s + 'T00:00:00Z').toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });

export function assertFonts(fontDir) {
  const missing = Object.keys(FONT_FILES).filter(f => !fs.existsSync(path.join(fontDir, f)));
  if (missing.length) throw new Error(`Missing vendored fonts in ${fontDir}: ${missing.join(', ')} — run scripts/vendor-fonts.sh`);
}
export function qrSvgPath(text) {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
  const n = qr.modules.size; let d = '';
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.modules.get(r, c)) d += `M${c} ${r}h1v1h-1z`;
  return { n, d };
}

let browserP = null;
const browser = () => browserP || (browserP = chromium.launch({ args: ['--font-render-hinting=none', '--disable-gpu'] }));
export async function closeRenderer() { if (browserP) { (await browserP).close(); browserP = null; } }

export async function renderCertificatePdf(cfg, payload, recordHash, signers, templateId = 'classic_v1') {
  assertFonts(cfg.fontDir);
  const template = selectPdfTemplate(templateId);
  const verifyUrl = `${cfg.verifyHost}/c/${payload.id}`;
  const qr = qrSvgPath('https://' + verifyUrl);
  // Admin-configurable signer name/title (falls back to cfg.signers'
  // own env-var defaults if the caller didn't pass any -- keeps this
  // function usable the old way for anything that still calls it
  // without a `signers` argument, e.g. an older test).
  const sig = signers || (() => { const [a, b] = cfg.signers.map(s => { const [name, title] = s.split('|'); return { name, title }; }); return { signer1: a, signer2: b }; })();
  const data = {
    recipient: payload.name, department: payload.department, role: payload.role, hours: String(payload.hours),
    period: `${fmtMonth(payload.period_start)} – ${fmtMonth(payload.period_end)}`, issueDate: fmtDate(payload.issued_at),
    certId: payload.id, signer1: sig.signer1.name, signer1_title: sig.signer1.title,
    signer2: sig.signer2.name, signer2_title: sig.signer2.title, verifyBase: cfg.verifyHost,
    fingerprint: recordHash.slice(0, 16).toUpperCase().match(/.{4}/g).join(' '), qrN: qr.n, qrPath: qr.d,
    screenLabel: template.screenLabel
  };
  const fontCss = Object.entries(FONT_FILES).map(([f, wv]) => { const [w, s] = wv.split(' ');
    return `@font-face{font-family:'Source Serif 4';font-weight:${w};font-style:${s};font-display:block;src:url(${cfg.renderOrigin}/_fonts/${f}) format('woff2')}`; }).join('');

  const ctx = await (await browser()).newContext({ viewport: { width: 1123, height: 794 }, deviceScaleFactor: 1, locale: 'en-GB', timezoneId: 'UTC', reducedMotion: 'reduce' });
  try {
    await ctx.route('**/*', route => {
      const u = new URL(route.request().url());
      if (u.origin === new URL(cfg.renderOrigin).origin) return route.continue();
      if (u.hostname === 'fonts.googleapis.com') return route.fulfill({ contentType: 'text/css', body: fontCss });
      if (u.hostname === 'cdn.jsdelivr.net') return route.fulfill({ contentType: 'text/javascript', body: '' }); // QR is injected
      // support.js boots the template's "dc" runtime by loading React/
      // ReactDOM (and Babel, for the design tool's own live preview) from
      // unpkg.com with a pinned version and a sha384 Subresource Integrity
      // hash on every <script> tag it injects -- Chromium itself refuses
      // the script if the fetched bytes don't match that hash, so letting
      // this one specific, already-integrity-checked host through doesn't
      // weaken the renderer's otherwise fully network-isolated sandbox.
      // Found by real end-to-end PDF rendering: without this, the "dc"
      // runtime never boots, __APEX_CERT_READY__ never fires, and every
      // sign() call times out and 500s -- i.e. no certificate, old or new,
      // could ever actually be signed in a real deployment.
      if (u.hostname === 'unpkg.com') return route.continue();
      return route.abort(); // no other network access during rendering
    });
    const page = await ctx.newPage();
    await page.addInitScript(d => { window.__APEX_CERT__ = d; }, data);
    await page.goto(`${cfg.renderOrigin}/${encodeURIComponent(template.file)}`, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForFunction(() => window.__APEX_CERT_READY__ === true, null, { timeout: 15000 });
    await page.evaluate(() => document.fonts.ready);
    const check = await page.evaluate((d) => {
      const root = document.querySelector('[data-screen-label="' + d.screenLabel + '"]');
      const fonts = ['400 14px "Source Serif 4"', '600 56px "Source Serif 4"', 'italic 400 14px "Source Serif 4"'].every(f => document.fonts.check(f));
      const text = root ? root.innerText : '';
      // Real finding from end-to-end rendering: raw scrollWidth/scrollHeight
      // always report ~60px of horizontal "overflow" here, on every
      // certificate regardless of its text -- not a content problem. The
      // template deliberately bleeds a faint (opacity 0.05) background
      // watermark pattern past the right edge, clipped by this root's own
      // `overflow:hidden`; scrollWidth counts that clipped, invisible
      // decorator anyway, which made this check a universal false
      // positive that would have failed every real signing. Overflow
      // should mean "visible content doesn't fit", so this unions the
      // bounding boxes of elements that are actually visible (skipping
      // near-invisible decorative art) instead of trusting raw
      // scroll dimensions.
      const overflow = !root || (() => {
        // CSS opacity is a per-element compositing effect, not inherited
        // by a child's own computed style -- the watermark svg carries
        // opacity:0.05, but its <polygon> children each report their OWN
        // opacity as "1", so a single-element check misses them. Walk
        // each candidate's ancestors (up to `root`) and multiply opacity
        // along the way to get the effective, as-rendered visibility.
        const effectiveOpacity = (el) => {
          let o = 1;
          for (let n = el; n && n !== root; n = n.parentElement) o *= parseFloat(getComputedStyle(n).opacity || '1');
          return o * parseFloat(getComputedStyle(root).opacity || '1');
        };
        const rb = root.getBoundingClientRect();
        let maxRight = rb.right, maxBottom = rb.bottom, minLeft = rb.left, minTop = rb.top;
        for (const el of root.querySelectorAll('*')) {
          if (getComputedStyle(el).visibility === 'hidden' || effectiveOpacity(el) < 0.5) continue;
          const r = el.getBoundingClientRect();
          if (r.width === 0 && r.height === 0) continue;
          maxRight = Math.max(maxRight, r.right); maxBottom = Math.max(maxBottom, r.bottom);
          minLeft = Math.min(minLeft, r.left); minTop = Math.min(minTop, r.top);
        }
        return (maxRight - minLeft) > rb.width + 1 || (maxBottom - minTop) > rb.height + 1;
      })();
      return { fonts, overflow, hasName: text.includes(d.recipient), hasId: text.includes(d.certId), hasQr: !!root.querySelector(`path[d="${d.qrPath}"]`),
        containsVolunteerMetadata: /VERIFIED HOURS|SERVICE PERIOD|DEPARTMENT \/ INITIATIVE|VOLUNTEER ROLE/i.test(text) };
    }, data);
    if (!check.fonts) throw new Error('Certificate fonts failed to load; refusing to render');
    if (check.overflow) throw new Error('Certificate content overflows the A4 frame');
    if (!check.hasName || !check.hasId || !check.hasQr) throw new Error('Rendered certificate does not contain the approved record');
    if (templateId === 'hybrid_v4' && check.containsVolunteerMetadata) throw new Error('V4 rendered unwanted volunteer metadata');
    await page.addStyleTag({ content: '@page{size:297mm 210mm;margin:0}html,body{margin:0!important;padding:0!important;background:#fff!important;width:297mm;height:210mm;overflow:hidden}' });
    const raw = await page.pdf({ width: '297mm', height: '210mm', printBackground: true, margin: { top: 0, right: 0, bottom: 0, left: 0 }, pageRanges: '1' });
    const doc = await PDFDocument.load(raw, { updateMetadata: false });
    if (doc.getPageCount() !== 1) throw new Error('Expected exactly one page');
    const { width, height } = doc.getPage(0).getSize();
    if (Math.abs(width - A4.w) > 1 || Math.abs(height - A4.h) > 1) throw new Error(`Page is ${width}×${height}pt, not A4 landscape`);
    const t = new Date(payload.issued_at + 'T00:00:00Z');
    doc.setTitle(`APEX Certificate of Appreciation — ${payload.id}`);
    doc.setAuthor('APEX'); doc.setCreator('APEX Certificate Service'); doc.setProducer('APEX Certificate Service');
    doc.setSubject(`Verify at https://${verifyUrl}`); doc.setKeywords([payload.id, `record-sha256:${recordHash}`]);
    doc.setCreationDate(t); doc.setModificationDate(t);
    return Buffer.from(await doc.save({ useObjectStreams: false }));
  } finally { await ctx.close(); }
}
