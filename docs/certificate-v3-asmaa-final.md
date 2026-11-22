# APEX Certificate V3 — Asmaa final review

## Scope and isolation
- New **opt-in** design file: `APEX Certificate V3 - Asmaa Final.dc.html`.
- Forked from V2 design without changing `APEX Certificate.dc.html` (legacy), `APEX Certificate V2.dc.html`, `server/src/pdf.js`, `APEX Verify.dc.html`, `server/src/app.js`, or the database.
- **Not connected to production issuance**. Every already signed PDF remains byte-for-byte unchanged. Never overwrite a signed PDF, whose exact SHA-256 is attested.
- Only new files are added on this branch; the draft pull request is based on the V2 branch.

## Asmaa's original feedback (21 Nov 2026, 20:51–21:25)
1. Preserve translucent APEX mark in the background.
2. Remove the duplicate large front logo, keep the circular coin-like APEX seal at **top center** (her final preference at 21:08).
3. Reduce the repeated appreciation paragraphs and crowded seven-column table.
4. Group essential data on the left; place QR on the right.
5. Keep the small robot at bottom right.
6. Add **navy**, not nearly-white `#F8FAFC`.
7. Keep the certificate concise and place additional official record information behind scanning the QR.

Her exact color photo is absent from the text-only WhatsApp export, so use existing APEX navy `#1C366F`, not an invented sample.

## Design implementation
- Silver seal centered in a clear white halo; two navy rules flank it; the small program label appears *below* the seal, removing the V2 header collision.
- Navy footer ribbon and left metadata accent; soft-tinted low-contrast panels but dark readable labels.
- One concise recognition sentence and a generous typographic hierarchy; adaptive `recipientSize` for longer names.
- Existing field values and signer roles preserved; neither authenticity nor volunteer hours are fabricated.
- QR code stays on the right, with **11 px padding** around a 92 px image at 114 px outer width. For a typical 33×33 module code, this gives approximately a four-module quiet zone. Test QR scans on printed A4.
- The QR uses the original `verifyBase/c/certId` contract and existing `window.__APEX_CERT__` injection. The existing `APEX Verify.dc.html` already displays the signed record and extensive verification details. No competing/unverified new verification portal was created.

## User-facing and security notes
- QR code **is not proof of authenticity by itself**. Only the official website's cryptographic validation and current registry status constitute verification.
- `verify.apex.org` is a configured target, **not confirmed live**. Do not imply QR verification is operational until the domain, TLS, server, registry and signing configuration are deployed and verified.
- V3 must never replace existing signed PDFs or alter their fingerprints. For any future rollout, make template choice *explicit for new drafts only* after visual and PDF QA.
- The screenshots and PDF test print are **visual previews** with sample data and are not signed credentials.

## Research used
- Supreme Council of Universities (Egypt), 2025 visual identity and certificate guidelines (A4, recipient hierarchy): https://scu.eg/download/visual-identity-guide-supreme-council-universities/
- W3C WCAG 2.2, text contrast and readability: https://www.w3.org/TR/WCAG22/
- IEC ISO/IEC 18004:2024 QR symbology and printing requirements: https://webstore.iec.ch/en/publication/99495
- W3C VC Data Model 2.0, verification/integrity concepts (reference principles only; this implementation does **not** claim W3C VC conformance): https://www.w3.org/TR/vc-data-model/
- General certificate layout: https://www.bcdiploma.com/en/blog/certificate-design

## Review checklist
- [ ] Static test passes (`node --test server/test/certificate-v3-isolation.test.js`)
- [ ] Default recipient renders without clipping on A4 297×210 mm
- [ ] Long recipient and department strings render without overlap or truncation
- [ ] QR opens only the intended registry route and scans from physical print
- [ ] Main production signing renderer still targets V1
- [ ] Existing signed PDFs, hashes, signer defaults, Verify page and API remain unchanged
- [ ] Manual design sign-off before any opt-in integration
