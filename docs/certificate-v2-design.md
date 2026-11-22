# APEX Certificate V2 — Asmaa design review

## Isolation and safety

- **Source:** `APEX Certificate.dc.html` from main commit `838488a904121269c7af98f8e83f440eb2312a12`.
- **New template:** `APEX Certificate V2.dc.html`.
- **Original:** `APEX Certificate.dc.html` remains unmodified.
- **Production:** Existing server PDF renderer (`server/src/pdf.js`) still loads the original V1 file. V2 is an opt-in design candidate, **not automatically used for issuance**.
- **Verification:** Existing signed records, signatures, QR validation, key management, IDs, and PDFs are unchanged. Never retroactively replace a published signed PDF, since its bytes are hash-attested.

## Layout changes

1. Moved the authentic circular seal into the top-center visual header.
2. Gave the APEX logo larger and cleaner placement at the top left.
3. Kept the subtle APEX brand watermark behind the design.
4. Replaced the seven-column metadata grid with four light metadata regions (department, role, service period, hours/date).
5. Removed repeated appreciation prose in favor of one short line.
6. Moved verification QR to the right, including the original certificate ID.
7. Preserved both configured signer names/titles and the small bottom-right robot.
8. Preserved the original `window.__APEX_CERT__` server-injection contract and fingerprint/QR input bindings.

## Usage and review

Open `APEX Certificate V2.dc.html` in the same design runtime used for V1. Preview its default sample and check long recipient/department names. The new file uses the same supporting assets and QR generation mechanism as V1.

This branch intentionally does **not** switch the live renderer to V2. A later explicit rollout can choose the template for *new* certificates only, with full PDF/print QA and independent approval. Avoid signing new certificates using V2 until it has passed its PDF-fit tests.

## Quick static checks

`server/test/certificate-v2-template.test.js` verifies that the V2 template has all required bindings and that the existing V1 page and renderer are still referenced.
