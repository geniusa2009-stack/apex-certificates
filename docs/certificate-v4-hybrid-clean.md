# APEX Certificate V4 — Hybrid Clean

## Exact user selection (22 Nov 2026)

- **Top:** use the second reference certificate design from the header through the recipient's full name (muted silver top band, round centered APEX seal, title, recipient).
- **Bottom:** use the first reference certificate (short appreciation paragraph, thin divider, two authorized signer blocks, QR at right, verification link, signed-record fingerprint, small robot at bottom-right).
- **Delete the entire mid-page volunteer metadata section:** Department / Initiative, Volunteer Role, Service Period, Verified Hours, Issued (not merely four items).
- Preserve breathing room and align the upper and lower portions naturally.

## Isolation

This V4 design is **a newly added independent file** at `APEX Certificate V4 - Hybrid Clean.dc.html`.
The new GitHub branch was created from V1 `main` at `838488a904121269c7af98f8e83f440eb2312a12`. No previously existing file was edited or removed. In particular, the original V1 template, old PDF renderer and signing code, Verify page, original record contents, previously issued PDFs, and database schema are left exactly untouched.

The issued-PDF path is deliberately unchanged and still renders `APEX Certificate.dc.html` (V1). V4 is a reviewable design and **not yet a production issuance option**.

The QR in V4 points to the pre-existing `https://verify.apex.org/c/<certificate-id>` path. The link requires the original deployed verification service to work, and there is no new verification backend. The visible layout omits volunteer data; the underlying signed record can still contain them, and the original Verify UI is the appropriate place to view them.

## Visual QA

- A local static preview (PNG and A4 PDF) was generated from the same layout geometry and sample values.
- One A4 landscape page (297×210 mm). Recipient names of 22, 78, and 105 characters were checked without detected clipping.
- QR was automatically decoded from the preview and returned `https://verify.apex.org/c/APX-2026-VR-04817`. This **does not confirm** the site is publicly live.
- Source Serif 4 / runtime fonts and real PDF-signing integration require separate validation in the production app before any issuance choice is offered.
- Preview is SAMPLE DATA, not a signed or official certificate.

## Future release (only if requested)

If the V4 layout is later selected for **new** signed certificates, the implementation must add a separate explicit rendering option and run PDF-level QA while preserving every old signed PDF byte-for-byte, the keys, and the existing audit trail. No automatic switching or database reissue was performed.
