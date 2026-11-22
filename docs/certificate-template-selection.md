# APEX Certificate templates: Classic V1 and Hybrid Clean V4

## Choice and layout
- Classic V1 (`classic_v1`) remains the default and uses the existing APEX Certificate.dc.html unchanged.
- Hybrid Clean V4 (`hybrid_v4`) is a separate imported design with top seal, recipient, appreciation, two signer blocks, QR, certificate ID, verification fingerprint and robot.
- V4 omits the volunteer metadata panel from the PDF, but underlying signed data and verification page retain department, role, period and hours.
- The Admin Create/Edit Draft dialog contains an explicit template dropdown and sample preview links; the selection is locked once submitted.

## Signing and immutability
- Both versions use the same independent review, Ed25519 canonical payload and signed PDF SHA-256 attestation.
- An additive schema migration sets the template_id column to classic_v1 for all existing rows; a guard prohibits changing it after signing.
- Already issued PDF bytes and signatures are never regenerated, and the old V1 template file is not edited.
- Reissued drafts inherit the old template as a starting point and can be edited before review.

## Safe rollout
1. Run GitHub CI with real Chromium PDF generation for V1 and V4.
2. Apply schema migration 004 on the dedicated Neon staging project and record in schema_migrations.
3. Verify the existing published certificate APX-2026-VR-5Q3ZNCZS remains Classic V1, same PDF hash.
4. Merge and deploy to existing Render free staging service.
5. Manually create and approve a new V4 test draft, then sign and publish and verify its QR and PDF.

Sample preview data is not a signed credential.
