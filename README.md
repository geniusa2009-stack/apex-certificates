# APEX Volunteer Certificate System

The three design files (`APEX Certificate`, `APEX Verify`, `APEX Issuance & Security`) are the real front-end. The `server/` directory issues, signs, renders, stores and serves certificates from them.

## Signing format (v1)
- Payload (signed, public): `{v, env, id, kid, name, department, role, period_start, period_end, hours, issued_at}`. Volunteer email and internal IDs are never signed or published.
- Canonical form: RFC 8785 JCS (`shared/apex-verify.js#canonicalize`). Integers only.
- Signature: Ed25519 over UTF-8 of `"apex-cert-v1:" + JCS(payload)`, base64url.
- Status statement (revoked/superseded): Ed25519 over `"apex-status-v1:" + JCS(statement)`.
- PDF attestation: `{v, type:"pdf", id, kid, sha256, bytes, record_hash}`. It is signed over `"apex-pdf-v1:" + …`. `sha256` is the hash of the exact stored PDF bytes. `record_hash` binds it to the signed payload.
- Keys: `GET /api/v1/keys.json` returns each key with `kid`, raw public key and status (`active`/`retired`/`compromised`). Retired keys still verify old certificates. Compromised keys never verify.
- What the PDF file itself proves: **the PDF carries no embedded PAdES digital signature.** You establish authenticity by matching its SHA-256 to the signed attestation on verify.apex.org.

## Verification states
| State | Meaning |
| --- | --- |
| VERIFIED | Signature is valid, the registry confirms the status, and the env matches. |
| REVOKED / SUPERSEDED | A signed status statement exists. |
| INVALID_SIGNATURE | The data, key, env or attestation does not match. |
| NOT_FOUND | No record exists, or the ID is malformed. |
| UNAVAILABLE | Network, HTTP, parse or browser-crypto failure, or no status confirmation. Never treated as success. |

## Deploy
1. `sh server/scripts/vendor-fonts.sh` downloads Source Serif 4 (OFL) and records `SHA256SUMS`. Commit both the fonts and the sums.
2. Provision Postgres 16. Then run `cd server && npm install && DATABASE_URL=… npm run migrate`.
3. Set up the signing key using one of two options:
   - `node server/scripts/gen-key.js`, then store the PEM in your secret manager and inject it as `APEX_SIGNING_KEY_PEM`.
   - Or use `APEX_KEY_PROVIDER=gcp-kms` with an `EC_SIGN_ED25519` key version.

   Choose a new `APEX_SIGNING_KID`.
4. Create users. The password goes in an env var, not argv: `APEX_NEW_PASSWORD=… node scripts/create-user.js lina@apex.org "Lina M. Haddad" issuer`. For approvers, add `--totp`; TOTP is mandatory for approvers by default.
5. Build and run: `docker build -t apex-cert . && docker run --env-file server/.env -p 8080:8080 apex-cert`.
   - Put it behind TLS at `verify.apex.org` and set `APEX_TRUST_PROXY=true`.
   - Rate limiting is in-memory, so it is per instance. For multiple instances, configure a Redis store.
6. Rotation: deploy a new kid and key. The previous active key is retired automatically. To mark a key as compromised: `update signing_keys set status='compromised' where kid=…`, then revoke and reissue the affected certificates.

The QR code and printed URL point to `https://verify.apex.org/c/<ID>`, which redirects to the verify page. The server injects `<meta name="apex-api-base" content="/api/v1">` into that page.

## Volunteer Passport, badges, bulk issuance (migration 002)
- Page: `APEX Volunteer Passport.dc.html`, served at `/volunteers/<public-id>`. Public API: `GET /api/v1/volunteers/<public-id>`, `GET /api/v1/badges/<BDG-id>` (Open Badges 3.0-*shaped* JSON; unsigned; not a certified OB 3.0 / W3C VC implementation).
- Every public response is built by `shared/passport-rules.js#publicProfile`. Profiles are private by default. Email, phone, birth date, address, staff notes and review notes are never returned. Private, disabled and unknown profiles return the same 404.
- Verified hours count only contributions with `status='verified'` and a reviewer different from the submitter. The DB enforces this too (`independent_review`). Reviewed contributions are immutable. Rows cannot be deleted.
- Badges need verified evidence that belongs to the recipient, or an authorised assessment. Self-award is blocked. Revoked badges stay in the DB and are hidden from the public.
- Bulk: `POST /admin/bulk/validate` (CSV + column mapping + idempotency key) → `POST /admin/bulk/:id/draft`. This step creates **drafts only**. Each draft still goes through submit → independent approve → sign → publish. Every row needs a verified `contribution_ref`. Duplicates and already-issued rows are held. Retries replay rather than duplicate. `GET /admin/bulk/:id/report.csv` exports the report.
- Volunteer self-service (role `volunteer`): `GET /api/v1/me`, `PUT /api/v1/me/privacy`, `POST /api/v1/me/contributions`, `POST /api/v1/me/contributions/:id/withdraw`.

## Status report (16 Nov 2026)
**Executed and passing.** These ran in a browser using the project script runner; see `test-results/shared-browser.txt`.
- 18 shared-verifier tests: JCS, real Ed25519 verify, field tamper, ID swap, revoked, superseded, stripped revocation, forged status, unknown key, compromised key, PDF attestation, and edited-PDF hash. Network/500/malformed responses never verify.
- 8 fixture checks, including that sample-signed data is rejected under the production env.

**Written, not executed here.** There is no Node, Postgres or Chromium in this environment. They run in CI via `.github/workflows/ci.yml`.
- `server/test/shared.test.js`: the Node signer interoperates with the browser verifier.
- `server/test/rules.test.js`: RBAC, no self-approval, state machine, strict validation, ID format, no PII in the payload.
- `server/test/audit.test.js`: hash-chain tamper detection and the RFC 6238 TOTP vectors.
- `server/test/integration.test.js`: full HTTP workflow on real Postgres, using a real Chromium A4 PDF when `RUN_PDF=1`. Covers:
  - self-approval blocked, unauthorized issuance blocked
  - publish → VERIFIED; served PDF hash = attested hash; edited PDF differs
  - DB refuses edits to signed data; audit table is append-only
  - reissue → SUPERSEDED; revoke → REVOKED; audit chain verifies

**Blocked / not done**
- No deployed endpoint, domain, DNS/TLS or production database. verify.apex.org is not live.
- No production signing key or KMS. The GCP KMS provider code is unverified.
- The sample records have no official PDF, because the server renderer could not run here. The upload comparison on sample records therefore reports "no official PDF fingerprint on record".
- Fonts are not vendored yet: the script must be run with network access.
- Not implemented:
  - PAdES/embedded PDF digital signatures
  - a multi-instance rate-limit store
  - email delivery of PDFs
  - a UI for user management and TOTP enrolment (CLI only)
- No GitHub repository was connected, so nothing was committed or pushed.
- The robot motion is CSS keyframes, not GSAP. It is preserved unchanged.
