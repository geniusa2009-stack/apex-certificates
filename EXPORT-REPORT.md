# Export Report

Generated: 2026-11-21T13:53:25.334Z
Archive: APEX-Credentials-Complete-Project.zip — root folder `APEX-Credentials/`, original paths preserved.

## Included (54 source files)
- Frontend: APEX Certificate / Verify / Issuance & Security / Volunteer Passport (.dc.html) + support.js runtime
- Shared: shared/apex-verify.js, shared/passport-rules.js
- Backend: server/src (app, audit, auth, config, db, index, issuance, keys, passport, pdf, rules, totp), server/scripts (create-user, gen-key, migrate, vendor-fonts.sh), server/migrations (001_init.sql, 002_passport.sql), server/package.json, server/.env.example
- Tests: server/test (audit, integration, passport, rules, shared), test-results (2 saved browser runs)
- Fixtures: samples/ (4 signed sample certificates, public keys.json, 1 synthetic volunteer bundle, README)
- Infra: Dockerfile, docker-compose.yml, .github/workflows/ci.yml, .gitignore
- Assets: original APEX logo (uploads/…jpg), onboarding reference (uploads/apex-onboarding_3.html), Broadsheet design-system files (_ds/), .thumbnail

## Security
- Scanned all text files for PEM private keys, JWK private "d" values, and common token formats: no matches.
- server/.env.example contains placeholders only (KMS key path is a commented template: projects/P/locations/L/…).
- No .env, private signing keys, passwords, tokens, databases, sessions or real volunteer PII exist in the workspace, so nothing had to be excluded. samples/keys.json holds public keys only; sample volunteer data is synthetic.

## Known missing dependencies
- No package-lock.json (never generated) — run `npm install` in server/.
- node_modules not included.
- PDF fonts not vendored — run server/scripts/vendor-fonts.sh.
- Production signing key not included by design — generate with server/scripts/gen-key.js or use KMS.
- The robot artwork is embedded inline in APEX Certificate.dc.html; no separate robot file exists.

## Test status
- test-results/passport-browser.txt: 34/34 passed
- test-results/shared-browser.txt: verification suite passed (26 tests)
- server/test: written, NOT yet executed in Node — run `npm test` in server/ (CI workflow included).

## Verification
- Every entry re-read from the finished archive and CRC32-checked against its source.
