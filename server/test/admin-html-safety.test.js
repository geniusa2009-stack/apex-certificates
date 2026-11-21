import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// Regression tests for the two Medium findings from the security audit:
//   1. Stored XSS via unescaped `actor_name` in the admin audit panels.
//   2. The admin page missing from the Dockerfile's COPY list.
// These read the real, shipped files -- not copies -- so a future edit
// that reintroduces either problem fails this suite.

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, '..', '..'); // server/test -> repo root
const adminHtmlPath = path.join(repoRoot, 'APEX Certificates Admin.dc.html');
const dockerfilePath = path.join(repoRoot, 'Dockerfile');
const appJsPath = path.join(here, '..', 'src', 'app.js');

const adminHtml = readFileSync(adminHtmlPath, 'utf8');

test('admin HTML defines an esc() HTML-escaping helper', () => {
  assert.match(adminHtml, /function esc\(/, 'esc() helper should exist');
});

test('esc() helper actually neutralizes HTML-significant characters', () => {
  const m = adminHtml.match(/function esc\(s\)\{[\s\S]*?\)\); \}/);
  assert.ok(m, 'could not locate esc() function body in the admin HTML');
  // eslint-disable-next-line no-new-func
  const esc = new Function(`${m[0]}; return esc;`)();
  const malicious = '<img src=x onerror=alert(1)>"\'&';
  const out = esc(malicious);
  assert.ok(!out.includes('<img'), 'escaped output must not contain a raw tag');
  assert.ok(!out.includes('"') , 'escaped output must not contain a raw double quote');
  assert.ok(!out.includes("'"), 'escaped output must not contain a raw single quote');
  assert.equal(out, '&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp;');
});

test('both audit-trail render sites wrap actor_name with esc(...)', () => {
  const certAudit = adminHtml.match(/document\.getElementById\('cert-audit'\)\.innerHTML = events\.map\(e =>[\s\S]*?No events yet/);
  const globalAudit = adminHtml.match(/document\.getElementById\('global-audit'\)\.innerHTML = events\.map\(e =>[\s\S]*?No activity yet/);
  assert.ok(certAudit, 'could not find cert-audit render block');
  assert.ok(globalAudit, 'could not find global-audit render block');
  assert.match(certAudit[0], /esc\(e\.actor_name/, 'cert-audit panel must escape actor_name');
  assert.match(globalAudit[0], /esc\(e\.actor_name/, 'global-audit panel must escape actor_name');
  // Guard against a raw, unescaped interpolation sneaking back in anywhere.
  assert.doesNotMatch(certAudit[0], /\$\{e\.actor_name \|\| e\.actor \|\| 'system'\}/);
  assert.doesNotMatch(globalAudit[0], /\$\{e\.actor_name \|\| e\.actor \|\| 'system'\}/);
});

test('Dockerfile COPY list includes every file in app.js PUBLIC_FILES', () => {
  const appJs = readFileSync(appJsPath, 'utf8');
  const publicFilesMatch = appJs.match(/PUBLIC_FILES = new Set\(\[([^\]]*)\]\)/);
  assert.ok(publicFilesMatch, 'could not find PUBLIC_FILES in app.js');
  const publicFiles = [...publicFilesMatch[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
  assert.ok(publicFiles.length > 0, 'PUBLIC_FILES parsed as empty -- regex likely stale');

  const dockerfile = readFileSync(dockerfilePath, 'utf8');
  const copyLine = dockerfile.split('\n').find((l) => l.startsWith('COPY [') && l.includes('.dc.html'));
  assert.ok(copyLine, 'could not find the public-file COPY line in the Dockerfile');

  for (const file of publicFiles) {
    assert.ok(
      copyLine.includes(`"${file}"`),
      `Dockerfile COPY list is missing "${file}" even though app.js serves it as a public file`
    );
  }
});
