import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateDraft } from '../src/rules.js';
import { selectPdfTemplate } from '../src/pdf.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const load = p => fs.readFileSync(path.join(root, p), 'utf8');
const draft = {
  name:'Test Volunteer', department:'APEX Student Support', role:'Mentor',
  period_start:'2026-06', period_end:'2026-11', hours:333
};

test('Classic V1 remains the default; V4 requires an explicit selection', () => {
  assert.equal(validateDraft(draft).template_id, 'classic_v1');
  assert.equal(validateDraft({ ...draft, template_id:'hybrid_v4' }).template_id, 'hybrid_v4');
  assert.equal(validateDraft(draft, { defaultTemplateId:'hybrid_v4' }).template_id, 'hybrid_v4');
  assert.equal(selectPdfTemplate().file, 'APEX Certificate.dc.html');
  assert.equal(selectPdfTemplate('hybrid_v4').file, 'APEX Certificate V4 - Hybrid Clean.dc.html');
});

test('unknown template and invalid types are rejected before signing', () => {
  for(const id of ['evil.html', '../invalid', '', null, 123, 'V4', false]) {
    assert.throws(() => validateDraft({ ...draft, template_id:id }), /Invalid certificate template/);
    assert.throws(() => selectPdfTemplate(id), /Unsupported certificate PDF template/);
  }
});

test('Hybrid V4 retains original design document and hides the volunteer metadata panel', () => {
  const v4 = load('APEX Certificate V4 - Hybrid Clean.dc.html');
  const mark = v4.split('<script type="text/x-dc"')[0];
  const required = ['data-screen-label="APEX Hybrid Certificate V4"', 'data-apex-hybrid-v4',
    '{{ recipient }}', '{{ signer1 }}', '{{ signer2 }}', '{{ qrPath }}',
    '{{ certId }}', '{{ fingerprint }}', 'APEX robot mark'];
  for (const token of required) assert.ok(mark.includes(token), 'V4 missing ' + token);
  for (const token of ['DEPARTMENT / INITIATIVE', 'VOLUNTEER ROLE', 'SERVICE PERIOD', 'VERIFIED HOURS', 'ISSUE DATE']) {
    assert.ok(!mark.includes(token), 'V4 accidentally exposed hidden metadata: ' + token);
  }
  assert.ok(v4.includes('window.__APEX_CERT__'), 'V4 uses trusted approved data injection');
});

test('V1 remains a separate original template and the Docker image packages both', () => {
  const original = load('APEX Certificate.dc.html');
  const docker = load('Dockerfile');
  const app = load('server/src/app.js');
  assert.ok(original.includes('Your commitment, collaboration, and initiative'));
  assert.ok(docker.includes('"APEX Certificate.dc.html"'));
  assert.ok(docker.includes('"APEX Certificate V4 - Hybrid Clean.dc.html"'));
  assert.ok(app.includes("'APEX Certificate V4 - Hybrid Clean.dc.html'"));
});
