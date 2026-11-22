import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const projectRoot = path.resolve(import.meta.dirname, '../..');
const v1 = fs.readFileSync(path.join(projectRoot, 'APEX Certificate.dc.html'), 'utf8');
const v2 = fs.readFileSync(path.join(projectRoot, 'APEX Certificate V2.dc.html'), 'utf8');
const renderer = fs.readFileSync(path.join(projectRoot, 'server/src/pdf.js'), 'utf8');

test('V2 is a separate opt-in certificate design', () => {
  assert.match(v2, /class Component extends DCLogic/);
  assert.match(v2, /window\.__APEX_CERT__/);
  for (const binding of ['recipient', 'department', 'role', 'period', 'hours', 'issueDate',
    'certId', 'signer1', 'signer1_title', 'signer2', 'signer2_title',
    'qrN', 'qrPath', 'verifyUrl', 'fingerprint']) {
    assert.ok(v2.includes('{{ ' + binding + ' }}'), 'missing binding: ' + binding);
  }
  assert.match(v2, /APEX robot mark/);
  assert.match(v2, /SCAN TO VERIFY/);
  assert.match(v2, /CERTIFICATE OF APPRECIATION/);
  assert.match(v1, /Your commitment, collaboration, and initiative/);
  assert.match(renderer, /APEX Certificate\.dc\.html/);
  assert.doesNotMatch(renderer, /APEX Certificate V2\.dc\.html/);
});
