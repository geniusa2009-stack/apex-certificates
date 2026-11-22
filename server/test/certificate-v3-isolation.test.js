import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '../..');
const read = p => fs.readFileSync(path.join(root, p), 'utf8');
const v1 = read('APEX Certificate.dc.html');
const v2 = read('APEX Certificate V2.dc.html');
const v3 = read('APEX Certificate V3 - Asmaa Final.dc.html');
const pdf = read('server/src/pdf.js');
const verify = read('APEX Verify.dc.html');

test('new design is independent and original renderer remains V1', () => {
  assert.notEqual(v1, v2);
  assert.notEqual(v2, v3);
  assert.match(v1, /Your commitment, collaboration, and initiative/);
  assert.match(pdf, /APEX Certificate\.dc\.html/);
  assert.doesNotMatch(pdf, /APEX Certificate V3/);
  assert.match(verify, /Certificate Verification/);
});
test('V3 keeps issuer-supplied canonical signed metadata and scanning contract', () => {
  assert.match(v3, /window\.__APEX_CERT__/);
  assert.match(v3, /class Component extends DCLogic/);
  assert.match(v3, /qrPath/);
  assert.match(v3, /const verifyUrl = /);
  assert.match(v3, /const recipientSize = /);
  for (const field of ['recipient','department','role','period','hours','issueDate','certId','signer1','signer1_title','signer2','signer2_title','qrN','qrPath','verifyUrl','fingerprint','recipientSize']) {
    assert.ok(v3.includes('{{ ' + field + ' }}'), 'missing V3 field: ' + field);
  }
});
test('V3 follows latest Asmaa feedback without modifying old markup', () => {
  assert.match(v3, /data-apex-v3="1"/);
  assert.match(v3, /left:507px;top:42px/);
  assert.match(v3, /left:881px;top:461px/);
  assert.match(v3, /padding:11px/);
  assert.match(v3, /background:#1C366F;border-radius:3px/);
  assert.match(v3, /SCAN FOR FULL RECORD/);
  assert.match(v3, /APEX robot mark/);
  assert.match(v3, /opacity:0\.05/);
  assert.doesNotMatch(v3, /APEX • VOLUNTEER SERVICE/);
  assert.doesNotMatch(v3, /width:85px;height:57px/);
});
