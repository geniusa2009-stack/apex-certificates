import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '../..');
const read = p => fs.readFileSync(path.join(root, p), 'utf8');
const legacy = read('APEX Certificate.dc.html');
const v4 = read('APEX Certificate V4 - Hybrid Clean.dc.html');
const renderer = read('server/src/pdf.js');
const marker = '<script type="text/x-dc" data-dc-script';
const markup = v4.slice(0, v4.indexOf(marker));
const data = v4.slice(v4.indexOf(marker));

test('V4 is an isolated addition; V1 signing continues using V1', () => {
  assert.match(legacy, /Your commitment, collaboration, and initiative/);
  assert.match(renderer, /APEX Certificate\\.dc\\.html/);
  assert.doesNotMatch(renderer, /Certificate V4/);
  assert.match(data, /window\\.__APEX_CERT__/);
  assert.match(data, /class Component extends DCLogic/);
});

test('hybrid has upper seal, recipient and lower signer/verifier layout', () => {
  for (const expr of ['data-apex-hybrid-v4', 'VOLUNTEER RECOGNITION PROGRAM', 'CERTIFICATE OF APPRECIATION', '{{ recipient }}',
    'In appreciation of dedicated volunteer service', '{{ signer1 }}', '{{ signer2 }}', '{{ qrPath }}',
    '{{ certId }}','{{ verifyUrl }}','{{ fingerprint }}','APEX robot mark']) {
    assert.ok(markup.includes(expr), 'missing: ' + expr);
  }
  assert.match(markup, /padding:12px/);
});

test('entire volunteer metadata panel is removed from visible V4', () => {
  for (const phrase of ['DEPARTMENT \\/ INITIATIVE', 'VOLUNTEER ROLE','SERVICE PERIOD','VERIFIED HOURS','ISSUE DATE','ISSUED']) {
    assert.ok(!markup.includes(phrase.replace('\\/','/')), 'metadata leaked into visible layout: ' + phrase);
  }
  assert.doesNotMatch(markup, /width:737px;height:158px/);
});
