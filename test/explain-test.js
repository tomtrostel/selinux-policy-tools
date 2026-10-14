'use strict';
// Tracing compiled rules back to source statements (server/explain.js), on a
// small m4 output file: statement parsing, the #line / call-marker index,
// direct and attribute matches, self, type transitions, exclusions, ranking
// by changed files, attribute membership ("because"). Any OS.
//   node test/explain-test.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const E = require('../server/explain');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/* ---------- statements ---------- */
let s = E.parseStatement('allow foo_t { etc_t bin_t }:{ file lnk_file } { read open };');
check(s && s.rt === 'allow' && same(s.srcs, ['foo_t']) && same(s.tgts, ['etc_t', 'bin_t']) && same(s.classes, ['file', 'lnk_file']) && same(s.perms, ['read', 'open']) && !s.loose, 'allow with sets', s);
s = E.parseStatement('allow foo_t { file_type -shadow_t }:file ~{ write };');
check(s.loose && same(s.tgts, ['file_type', 'shadow_t']), 'exclusions and complements mark the statement loose', s);
check(E.parseStatement('allow foo_t self:process *;').loose, '* permissions: loose');
s = E.parseStatement('type_transition foo_t tmp_t:file foo_tmp_t;');
check(s.rt === 'type_transition' && same(s.perms, ['foo_tmp_t']), 'type_transition: the default type in perms', s);
check(same(E.parseStatement('typeattribute foo_t domain, daemon;'), { rt: 'typeattribute', type: 'foo_t', attrs: ['domain', 'daemon'] }), 'typeattribute');
check(same(E.parseStatement('type foo_t, domain;'), { rt: 'typeattribute', type: 'foo_t', attrs: ['domain'] }) && E.parseStatement('type foo_t;') === null, '"type T, attrs" counts as membership; a bare type is no statement');
check(E.parseStatement('allow foo_t bar_t file read;') === null && E.parseStatement('allow foo_t bar_t:file read') === null && E.parseStatement('role r types t;') === null, 'malformed or other statements: null');

/* ---------- index of an m4 output ---------- */
const at = (n, lines) => lines.flatMap(l => [`#line ${n}`, l]);
const OUT = [
  '#line 1 "policy/modules/services/foo.te"',
  'module foo 1.0;',
  '#line 3',
  'type foo_t, domain;',
  ...at(5, ['##### begin files_read_etc(foo_t) depth: 1', 'allow foo_t etc_t:file { read open getattr };', '##### begin files_search_etc(foo_t) depth: 2',
    'allow foo_t etc_t:dir search;', '##### end files_search_etc depth: 1', '##### end files_read_etc depth: 0']),
  '#line 7',
  'allow foo_t self:process signal;',
  '#line 8',
  'type_transition foo_t tmp_t:file foo_tmp_t;',
  '#line 9',
  'typeattribute foo_t can_read_shadow;',
  '#line 1 "policy/modules/system/authlogin.te"',
  'allow can_read_shadow shadow_t:file { read open };',
  '#line 2',
  'allow domain etc_t:file read;',
  '#line 1 "policy/support/obj_perm_sets.spt"',
  'allow ignored_t ignored_t:file read;',
].join('\n');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-explain-'));
const outFile = path.join(tmp, 'foo.tmp');
fs.writeFileSync(outFile, OUT);
const resolve = (f) => (/\.te$/.test(f) ? `/src/${f}` : null);
const sts = E.indexBuild([outFile, path.join(tmp, 'missing.tmp')], resolve);
const FOO = '/src/policy/modules/services/foo.te', AUTH = '/src/policy/modules/system/authlogin.te';
const find = (pred) => sts.find(pred);
check(sts.length === 8, `statements indexed from editable sources only (${sts.length}); a missing output is skipped`, sts.map(x => `${x.rt} ${x.line}`));
const rd = find(x => x.rt === 'allow' && x.perms.includes('getattr'));
check(rd.path === FOO && rd.line === 4 && same(rd.chain, ['files_read_etc(foo_t)']), 'a call\'s statement: its call line and the call chain', rd);
const sr = find(x => x.classes && x.classes.includes('dir'));
check(sr.line === 4 && same(sr.chain, ['files_read_etc(foo_t)', 'files_search_etc(foo_t)']), 'a nested call\'s statement: the whole chain, outermost first', sr);
check(find(x => x.rt === 'allow' && x.tgts.includes('self')).line === 6 && find(x => x.rt === 'allow' && x.tgts.includes('self')).chain === null, 'a plain statement: its own line, no chain');
check(find(x => x.path === AUTH && x.srcs.includes('can_read_shadow')).line === 0, 'a #line with another file switches files');
const index = E.byName(sts);
check(index.get('foo_t').length >= 5 && index.get('etc_t').length === 3 && index.get('can_read_shadow').length === 1, 'byName: statements under every name they mention (memberships under the type)');

/* ---------- explaining compiled rules ---------- */
const side = { index, attrs: { foo_t: ['domain', 'can_read_shadow'], shadow_t: ['file_type'], etc_t: ['file_type'] }, gained: new Map(), changedFiles: new Set() };
let x = E.explainRule({ rt: 'allow', s: 'foo_t', t: 'etc_t', c: 'file', perms: ['read'] }, ['read'], side);
check(x.origins.length === 2 && x.origins[0].path === FOO && x.origins[0].line === 4 && x.origins[0].via === 'files_read_etc(foo_t)' && x.origins[0].text === 'allow foo_t etc_t:file { read open getattr };' && x.origins[1].path === AUTH,
  'direct statement first (with its text read back and the call), then the attribute rule (domain)', x.origins.map(o => `${o.path}:${o.line} ${o.via}`));
x = E.explainRule({ rt: 'allow', s: 'foo_t', t: 'etc_t', c: 'file', perms: ['getattr'] }, ['getattr'], side);
check(x.origins.length === 1 && x.origins[0].line === 4, 'only statements granting the changed permissions');
x = E.explainRule({ rt: 'allow', s: 'foo_t', t: 'foo_t', c: 'process', perms: ['signal'] }, ['signal'], side);
check(x.origins.length === 1 && x.origins[0].line === 6, 'self rules match when source and target are the same');
x = E.explainRule({ rt: 'type_transition', s: 'foo_t', t: 'tmp_t', c: 'file', perms: ['foo_tmp_t'] }, ['foo_tmp_t'], side);
check(x.origins.length === 1 && x.origins[0].line === 7, 'type_transition matched by its default type');
side.gained.set('foo_t', new Set(['can_read_shadow']));
x = E.explainRule({ rt: 'allow', s: 'foo_t', t: 'shadow_t', c: 'file', perms: ['read'] }, ['read'], side);
check(x.origins.length === 1 && x.origins[0].path === AUTH && x.origins[0].because && x.origins[0].because[0].path === FOO && x.origins[0].because[0].line === 8 && /typeattribute foo_t can_read_shadow/.test(x.origins[0].because[0].text),
  'an attribute rule the type newly gets: "because" points at the typeattribute statement', x.origins);
side.changedFiles = new Set([AUTH]);
x = E.explainRule({ rt: 'allow', s: 'foo_t', t: 'etc_t', c: 'file', perms: ['read'] }, ['read'], side);
check(x.origins[0].path === AUTH, 'statements in changed files rank first');
x = E.explainRule({ rt: 'allow', s: 'foo_t', t: 'etc_t', c: 'file', perms: ['read'] }, ['read'], side, 1);
check(x.origins.length === 1 && x.more === 1, 'max limits the origins; more counts the rest');
check(E.explainRule({ rt: 'allow', s: 'bar_t', t: 'etc_t', c: 'file', perms: ['read'] }, ['read'], side).origins.length === 0, 'nothing for a rule no statement produces');
check(E.membershipOrigins('foo_t', 'domain', side).length === 1 && E.membershipOrigins('foo_t', 'domain', side)[0].line === 2, 'membershipOrigins: "type T, attr" declarations count');
E.releaseTexts();
E.dropCache();

fs.rmSync(tmp, { recursive: true, force: true });
console.log(failures ? `\n${failures} check(s) failed` : '\nall explain checks passed');
process.exit(failures ? 1 : 0);
