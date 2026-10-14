'use strict';
// The selinux.checks language (server/checks.js): every check form, the
// permission groups and default classes, comments, and the error messages
// with their columns. Any OS.
//   node test/checks-test.js
const { parseChecks, PERM_GROUPS, FILE_CLASSES, KEYWORDS } = require('../server/checks');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2000).replace(/\n/g, '\n     ')); }
};
const one = (line) => { const p = parseChecks(line + '\n'); return p.checks[0] || { error: p.errors[0] }; };
const error = (line) => { const p = parseChecks(line + '\n'); return p.errors[0] || null; };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/* ---------- access: only / never / require … may ---------- */
let c = one('only auditd_t may write auditd_log_t');
check(c.kind === 'only' && same(c.sources, ['auditd_t']) && same(c.targets, ['auditd_log_t']) && same(c.perms, PERM_GROUPS.write) && same(c.classes, FILE_CLASSES) && c.permsLabel === 'write',
  'only … may write: the write group, file-like classes by default', c);
c = one('never user_t, staff_t may read shadow_t');
check(c.kind === 'never' && same(c.sources, ['user_t', 'staff_t']) && same(c.perms, PERM_GROUPS.read), 'never with a comma-separated list; read = read open map', c);
c = one('require syslogd_t may { append create } var_log_t:file');
check(c.kind === 'require' && same(c.perms, ['append', 'create']) && same(c.classes, ['file']), 'require with exact permissions and a class', c);
check(same(one('require x_t may read y_t').classes, ['file']), 'require defaults to the file class');
check(same(one('never x_t may { read } y_t').perms, ['read']), '{ read } is exactly read, not the group');
check(one('never x_t may any y_t').perms === '*' && same(one('never x_t may { any } y_t').perms, ['any']), 'any = every permission (but { any } is a permission named any)');
check(same(one('never x_t may execute y_t').perms, PERM_GROUPS.execute) && same(one('never x_t may getattr y_t').perms, ['getattr']), 'execute group; a single permission as written');
check(same(one('never x_t may write y_t:{ file dir }').classes, ['file', 'dir']) && same(one('never x_t may write y_t z_t:dir').targets, ['y_t', 'z_t']), 'several classes and targets');
check(same(one('never * may write shadow_t').sources, ['*']), "'*' (every domain) with never");
check(/only makes sense with 'never'/.test(error('only * may write shadow_t').msg), "'*' with only is refused");

/* ---------- reaches / flows ---------- */
c = one('never user_t reaches sysadm_t');
check(c.kind === 'reaches' && same(c.sources, ['user_t']) && same(c.targets, ['sysadm_t']) && !c.through, 'reaches', c);
c = one('never user_t reaches passwd_t except through wrap_t other_t');
check(same(c.through, ['wrap_t', 'other_t']), 'reaches … except through', c);
check(/Expected 'through'/.test(error('never a_t reaches b_t except c_t').msg) && /after 'except through'/.test(error('never a_t reaches b_t except through').msg), 'except without through, or with nothing after it');
check(/only works with 'never'/.test(error('only a_t reaches b_t').msg), 'reaches only with never');
c = one('never shadow_t flows to user_t except passwd_t chkpwd_t weight 3');
check(c.kind === 'flows' && same(c.targets, ['user_t']) && same(c.except, ['passwd_t', 'chkpwd_t']) && c.weight === 3, 'flows to … except … weight', c);
check(one('never a_t flows to b_t').weight === 10 && same(one('never a_t flows to b_t').except, []), 'flows: weight 10 and no exceptions by default');
check(/Expected a weight from 1/.test(error('never a_t flows to b_t weight 11').msg) && /Expected 'to'/.test(error('never a_t flows b_t').msg) && /doesn't work with 'flows to'/.test(error('never * flows to b_t').msg),
  'flows errors: weight, missing to, *');

/* ---------- roles, users, logins ---------- */
check(same(one('only sysadm_r may run sysadm_t'), { ...one('only sysadm_r may run sysadm_t'), kind: 'only-run', sources: ['sysadm_r'], targets: ['sysadm_t'] }), 'roles: only … may run');
check(one('never staff_u may use sysadm_r').kind === 'never-use', 'users: never … may use');
check(one('only staff_u user_u may log in').kind === 'only-login' && same(one('only staff_u user_u may log in').users, ['staff_u', 'user_u']), 'users: may log in');
check(/works with 'only' and 'never'/.test(error('require staff_u may log in').msg) && /Expected 'in'/.test(error('never a_u may log').msg), 'may log in errors');
c = one('never login %wheel alice reaches sysadm_t except through newrole_t');
check(c.kind === 'login-reaches' && same(c.logins, ['%wheel', 'alice']) && same(c.through, ['newrole_t']), 'never login … reaches … except through (with %group)', c);
c = one('never login * may read shadow_t:file');
check(c.kind === 'login-may' && same(c.logins, ['*']) && same(c.classes, ['file']), 'never login … may', c);
check(one('never login __default__ maps to unconfined_u').kind === 'login-maps', 'never login … maps to');
check(/start with 'never'/.test(error('only login alice reaches a_t').msg) && /Expected 'reaches', 'may' or 'maps to'/.test(error('never login alice runs a_t').msg), 'login errors');

/* ---------- levels ---------- */
c = one('never container_t svirt_t may ignore levels on { file dir }');
check(c.kind === 'never-levels' && same(c.sources, ['container_t', 'svirt_t']) && same(c.classes, ['file', 'dir']), 'may ignore levels on …', c);
check(one('only init_t may ignore levels').kind === 'only-levels' && same(one('only init_t may ignore levels').classes, []), 'only … may ignore levels (no classes: all)');
c = one('require container_t isolated by levels on process weight 5');
check(c.kind === 'require-isolated' && same(c.sources, ['container_t']) && same(c.classes, ['process']) && c.weight === 5, 'require … isolated by levels on … weight', c);
check(one('require container_t isolated by levels').weight === 10, 'isolated: weight 10 by default');
check(/works with 'require'/.test(error('never container_t isolated by levels').msg) && /Expected 'by levels'/.test(error('require container_t isolated levels').msg)
  && /Expected a weight from 1/.test(error('require c_t isolated by levels weight 0').msg) && /doesn't work with 'isolated by levels'/.test(error('require * isolated by levels').msg)
  && /Unexpected 'extra'/.test(error('require c_t isolated by levels extra').msg), 'isolated errors: kind, by levels, weight, *, extra words');

/* ---------- file structure and errors ---------- */
const p = parseChecks([
  '# comment line',
  '',
  'never a_t may read b_t   # trailing comment',
  'maybe a_t may read b_t',
  'never a_t',
  'never a_t may read b_t:',
  'never a_t may read b_t:file extra',
  'never a_t may read',
  'only a_t may',
].join('\n'));
check(p.checks.length === 1 && p.checks[0].line === 2 && p.checks[0].text === 'never a_t may read b_t   # trailing comment', 'comments and blank lines skipped; line numbers kept', p.checks);
const e = (l) => p.errors.find(x => x.l === l);
check(/Expected 'only', 'never' or 'require'/.test(e(3).msg) && e(3).c === 0 && e(3).len === 5, 'unknown first word: error at column 0 over the word', e(3));
check(/Expected 'may', 'reaches' or 'flows to'/.test(e(4).msg), 'no verb');
check(/after ":"/.test(e(5).msg), 'a colon without a class');
check(/Unexpected 'extra'/.test(e(6).msg) && e(6).c === 'never a_t may read b_t:file '.length, 'extra words: error on the word', e(6));
check(/Expected the target/.test(e(7).msg) && /Expected permissions/.test(e(8).msg), 'missing targets, missing permissions');
check(p.checks.every((x, i) => x.id === i), 'ids number the checks');
check(['ignore', 'levels', 'isolated', 'by', 'through', 'login'].every(k => KEYWORDS.includes(k)), 'keywords include the newer ones (completion and highlighting)');

console.log(failures ? `\n${failures} check(s) failed` : '\nall checks-language checks passed');
process.exit(failures ? 1 : 0);
