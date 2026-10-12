// User editor: the user model in server/service.js, the users / seusers / contexts /
// kernel.te edits (server/userfiles.js), and the webview against a fake DOM. Any OS.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const S = require('../server/service');
const F = require('../server/userfiles');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + (typeof extra === 'string' ? extra : JSON.stringify(extra, null, 1)).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

// An upstream-like tree (4-argument role templates) and a Fedora-like one (role, domain).
const has = new Set(['userdom_unpriv_user_template', 'userdom_admin_user_template', 'userdom_base_user_template', 'sudo_role_template', 'ssh_role_template', 'cron_role',
  'sysadm_role_change', 'staff_role_change_to', 'logging_admin', 'logging_send_syslog_msg', 'mozilla_role']);
const UP = { sudo_role_template: ['role_prefix', 'user_domain', 'user_exec_domain', 'role'], ssh_role_template: ['role_prefix', 'domain', 'user_exec_domain', 'role'],
  cron_role: ['role_prefix', 'domain', 'user_exec_domain', 'role'], sysadm_role_change: ['role', 'domain'], staff_role_change_to: ['role'], logging_admin: ['domain', 'role'], mozilla_role: ['role_prefix', 'domain', 'user_exec_domain', 'role'] };
const FED = { ...UP, sudo_role_template: ['role_prefix', 'user_role', 'user_domain'], cron_role: ['role', 'userdomain_prefix'], mozilla_role: ['role', 'domain'], sysadm_role_change: ['role'] };
const ctxOf = (params) => ({ has: (n) => has.has(n), optional: (n) => !/^(userdom|logging)/.test(n), moduleArgs: 1, params: (n) => params[n],
  roleIfaces: { sysadm_r: { change: 'sysadm_role_change' }, staff_r: { changeTo: 'staff_role_change_to' } }, roleExists: (r) => ['staff_r', 'sysadm_r'].includes(r), typeExists: () => false });
const up = ctxOf(UP), fed = ctxOf(FED);

/* ---------- the role module ---------- */

const m = S.newUserModel();
Object.assign(m, { name: 'ops', summary: 'Operators', roleCalls: ['sudo_role_template', 'ssh_role_template', 'logging_admin', 'mozilla_role'], switchTo: ['sysadm_r'], enteredFrom: ['staff_r'],
  extra: ['logging_send_syslog_msg'], caps: ['kill'], logins: [{ login: 'alice', range: '' }], ways: ['ssh', 'console'] });
check(S.validate(m, up, { isNew: true }).length === 0, 'a valid user model', S.validate(m, up, { isNew: true }));
let p = S.plan(m, up, null);
check(/^role ops_r;\nuserdom_unpriv_user_template\(ops\)$/m.test(p.te), 'declares the role and calls the kind\'s template', p.te);
check(/sudo_role_template\(ops, ops_t, ops_application_exec_domain, ops_r\)/.test(p.te) && /mozilla_role\(ops, ops_t, ops_application_exec_domain, ops_r\)/.test(p.te), 'upstream role calls: prefix, domain, application attribute, role');
check(/logging_admin\(ops_t, ops_r\)/.test(p.te) && /sysadm_role_change\(ops_r, ops_t\)/.test(p.te) && /staff_role_change_to\(ops_r\)/.test(p.te), 'admin call, switch to sysadm_r, entered from staff_r');
check(/^allow ops_t self:capability kill;$/m.test(p.te) && /^logging_send_syslog_msg\(ops_t\)$/m.test(p.te), 'more rights for its domain as for a service');
check(/optional_policy\(`\n\tsudo_role_template/.test(p.te) && !/optional_policy\(`\n\tlogging_admin/.test(p.te), 'calls into modules that may be off go in optional_policy');
check(/interface\(`ops_role_change',`[\s\S]*role ops_r;[\s\S]*allow \$1 ops_r;/.test(p.if) && p.fc === '', '.if: ops_role_change; no file contexts');
p = S.plan(m, fed, null);
check(/sudo_role_template\(ops, ops_r, ops_t\)/.test(p.te) && /mozilla_role\(ops_r, ops_t\)/.test(p.te) && /sysadm_role_change\(ops_r\)/.test(p.te), 'Fedora role calls: (prefix, role, domain), (role, domain)');
const conf = { ...m, user: { kind: 'confined' }, ways: [], logins: [] };
check(/userdom_base_user_template\(ops\)/.test(S.plan(conf, up, null).te), 'confined admin: upstream base template (no confined_admin template)');
const bad = S.validate({ ...m, name: 'staff', roleCalls: ['nope_role', 'sudo_role_template'], switchTo: ['dbadm_r'], logins: [{ login: 'bob smith', range: 'x' }, { login: 'root', range: '' }] }, { ...up, has: (n) => has.has(n) && n !== 'nope_role' }, { isNew: true, loginTaken: (n) => (n === 'root' ? 'unconfined_u' : null) });
for (const re of [/staff_r already exists/, /nope_role doesn't exist/, /change to dbadm_r/, /"bob smith" isn't a Linux login/, /Range "x"/, /root is already mapped to unconfined_u/]) check(bad.some(x => re.test(x)), `refused: ${re}`, bad);
const cv = S.validate({ ...conf, ways: ['ssh'] }, up, { isNew: true });
check(cv.some(x => /doesn't log in itself/.test(x)), 'a confined role with ways in is refused');
check(S.validate({ ...conf, enteredFrom: [] }, up, { isNew: true }).some(x => /Note: no role may switch to ops_r/.test(x)), 'a confined role nobody switches to: noted');
check(!S.validate({ ...m, roleCalls: ['sudo_role_template'], name: 'x2' }, { ...up, params: () => null }, { isNew: true }).length === false, 'an undocumented role call can\'t be filled');

/* ---------- users, seusers, contexts, kernel.te ---------- */

const USERS = 'gen_user(system_u,, system_r, s0, s0 - mls_systemhigh, mcs_allcats)\ngen_user(staff_u, staff, staff_r sysadm_r ifdef(`enable_mls\',`secadm_r auditadm_r\'), s0, s0 - mls_systemhigh, mcs_allcats)\nifdef(`direct_sysadm_daemon\',`\n\tgen_user(root, sysadm, sysadm_r staff_r system_r, s0, s0 - mls_systemhigh, mcs_allcats)\n\')\ngen_user(user_u, user, user_r, s0, s0)\n';
const gu = F.parseGenUsers(USERS);
check(gu.length === 4 && gu[1].roles.includes('ifdef(') && !gu[1].simple && gu[3].simple && gu[2].name === 'root', 'gen_user lines parsed (roles with ifdef are not simple)', gu);
let u = F.editUsers(USERS, { ...m, grantUsers: ['staff_u', 'user_u'] }, { comment: 'Operators', prefix: 'user' });
check(/\n\n# Operators\ngen_user\(ops_u, user, ops_r sysadm_r, s0, s0\)\n$/.test(u), 'new gen_user line at the end with its comment', u);
check(/gen_user\(staff_u, staff, staff_r sysadm_r ops_r ifdef/.test(u) && /gen_user\(user_u, user, user_r ops_r, s0, s0\)/.test(u), 'granted users get the role (before an ifdef in the roles)');
u = F.editUsers(u, { ...m, range: 's0 - mls_systemhigh', cats: 'mcs_allcats', grantUsers: ['staff_u'] }, { prevGrant: ['staff_u', 'user_u'], prefix: 'user' });
check(/gen_user\(ops_u, user, ops_r sysadm_r, s0, s0 - mls_systemhigh, mcs_allcats\)/.test(u) && /gen_user\(user_u, user, user_r, s0, s0\)/.test(u), 'its line rewritten in place; a user no longer granted loses the role', u);
const SE = 'root:unconfined_u:s0-s0:c0.c1023\nbob:ops_u:s0\nold:ops_u\n__default__:unconfined_u:s0-s0:c0.c1023\n';
const se = F.editSeusers(SE, { ...m, logins: [{ login: 'alice', range: '' }, { login: 'bob', range: 's0-s0:c0.c5' }] });
check(se === 'root:unconfined_u:s0-s0:c0.c1023\nbob:ops_u:s0-s0:c0.c5\nalice:ops_u\n__default__:unconfined_u:s0-s0:c0.c1023\n', 'seusers: changed range rewritten, removed login gone, new one before __default__', se);
const ct = F.contextsText({ ...m, roleCalls: ['sudo_role_template', 'su_role_template'], ways: ['ssh', 'cron'] }, { typeExists: (t) => t !== 'sshd_session_t' });
check(ct === 'system_r:sshd_t:s0\t\tops_r:ops_t:s0\nsystem_r:crond_t:s0\t\tops_r:ops_t:s0\nops_r:ops_sudo_t:s0\t\tops_r:ops_t:s0 sysadm_r:sysadm_t:s0\nops_r:ops_su_t:s0\t\tops_r:ops_t:s0 sysadm_r:sysadm_t:s0\n', 'contexts file: ways in, then after sudo and su', ct);
const K = 'policy_module(kernel)\n\nrole system_r;\nrole sysadm_r;\n\nifdef(`enable_mls\',`\n\trole secadm_r;\n\')\n';
check(F.editKernelRoles(K, 'ops_r') === K.replace('role sysadm_r;\n', 'role sysadm_r;\nrole ops_r;\n') && F.editKernelRoles(K, 'sysadm_r') === K && F.editKernelRoles('x', 'a_r') === null, 'kernel.te: role added after the top-level ones, once');

/* ---------- webview ---------- */

class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this._text = ''; this.open = false; this.nodeType = 1; this.checked = false; this.disabled = false; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set className(v) { this.attrs.class = v; } get className() { return this.attrs.class || ''; }
  append(...cs) { for (let c of cs) { if (typeof c === 'string') c = text(c); this.children.push(c); c.parent = this; } }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'open') this.open = true; if (k === 'value') this.value = String(v); if (k === 'checked') this.checked = true; if (k === 'disabled') this.disabled = true; }
  addEventListener(ev, f) { (this.listeners[ev] = this.listeners[ev] || []).push(f); }
  fire(ev) { for (const f of this.listeners[ev] || []) f({ target: this, currentTarget: this, preventDefault() {}, stopPropagation() {} }); }
  all(pred, out = []) { for (const c of this.children) { if (c.tag && pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
}
const text = (s) => ({ nodeType: 3, textContent: s });
const byId = {};
for (const id of ['form', 'preview', 'status', 'apply', 'title']) byId[id] = new El(id);
const posted = [];
const winListeners = [];
const timers = [];
const wctx = {
  setTimeout: (f) => { timers.push(f); return timers.length; }, clearTimeout: () => {},
  acquireVsCodeApi: () => ({ postMessage: (msg) => posted.push(JSON.parse(JSON.stringify(msg))), getState: () => null, setState: () => {} }),
  document: { getElementById: (id) => byId[id], createElement: (tag) => new El(tag), createTextNode: text },
  window: { addEventListener: (ev, f) => winListeners.push(f) },
};
vm.createContext(wctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/user.js'), 'utf8'), wctx);
const send = (data) => winListeners.forEach(f => f({ data }));
const flush = () => { while (timers.length) timers.shift()(); };
const last = (cmd) => [...posted].reverse().find(x => x.cmd === cmd);
const find = (pred) => byId.form.all(pred);
check(posted[0] && posted[0].cmd === 'ready', 'webview asks for the catalog');
const info = {
  isNew: true, model: S.newUserModel(), users: ['staff_u', 'sysadm_u'], prefixDefault: 'user', seusers: [{ login: 'root', user: 'unconfined_u' }],
  interfaces: [{ n: 'logging_send_syslog_msg', s: 'Send syslog messages.' }],
  catalog: S.userCatalog({ ...fed, roleCalls: [{ n: 'sudo_role_template', s: 'sudo', m: 'sudo', g: 'login' }, { n: 'cron_role', s: 'cron', m: 'cron', g: 'apps' }, { n: 'logging_admin', s: 'Administer logs', m: 'logging', g: 'admin' }] },
    F.WAYS),
};
send({ cmd: 'init', info });
check(find(e => e.tag === 'details').length === 6, 'six sections: user, logins, roles, programs, rights, levels');
const input = (ph) => find(e => e.tag === 'input' && (e.attrs.placeholder || '').startsWith(ph))[0];
const name = input('e.g. ops');
name.value = 'ops'; name.fire('input');
flush();
check(last('plan') && last('plan').model.name === 'ops', 'typing a name asks for a plan');
const radios = find(e => e.tag === 'input' && e.attrs.type === 'radio');
check(radios.length === info.catalog.kinds.length && radios.some(r => r.checked), `kinds as radios (${radios.length})`);
const boxOf = (label) => find(e => e.tag === 'label' && e.textContent.startsWith(label))[0].all(e => e.tag === 'input')[0];
const cron = boxOf('Cron jobs');
cron.checked = true; cron.fire('change');
flush();
check(last('plan').model.ways.includes('cron') && last('plan').model.roleCalls.includes('cron_role'), 'ticking cron jobs adds cron_role');
const lg = input('login, %group');
lg.value = 'root'; lg.fire('input');
flush();
send({ cmd: 'init', info: { ...info, model: last('plan').model } });
check(/now unconfined_u/.test(byId.form.textContent), 'a login already mapped elsewhere is marked');
radios.find(r => r.attrs.value === 'confined').fire('change');
flush();
check(last('plan').model.user.kind === 'confined' && last('plan').model.ways.length === 0 && /has no logins of its own/.test(byId.form.textContent), 'confined: ways cleared, logins explained');
const search = input('search: apache');
search.value = 'log'; search.fire('input');
const hit = find(e => (e.attrs.class || '') === 'hit' && /logging_admin/.test(e.textContent))[0];
check(!!hit, 'role call search finds logging_admin');
hit.fire('click');
flush();
check(last('plan').model.roleCalls.includes('logging_admin'), 'clicking a hit adds it');
send({ cmd: 'plan', plan: { problems: ['Note: something'], files: [{ path: '/t/policy/modules/roles/ops.te', kind: 'te', exists: false, diff: [['+', 'role ops_r;']] }, { path: '/t/policy/users', kind: 'users', exists: true, diff: [[' ', 'gen_user(x)'], ['+', 'gen_user(ops_u)']] }] } });
check(!byId.apply.disabled && /ops\.te \(new\)/.test(byId.preview.textContent) && /\+ role ops_r;/.test(byId.preview.textContent), 'preview: tabs and diff; Create enabled with notes only');
send({ cmd: 'plan', plan: { problems: ['A role named ops_r already exists.'], files: [] } });
check(byId.apply.disabled && /already exists/.test(byId.preview.textContent), 'a problem disables Create');

console.log(failures ? `${failures} FAILED` : 'all user checks passed');
process.exit(failures ? 1 : 0);
