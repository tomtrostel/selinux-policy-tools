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
/* ---------- an existing user's kind changed; kinds that can't link ---------- */

// A tree where the X kind's template needs xdm_t and the xserver module is off (CLIP).
const xctx = { ...up, has: (n) => has.has(n) || /^userdom_restricted/.test(n),
  linkBlockers: (t) => (t === 'userdom_restricted_xwindows_user_template' ? [{ name: 'xdm_t', modules: ['xserver'] }] : []) };
const xte = 'policy_module(ro, 1.0.0)\n\n########################################\n#\n# Declarations\n#\n\nrole ro_r;\nuserdom_restricted_xwindows_user_template(ro)\n\n########################################\n#\n# ro local policy\n#\n';
const kinds = S.userCatalog(xctx, []).kinds;
const kx = kinds.find(k => k.id === 'restricted_x'), kr = kinds.find(k => k.id === 'restricted');
check(kx && /needs xdm_t, which only the xserver module \(off in modules\.conf\) declares/.test(kx.blocked) && kr && kr.blocked === '', 'catalog: the X kind is blocked here (xdm_t, xserver off), the terminal kind isn\'t', kinds);
const xrec = S.recognize({ te: xte, if: '', fc: '' }, xctx, { user: true, module: 'ro' });
check(xrec.model && xrec.model.user.kind === 'restricted_x', 'read back as a restricted desktop user', xrec.error || xrec.model && xrec.model.user);
const xv = S.validate(xrec.model, xctx, { isNew: false, baseline: xrec.model });
check(xv.some(x => /^Note: userdom_restricted_xwindows_user_template needs xdm_t/.test(x)) && !xv.some(x => /^userdom_restricted_xwindows/.test(x)), 'kept as it is: a note that it won\'t link, not an error', xv);
const xm = JSON.parse(JSON.stringify(xrec.model));
xm.user.kind = 'restricted';
check(!S.validate(xm, xctx, { isNew: false, baseline: xrec.model }).some(x => /xdm_t|have no|has no/.test(x)), 'switched to the terminal kind: nothing in the way', S.validate(xm, xctx, { isNew: false, baseline: xrec.model }));
const xp = S.plan(xm, xctx, { te: xte, if: '', fc: '' }, null);
check(xp.te === xte.replace('userdom_restricted_xwindows_user_template(ro)', 'userdom_restricted_user_template(ro)'),
  'the template call is replaced on its own line; nothing else changes', xp.te);
check(S.plan(xm, xctx, { te: xp.te, if: '', fc: '' }, null).te === xp.te, 'planned again on the result: no further change');
const xback = S.recognize({ te: xp.te, if: '', fc: '' }, xctx, { user: true, module: 'ro' }).model;
const bm = JSON.parse(JSON.stringify(xback)); bm.user.kind = 'restricted_x';
check(S.validate(bm, xctx, { isNew: false, baseline: xback }).some(x => /^userdom_restricted_xwindows_user_template needs xdm_t.*wouldn't link/.test(x)), 'switching to a kind that can\'t link is an error');
const xnew = { ...S.newUserModel(), name: 'kiosk', user: { kind: 'restricted_x' }, logins: [] };
check(S.validate(xnew, xctx, { isNew: true }).some(x => /^userdom_restricted_xwindows_user_template needs xdm_t/.test(x)), 'a new user of that kind: refused too');

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

/* ---------- standalone: the RPM spec creates the user ---------- */

const P = require('../server/packaging');
const su = { U: 'ops_u', roles: ['ops_r', 'sysadm_r'], level: 's0', range: 's0-s0:c0.c1023', prefix: 'user', logins: [{ login: 'alice', range: '' }, { login: "%o'ps", range: 's0' }], grant: ['staff_u'], contexts: true };
const spec = P.specText({ name: 'ops', user: su, date: new Date(2026, 9, 12) });
check(/^Source3: +ops_u_default_contexts$/m.test(spec) && /%config\(noreplace\) %\{_sysconfdir\}\/selinux\/%\{selinuxtype\}\/contexts\/users\/ops_u/.test(spec) && /Requires\(post\): policycoreutils-python-utils/.test(spec), 'spec: contexts file shipped, semanage required');
const post = spec.slice(spec.indexOf('%post\n'), spec.indexOf('%postun')), postun = spec.slice(spec.indexOf('%postun'), spec.indexOf('%posttrans'));
check(post.indexOf('%selinux_modules_install') < post.indexOf('semanage user -a') && postun.indexOf('semanage user -d') < postun.indexOf('%selinux_modules_uninstall'), 'the user is created after the module, removed before it');
check(/'%%o'\\''ps'/.test(spec) && /printf "%%s "/.test(spec) && !/[^%]%s /.test(spec), 'a %group and quotes escaped for rpm and the shell; no bare % macros');
const back = F.readSpecUser(spec, 'ops_u', 'ops_r');
check(JSON.stringify(back) === JSON.stringify({ userRoles: ['ops_r', 'sysadm_r'], level: 's0', range: 's0-s0:c0.c1023', prefix: 'user', logins: [{ login: 'alice', range: '' }, { login: "%o'ps", range: 's0' }], grantUsers: ['staff_u'] }), 'the spec reads back as written', back);
check(/^rpm: .* ops_u_default_contexts$/m.test(P.makefileText('ops', ['ops_u_default_contexts'])), 'Makefile: rpm depends on the contexts file');

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

// The automation preset and the reach preview.
send({ cmd: 'init', info });
find(e => e.tag === 'button' && e.textContent === 'Automation account')[0].fire('click');
flush();
const am = last('plan').model;
check(am.user.kind === 'unpriv' && am.ways.join() === 'ssh,cron' && am.roleCalls.join() === 'sudo_role_template,cron_role' && am.preset === 'automation', 'automation preset: ordinary user, ssh + cron, sudo + cron_role', am);
check(/one narrow role/.test(byId.form.textContent) && /ROLE=<role> TYPE=<domain> NOPASSWD/.test(byId.form.textContent), 'its note explains the narrow role and the sudoers line');
send({ cmd: 'plan', plan: { problems: [], files: [{ path: '/t/a.te', kind: 'te', exists: false, diff: [['+', 'x']] }] } });
const pb = byId.preview.all(e => e.tag === 'button' && e.textContent === 'Preview what it can reach')[0];
pb.fire('click');
check(last('preview') && last('preview').model.name === am.name && /Building a scratch copy/.test(byId.preview.textContent), 'Preview asks the server and shows it is building');
send({ cmd: 'preview', result: { buildMs: 9100, roles: ['ops_r', 'logops_r'], ways: [{ label: 'ssh', contexts: [{ role: 'ops_r', type: 'ops_t' }] }], reached: 12, before: { reached: 10, abilities: [] },
  abilities: [{ id: 'shadow', label: 'can read password hashes (/etc/shadow)', severity: 'medium', domain: 'chkpwd_t', path: [{ text: 'ops_t → chkpwd_t (runs chkpwd_exec_t)' }] }],
  gained: [{ name: 'logops_t', path: [{ text: 'ops_t → newrole_t' }, { text: 'newrole_t → logops_t' }] }], lost: ['mail_t'], notes: [] } });
const pt = byId.preview.textContent;
check(/ssh: ops_r:ops_t/.test(pt) && /Reaches 12 domains \(was 10: \+1, −1\)/.test(pt) && /chkpwd_t/.test(pt) && /\(new\)/.test(pt) && /can reach now and couldn't before/.test(pt) && /no longer reach/.test(pt), 'preview result: ways, count with the difference, abilities (new), gained and lost');
const nm = find(e => e.tag === 'input' && (e.attrs.placeholder || '').startsWith('e.g. ops'))[0];
nm.value = 'ops2'; nm.fire('input');
send({ cmd: 'plan', plan: { problems: [], files: [] } });
check(/The form changed since/.test(byId.preview.textContent), 'a change after the preview marks it stale');

// An existing user: name and kind fixed, its lines kept as they are listed, Apply.
const staff = { ...S.newUserModel(), name: 'staff', module: 'staff', declaredBy: { name: 'userdom_unpriv_user_template', args: ['staff'] }, genUser: { exists: true, simple: false },
  logins: [{ login: '__default__', range: 's0' }], ways: ['ssh'], waysDefault: ['ssh'], waysFrom: 'default', userRoles: null };
send({ cmd: 'init', info: { ...info, isNew: false, module: 'staff', model: staff, kept: [{ l: 41, endL: 41, text: 'ifdef(`foo\',`allow staff_t self:x y;\')' }], files: { te: '/t/staff.te' }, usersFile: '/t/policy/users' } });
check(/User: staff_u \(staff\)/.test(byId.title.textContent) && byId.apply.textContent === 'Apply', `title for an existing user: ${byId.title.textContent}`);
const kindRadios = () => find(e => e.tag === 'input' && e.attrs.type === 'radio' && e.attrs.name === 'kind');
check(kindRadios().length === info.catalog.kinds.length && kindRadios().find(r => r.attrs.value === 'unpriv').checked && /userdom_unpriv_user_template\(staff\) \(now\)/.test(byId.form.textContent),
  'kind: the current one checked, with its template call as written');
check(/written with ifdef\(\) or more than once/.test(byId.form.textContent) && /default_contexts/.test(byId.form.textContent), 'its gen_user line is left alone; ways from default_contexts marked');
const kl = find(e => (e.attrs.class || '') === 'keptline')[0];
kl.fire('click');
check(kl && /42/.test(kl.textContent) && last('open').path === '/t/staff.te' && last('open').line === 41, 'kept lines listed; clicking opens the line');
check(!posted.some(x => x.cmd === 'plan' && x.model && x.model.name === 'staff'), 'no plan until something changes');
kindRadios().find(r => r.attrs.value === 'admin').fire('change');
flush();
check(last('plan') && last('plan').model.name === 'staff' && last('plan').model.user.kind === 'admin', 'an existing user\'s kind can be changed');
// A kind whose template can't link here is disabled, unless it is the user's own.
const blockedInfo = { ...info, isNew: false, module: 'staff', model: { ...staff, user: { kind: 'unpriv' } },
  catalog: { ...info.catalog, kinds: info.catalog.kinds.map(k => (k.id === 'admin' || k.id === 'unpriv' ? { ...k, blocked: 'needs xdm_t, which only the xserver module (off in modules.conf) declares' } : k)) } };
send({ cmd: 'init', info: blockedInfo });
check('disabled' in kindRadios().find(r => r.attrs.value === 'admin').attrs && !('disabled' in kindRadios().find(r => r.attrs.value === 'unpriv').attrs) && /so the tree can't link it/.test(byId.form.textContent),
  'a kind that can\'t link is disabled and says why; the user\'s own kind stays selectable');

/* ---------- every user role module of a tree (optional argument) ---------- */

if (process.argv[2]) survey(process.argv[2]);

console.log(failures ? `${failures} FAILED` : 'all user checks passed');
process.exit(failures ? 1 : 0);

function survey(root) {
  const { PolicyIndex } = require('../server/indexer');
  const idx = new PolicyIndex(() => {});
  idx.scanRoots([root]);
  const tctx = F.userTreeCtx(idx, {
    has: (n) => idx.defs.has(n), moduleArgs: 2, typeExists: (t) => idx.decls.has(t),
    optional: (n) => { const d = (idx.defs.get(n) || [])[0]; return !!d && !/[\\/](kernel|system)[\\/]/.test(d.path); },
    declares: (n) => (((idx.defs.get(n) || [])[0] || {}).declPatterns || []).map(x => x.pattern),
  });
  // The tree's users file (Fedora's policy/users points at dist/targeted/users) and appconfig-mcs files.
  const tree = path.dirname(root);
  const readOr = (...ps) => { for (const x of ps) { try { const t = fs.readFileSync(x, 'utf8'); if (!/^\.\.?\//.test(t.trim())) return t; } catch { /* next */ } } return null; };
  const usersText = readOr(path.join(root, 'users'), path.join(tree, 'dist/targeted/users'));
  const cfg = path.join(tree, 'config', 'appconfig-mcs');
  const seText = readOr(path.join(cfg, 'seusers')), defaults = readOr(path.join(cfg, 'default_contexts'));
  const mods = idx.modules().filter(m => m.files.te && S.userDomainOf(fs.readFileSync(m.files.te, 'utf8')));
  let same = 0, edits = 0, bad = 0;
  const textsOf = (m, stem) => ({ te: fs.readFileSync(m.files.te, 'utf8'), if: m.files.if ? fs.readFileSync(m.files.if, 'utf8') : '', fc: m.files.fc ? fs.readFileSync(m.files.fc, 'utf8') : '',
    users: usersText, seusers: seText, defaults, contexts: readOr(path.join(cfg, `${stem}_u_default_contexts`)) });
  const read = (t, mod) => {
    const rec = S.recognize({ te: t.te, if: t.if, fc: t.fc }, tctx, { user: true, module: mod });
    if (rec.error) return rec;
    F.readUser(rec.model, t);
    return rec;
  };
  const apply = (t, prev, model) => {
    const out = S.plan(model, tctx, { te: t.te, if: t.if, fc: t.fc }, null);
    if (out.error) return { error: out.error };
    return { ...t, te: out.te, if: out.if, fc: out.fc,
      users: t.users == null ? null : F.editUsers(t.users, model, { prev, prevGrant: prev.grantUsers, prefix: prev.prefix }),
      seusers: t.seusers == null || !prev.genUser.exists ? t.seusers : F.editSeusers(t.seusers, model),
      contexts: F.editContexts(t.contexts, model, prev, { typeExists: tctx.typeExists }), defaults: F.editDefaults(t.defaults, model, prev) };
  };
  const sorted = (a) => [...(a || [])].sort();
  const norm = (m) => JSON.stringify([sorted(m.roleCalls), sorted(m.switchTo), sorted(m.enteredFrom), sorted(m.caps), sorted(m.self), sorted(m.access), sorted(m.extra),
    sorted(m.ways), (m.logins || []).map(l => `${l.login}:${l.range}`).sort(), sorted(m.grantUsers), m.genUser && m.genUser.simple ? sorted(m.userRoles) : null,
    (m.booleans || []).map(b => b.name).sort()]);
  const apps = tctx.roleCalls.filter(c => c.g === 'apps' || c.g === 'admin');
  const muts = [
    ['add a capability', m => { const c = ['kill', 'sys_nice', 'dac_read_search', 'sys_rawio'].find(x => !m.caps.includes(x)); if (c) m.caps.push(c); }],
    ['remove a capability', m => { m.caps.splice(0, 1); }],
    ['add an interface', m => { if (!m.extra.includes('dev_read_sound')) m.extra.push('dev_read_sound'); }],
    ['remove an interface', m => { m.extra.splice(0, 1); }],
    ['add a role call', m => { const c = apps.find(x => !m.roleCalls.includes(x.n) && S.roleCallArgs(x.n, m, tctx)); if (c) m.roleCalls.push(c.n); }],
    ['remove a role call', m => { m.roleCalls.splice(0, 1); }],
    ['add sudo', m => { if (tctx.has('sudo_role_template') && !m.roleCalls.includes('sudo_role_template')) m.roleCalls.push('sudo_role_template'); }],
    ['add a role switch', m => { const r = Object.entries(tctx.roleIfaces).find(([r2, x]) => x.change && r2 !== `${m.name}_r` && !m.switchTo.includes(r2)); if (r) m.switchTo.push(r[0]); }],
    ['remove a role switch', m => { m.switchTo.splice(0, 1); }],
    ['add entered from', m => { const r = Object.entries(tctx.roleIfaces).find(([r0, x]) => x.changeTo && r0 !== `${m.name}_r` && !m.enteredFrom.includes(r0)); if (r) m.enteredFrom.push(r[0]); }],
    ['toggle a way in', m => { if ((m.waysDefault || []).includes('console')) return; if (m.ways.includes('console')) m.ways.splice(m.ways.indexOf('console'), 1); else m.ways.push('console'); }],
    ['add a login', m => { if (m.genUser.exists) m.logins.push({ login: 'zzsurvey', range: '' }); }],
    ['grant another user', m => { const u = F.parseGenUsers(usersText || '').find(x => x.simple && x.name !== `${m.name}_u` && x.name !== 'system_u' && !m.grantUsers.includes(x.name)); if (u) m.grantUsers.push(u.name); }],
    ['add a boolean', m => { m.booleans.push({ name: `${m.name}_e2e_extra`, desc: 'Test boolean.', default: false, _new: true, grants: { caps: ['kill'], extra: [], access: [], self: [], net: { listen: [], connect: [] } } }); }],
  ];
  const fails = [];
  for (const m of mods) {
    const stem = S.userDomainOf(fs.readFileSync(m.files.te, 'utf8')).stem;
    const t = textsOf(m, stem);
    const rec = read(t, m.module);
    if (rec.error) { fails.push(`${m.module}: ${rec.error}`); continue; }
    const noop = apply(t, rec.model, JSON.parse(JSON.stringify(rec.model)));
    if (!noop.error && ['te', 'if', 'fc', 'users', 'seusers', 'contexts', 'defaults'].every(k => noop[k] === t[k])) same++;
    else fails.push(`${m.module}: no-op changed ${['te', 'if', 'fc', 'users', 'seusers', 'contexts'].filter(k => noop[k] !== t[k]).join(', ') || noop.error}`);
    for (const [what, mut] of muts) {
      const want = JSON.parse(JSON.stringify(rec.model));
      mut(want);
      // The gen_user line follows the role switches added or removed (simple lines only).
      if (want.userRoles) { const was = new Set(rec.model.switchTo), now = new Set(want.switchTo); want.userRoles = want.userRoles.filter(r => !(was.has(r) && !now.has(r))); for (const r of now) if (!was.has(r) && !want.userRoles.includes(r)) want.userRoles.push(r); }
      if (norm(want) === norm(rec.model)) continue;
      const t2 = apply(t, rec.model, want);
      edits++;
      const r2 = t2.error ? t2 : read(t2, m.module);
      if (r2.error) { bad++; fails.push(`${m.module} / ${what}: ${r2.error}`); continue; }
      if (norm(r2.model) !== norm(want)) { bad++; fails.push(`${m.module} / ${what}: reads back as\n${norm(r2.model)}\nnot\n${norm(want)}`); continue; }
      const t3 = apply(t2, r2.model, JSON.parse(JSON.stringify(r2.model)));
      if (['te', 'users', 'seusers', 'contexts'].some(k => t3[k] !== t2[k])) { bad++; fails.push(`${m.module} / ${what}: not idempotent`); }
    }
  }
  check(mods.length && same === mods.length, `${root}: ${same} of ${mods.length} user role modules unchanged by a no-op edit (${mods.map(x => x.module).join(' ')})`, fails.filter(x => /no-op|isn't/.test(x)));
  check(!bad, `${root}: ${edits - bad} of ${edits} edits read back as the edited model and are idempotent`, fails.filter(x => !/no-op/.test(x)).slice(0, 8).map(x => (x.length > 300 ? `${x.slice(0, 300)} …` : x)).join('\n'));
}
