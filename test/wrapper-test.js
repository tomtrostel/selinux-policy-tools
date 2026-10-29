// Wrapped programs: the module the wrapper editor writes, read back, edited
// with hand edits kept, validation, checks and the spec's blocks; the
// webview with a fake DOM. Any OS.
//   node test/wrapper-test.js
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const W = require('../server/wrapper');
const packaging = require('../server/packaging');
const C = require('../server/checks');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + (typeof extra === 'string' ? extra : JSON.stringify(extra, null, 1)).slice(0, 3000).replace(/\n/g, '\n     ')); }
};

const IFACES = new Set(['files_security_file', 'libs_use_ld_so', 'libs_use_shared_libs', 'miscfiles_read_localization', 'userdom_use_user_terminals', 'logging_send_syslog_msg', 'sysnet_read_config']);
const ctx = { has: (n) => IFACES.has(n), optional: (n) => n === 'sysnet_read_config', moduleArgs: 2, moduleExists: (n) => n === 'apache' };

/* ---------- a new module ---------- */

const model = W.newModel();
Object.assign(model, { name: 'rowrap', summary: 'Programs read-only users may run', chroot: '/var/chroot/ro/', likeRoot: true, protectedDir: '/.rowrap', wrapperDir: '/opt/rowrap/bin', role: 'roshell_r', domain: 'roshell_t', logins: '%rousers alice' });
const a = W.newProgram('/usr/sbin/someprog', ctx);
check(a.stem === 'someprog' && a.wrapper === 'someprog' && a.copy === 'someprog.real' && a.ifaces.length === 4, 'a new program: short name, wrapper and copy names, the default interfaces', a);
Object.assign(a, { origType: 'someprog_exec_t', target: 'someprog_t', roles: ['someprog_helper_t'], selfRules: [{ c: 'file', perms: ['execute_no_trans', 'read'] }], pkg: 'someprog-tools' });
a.ifaces.push('sysnet_read_config');
const b = W.newProgram('/usr/bin/plain-tool', ctx);
Object.assign(b, { stem: 'plain_tool', origType: 'bin_t', target: '' });
model.programs.push(a, b);
const out = W.render(model, ctx);
const te = out.te;
check(/^policy_module\(rowrap, 1\.0\.0\)/.test(te) && /# wrapper-chroot: \/var\/chroot\/ro\n/.test(te) && /# wrapper-user: roshell_r roshell_t\n# wrapper-logins: %rousers alice\n/.test(te), 'header: module, chroot (trailing / dropped), user, logins');
check(/gen_require\(`\n\trole roshell_r;\n\ttype roshell_t, someprog_t, someprog_helper_t;\n'\)/.test(te), 'gen_require: the role, the user domain and the domains used', te.slice(0, 900));
check(/type rowrap_someprog_t;\ntype rowrap_someprog_exec_t;\ntype rowrap_someprog_real_exec_t;\ndomain_type\(rowrap_someprog_t\)\ndomain_entry_file\(rowrap_someprog_t, rowrap_someprog_exec_t\)\nfiles_security_file\(rowrap_someprog_real_exec_t\)/.test(te),
  'wrapper domain + entry; the copy a security file (not exec_type / entry_type; out of broad rules on other files)');
check(/files_type\(rowrap_someprog_real_exec_t\)/.test(W.render(model, { ...ctx, has: (n) => n !== 'files_security_file' && IFACES.has(n) }).te), 'files_type where the policy has no files_security_file');
check(/domtrans_pattern\(roshell_t, rowrap_someprog_exec_t, rowrap_someprog_t\)/.test(te) && /domtrans_pattern\(rowrap_someprog_t, rowrap_someprog_real_exec_t, someprog_t\)/.test(te), 'user → wrapper → original domain');
check(/allow someprog_t rowrap_someprog_real_exec_t:file \{ entrypoint mmap_exec_file_perms ioctl lock \};\nallow someprog_t rowrap_someprog_real_exec_t:file \{ execute_no_trans read \};\nrole roshell_r types \{ someprog_t someprog_helper_t \};/.test(te),
  'the copy is an entry point of the original domain; its rules on its own file copied; the role gets the domains', te);
check(/optional_policy\(`\n\tsysnet_read_config\(rowrap_someprog_t\)\n'\)/.test(te) && /^libs_use_ld_so\(rowrap_someprog_t\)$/m.test(te), 'interfaces of optional modules in optional_policy');
check(/can_exec\(rowrap_plain_tool_t, rowrap_plain_tool_real_exec_t\)/.test(te) && /has no domain of its own/.test(te), 'a program without its own domain runs in the wrapper\'s');
check(/allow rowrap_someprog_t rowrap_protected_t:dir search_dir_perms;/.test(te) && /type rowrap_protected_t;\nfiles_security_file\(rowrap_protected_t\)/.test(te), 'the protected directory: searchable by the wrappers only');
const fc = out.fc;
check(/^\/opt\/rowrap\/bin\/someprog\t\t--\tgen_context\(system_u:object_r:rowrap_someprog_exec_t,s0\)$/m.test(fc) && /^\/\\\.rowrap\t\t-d\tgen_context\(system_u:object_r:rowrap_protected_t,s0\)$/m.test(fc)
  && /^\/\\\.rowrap\/someprog\\\.real\t\t--/m.test(fc) && /^\/opt\/rowrap\/bin\/plain-tool\t/m.test(fc), 'file contexts: paths inside the chroot, regex characters escaped', fc);
const own = W.render({ ...model, likeRoot: false }, ctx).fc;
check(/^\/var\/chroot\/ro\/\\\.rowrap\t/m.test(own) && /# wrapper-labels: own/.test(W.render({ ...model, likeRoot: false }, ctx).te), 'without the equivalence: the chroot prefix in each line');
check(/^## <summary>Wrapped programs: Programs read-only users may run<\/summary>/.test(out.if), '.if summary');
check(W.render({ ...model }, { ...ctx, moduleArgs: 1 }).te.startsWith('policy_module(rowrap)\n'), 'one-argument policy_module where the tree uses it');

/* ---------- read back, edits ---------- */

const rec = W.recognize(out);
check(!rec.error && JSON.stringify(rec.model) === JSON.stringify({ ...model, chroot: '/var/chroot/ro', logins: '%rousers alice', programs: model.programs.map(p => ({ ...p, pkg: p.pkg || null })) }), 'read back: the same model', { got: rec.model, want: model });
check(W.recognize({ te: 'policy_module(x, 1.0)\n', fc: '' }).error, 'a module the editor didn\'t write is refused');
let p = W.plan(model, ctx, out);
check(p.te === out.te && p.fc === out.fc && p.if === out.if && !p.kept.length, 'no-op: identical files');
const hand = out.te.replace('# The wrapper runs the protected copy.\n', '# The wrapper runs the protected copy.\nallow rowrap_someprog_t self:capability setuid;\n') + '\n# mine\ndontaudit roshell_t rowrap_protected_t:dir getattr;\n';
const m2 = JSON.parse(JSON.stringify(model));
m2.programs = [m2.programs[0]];
m2.programs[0].roles = [];
p = W.plan(m2, ctx, { ...out, te: hand, fc: out.fc + '/opt/rowrap/bin/extra\t--\tgen_context(system_u:object_r:bin_t,s0)\n' });
check(!/plain_tool/.test(p.te) && !/someprog_helper_t/.test(p.te) && p.te.includes(W.LOCAL_HEADER) && /allow rowrap_someprog_t self:capability setuid;/.test(p.te.split(W.LOCAL_HEADER)[1]) && /dontaudit roshell_t/.test(p.te.split(W.LOCAL_HEADER)[1]),
  'an edit: program and role removed; hand-written lines kept in the local section', p.te.split(W.LOCAL_HEADER)[1]);
check(p.kept.length === 4 && /extra/.test(p.fc.split(W.LOCAL_HEADER)[1] || ''), 'kept lines listed (te and fc)', p.kept);
const again = W.plan(m2, ctx, { te: p.te, fc: p.fc, if: p.if });
check(again.te === p.te && again.fc === p.fc, 'editing again keeps the local section as it is (idempotent)', again.te.split(W.LOCAL_HEADER)[1]);

/* ---------- validation ---------- */

const types = new Set(['roshell_t', 'someprog_t', 'someprog_helper_t']);
const opts = { isNew: true, typeExists: (t) => types.has(t), roleExists: (r) => r === 'roshell_r', hostExists: (x) => x === '/opt/rowrap/bin/plain-tool' };
let v = W.validate(model, ctx, opts);
check(v.some(x => /plain-tool exists on the host too/.test(x)) && v.some(x => /^Note: \/usr\/bin\/plain-tool has no domain of its own/.test(x)), 'a wrapper path the host has is refused (the equivalence would relabel it); no-domain note', v);
v = W.validate({ ...model, name: 'apache', chroot: '/', protectedDir: '/opt/rowrap/bin/x', programs: [{ ...a, ifaces: ['nope_iface'], target: 'gone_t' }, { ...a }] }, ctx, opts);
check(v.some(x => /apache already exists/.test(x)) && v.some(x => /chroot must be/.test(x)) && v.some(x => /separate directories/.test(x)) && v.some(x => /no interface nope_iface/.test(x)) && v.some(x => /no domain gone_t/.test(x)) && v.some(x => /Two programs/.test(x)),
  'name taken, chroot /, overlapping directories, unknown interface and domain, duplicates', v);
v = W.validate({ ...model, programs: [] , role: '' }, ctx, opts);
check(v.some(x => /Pick the user/.test(x)) && v.some(x => /at least one program/.test(x)), 'no user, no programs');
check(W.validate({ ...model, programs: [a] }, ctx, { ...opts, hostExists: () => false }).length === 0, 'a complete model passes', W.validate({ ...model, programs: [a] }, ctx, { ...opts, hostExists: () => false }));
check(W.validate({ ...model, programs: [a], logins: '' }, ctx, { ...opts, hostExists: () => false }).some(x => /^Note: give the Linux logins/.test(x)) && W.validate({ ...model, programs: [a], logins: 'bad login!' }, ctx, opts).some(x => /isn't one/.test(x)), 'logins: a note without them; bad names refused');
const tv = (logins, tree) => W.validate({ ...model, programs: [a], logins }, ctx, { ...opts, tree, hostExists: () => false });
check(tv('%ro rouser', true).some(x => /^Note: a tree's build keeps only seusers lines .* can't map %ro and/.test(x)) && !tv('%ro', false).some(x => /tree's build/.test(x)) && !tv('rouser', true).some(x => /tree's build/.test(x)),
  'logins: a %group in a tree gets a note (its build drops the line), not standalone');

/* ---------- checks ---------- */

const ct = W.checksText(model);
const pc = C.parseChecks(ct);
check(!pc.errors.length && pc.checks.length === 3, 'checks lines parse', { ct, errors: pc.errors });
check(pc.checks[0].kind === 'never' && pc.checks[0].targets.join() === 'rowrap_someprog_real_exec_t,rowrap_plain_tool_real_exec_t' && pc.checks[0].perms.join() === 'execute,read,getattr' && pc.checks[2].kind === 'login-reaches' && pc.checks[2].logins.join() === '%rousers,alice' && pc.checks[2].through.join() === 'rowrap_someprog_t', 'never execute/read/stat the copies; the logins reach the domain only through the wrapper', pc.checks);
check(!/reaches/.test(W.checksText({ ...model, logins: '' })), 'without logins: no reach check (a type-level one ignores roles)');
check(C.parseChecks('never login %ro reaches a_t except through w_t\n').checks[0].through.join() === 'w_t' && C.parseChecks('never login x reaches a_t except w_t\n').errors.length === 1, 'login reaches … except through parses');
const bad = C.parseChecks('never a_t reaches b_t except c_t\nnever a_t reaches b_t except through\n');
check(bad.errors.length === 2 && /'through'/.test(bad.errors[0].msg), 'except needs through and a domain', bad.errors);
check(!C.parseChecks('never a_t reaches b_t\n').checks[0].through, 'plain reaches: no through');

/* ---------- setup commands and the spec ---------- */

const cmds = W.setupCommands(model);
check(cmds[0] === "semanage fcontext -a -e / '/var/chroot/ro'" && cmds.includes("cp -p '/usr/sbin/someprog' '/var/chroot/ro/.rowrap/someprog.real'") && cmds[cmds.length - 1] === "restorecon -R '/var/chroot/ro'", 'setup commands', cmds);
const w = { likeRoot: true, chroot: '/var/chroot/ro', protected: '/var/chroot/ro/.rowrap', copies: [{ from: '/usr/sbin/someprog', to: '/var/chroot/ro/.rowrap/someprog.real', pkg: 'someprog-tools' }, { from: '/usr/bin/plain-tool', to: '/var/chroot/ro/.rowrap/plain-tool.real', pkg: null }] };
const spec = packaging.specText({ name: 'rowrap', wrapper: w, date: new Date(2026, 9, 13) });
check(/%post\n%selinux_modules_install[^\n]*\n# BEGIN wrapped programs[^\n]*\nsemanage fcontext -a -e \/ '\/var\/chroot\/ro'/.test(spec) && /cp -p '\/usr\/sbin\/someprog' '\/var\/chroot\/ro\/\.rowrap\/someprog\.real' \|\| :/.test(spec),
  '%post: equivalence, protected directory, copies', spec);
check(/%triggerin -- someprog-tools\n[^\n]*\ncp -p '\/usr\/sbin\/someprog' [^\n]*&& restorecon/.test(spec) && !/%triggerin -- null/.test(spec), 'a trigger per package refreshes its copies (none without a package)');
check(/if \[ \$1 -eq 0 \]; then\n    # BEGIN wrapped programs[^\n]*\n    rm -f '\/var\/chroot\/ro\/\.rowrap\/someprog\.real'[\s\S]*semanage fcontext -d -e \/[\s\S]*%selinux_modules_uninstall/.test(spec), '%postun takes the copies and the equivalence away before the module');
check(/Requires\(post\): policycoreutils-python-utils/.test(spec), 'semanage required');
const w2 = { ...w, copies: [w.copies[0], { from: '/usr/bin/other', to: '/var/chroot/ro/.rowrap/other.real', pkg: 'otherpkg' }] };
const edited = spec.replace('Summary:', 'Summary: (mine)');
const up = packaging.updateWrapperSpec(edited, w2);
check(up && /Summary: \(mine\)/.test(up) && /%triggerin -- otherpkg/.test(up) && !/plain-tool/.test(up) && (up.match(/# BEGIN wrapped programs/g) || []).length === 3, 'the spec\'s blocks rewritten, the rest kept', up);
check(packaging.updateWrapperSpec(spec.replace(/# END wrapped programs/, ''), w2) === null, 'markers gone: not rewritten');
check(/%%/.test(packaging.wrapperBlocks({ ...w, chroot: '/srv/100%' }).post), '% doubled in the spec');

/* ---------- webview ---------- */

class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this._text = ''; this.open = false; this.nodeType = 1; this.checked = false; this.disabled = false; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set className(v) { this.attrs.class = v; } get className() { return this.attrs.class || ''; }
  append(...cs) { for (let c of cs) { if (typeof c === 'string') c = textNode(c); this.children.push(c); c.parent = this; } }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'open') this.open = true; if (k === 'value') this.value = String(v); if (k === 'checked') this.checked = true; if (k === 'disabled') this.disabled = true; }
  addEventListener(ev, f) { (this.listeners[ev] = this.listeners[ev] || []).push(f); }
  fire(ev, extra = {}) { for (const f of this.listeners[ev] || []) f({ target: this, currentTarget: this, key: extra.key, preventDefault() {}, stopPropagation() {} }); }
  all(pred, out = []) { for (const c of this.children) { if (c.tag && pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
}
const textNode = (s) => ({ nodeType: 3, textContent: s });
const byId = {};
for (const id of ['form', 'preview', 'status', 'title', 'apply']) byId[id] = new El(id);
const posted = [];
const winListeners = [];
const wctx = {
  setTimeout: (f) => { f(); return 0; }, clearTimeout: () => {},
  acquireVsCodeApi: () => ({ postMessage: (m) => posted.push(JSON.parse(JSON.stringify(m))), getState: () => null, setState: () => {} }),
  document: { getElementById: (id) => byId[id], createElement: (tag) => new El(tag), createTextNode: textNode },
  window: { addEventListener: (ev, f) => winListeners.push(f) },
};
vm.createContext(wctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/wrapper.js'), 'utf8'), wctx);
const send = (data) => winListeners.forEach(f => f({ data }));
const last = (cmd) => [...posted].reverse().find(m => m.cmd === cmd);
const all = (pred) => byId.form.all(pred);
const input = (ph) => all(e => e.tag === 'input' && (e.attrs.placeholder || '').includes(ph))[0];
const button = (t) => [...all(e => e.tag === 'button'), ...byId.preview.all(e => e.tag === 'button')].find(e => e.textContent === t);

check(last('ready'), 'ready posted');
const info = { isNew: true, model: W.newModel(), users: [{ role: 'roshell_r', domain: 'roshell_t' }, { role: 'staff_r', domain: 'staff_t' }], standalone: false, canStandalone: true,
  folder: '/ws', folderSuffix: '-selinux', layers: ['admin', 'services'], defaultLayer: 'admin', interfaces: [{ n: 'logging_send_syslog_msg', s: 'Send syslog messages', m: 'logging' }],
  defaults: ['libs_use_ld_so', 'libs_use_shared_libs'], licenses: null, checksFile: '/ws/selinux.checks', linux: true };
send({ cmd: 'init', info });
check(/New Wrapped Programs/.test(byId.title.textContent) && !!input('e.g. rowrap'), 'form shown');
input('e.g. rowrap').value = 'rowrap'; input('e.g. rowrap').fire('input');
check(last('plan') && last('plan').model.name === 'rowrap' && last('plan').model.protectedDir === '/.rowrap' && last('plan').model.wrapperDir === '/opt/rowrap/bin', 'name typed: protected and wrapper directories filled in from it', last('plan'));
input('/var/chroot').value = '/var/chroot/ro'; input('/var/chroot').fire('input');
const sel = all(e => e.tag === 'select' && /role/i.test(e.attrs.title || ''))[0];
sel.value = '0'; sel.fire('change');
check(last('plan').model.role === 'roshell_r' && last('plan').model.domain === 'roshell_t', 'user picked');
input('/usr/sbin/').value = '/usr/sbin/someprog'; input('/usr/sbin/').fire('input');
button('Add program').fire('click');
const look = last('program');
check(look && look.path === '/usr/sbin/someprog' && look.chroot === '/var/chroot/ro', 'adding a program looks it up', look);
send({ cmd: 'program', key: look.key, result: { path: '/usr/sbin/someprog', origType: 'someprog_exec_t', context: 'system_u:object_r:someprog_exec_t:s0', policy: 'Last build of clip', generic: false, pkg: 'someprog-tools',
  target: 'someprog_t', candidates: [{ domain: 'someprog_t', selfRules: [{ c: 'file', perms: ['execute_no_trans'] }], conditionalRules: 0, auto: [{ domain: 'someprog_helper_t', conditional: [] }] }, { domain: 'other_t', selfRules: [], auto: [] }],
  chroot: '/var/chroot/ro', chrootExists: true, libs: { total: 5, missing: ['/lib64/libfoo.so.1'] }, needs: [{ type: 'someprog_var_lib_t', path: '/var/lib/someprog', present: false, access: ['manage'] }, { type: 'etc_t', path: '/etc', present: true, access: ['read'] }] } });
let pm = last('plan').model.programs[0];
check(pm && pm.target === 'someprog_t' && pm.origType === 'someprog_exec_t' && pm.roles.join() === 'someprog_helper_t' && pm.selfRules[0].perms.join() === 'execute_no_trans' && pm.pkg === 'someprog-tools' && pm.ifaces.join() === 'libs_use_ld_so,libs_use_shared_libs',
  'the looked-up program fills the model: domain, rules, domains it starts, package, interfaces', pm);
const t = byId.form.textContent;
check(/someprog_exec_t/.test(t) && /libfoo\.so\.1/.test(t) && /\/var\/lib\/someprog/.test(t) && /not in the chroot/.test(t), 'what the copy will miss in the chroot is listed', t.slice(t.indexOf('someprog_exec_t'), t.indexOf('someprog_exec_t') + 900));
const runs = all(e => e.tag === 'select' && /domain the copy runs in/i.test(e.attrs.title || ''))[0];
runs.value = ''; runs.fire('change');
pm = last('plan').model.programs[0];
check(pm.target === '' && pm.roles.length === 0 && pm.selfRules.length === 0, 'run in the wrapper\'s domain instead: no transition, no rules copied');
runs.value = 'other_t'; runs.fire('change');
check(last('plan').model.programs[0].target === 'other_t', 'another candidate domain');
const dirIn = input('/opt/NAME/bin');
dirIn.value = '/usr/local/wrap'; dirIn.fire('input');
const protIn = input('/.NAME');
protIn.value = '/.hidden'; protIn.fire('input');
input('e.g. rowrap').value = 'rw2'; input('e.g. rowrap').fire('input');
const ft = byId.form.textContent;
check(input('/opt/NAME/bin') === dirIn && /\/usr\/local\/wrap\/someprog/.test(ft) && !/\/opt\/rowrap\/bin\/someprog/.test(ft) && /\/\.hidden\/someprog\.real/.test(ft) && /rw2_someprog_t, rw2_someprog_real_exec_t/.test(ft),
  'typed directories and name update the program cards\' paths and types without re-rendering', ft.slice(ft.indexOf('Wrapper'), ft.indexOf('Wrapper') + 300));
input('e.g. rowrap').value = 'rowrap'; input('e.g. rowrap').fire('input');
send({ cmd: 'plan', plan: { problems: ['Note: something to know'], files: [{ path: '/t/policy/modules/admin/rowrap.te', kind: 'te', exists: false, text: 'x', changed: true, diff: [['+', 'policy_module(rowrap, 1.0.0)']] }], commands: ["semanage fcontext -a -e / '/var/chroot/ro'"] } });
const pv = byId.preview.textContent;
check(/something to know/.test(pv) && /semanage fcontext -a -e/.test(pv) && /policy_module\(rowrap/.test(pv) && !byId.apply.disabled, 'preview: notes, setup commands for each system, files; Create enabled');
byId.apply.fire('click');
check(last('apply') && last('apply').model.name === 'rowrap', 'Create sends the model');

console.log(failures ? `\n${failures} check(s) failed` : '\nall wrapper checks passed');
process.exit(failures ? 1 : 0);
