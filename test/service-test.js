// Service editor (server/service.js + media/service.js), no VS Code or tree needed:
//  - a new module rendered from a model reads back as the same model;
//  - edits to an existing module change only the lines of changed settings,
//    and an unchanged model leaves the files byte-identical;
//  - the webview runs a session against a fake DOM.
// With a policy dir, also every daemon module in it: unchanged round trip and
// 15 kinds of edits each (`node test/service-test.js ../selinux-policy/policy`).
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const svc = require('../server/service');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + String(typeof extra === 'string' ? extra : JSON.stringify(extra, null, 1)).slice(0, 2000).replace(/\n/g, '\n     ')); }
};

/* ---------- a tree-like context ---------- */

const KNOWN = new Set(`init_daemon_domain files_pid_file files_pid_filetrans files_type files_var_lib_filetrans logging_log_file logging_log_filetrans
files_config_file files_tmp_file files_tmp_filetrans systemd_unit_file init_script_file manage_dirs_pattern manage_files_pattern manage_sock_files_pattern
manage_lnk_files_pattern list_dirs_pattern read_files_pattern read_lnk_files_pattern append_files_pattern create_files_pattern setattr_files_pattern
logging_send_syslog_msg miscfiles_read_localization auth_use_nsswitch kernel_read_system_state dbus_system_bus_client mta_send_mail
corenet_tcp_sendrecv_generic_if corenet_tcp_sendrecv_generic_node corenet_tcp_bind_generic_node corenet_tcp_bind_http_port corenet_sendrecv_http_server_packets
corenet_tcp_connect_http_port corenet_udp_sendrecv_generic_if corenet_udp_sendrecv_generic_node corenet_udp_bind_generic_node corenet_udp_bind_ntp_port
corenet_tcp_connect_all_ports corenet_tcp_connect_postgresql_port files_search_pids files_search_var_lib logging_search_logs files_search_etc
admin_pattern init_labeled_script_domtrans signal_perms dev_read_urand nis_use_ypbind dev_read_sound`.split(/\s+/));
const OPTIONAL = new Set(['dbus_system_bus_client', 'mta_send_mail', 'nis_use_ypbind']);
const ctx = { has: (n) => KNOWN.has(n), optional: (n) => OPTIONAL.has(n), moduleArgs: 2, moduleExists: (n) => n === 'rpcbind', typeExists: () => false };

const norm = (m) => JSON.stringify({
  files: m.files.map(f => [f.kind, svc.fileType(m, f, ctx), f.access, (f.paths || []).map(p => p.replace(/%/g, m.name)).sort()]).sort(),
  self: [...m.self].sort(), caps: [...m.caps].sort(),
  listen: m.net.listen.map(x => x.proto + x.port).sort(), connect: m.net.connect.map(x => x.proto + x.port).sort(),
  access: [...m.access].sort(), extra: [...m.extra].sort(), permissive: !!m.permissive, exec: m.exec.map(p => p.replace(/%/g, m.name)).sort(),
});

/* ---------- new module ---------- */

const model = svc.newModel();
Object.assign(model, { name: 'webby', summary: 'A small web service' });
model.files.push({ kind: 'state', paths: ['/var/lib/%/'], access: 'manage' }, { kind: 'log', paths: ['/var/log/%/'], access: 'append' }, { kind: 'config', paths: ['/etc/%.conf'], access: 'read' });
model.caps = ['setuid', 'setgid', 'net_bind_service'];
model.net.listen.push({ proto: 'tcp', port: 'http' });
model.net.connect.push({ proto: 'tcp', port: 'postgresql' });
model.access.push('nsswitch', 'dbus');
model.extra.push('dev_read_sound');
model.provides = ['domtrans', 'read_config', 'read_log', 'admin'];
check(svc.validate(model, ctx, { isNew: true }).length === 0, 'new model validates', svc.validate(model, ctx, { isNew: true }));
check(svc.validate({ ...model, name: 'rpcbind' }, ctx, { isNew: true }).some(p => /already exists/.test(p)) &&
  svc.validate({ ...model, name: 'Web-1' }, ctx, { isNew: true }).some(p => /name must/.test(p)), 'name checks: existing module, bad characters');
const out = svc.plan(model, ctx, null);
check(/^policy_module\(webby, 1\.0\.0\)/.test(out.te), '.te starts with policy_module');
for (const line of ['type webby_t;', 'type webby_exec_t;', 'init_daemon_domain(webby_t, webby_exec_t)', 'files_pid_file(webby_var_run_t)', 'logging_log_file(webby_log_t)',
  'allow webby_t self:capability { setuid setgid net_bind_service };', 'allow webby_t self:fifo_file rw_fifo_file_perms;', 'allow webby_t self:tcp_socket create_stream_socket_perms;',
  'files_pid_filetrans(webby_t, webby_var_run_t, { dir file sock_file })', 'append_files_pattern(webby_t, webby_log_t, webby_log_t)', 'read_files_pattern(webby_t, webby_conf_t, webby_conf_t)',
  'corenet_tcp_bind_http_port(webby_t)', 'corenet_tcp_connect_postgresql_port(webby_t)', 'auth_use_nsswitch(webby_t)', 'dev_read_sound(webby_t)',
  "optional_policy(`\n\tdbus_system_bus_client(webby_t)\n')"]) check(out.te.includes(line), `.te has ${line.split('\n')[0]}`, out.te);
check(!/corenet_tcp_connect_postgresql_port[\s\S]*optional_policy[\s\S]*corenet/.test(out.te) && out.te.indexOf('corenet_tcp_sendrecv_generic_if') === out.te.lastIndexOf('corenet_tcp_sendrecv_generic_if'), 'shared network rules appear once');
check(out.fc.includes('/usr/bin/webby\t--\tgen_context(system_u:object_r:webby_exec_t,s0)') && out.fc.includes('/var/lib/webby(/.*)?\t\tgen_context(system_u:object_r:webby_var_lib_t,s0)') &&
  out.fc.includes('/etc/webby\\.conf\t--\tgen_context(system_u:object_r:webby_conf_t,s0)') && out.fc.includes('/usr/lib/systemd/system/webby\\.service\t--'), '.fc: program, directory tree, single file, unit', out.fc);
check(/^## <summary>A small web service<\/summary>/.test(out.if) && /interface\(`webby_domtrans'/.test(out.if) && /interface\(`webby_read_config'/.test(out.if) && /interface\(`webby_admin'/.test(out.if) &&
  /admin_pattern\(\$1, webby_var_lib_t\)/.test(out.if) && !/webby_read_lib_files/.test(out.if), '.if: summary and the chosen interfaces', out.if);
const rec = svc.recognize(out, ctx, {});
check(!rec.error && norm(rec.model) === norm(model), 'the new module reads back as the same model', [norm(rec.model), norm(model)]);
check(rec.kept.length === 0, 'nothing in the new module is left unmodelled', rec.kept);
check(svc.plan(rec.model, ctx, out).te === out.te, 'unchanged model: .te untouched');

/* ---------- editing ---------- */

const edit = (texts, f) => { const r = svc.recognize(texts, ctx, {}); const m = JSON.parse(JSON.stringify(r.model)); f(m); return { m, out: svc.plan(m, ctx, texts) }; };
const changedLines = (a, b) => svc.lineDiff(a, b).filter(x => x[0] !== ' ');

let e = edit(out, m => { m.caps = m.caps.filter(c => c !== 'net_bind_service').concat('sys_chroot'); });
check(JSON.stringify(changedLines(out.te, e.out.te)) === JSON.stringify([['-', 'allow webby_t self:capability { setuid setgid net_bind_service };'], ['+', 'allow webby_t self:capability { setuid setgid sys_chroot };']]),
  'capability change rewrites only that line', changedLines(out.te, e.out.te));
e = edit(out, m => { m.files = m.files.filter(f => f.kind !== 'log'); });
const d = changedLines(out.te, e.out.te);
check(d.every(x => x[0] === '-') && d.some(x => /logging_log_file/.test(x[1])) && d.some(x => /logging_log_filetrans/.test(x[1])) && !/webby_log_t/.test(e.out.te) && !/webby_log_t/.test(e.out.fc),
  'removing a file type removes its declaration, rules and file contexts', d);
e = edit(out, m => { m.net.listen = []; });
check(!/corenet_tcp_bind_http_port|corenet_tcp_bind_generic_node/.test(e.out.te) && /corenet_tcp_sendrecv_generic_if/.test(e.out.te) && /self:tcp_socket/.test(e.out.te),
  'removing the listening port keeps rules the outgoing connection still needs', changedLines(out.te, e.out.te));
e = edit(out, m => { m.access = m.access.filter(a => a !== 'dbus'); m.extra.push('nis_use_ypbind'); });
check(!/dbus_system_bus_client/.test(e.out.te) && /optional_policy\(`\n\tnis_use_ypbind\(webby_t\)\n'\)/.test(e.out.te) && (e.out.te.match(/optional_policy/g) || []).length === 1,
  'empty optional_policy block removed; new optional call wrapped', e.out.te.slice(-200));
e = edit(out, m => { m.files.find(f => f.kind === 'state').paths.push('/srv/webby/'); m.exec.push('/usr/libexec/webby-helper'); });
check(changedLines(out.fc, e.out.fc).length === 2 && e.out.te === out.te &&
  /\/usr\/bin\/webby\t--\t\S+\n\/usr\/libexec\/webby-helper\t--/.test(e.out.fc) && /\/var\/lib\/webby\(\/\.\*\)\?\t\t\S+\n\/srv\/webby\(\/\.\*\)\?/.test(e.out.fc),
  'new paths go next to the same type’s lines; .te untouched', changedLines(out.fc, e.out.fc));
e = edit(out, m => { m.files.find(f => f.kind === 'config').access = 'manage'; m.permissive = true; });
check(/manage_files_pattern\(webby_t, webby_conf_t, webby_conf_t\)/.test(e.out.te) && !/read_files_pattern\(webby_t, webby_conf_t/.test(e.out.te) && /^permissive webby_t;$/m.test(e.out.te),
  'access change swaps the rules; permissive added', changedLines(out.te, e.out.te));
e = edit(out, m => { m.provides = ['domtrans', 'read_config', 'read_log', 'admin', 'exec', 'manage_lib_files']; });
check(e.out.if.startsWith(out.if.trimEnd()) && /webby_exec'/.test(e.out.if) && /webby_manage_lib_files'/.test(e.out.if), 'new interfaces appended to the .if');

// An existing hand-written module: everything not modelled stays.
const legacy = {
  te: `policy_module(legacyd, 1.2.0)

########################################
#
# Declarations
#

## <desc><p>Allow legacyd to do something.</p></desc>
gen_tunable(legacyd_something, false)

type legacyd_t;
type legacyd_exec_t;
init_daemon_domain(legacyd_t, legacyd_exec_t)

type legacyd_var_run_t;
files_pid_file(legacyd_var_run_t)

########################################
#
# Local policy
#

allow legacyd_t self:capability { chown setuid };  # trailing comment
allow legacyd_t self:process signal;
allow legacyd_t self:fifo_file rw_fifo_file_perms;

manage_files_pattern(legacyd_t, legacyd_var_run_t, legacyd_var_run_t)
manage_dirs_pattern(legacyd_t, legacyd_var_run_t, legacyd_var_run_t)
files_pid_filetrans(legacyd_t, legacyd_var_run_t, { file dir })

kernel_read_system_state(legacyd_t)
logging_send_syslog_msg(legacyd_t)

tunable_policy(\`legacyd_something',\`
	dev_read_urand(legacyd_t)
')

optional_policy(\`
	mta_send_mail(legacyd_t)
	nis_use_ypbind(legacyd_t)
')
`,
  if: '## <summary>Legacy daemon</summary>\n',
  fc: '/usr/sbin/legacyd\t--\tgen_context(system_u:object_r:legacyd_exec_t,s0)\n/var/run/legacyd\\.pid\t--\tgen_context(system_u:object_r:legacyd_var_run_t,s0)\n',
};
const lr = svc.recognize(legacy, ctx, {});
check(!lr.error && lr.model.summary === 'Legacy daemon' && lr.model.caps.join() === 'setuid,chown' && lr.model.self.join() === 'fifo' && lr.model.access.includes('mail') &&
  lr.model.extra.includes('nis_use_ypbind') && lr.model.files[0].access === 'manage' && lr.model.files[0].paths[0] === '/var/run/legacyd.pid',
  'legacy module recognized (caps, self, optional calls, file type)', lr.model);
check(lr.kept.length === 2 && lr.kept.some(k => /dev_read_urand/.test(k.text)) && lr.kept.some(k => /self:process signal/.test(k.text)), 'conditional and partial rules are kept as is', lr.kept);
check(svc.plan(JSON.parse(JSON.stringify(lr.model)), ctx, legacy).te === legacy.te, 'legacy: unchanged model, identical .te');
e = edit(legacy, m => { m.caps = ['setuid']; m.access = m.access.filter(a => a !== 'mail'); m.self.push('signal'); m.files[0].access = 'read'; });
check(/allow legacyd_t self:capability setuid;  # trailing comment/.test(e.out.te), 'capability line rewritten, comment kept', e.out.te);
check(/allow legacyd_t self:process \{ signal signal_perms \};/.test(e.out.te), 'new perm added to the existing class line');
check(/optional_policy\(`\n\tnis_use_ypbind\(legacyd_t\)\n'\)/.test(e.out.te), 'call removed from a shared optional_policy block, block kept');
check(!/files_pid_filetrans/.test(e.out.te) && /read_files_pattern\(legacyd_t, legacyd_var_run_t/.test(e.out.te) && /gen_tunable\(legacyd_something/.test(e.out.te) && /tunable_policy/.test(e.out.te),
  'manage → read drops the hand-written filetrans too; unrelated parts untouched', changedLines(legacy.te, e.out.te));
e = edit(legacy, m => { m.files.push({ kind: 'state', type: '', paths: ['/var/lib/legacyd/'], access: 'manage', _new: true }); });
const dl = changedLines(legacy.te, e.out.te);
const at = (s) => e.out.te.split('\n').findIndex(l => l.includes(s));
check(dl.every(x => x[0] === '+') && at('type legacyd_var_lib_t;') > at('files_pid_file(') && at('type legacyd_var_lib_t;') < at('# Local policy') &&
  at('manage_files_pattern(legacyd_t, legacyd_var_lib_t') > at('logging_send_syslog_msg') && at('manage_files_pattern(legacyd_t, legacyd_var_lib_t') < at('tunable_policy'),
  'new file type: declaration with the others, rules after the domain’s last top-level rule', dl);

/* ---------- paths ---------- */

for (const [p, spec] of [['/var/lib/foo/', '/var/lib/foo(/.*)?'], ['/etc/foo.conf', '/etc/foo\\.conf'], ['/run/foo.*', '/run/foo.*'], ['/opt/a-b/c_d/', '/opt/a-b/c_d(/.*)?']]) {
  check(svc.fcFromPath(p).spec === spec && svc.pathFromFc(spec) === p, `path ${p} ⇄ ${spec}`);
}

/* ---------- webview ---------- */

class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this._text = ''; this.checked = false; this.hidden = false; this.open = false; this.scrollTop = 0; this.nodeType = 1; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set className(v) { this.attrs.class = v; } get className() { return this.attrs.class || ''; }
  append(...cs) { for (let c of cs) { if (typeof c === 'string') c = text(c); this.children.push(c); c.parent = this; } }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'open') this.open = true; }
  addEventListener(ev, f) { (this.listeners[ev] = this.listeners[ev] || []).push(f); }
  fire(ev) { for (const f of this.listeners[ev] || []) f({ target: this }); }
  all(pred, out = []) { for (const c of this.children) { if (c.tag && pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
  set placeholder(v) { this.attrs.placeholder = v; }
  querySelectorAll(sel) { return this.all(e => (sel.startsWith('.') ? (e.attrs.class || '').split(' ').includes(sel.slice(1)) : e.tag === sel)); }
}
const text = (s) => ({ nodeType: 3, textContent: s });
const byId = {};
for (const id of ['form', 'preview', 'title', 'status', 'apply', 'stale', 'reload']) byId[id] = new El(id);
const posted = [];
const winListeners = [];
const docRoot = new El('root');
docRoot.append(byId.form);
const wctx = {
  setTimeout, clearTimeout,
  acquireVsCodeApi: () => ({ postMessage: (m) => posted.push(JSON.parse(JSON.stringify(m))) }),
  document: {
    getElementById: (id) => byId[id],
    createElement: (tag) => new El(tag),
    createTextNode: text,
    querySelectorAll: (sel) => docRoot.all(e => (sel.startsWith('.') ? (e.attrs.class || '').split(' ').includes(sel.slice(1)) : e.tag === sel)),
  },
  window: { addEventListener: (ev, f) => winListeners.push(f) },
};
vm.createContext(wctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/service.js'), 'utf8'), wctx);
const send = (data) => winListeners.forEach(f => f({ data }));
const wait = (ms) => new Promise(r => setTimeout(r, ms));
const last = (cmd) => [...posted].reverse().find(m => m.cmd === cmd);
const form = byId.form;
const find = (pred) => form.all(pred);
const buttonText = (t) => find(e => e.tag === 'button' && e.textContent.includes(t))[0];
const checkbox = (label) => find(e => e.tag === 'label' && e.textContent.includes(label)).map(l => l.children.find(c => c.tag === 'input'))[0];

(async () => {
  check(posted[0] && posted[0].cmd === 'ready', 'webview asks for data when loaded');
  const info = { isNew: true, catalog: svc.catalog(ctx), ports: [{ name: 'http', nums: 'tcp 80,443' }, { name: 'ntp', nums: 'udp 123' }],
    interfaces: [{ n: 'dev_read_urand', s: 'Read from pseudo random number generator devices (e.g., /dev/urandom).', m: 'devices' }, { n: 'nis_use_ypbind', s: 'Use the ypbind service.', m: 'nis' }],
    layers: ['contrib', 'services', 'system'], defaultLayer: 'contrib', mode: 'tree', model: svc.newModel() };
  send({ cmd: 'init', info });
  check(last('plan') && last('plan').where === 'contrib' && byId.title.textContent === 'New service', 'init: renders and asks for a plan (default layer)');
  const sections = find(e => e.tag === 'details').map(d => d.children[0].children[0].textContent);
  check(['Service', 'Files', 'Network', 'System access', 'Process and capabilities', 'Other interfaces', 'Interfaces for other modules'].every(s => sections.includes(s)), `sections: ${sections.join(', ')}`);
  const name = find(e => e.attrs.id === 'name')[0];
  name.value = 'webby'; name.fire('input');
  buttonText('+ State data').fire('click');
  checkbox('Bind ports below 1024').checked = true; checkbox('Bind ports below 1024').fire('change');
  checkbox('Use the D-Bus system bus').checked = true; checkbox('Use the D-Bus system bus').fire('change');
  buttonText('+ Add port').fire('click');
  const port = find(e => e.tag === 'input' && e.attrs.list === 'ports')[0];
  port.value = 'http_port_t'; port.fire('change');
  const search = find(e => e.tag === 'input' && /Search interfaces/.test(e.attrs.placeholder || ''))[0];
  search.value = 'random'; search.fire('input');
  const hit = find(e => e.attrs.class === 'hit');
  check(hit.length === 1 && hit[0].textContent.includes('dev_read_urand'), 'interface search matches words in the summary');
  hit[0].fire('click');
  await wait(400);
  const p = last('plan').model;
  check(p.name === 'webby' && p.files.some(f => f.kind === 'state' && f.paths[0] === '/var/lib/%/') && p.caps.includes('net_bind_service') && p.access.includes('dbus') &&
    p.net.listen[0].port === 'http' && p.extra.includes('dev_read_urand'), 'edits end up in the model sent for planning', p);
  const ws = svc.validate(p, ctx, { isNew: true });
  send({ cmd: 'plan', plan: { problems: ws, files: [{ kind: 'te', path: '/t/webby.te', exists: false, changed: true, text: svc.plan(p, ctx, null).te, diff: [] }, { kind: 'conf', path: '/t/modules.conf', exists: true, changed: true, text: 'x = module\nwebby = module', diff: [[' ', 'x = module'], ['+', 'webby = module']] }] } });
  check(!byId.apply.disabled && byId.apply.textContent === 'Create module' && /2 files to create/.test(byId.status.textContent), `apply enabled: ${byId.status.textContent}`);
  check(/corenet_tcp_bind_http_port\(webby_t\)/.test(byId.preview.textContent), 'preview shows the new .te');
  send({ cmd: 'plan', plan: { problems: ['A module named webby already exists.'], files: [] } });
  check(byId.apply.disabled && /1 problem/.test(byId.status.textContent), 'a problem disables apply');
  byId.apply.disabled = false; byId.apply.fire('click');
  check(last('apply') && last('apply').model.name === 'webby', 'apply posts the model');
  // Existing module: kept statements, existing interfaces disabled.
  const r2 = svc.recognize(legacy, ctx, {});
  send({ cmd: 'init', info: { ...info, isNew: false, module: 'legacyd', layer: 'contrib', files: { te: '/t/legacyd.te' }, model: { ...r2.model, provides: [] }, kept: r2.kept, provided: ['legacyd_domtrans'], domains: r2.domains } });
  check(byId.title.textContent === 'Service: legacyd' && find(e => e.attrs.class === 'keptline').length === 2, 'existing module: title, kept statements listed');
  const dom = checkbox('Run the service’s program in its domain');
  check(dom && dom.checked && dom.attrs.disabled !== undefined, 'existing interfaces are checked and cannot be unchecked');
  find(e => e.attrs.class === 'keptline')[0].fire('click');
  check(last('open') && last('open').path === '/t/legacyd.te' && last('open').line === lr.kept[0].l, 'clicking a kept statement opens it');

  // Every daemon module of a real tree.
  const dir = process.argv[2];
  if (dir) await survey(dir);
  console.log(failures ? `\n${failures} check(s) failed` : '\nall service checks passed');
  process.exit(failures ? 1 : 0);
})().catch(err => { console.error(err); process.exit(1); });

async function survey(root) {
  const { PolicyIndex } = require('../server/indexer');
  const idx = new PolicyIndex(() => {});
  idx.scanRoots([root]);
  const layerOf = new Map();
  for (const [n, l] of idx.defs) layerOf.set(n, l[0].path);
  const tctx = { has: (n) => idx.defs.has(n), optional: (n) => { const p = layerOf.get(n); return !!p && !/[\\/](kernel|system)[\\/]/.test(p); }, moduleArgs: 2 };
  const muts = [
    m => { const c = ['sys_chroot', 'kill', 'setuid'].find(x => !m.caps.includes(x)); if (c) m.caps.push(c); },
    m => { m.caps.splice(0, 1); },
    m => { if (!m.self.includes('rlimit')) m.self.push('rlimit'); },
    m => { const t = m.name.replace(/-/g, '_') + '_cache_t'; if (!m.files.some(f => f.type === t)) m.files.push({ kind: 'cache', type: t, paths: [`/var/cache/${m.name}/`], access: 'manage' }); },
    m => { const i = m.files.findIndex(f => f.kind === 'tmp'); if (i >= 0) m.files.splice(i, 1); },
    m => { const f = m.files.find(x => x.access === 'manage' && x.kind !== 'tmp'); if (f) f.access = 'read'; },
    m => { const f = m.files.find(x => x.paths.length); if (f) f.paths.push(f.paths[0].endsWith('/') ? f.paths[0].slice(0, -1) + '2/' : f.paths[0] + '2'); },
    m => { if (!m.net.listen.some(x => x.port === 'http')) m.net.listen.push({ proto: 'tcp', port: 'http' }); },
    m => { m.net.listen.splice(0, 1); },
    m => { if (!m.access.includes('dbus')) m.access.push('dbus'); },
    m => { m.access.splice(0, 1); },
    m => { m.extra.splice(0, 1); },
    m => { if (!m.extra.includes('dev_read_sound')) m.extra.push('dev_read_sound'); },
    m => { m.permissive = !m.permissive; },
    m => { m.exec.push('/usr/sbin/' + m.name + 'x'); },
  ];
  const tnorm = (m) => JSON.stringify([m.files.map(f => [f.kind, f.type, f.access, [...f.paths].sort()]).sort(), [...m.self].sort(), [...m.caps].sort(),
    m.net.listen.map(x => x.proto + x.port).sort(), m.net.connect.map(x => x.proto + x.port).sort(), [...m.access].sort(), [...m.extra].sort(), m.permissive, [...m.exec].sort()]);
  let mods = 0, same = 0, edits = 0, good = 0;
  const bad = [];
  for (const f of idx.files.values()) {
    if (!f.path.endsWith('.te') || !/modules/.test(f.path)) continue;
    const te = fs.readFileSync(f.path, 'utf8');
    if (!/init_daemon_domain\(/.test(te)) continue;
    const base = f.path.slice(0, -3);
    const rd = (p) => (fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '');
    const texts = { te, if: rd(base + '.if'), fc: rd(base + '.fc') };
    const r = svc.recognize(texts, tctx, {});
    if (r.error) continue;
    mods++;
    const o = svc.plan(JSON.parse(JSON.stringify(r.model)), tctx, texts);
    if (o.te === texts.te && o.if === texts.if && o.fc === texts.fc) same++; else bad.push(`unchanged ${f.path}`);
    for (const [i, mut] of muts.entries()) {
      edits++;
      const m = JSON.parse(JSON.stringify(r.model));
      mut(m);
      const out2 = svc.plan(m, tctx, texts);
      const r2 = svc.recognize(out2, tctx, { domain: m.domain });
      const again = svc.plan(JSON.parse(JSON.stringify(m)), tctx, out2);
      if (!r2.error && tnorm(r2.model) === tnorm(m) && again.te === out2.te && again.fc === out2.fc) good++;
      else bad.push(`edit ${i} ${f.path}`);
    }
  }
  check(mods > 0 && same === mods, `${root}: ${same} of ${mods} daemon modules unchanged by a no-op edit`, bad.filter(b => b.startsWith('unchanged')).slice(0, 10));
  check(good === edits, `${root}: ${good} of ${edits} edits read back as the edited model and are idempotent`, bad.filter(b => b.startsWith('edit')).slice(0, 10));
}
