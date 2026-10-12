// Service editor (server/service.js + media/service.js), no VS Code or tree needed:
//  - a new module rendered from a model reads back as the same model;
//  - edits to an existing module change only the lines of changed settings,
//    and an unchanged model leaves the files byte-identical;
//  - the webview runs a session against a fake DOM.
// With a policy dir, also every daemon module in it: unchanged round trip and
// 26 kinds of edits each (`node test/service-test.js ../selinux-policy/policy`).
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
domain_type domain_entry_file domtrans_pattern corenet_tcp_connect_all_ports corenet_tcp_connect_postgresql_port corenet_tcp_bind_postgresql_port corenet_tcp_bind_ntp_portfiles_search_pids files_search_var_lib logging_search_logs files_search_etc
admin_pattern init_labeled_script_domtrans signal_perms dev_read_urand nis_use_ypbind dev_read_sound corenet_tcp_bind_all_ports kernel_read_kernel_sysctls`.split(/\s+/));
const OPTIONAL = new Set(['dbus_system_bus_client', 'mta_send_mail', 'nis_use_ypbind']);
const ctx = { has: (n) => KNOWN.has(n), optional: (n) => OPTIONAL.has(n), moduleArgs: 2, moduleExists: (n) => n === 'rpcbind', typeExists: () => false,
  boolExists: (n) => ['use_nfs_home_dirs', 'legacyd_something'].includes(n) };

const grantsNorm = (g) => ({ self: [...(g.self || [])].sort(), caps: [...(g.caps || [])].sort(),
  listen: ((g.net || {}).listen || []).map(x => x.proto + x.port).sort(), connect: ((g.net || {}).connect || []).map(x => x.proto + x.port).sort(),
  access: [...(g.access || [])].sort(), extra: [...(g.extra || [])].sort() });
const boolsNorm = (m) => (m.booleans || []).map(b => [b.name.replace(/%/g, m.name), !!b.external, b.external ? null : !!b.default, b.external ? null : (b.desc || '').trim(), grantsNorm(b.grants || {})])
  .sort((a, b) => a[0].localeCompare(b[0]));
const helpersNorm = (m) => (m.helpers || []).map(h => [svc.helperNames(m, h).H, svc.helperNames(m, h).HE, !!h.signal, (h.exec || []).map(p => p.replace(/%/g, m.name)).sort(),
  (h.files || []).filter(x => x.access && x.access !== 'none').map(x => `${x.type}:${x.access}`).sort(), grantsNorm(h)]).sort((a, b) => a[0].localeCompare(b[0]));
const norm = (m) => JSON.stringify({ helpers: helpersNorm(m),
  files: m.files.map(f => [f.kind, svc.fileType(m, f, ctx), f.access, (f.paths || []).map(p => p.replace(/%/g, m.name)).sort()]).sort(),
  ...grantsNorm(m), permissive: !!m.permissive, exec: m.exec.map(p => p.replace(/%/g, m.name)).sort(), booleans: boolsNorm(m),
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
model.booleans = [
  { name: '%_connect_any', desc: 'Allow webby to connect to any TCP port', default: false, grants: { self: ['rlimit'], net: { listen: [], connect: [{ proto: 'tcp', port: 'all' }] } } },
  { name: 'use_nfs_home_dirs', external: true, grants: { extra: ['nis_use_ypbind'] } },
];
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
check(out.te.includes('## <desc>\n##\t<p>\n##\tAllow webby to connect to any TCP port\n##\t</p>\n## </desc>\ngen_tunable(webby_connect_any, false)') &&
  out.te.indexOf('gen_tunable(webby_connect_any') < out.te.indexOf('type webby_t;'), 'boolean declared with its description, before the types', out.te);
check(out.te.includes("tunable_policy(`webby_connect_any',`\n\tallow webby_t self:process setrlimit;\n\tcorenet_tcp_connect_all_ports(webby_t)\n')"), 'boolean grants inside tunable_policy', out.te);
check(out.te.includes("optional_policy(`\n\ttunable_policy(`use_nfs_home_dirs',`\n\t\tnis_use_ypbind(webby_t)\n\t')\n')") && !/gen_tunable\(use_nfs_home_dirs/.test(out.te),
  'existing boolean: not declared; optional call wrapped optional_policy > tunable_policy', out.te);
check(svc.validate({ ...model, booleans: [{ name: 'Bad-Name', grants: {} }, { name: 'no_such_bool', external: true, grants: { caps: ['kill'] } }, { name: 'legacyd_something', grants: { caps: ['kill'] } }] }, ctx, { isNew: true }).filter(p => /Boolean name|no boolean no_such_bool|already exists: add it/.test(p)).length === 3,
  'boolean checks: bad name, unknown existing boolean, new name taken');
check(out.te.indexOf('corenet_tcp_sendrecv_generic_if') === out.te.lastIndexOf('corenet_tcp_sendrecv_generic_if'), 'shared network rules appear once');
check(out.fc.includes('/usr/bin/webby\t--\tgen_context(system_u:object_r:webby_exec_t,s0)') && out.fc.includes('/var/lib/webby(/.*)?\t\tgen_context(system_u:object_r:webby_var_lib_t,s0)') &&
  out.fc.includes('/etc/webby\\.conf\t--\tgen_context(system_u:object_r:webby_conf_t,s0)') && out.fc.includes('/usr/lib/systemd/system/webby\\.service\t--'), '.fc: program, directory tree, single file, unit', out.fc);
check(/^## <summary>A small web service<\/summary>/.test(out.if) && /interface\(`webby_domtrans'/.test(out.if) && /interface\(`webby_read_config'/.test(out.if) && /interface\(`webby_admin'/.test(out.if) &&
  /admin_pattern\(\$1, webby_var_lib_t\)/.test(out.if) && !/webby_read_lib_files/.test(out.if), '.if: summary and the chosen interfaces', out.if);
const rec = svc.recognize(out, ctx, {});
check(!rec.error && norm(rec.model) === norm(model), 'the new module reads back as the same model', [norm(rec.model), norm(model)]);
check(rec.kept.length === 0, 'nothing in the new module is left unmodelled', rec.kept);
check(svc.plan(rec.model, ctx, out).te === out.te, 'unchanged model: .te untouched');

/* ---------- helper domains ---------- */

const hm = JSON.parse(JSON.stringify(model));
hm.helpers = [{ name: '%_helper', exec: ['/usr/libexec/%-helper'], signal: true, files: [{ type: 'webby_var_lib_t', access: 'read' }, { type: 'webby_log_t', access: 'append' }],
  self: ['fifo'], caps: ['setuid'], net: { listen: [], connect: [{ proto: 'tcp', port: 'http' }] }, access: ['syslog'], extra: ['dev_read_sound', 'nis_use_ypbind'] }];
check(svc.validate(hm, ctx, { isNew: true }).length === 0, 'model with a helper validates', svc.validate(hm, ctx, { isNew: true }));
const ho = svc.plan(hm, ctx, null);
for (const line of ['type webby_helper_t;\ntype webby_helper_exec_t;\ndomain_type(webby_helper_t)\ndomain_entry_file(webby_helper_t, webby_helper_exec_t)\nrole system_r types webby_helper_t;',
  'domtrans_pattern(webby_t, webby_helper_exec_t, webby_helper_t)', 'allow webby_t webby_helper_t:process signal;', '# webby_helper_t local policy',
  'allow webby_helper_t self:capability setuid;', 'allow webby_helper_t self:tcp_socket create_stream_socket_perms;', 'read_files_pattern(webby_helper_t, webby_var_lib_t, webby_var_lib_t)',
  'append_files_pattern(webby_helper_t, webby_log_t, webby_log_t)', 'logging_log_filetrans(webby_helper_t, webby_log_t, { dir file })', 'corenet_tcp_connect_http_port(webby_helper_t)',
  'logging_send_syslog_msg(webby_helper_t)', "optional_policy(`\n\tnis_use_ypbind(webby_helper_t)\n')"]) check(ho.te.includes(line), `helper: .te has ${line.split('\n')[0]}`, ho.te);
check(ho.te.indexOf('# webby_helper_t local policy') > ho.te.indexOf("tunable_policy(`webby_connect_any'"), 'helper section comes after the service’s rules and booleans');
check(ho.fc.includes('/usr/libexec/webby-helper\t--\tgen_context(system_u:object_r:webby_helper_exec_t,s0)'), 'helper program labeled in the .fc', ho.fc);
const hr = svc.recognize(ho, ctx, {});
check(!hr.error && norm(hr.model) === norm(hm) && hr.kept.length === 0, 'the module with a helper reads back as the same model, nothing kept', [norm(hr.model), norm(hm), hr.kept]);
check(svc.plan(JSON.parse(JSON.stringify(hr.model)), ctx, ho).te === ho.te, 'helper: unchanged model, identical .te');
check(svc.validate({ ...hm, helpers: [{ name: 'Bad-1' }, { name: 'webby' }, { name: 'x', files: [{ type: 'nope_t', access: 'read' }], extra: ['no_such_iface'] }] }, ctx, { isNew: true })
  .filter(p => /Helper name|name of another type|isn't one of this service's file types|no_such_iface doesn't exist in this policy for helper/.test(p)).length === 4, 'helper checks: bad name, clash with the domain, unknown file type, unknown interface',
  svc.validate({ ...hm, helpers: [{ name: 'Bad-1' }, { name: 'webby' }, { name: 'x', files: [{ type: 'nope_t', access: 'read' }], extra: ['no_such_iface'] }] }, ctx, { isNew: true }));
check(svc.validate({ ...hm, exec: ['/usr/bin/%', '/usr/libexec/webby-helper'] }, ctx, { isNew: true }).some(p => /webby-helper is labeled both webby_exec_t and webby_helper_exec_t/.test(p)), 'a path labeled for two types is refused');
let he = svc.plan((() => { const m = JSON.parse(JSON.stringify(hr.model)); const h = m.helpers[0]; h.caps.push('kill'); h.files[0].access = 'manage'; h.extra = h.extra.filter(x => x !== 'dev_read_sound'); h.signal = false; return m; })(), ctx, ho);
let hd = svc.lineDiff(ho.te, he.te).filter(x => x[0] !== ' ');
check(hd.some(x => x[0] === '+' && x[1] === 'allow webby_helper_t self:capability { setuid kill };') && hd.some(x => x[0] === '+' && x[1] === 'manage_files_pattern(webby_helper_t, webby_var_lib_t, webby_var_lib_t)') &&
  hd.some(x => x[0] === '-' && x[1] === 'read_files_pattern(webby_helper_t, webby_var_lib_t, webby_var_lib_t)') && hd.some(x => x[0] === '-' && /dev_read_sound\(webby_helper_t\)/.test(x[1])) &&
  hd.some(x => x[0] === '-' && x[1] === 'allow webby_t webby_helper_t:process signal;') && !hd.some(x => /webby_t self|webby_t, webby_var_lib/.test(x[1])), 'editing a helper changes only its lines', hd);
he = svc.plan({ ...JSON.parse(JSON.stringify(hr.model)), helpers: [] }, ctx, ho);
check(!/webby_helper/.test(he.te) && !/webby_helper/.test(he.fc) && he.te.replace(/\s+$/, '') === out.te.replace(/\s+$/, ''), 'removing the helper removes its declarations, rules, section and file contexts', svc.lineDiff(out.te, he.te).filter(x => x[0] !== ' '));
// Adding a helper to an existing module that has none: declarations, the domain's rules, a new section at the end.
he = svc.plan({ ...JSON.parse(JSON.stringify(rec.model)), helpers: hm.helpers }, ctx, out);
const her = svc.recognize(he, ctx, {});
check(norm(her.model) === norm(hm) && her.kept.length === 0 && /\n# webby_helper_t local policy\n#\n\n/.test(he.te) && he.te.startsWith(out.te.split('\n').slice(0, 5).join('\n')),
  'a helper added to an existing module reads back the same', [norm(her.model), her.kept]);

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
check(!/dbus_system_bus_client/.test(e.out.te) && /optional_policy\(`\n\tnis_use_ypbind\(webby_t\)\n'\)/.test(e.out.te) && (e.out.te.match(/optional_policy/g) || []).length === 2,
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
check(lr.kept.length === 1 && lr.kept.some(k => /self:process signal/.test(k.text)), 'partial self rules are kept as is', lr.kept);
check(JSON.stringify(boolsNorm(lr.model)) === JSON.stringify([['legacyd_something', false, false, 'Allow legacyd to do something.', grantsNorm({ access: ['urandom'] })]]), 'boolean recognized: name, default, description, grants', boolsNorm(lr.model));
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

/* ---------- booleans ---------- */

const bool = (m, n) => m.booleans.find(b => b.name === n);
e = edit(out, m => { bool(m, 'use_nfs_home_dirs').grants.extra = []; });
check(!/use_nfs_home_dirs/.test(e.out.te) && changedLines(out.te, e.out.te).every(x => x[0] === '-'), 'last grant of a boolean removed: the nested optional_policy > tunable_policy goes', changedLines(out.te, e.out.te));
e = edit(out, m => { bool(m, 'webby_connect_any').grants.caps = ['kill']; bool(m, 'webby_connect_any').grants.access = ['mail']; });
check(e.out.te.includes("tunable_policy(`webby_connect_any',`\n\tallow webby_t self:process setrlimit;\n\tcorenet_tcp_connect_all_ports(webby_t)\n\tallow webby_t self:capability kill;\n')") &&
  e.out.te.includes("optional_policy(`\n\ttunable_policy(`webby_connect_any',`\n\t\tmta_send_mail(webby_t)\n\t')\n')"), 'new grants go into the boolean’s block; an optional one gets its own nested block', e.out.te);
e = edit(out, m => { bool(m, 'webby_connect_any').default = true; });
check(JSON.stringify(changedLines(out.te, e.out.te)) === JSON.stringify([['-', 'gen_tunable(webby_connect_any, false)'], ['+', 'gen_tunable(webby_connect_any, true)']]), 'changing the default changes only the gen_tunable line', changedLines(out.te, e.out.te));
e = edit(out, m => { bool(m, 'webby_connect_any').desc = 'Allow webby to connect to every TCP port'; });
check(changedLines(out.te, e.out.te).length === 2 && /every TCP port/.test(e.out.te), 'changing the description changes only its line', changedLines(out.te, e.out.te));
e = edit(out, m => { m.booleans = m.booleans.filter(b => b.name !== 'webby_connect_any'); });
check(!/webby_connect_any|<desc>|corenet_tcp_connect_all_ports/.test(e.out.te) && changedLines(out.te, e.out.te).every(x => x[0] === '-'), 'removing a boolean removes its declaration, description and block', changedLines(out.te, e.out.te));
e = edit(legacy, m => { m.booleans.push({ name: 'legacyd_extra', desc: 'Allow legacyd extra things.', default: false, external: false, _new: true, grants: { extra: ['dev_read_sound'], caps: ['kill'] } }); });
const lat = (s) => e.out.te.split('\n').findIndex(l => l.includes(s));
check(changedLines(legacy.te, e.out.te).every(x => x[0] === '+') && lat('gen_tunable(legacyd_extra') > lat('gen_tunable(legacyd_something') && lat('gen_tunable(legacyd_extra') < lat('type legacyd_t;') &&
  lat("tunable_policy(`legacyd_extra'") > lat('nis_use_ypbind') && e.out.te.includes("tunable_policy(`legacyd_extra',`\n\tallow legacyd_t self:capability kill;\n\tdev_read_sound(legacyd_t)\n')"),
  'new boolean in a hand-written module: declared next to the other, block after the domain’s rules', changedLines(legacy.te, e.out.te));
e = edit(legacy, m => { bool(m, 'legacyd_something').grants.caps = ['kill']; });
check(e.out.te.includes("tunable_policy(`legacyd_something',`\n\tdev_read_urand(legacyd_t)\n\tallow legacyd_t self:capability kill;\n')"), 'grant added inside the existing block', e.out.te);
e = edit(legacy, m => { bool(m, 'legacyd_something').grants.access = []; });
check(!/tunable_policy/.test(e.out.te) && /gen_tunable\(legacyd_something, false\)/.test(e.out.te), 'block emptied: removed; the declaration stays', changedLines(legacy.te, e.out.te));
const added = svc.recognize(edit(legacy, m => { m.booleans.push({ name: 'use_nfs_home_dirs', external: true, grants: { access: ['mail'] } }); }).out, ctx, {});
check(JSON.stringify(boolsNorm(added.model).map(b => [b[0], b[1]])) === JSON.stringify([['legacyd_something', false], ['use_nfs_home_dirs', true]]), 'an existing boolean used here reads back as existing (not declared here)', boolsNorm(added.model));

// Conditional policy can't hold everything, and the same grant always and under a boolean is refused.
const ctxC = { ...ctx, condSafe: (n) => n !== 'dbus_system_bus_client' };
const mC = JSON.parse(JSON.stringify(model));
mC.access = mC.access.filter(a => a !== 'dbus');
mC.booleans = [{ name: 'webby_x', desc: 'x', default: false, _new: true, grants: { access: ['dbus'], caps: ['setuid'], extra: [], self: [], net: { listen: [], connect: [] } } }];
const pc = svc.validate(mC, ctxC, { isNew: true });
check(pc.some(p => /"Use the D-Bus system bus" can't be granted under webby_x: dbus_system_bus_client\(\)/.test(p)) && pc.some(p => /capability setuid under webby_x is already always allowed/.test(p)),
  'under a boolean: interfaces conditional policy refuses, and grants that are already always there, are refused', pc);
check(!svc.validate(mC, ctxC, { isNew: false, baseline: JSON.parse(JSON.stringify(mC)) }).some(p => /webby_x/.test(p) && !/Note/.test(p)), 'an existing module isn’t blamed for what it already has');
check(svc.catalog(ctxC).access.flatMap(g => g.items).find(i => i.id === 'dbus').cond === false, 'catalog marks items that can’t be under a boolean');

/* ---------- port types ---------- */

const portsNorm = (m) => JSON.stringify((m.ports || []).map(p => [(p.name || '').trim() || m.name, (p.nums || []).filter(x => x.port).map(x => `${x.proto} ${x.port}`)]));
{
  // In a tree: network_port() lines in corenetwork.te.in; the generated corenet_* interfaces are used.
  const ctxT = { ...ctx, corenet: true, portRef: 'http', typeExists: (t) => t === 'http_port_t',
    portNums: [{ name: 'http', proto: 'tcp', lo: 80, hi: 80 }, { name: 'zebra', proto: 'tcp', lo: 2600, hi: 2604 }] };
  const corenet = { text: 'network_port(afs, tcp,7000,s0)\nnetwork_port(http, tcp,80,s0, tcp,443,s0)\nnetwork_port(zope, tcp,8021,s0) # zope\n', ports: [] };
  const mt = svc.newModel();
  Object.assign(mt, { name: 'webby', summary: 'Web' });
  mt.ports = [{ name: '', nums: [{ proto: 'tcp', port: '9999' }], _new: true }];
  mt.net.listen.push({ proto: 'tcp', port: 'webby' });
  const vt = svc.validate(mt, ctxT, { isNew: true });
  check(!vt.some(p => !p.startsWith('Note:')), 'tree: a new port type validates and its interfaces count as present', vt);
  const ot = svc.plan(mt, ctxT, null, corenet);
  check(/corenet_tcp_bind_webby_port\(webby_t\)/.test(ot.te) && /corenet_sendrecv_webby_server_packets\(webby_t\)/.test(ot.te) && !/webby_port_t/.test(ot.te), 'tree: the .te uses the generated interfaces', ot.te);
  check(JSON.stringify(changedLines(corenet.text, ot.net)) === JSON.stringify([['+', 'network_port(webby, tcp,9999,s0)']]) && ot.net.indexOf('webby') > ot.net.indexOf('http') && ot.net.indexOf('webby') < ot.net.indexOf('zope'),
    'tree: network_port line added in alphabetical place', ot.net);
  const bad = (nums, name = '') => svc.validate({ ...mt, ports: [{ name, nums, _new: true }] }, ctxT, { isNew: true }).filter(p => /port/i.test(p));
  check(bad([{ proto: 'tcp', port: '80' }]).some(p => /already belongs to http_port_t/.test(p)) && bad([{ proto: 'tcp', port: '2601' }]).some(p => /^Note: .*overlaps zebra_port_t \(2600-2604\)/.test(p)) &&
    bad([{ proto: 'udp', port: '80' }]).every(p => p.startsWith('Note:')), 'tree: a number another port type has is refused; overlapping a range is a note; protocols are separate');
  check(bad([{ proto: 'tcp', port: '70000' }]).some(p => /outside/.test(p)) && bad([{ proto: 'tcp', port: '9-1' }]).some(p => /outside|backwards/.test(p)) && bad([{ proto: 'tcp', port: 'x' }]).some(p => /isn't a port number/.test(p)) &&
    bad([]).some(p => /no port numbers/.test(p)) && bad([{ proto: 'tcp', port: '9999' }], 'http').some(p => /http_port_t already exists/.test(p)) && bad([{ proto: 'tcp', port: '9999' }], 'Bad-1').some(p => /must start/.test(p)),
    'tree: bad numbers, no numbers, existing and malformed names');
  check(svc.validate({ ...mt, net: { listen: [], connect: [] } }, ctxT, { isNew: true }).some(p => /^Note: port type webby_port_t isn't used yet/.test(p)), 'tree: an unused port type is a note');
  // Editing: the module's port types come from corenetwork.te.in (the server passes them).
  const existing = { te: ot.te, if: ot.if, fc: ot.fc };
  const cn2 = { text: ot.net, ports: [{ name: 'webby', nums: [{ proto: 'tcp', port: '9999', level: 's0' }] }] };
  const rt = svc.recognize(existing, ctxT, { ports: cn2.ports });
  check(portsNorm(rt.model) === '[["webby",["tcp 9999"]]]' && rt.model.net.listen.some(x => x.port === 'webby') && rt.kept.length === 0, 'tree: the port type and its use read back', [portsNorm(rt.model), rt.kept]);
  const same = svc.plan(JSON.parse(JSON.stringify(rt.model)), ctxT, existing, cn2);
  check(same.te === existing.te && same.net === cn2.text, 'tree: unchanged model leaves the .te and corenetwork.te.in alone');
  const m2 = JSON.parse(JSON.stringify(rt.model));
  m2.ports[0].nums.push({ proto: 'udp', port: '9999' });
  const e2 = svc.plan(m2, ctxT, existing, cn2);
  check(e2.te === existing.te && JSON.stringify(changedLines(cn2.text, e2.net)) === JSON.stringify([['-', 'network_port(webby, tcp,9999,s0)'], ['+', 'network_port(webby, tcp,9999,s0, udp,9999,s0)']]),
    'tree: changing the numbers rewrites only the network_port line', changedLines(cn2.text, e2.net));
}
{
  // Standalone: the module declares the type; numbers become semanage commands.
  const ms = svc.newModel();
  Object.assign(ms, { name: 'webby', summary: 'Web' });
  ms.ports = [{ name: '', nums: [{ proto: 'tcp', port: '9999' }, { proto: 'udp', port: '9999' }], _new: true }];
  ms.net.listen.push({ proto: 'tcp', port: 'webby' });
  ms.booleans = [{ name: 'webby_relay', desc: 'Let webby relay', default: false, grants: { net: { listen: [], connect: [{ proto: 'udp', port: 'webby' }] } } }];
  const vs = svc.validate(ms, ctx, { isNew: true });
  check(!vs.some(p => !p.startsWith('Note:')) && vs.some(p => /semanage port -a -t webby_port_t -p tcp 9999; semanage port -a -t webby_port_t -p udp 9999/.test(p)), 'standalone: validates, with the semanage commands as a note', vs);
  const os = svc.plan(ms, ctx, null, null);
  check(os.net === null && os.te.includes('# Port numbers: a module can\'t set them, so after installing run\n#\tsemanage port -a -t webby_port_t -p tcp 9999\n#\tsemanage port -a -t webby_port_t -p udp 9999\ntype webby_port_t;\ncorenet_port(webby_port_t)') &&
    /^allow webby_t webby_port_t:tcp_socket name_bind;$/m.test(os.te) && /corenet_tcp_bind_generic_node\(webby_t\)/.test(os.te) &&
    os.te.includes("tunable_policy(`webby_relay',`\n\tallow webby_t webby_port_t:udp_socket { recv_msg send_msg };\n')"), 'standalone: declaration, semanage comment, plain rules (also under a boolean)', os.te);
  const rs = svc.recognize(os, ctx, {});
  check(portsNorm(rs.model) === '[["webby",["tcp 9999","udp 9999"]]]' && norm(rs.model) === norm(ms) && rs.kept.length === 0, 'standalone: reads back as the same model', [portsNorm(rs.model), norm(rs.model), norm(ms), rs.kept]);
  check(svc.plan(JSON.parse(JSON.stringify(rs.model)), ctx, os).te === os.te, 'standalone: unchanged model, identical .te');
  const m3 = JSON.parse(JSON.stringify(rs.model));
  m3.ports[0].nums = [{ proto: 'tcp', port: '9998' }];
  const e3 = svc.plan(m3, ctx, os);
  check(JSON.stringify(changedLines(os.te, e3.te)) === JSON.stringify([['-', '#\tsemanage port -a -t webby_port_t -p tcp 9999'], ['-', '#\tsemanage port -a -t webby_port_t -p udp 9999'], ['+', '#\tsemanage port -a -t webby_port_t -p tcp 9998']]),
    'standalone: changing the numbers changes only the semanage comment', changedLines(os.te, e3.te));
  const m4 = JSON.parse(JSON.stringify(rs.model));
  m4.ports = []; m4.net.listen = []; m4.booleans[0].grants.net.connect = [];
  const e4 = svc.plan(m4, ctx, os);
  check(!/webby_port_t|corenet_port/.test(e4.te) && changedLines(os.te, e4.te).every(x => x[0] === '-'), 'standalone: removing the port type and its uses removes its declaration and rules', changedLines(os.te, e4.te));
  const m5 = JSON.parse(JSON.stringify(rs.model));
  m5.ports = [];
  check(svc.validate(m5, ctx, {}).some(p => /No tcp port type webby_port_t/.test(p)), 'standalone: removing a port type still in use is refused');
}

{
  // Upstream refpolicy has no corenet_udp_sendrecv_X_port: a UDP client of X is the generic rules + X's client packets.
  const K = new Set(['init_daemon_domain', 'corenet_udp_bind_ntp_port', 'corenet_tcp_bind_ntp_port', 'corenet_sendrecv_ntp_client_packets', 'corenet_udp_sendrecv_generic_if', 'corenet_udp_sendrecv_generic_node']);
  const ctxU = { ...ctx, has: (n) => K.has(n) };
  const mu = svc.newModel();
  Object.assign(mu, { name: 'upd', files: [], access: [] });
  mu.booleans = [{ name: 'upd_b', desc: 'd', grants: { net: { listen: [], connect: [{ proto: 'udp', port: 'ntp' }] } } }];
  const vu = svc.validate(mu, ctxU, { isNew: true });
  const ou = svc.plan(mu, ctxU, null);
  const ru = svc.recognize(ou, ctxU, {});
  check(!vu.some(p => !p.startsWith('Note:')) && ou.te.includes("tunable_policy(`upd_b',`\n\tcorenet_sendrecv_ntp_client_packets(upd_t)\n')") &&
    JSON.stringify(ru.model.booleans[0].grants.net.connect) === '[{"proto":"udp","port":"ntp"}]' && !ru.model.booleans[0].grants.extra.length,
    'upstream trees: connecting to a UDP port validates, is written and reads back', [vu, ru.model.booleans[0].grants]);
}

/* ---------- paths ---------- */

for (const [p, spec] of [['/var/lib/foo/', '/var/lib/foo(/.*)?'], ['/etc/foo.conf', '/etc/foo\\.conf'], ['/run/foo.*', '/run/foo.*'], ['/opt/a-b/c_d/', '/opt/a-b/c_d(/.*)?']]) {
  check(svc.fcFromPath(p).spec === spec && svc.pathFromFc(spec) === p, `path ${p} ⇄ ${spec}`);
}

/* ---------- other init entry calls, template-declared domains, logins ---------- */

{
  const LOGIN = ['init_system_domain', 'init_domain', 'init_ranged_daemon_domain', 'auth_login_pgm_domain', 'userdom_spec_domtrans_all_users', 'userdom_signal_all_users',
    'auth_rw_login_records', 'term_login_pty', 'term_create_pty', 'term_use_unallocated_ttys', 'term_setattr_unallocated_ttys', 'srv_server_template'];
  const lctx = { ...ctx, has: (n) => KNOWN.has(n) || LOGIN.includes(n), declares: (n) => (n === 'srv_server_template' ? ['$1_t', '$1_devpts_t'] : []) };
  // A display-manager-like module: init_domain + init_system_domain, no init_daemon_domain.
  const dm = { te: `policy_module(dm, 1.0.0)

type dm_t;
type dm_exec_t;
init_domain(dm_t, dm_exec_t)
init_system_domain(dm_t, dm_exec_t)

type dmx_t;
type dmx_exec_t;
init_ranged_daemon_domain(dmx_t, dmx_exec_t, s0 - mcs_systemhigh)

########################################
#
# dm local policy
#

allow dm_t self:process signal_perms;
auth_login_pgm_domain(dm_t)
`, if: '## <summary>dm</summary>\n', fc: '' };
  check(svc.daemonDomains(dm.te).map(d => `${d.domain}:${d.via}`).join() === 'dm_t:init_domain,dmx_t:init_ranged_daemon_domain', 'domains started by init_domain / init_ranged_daemon_domain are services too');
  let r = svc.recognize(dm, lctx, {});
  check(!r.error && r.model.entries.map(e => e.name).join() === 'init_domain,init_system_domain' && r.model.access.includes('loginpgm') && !r.kept.length, 'entry calls read back as written; auth_login_pgm_domain is the "log users in" option', r.error || r.model.entries);
  let o = svc.plan(JSON.parse(JSON.stringify(r.model)), lctx, dm);
  check(o.te === dm.te, 'no-op edit leaves it unchanged');
  const m1 = JSON.parse(JSON.stringify(r.model));
  m1.caps.push('setuid'); m1.access.push('sessions');
  o = svc.plan(m1, lctx, dm);
  check(!/init_daemon_domain/.test(o.te) && /userdom_spec_domtrans_all_users\(dm_t\)/.test(o.te) && /userdom_signal_all_users\(dm_t\)/.test(o.te) && /setuid/.test(o.te), 'an edit keeps init_domain/init_system_domain (no init_daemon_domain added)', o.te);
  r = svc.recognize(dm, lctx, { domain: 'dmx_t' });
  check(r.model.entries.length === 1 && r.model.entries[0].args.join() === 's0 - mcs_systemhigh' && svc.plan(JSON.parse(JSON.stringify(r.model)), lctx, dm).te === dm.te, 'a ranged entry keeps its range');
  // A domain declared by a template.
  const sv = { te: `policy_module(srv, 1.0.0)

type srvd_exec_t;
srv_server_template(srvd)
init_daemon_domain(srvd_t, srvd_exec_t)

allow srvd_t self:process signal_perms;
`, if: '', fc: '' };
  r = svc.recognize(sv, lctx, {});
  check(!r.error && r.model.domain === 'srvd_t' && r.model.declaredBy && r.model.declaredBy.name === 'srv_server_template' && !r.kept.length, 'a domain declared by a template: the template call is its declaration', r.error || r.model.declaredBy);
  const m2 = JSON.parse(JSON.stringify(r.model)); m2.caps.push('kill');
  o = svc.plan(m2, lctx, sv);
  check(!/^type srvd_t;/m.test(o.te) && /srv_server_template\(srvd\)/.test(o.te) && /kill/.test(o.te), 'editing it adds no type srvd_t (the template declares it)', o.te);
  // A new login service with a pty type of its own.
  const lm = svc.newModel();
  Object.assign(lm, { name: 'logind2', exec: ['/usr/sbin/logind2'], access: ['loginpgm', 'sessions', 'loginrecords', 'ttys'], loginPty: true });
  o = svc.plan(lm, lctx, null);
  check(/auth_login_pgm_domain\(logind2_t\)/.test(o.te) && /^type logind2_devpts_t;$/m.test(o.te) && /term_login_pty\(logind2_devpts_t\)/.test(o.te) && /term_create_pty\(logind2_t, logind2_devpts_t\)/.test(o.te)
    && /allow logind2_t logind2_devpts_t:chr_file \{ rw_chr_file_perms setattr_chr_file_perms relabelfrom \};/.test(o.te) && /term_use_unallocated_ttys\(logind2_t\)/.test(o.te), 'new login service: login options and a pty type of its own', o.te);
  const rl = svc.recognize(o, lctx, {});
  check(rl.model.loginPty && ['loginpgm', 'sessions', 'loginrecords', 'ttys'].every(a => rl.model.access.includes(a)) && !rl.kept.length, 'it reads back with the same options');
  const lm2 = JSON.parse(JSON.stringify(rl.model)); lm2.loginPty = false;
  o = svc.plan(lm2, lctx, o);
  check(!/devpts/.test(o.te), 'turning the pty off removes its type and rules');
  const hd = svc.newModel(); Object.assign(hd, { name: 'hd', exec: ['/usr/bin/hd'], files: [{ kind: 'other', type: 'hd_home_t', paths: ['HOME_DIR/.hd/', 'rel/x'], access: 'read' }] });
  const hp = svc.validate(hd, lctx, { isNew: true });
  check(!hp.some(p => p.includes('"HOME_DIR/.hd/"')) && hp.some(p => p.includes('"rel/x"')), 'paths: HOME_DIR/ (the .fc home placeholder) accepted, relative ones refused', hp);
  check(svc.catalog(lctx).loginPty && svc.catalog(lctx).access.some(g => g.group === 'Logins' && g.items.some(i => i.id === 'loginpgm' && i.help)) && !svc.catalog(ctx).loginPty, 'catalog: Logins options and the pty option where the tree has the interfaces');
}

/* ---------- RPM packaging (standalone modules) ---------- */

const pkgSpec = require('../server/packaging');
check(/^License:\s+MIT$/m.test(pkgSpec.specText({ name: 'x' })) && /^License:\s+GPL-2\.0-or-later$/m.test(pkgSpec.specText({ name: 'x', license: 'GPL-2.0-or-later' })), 'spec License: MIT by default, or the given one');
check(!/semanage/.test(pkgSpec.specText({ name: 'x' })) && /semanage port -d -t x_port_t -p udp 9/.test(pkgSpec.specText({ name: 'x', ports: [{ type: 'x_port_t', proto: 'udp', port: '9' }] })), 'spec: port labels only when the module has port numbers');
check(/^\* \w{3} \w{3} \d{2} \d{4} A B <a@b> - 2\.1-1$/m.test(pkgSpec.specText({ name: 'x', version: '2.1', packager: 'A B <a@b>' })), 'spec: %changelog entry with date, packager and version');
check(/^rpm: /m.test(pkgSpec.makefileText('x')) && /\trpmbuild -bb/.test(pkgSpec.makefileText('x')), 'Makefile: rpm target with a tab-indented recipe');

// Saving a license from the form: stored in the settings (user level unless the workspace sets it).
(() => {
  const Module = require('module');
  const store = { global: { 'packaging.customLicenses': ['LicenseRef-Old'] }, workspace: {} };
  const updates = [];
  const conf = {
    get: (k) => (k in store.workspace ? store.workspace[k] : store.global[k]),
    inspect: (k) => ({ workspaceValue: store.workspace[k] }),
    update: async (k, v, target) => { updates.push([k, v, target]); (target === 2 ? store.workspace : store.global)[k] = v; },
  };
  const messages = [];
  const stub = { workspace: { getConfiguration: () => conf }, ConfigurationTarget: { Global: 1, Workspace: 2 },
    window: { showWarningMessage: (m) => messages.push(m), setStatusBarMessage: () => {} } };
  const load = Module._load;
  Module._load = function (req, ...rest) { return req === 'vscode' ? stub : req === 'vscode-languageclient/node' ? { LanguageClient: class {}, TransportKind: {} } : load.call(this, req, ...rest); };
  const { saveLicense } = require('../client/extension');
  Module._load = load;
  return (async () => {
    let r = await saveLicense(' LicenseRef-Acme ', false, false);
    check(r.license === 'LicenseRef-Acme' && updates.length === 1 && updates[0][1].join() === 'LicenseRef-Old,LicenseRef-Acme' && updates[0][2] === 1 && r.licenses.custom.join() === 'LicenseRef-Old,LicenseRef-Acme' && r.licenses.default === 'MIT',
      'Save to my list: appended to selinux.packaging.customLicenses in the user settings', updates);
    await saveLicense('LicenseRef-Acme', true, false);
    check(updates.length === 2 && updates[1][0] === 'packaging.license' && updates[1][1] === 'LicenseRef-Acme', 'Save as my default: no duplicate in the list, sets selinux.packaging.license', updates);
    await saveLicense('Apache-2.0', false, false);
    check(updates.length === 2, 'common licenses are not added to the saved list');
    store.workspace['packaging.license'] = 'GPL-2.0-only';
    await saveLicense('MIT', true, true);
    check(updates.length === 3 && updates[2][2] === 2 && store.workspace['packaging.license'] === 'MIT', 'a default the workspace sets is changed in the workspace settings', updates);
    r = await saveLicense('Acme #1', false, false);
    check(r.license === null && updates.length === 3 && /can't contain/.test(messages[0] || ''), 'a license with # is refused with a message, nothing stored');
  })();
})();

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
  // A new boolean with a capability, a port and an interface; and an existing boolean.
  buttonText('+ New boolean').fire('click');
  const boolCard = () => find(e => e.attrs.class === 'bool');
  const bname = boolCard()[0].all(e => e.tag === 'input' && /connect_any/.test(e.attrs.placeholder || ''))[0];
  bname.value = 'webby_connect_any'; bname.fire('input');
  const menu = boolCard()[0].all(e => e.tag === 'select' && e.children.some(c => c.tag === 'option' && /Add system access/.test(c.textContent)))[0];
  menu.value = 'cap:kill'; menu.fire('change');
  const bport = boolCard()[0].all(e => e.tag === 'input' && e.attrs.list === 'ports')[0];
  bport.value = 'all'; bport.fire('input');
  // (a real <select> starts on its first option; the fake one doesn't)
  const [bdir, bproto] = bport.parent.children.filter(e => e.tag === 'select');
  bdir.value = 'connect'; bproto.value = 'tcp';
  boolCard()[0].all(e => e.tag === 'button' && e.textContent === '+ Add')[0].fire('click');
  const existing = find(e => e.tag === 'input' && e.attrs.list === 'bools')[0];
  existing.value = 'use_nfs_home_dirs';
  find(e => e.tag === 'button' && e.textContent === '+ Add' && e.parent && e.parent.attrs.class === 'adds')[0].fire('click');
  check(boolCard().length === 2 && /Kill|Signal processes of other users/.test(boolCard()[0].textContent) && /Connect to TCP any port/.test(boolCard()[0].textContent) && /existing boolean/.test(boolCard()[1].textContent),
    'booleans: new one with chips for its grants, existing one marked');
  // A port type of its own, with a number.
  buttonText('+ New port type').fire('click');
  const pnum = find(e => e.tag === 'input' && e.attrs.placeholder === 'e.g. 8080')[0];
  pnum.value = '9999'; pnum.fire('input');
  check(find(e => e.tag === 'datalist' && e.attrs.id === 'ports')[0].children.some(o => o.value === 'webby' && /new port type/.test(o.textContent)), 'the new port type is offered in the port pickers');
  // A helper program: name, read access to the state data, a capability.
  buttonText('+ New helper program').fire('click');
  const helperCard = () => find(e => e.attrs.class === 'bool helper')[0];
  const hname = helperCard().all(e => e.tag === 'input' && e.attrs.placeholder === 'webby_helper')[0];
  hname.value = 'webby_worker_t'; hname.fire('change');
  const stateSel = helperCard().all(e => e.tag === 'select' && e.parent.children.some(c => c.tag === 'code' && c.textContent === 'webby_var_lib_t'))[0];
  stateSel.value = 'read'; stateSel.fire('change');
  const hmenu = helperCard().all(e => e.tag === 'select' && e.children.some(c => c.tag === 'option' && /Add system access/.test(c.textContent)))[0];
  hmenu.value = 'cap:setuid'; hmenu.fire('change');
  check(helperCard() && /webby_worker/.test(helperCard().all(e => e.tag === 'input')[0].value) && /Change its user ID|setuid/.test(helperCard().textContent) && boolCard().length === 2,
    'helper card: name, file access, capability chip (boolean cards unaffected)');
  {
    const cat = svc.catalog(ctx);
    const noHelp = [...cat.fileKinds.map(k => ['file', k.id, k.help]), ...cat.access.flatMap(g => g.items).map(i => ['access', i.id, i.help]),
      ...cat.self.map(s => ['self', s.id, s.help]), ...cat.caps.map(c => ['cap', c.name, c.help]), ...cat.provides.map(p => ['provides', p.id, p.help]),
      ...Object.keys(cat.accessLabels).map(a => ['level', a, cat.accessHelp[a]])].filter(x => !x[2]);
    check(!noHelp.length, 'every catalog item has hover help', noHelp);
    const untitled = find(e => (e.tag === 'button' || e.tag === 'select' || e.tag === 'textarea' || (e.tag === 'input' && e.attrs.type === 'text') ||
      (e.tag === 'label' && e.attrs.class && e.attrs.class.startsWith('check'))) && !e.attrs.title).map(e => `${e.tag} ${e.textContent.slice(0, 40)}`);
    check(!untitled.length, 'every button, field and checkbox in the form has hover help', untitled);
    const tmp = buttonText('+ Temporary files');
    check(tmp && /webby_tmp_t/.test(tmp.attrs.title) && /\/tmp/.test(tmp.attrs.title), `"+ Temporary files" explains itself with the module's type: ${tmp && tmp.attrs.title}`);
  }
  await wait(400);
  const p = last('plan').model;
  check(p.name === 'webby' && p.files.some(f => f.kind === 'state' && f.paths[0] === '/var/lib/%/') && p.caps.includes('net_bind_service') && p.access.includes('dbus') &&
    p.net.listen[0].port === 'http' && p.extra.includes('dev_read_urand'), 'edits end up in the model sent for planning', p);
  check(p.helpers.length === 1 && p.helpers[0]._new && p.helpers[0].name === 'webby_worker' && p.helpers[0].signal && p.helpers[0].exec[0] === '/usr/libexec/%-helper' &&
    JSON.stringify(p.helpers[0].files) === '[{"type":"webby_var_lib_t","access":"read"}]' && p.helpers[0].caps.join() === 'setuid' && svc.validate(p, ctx, { isNew: true }).every(x => x.startsWith('Note:')),
    'helper in the planned model, and it validates', [p.helpers, svc.validate(p, ctx, { isNew: true })]);
  check(p.ports.length === 1 && p.ports[0]._new && p.ports[0].name === '' && p.ports[0].nums[0].port === '9999' && p.ports[0].nums[0].proto === 'tcp', 'new port type in the planned model', p.ports);
  check(p.booleans.length === 2 && p.booleans[0].name === 'webby_connect_any' && p.booleans[0]._new && p.booleans[0].grants.caps[0] === 'kill' && p.booleans[0].grants.net.connect[0].port === 'all' &&
    p.booleans[1].external && p.booleans[1].name === 'use_nfs_home_dirs', 'booleans in the planned model', p.booleans);
  const ws = svc.validate(p, ctx, { isNew: true });
  send({ cmd: 'plan', plan: { problems: ws, files: [{ kind: 'te', path: '/t/webby.te', exists: false, changed: true, text: svc.plan(p, ctx, null).te, diff: [] }, { kind: 'conf', path: '/t/modules.conf', exists: true, changed: true, text: 'x = module\nwebby = module', diff: [[' ', 'x = module'], ['+', 'webby = module']] }] } });
  check(!byId.apply.disabled && byId.apply.textContent === 'Create module' && /2 files to create/.test(byId.status.textContent), `apply enabled: ${byId.status.textContent}`);
  check(/corenet_tcp_bind_http_port\(webby_t\)/.test(byId.preview.textContent), 'preview shows the new .te');
  send({ cmd: 'plan', plan: { problems: ['A module named webby already exists.'], files: [] } });
  check(byId.apply.disabled && /1 problem/.test(byId.status.textContent), 'a problem disables apply');
  byId.apply.disabled = false; byId.apply.fire('click');
  check(last('apply') && last('apply').model.name === 'webby', 'apply posts the model');
  // In a tree workspace: in the tree or a standalone module (RPM); switching keeps the form.
  send({ cmd: 'init', info: { ...info, canStandalone: true, standalone: false }, keep: true });
  const radios = find(e => e.tag === 'input' && e.attrs.type === 'radio');
  check(radios.length === 2 && radios[0].checked && !radios[1].checked && radios.every(r => r.parent && r.parent.attrs.title), 'kind: in the tree / standalone, with hover help');
  radios[1].fire('change');
  check(last('standalone') && last('standalone').on === true, 'choosing standalone asks for the devel-header catalog');
  const LICS = { common: [{ id: 'MIT', label: 'MIT' }, { id: 'Apache-2.0', label: 'Apache License 2.0' }], custom: ['LicenseRef-Old'], default: 'MIT' };
  send({ cmd: 'init', info: { ...info, mode: 'module', layers: null, folder: '/ws', folderSuffix: '-selinux', canStandalone: true, standalone: true, licenses: LICS }, keep: true });
  check(find(e => e.attrs.id === 'name')[0].value === 'webby' && last('plan').standalone === true && /\/ws\/<name>-selinux/.test(JSON.stringify(find(e => e.tag === 'input' && e.attrs.placeholder && e.attrs.placeholder.includes('<name>')).map(e => e.attrs.placeholder))),
    'standalone: the form keeps its contents, plans say standalone, folder defaults to NAME-selinux');
  check(/make rpm/.test(form.textContent), 'standalone: says what the packaging files are');
  // License: common ones, saved ones, or one of your own (stored in the settings).
  const licSelect = () => find(e => e.tag === 'select' && (e.attrs.title || '').startsWith('The license'))[0];
  check(licSelect() && licSelect().children.map(o => o.textContent).join('|') === 'MIT|Apache License 2.0 (Apache-2.0)|LicenseRef-Old (saved)|Custom…' && last('plan').license === 'MIT' && /your default/.test(form.textContent),
    `license picker: ${licSelect() && licSelect().children.map(o => o.textContent).join('|')}; your default MIT selected`);
  licSelect().value = 'Apache-2.0'; licSelect().fire('change');
  await wait(300);
  check(last('plan').license === 'Apache-2.0', 'a common license: plans use it');
  buttonText('Make it my default').fire('click');
  check(last('saveLicense') && last('saveLicense').license === 'Apache-2.0' && last('saveLicense').asDefault && last('saveLicense').defaultOnly, 'Make it my default stores the default only');
  licSelect().value = '__custom__'; licSelect().fire('change');
  const licInput = () => find(e => e.tag === 'input' && e.attrs.placeholder === 'e.g. LicenseRef-Acme-Proprietary')[0];
  check(licInput() && buttonText('Save to my list') && buttonText('Save as my default'), 'Custom…: a field with Save to my list / Save as my default');
  await wait(300);
  check((last('plan').license || '') === '', 'Custom… starts empty (the plan then reports it)');
  licInput().value = 'LicenseRef-Acme'; licInput().fire('input');
  await wait(300);
  check(last('plan').license === 'LicenseRef-Acme', 'the typed license goes into the plan');
  buttonText('Save to my list').fire('click');
  check(last('saveLicense').license === 'LicenseRef-Acme' && !last('saveLicense').asDefault, 'Save to my list asks to store it');
  send({ cmd: 'licenseSaved', license: 'LicenseRef-Acme', licenses: { ...LICS, custom: ['LicenseRef-Old', 'LicenseRef-Acme'] } });
  check(licSelect().children.some(o => o.textContent === 'LicenseRef-Acme (saved)' && o.attrs.selected !== undefined) && !licInput(), 'saved: offered in the list and selected');
  byId.apply.disabled = false; byId.apply.fire('click');
  check(last('apply').standalone === true && last('apply').license === 'LicenseRef-Acme', 'apply says standalone, with the license');
  // Other interfaces: what one compiles to (on demand), and finding one by what the service needs.
  const extraChip = () => find(e => (e.attrs.class || '').split(' ').includes('extra'))[0];
  check(!!extraChip(), 'existing other interfaces are listed');
  const extraName = extraChip().all(e => e.tag === 'code')[0].textContent;
  extraChip().all(e => e.tag === 'button' && e.textContent === '▸')[0].fire('click');
  check(last('grants') && last('grants').domain === 'webby_t' && last('grants').names.join() === extraName, `▸ asks what ${extraName}(webby_t) compiles to`);
  send({ cmd: 'grants', domain: 'webby_t', result: { grants: { [extraName]: { rules: [{ text: 'allow webby_t urandom_device_t:chr_file { open read };', cond: false }], attrs: ['some_attr'], cond: 0 } } } });
  check(/allow webby_t urandom_device_t:chr_file \{ open read \};/.test(extraChip().textContent) && /some_attr/.test(extraChip().textContent), 'the rules it compiles to are shown, with the attributes it adds');
  const what = find(e => e.tag === 'input' && (e.attrs.placeholder || '').startsWith('type or path'))[0];
  const selects = [find(e => e.tag === 'select' && (e.attrs.title || '').startsWith('The kind of object'))[0], find(e => e.tag === 'select' && e.attrs.title === 'What the service must be able to do with it')[0]].filter(Boolean);
  check(what && selects.length === 2 && selects[1].children.some(o => o.textContent === 'write'), 'Find by need: a type or path, the kind of object, what to do');
  what.value = 'etc_t'; selects[1].value = 'open write';
  buttonText('Find').fire('click');
  const fq = last('find');
  check(fq && fq.query.domain === 'webby_t' && fq.query.target === 'etc_t' && fq.query.tclass === 'file' && fq.query.perms.join() === 'open,write', 'Find sends the need', fq);
  what.value = '/var/log/webby.log'; buttonText('Find').fire('click');
  check(last('find').query.path === '/var/log/webby.log' && !last('find').query.target, 'a path is sent as a path (looked up on the host)');
  send({ cmd: 'found', id: fq.id, result: { target: 'etc_t', resolved: null, notes: [], suggest: { list: [
    { name: 'files_rw_etc_files', covers: true, missing: [], owner: true, extra: 16, grants: ['etc_t dir: search'], summary: 'Read and write generic files in /etc.' },
    { name: 'files_manage_etc_files', covers: true, missing: [], owner: true, extra: 42, grants: [], summary: '' }] } } });
  const found = find(e => e.attrs.class === 'iface' && /files_rw_etc_files/.test(e.textContent))[0];
  check(found && /narrowest/.test(found.textContent) && /also grants: etc_t dir: search/.test(found.textContent), 'found: ranked, narrowest tagged, what else it grants');
  found.all(e => e.tag === 'button' && e.textContent === 'Add')[0].fire('click');
  await wait(300);
  check(last('plan').model.extra.includes('files_rw_etc_files'), 'Add puts it in the service');
  // Logins: the options and the pty type of its own.
  const lcat = svc.catalog({ ...ctx, has: (n) => KNOWN.has(n) || ['auth_login_pgm_domain', 'userdom_spec_domtrans_all_users', 'userdom_signal_all_users', 'term_login_pty', 'term_create_pty'].includes(n) });
  send({ cmd: 'init', info: { ...info, catalog: lcat, licenses: null, standalone: false, canStandalone: false }, keep: true });
  check(checkbox('Log users in') && checkbox('Start users’ sessions'), 'Logins options in System access');
  const pty = checkbox('Pseudo-terminals for logins');
  check(pty && /webby_devpts_t/.test(find(e => e.tag === 'label' && e.textContent.includes('Pseudo-terminals')).map(l => l.attrs.title + l.textContent).join('')), 'the pty option names the type it adds');
  pty.checked = true; pty.fire('change');
  await wait(300);
  check(last('plan').model.loginPty === true, 'ticking it puts loginPty in the plan');
  // Existing module: kept statements, existing interfaces disabled.
  const r2 = svc.recognize(legacy, ctx, {});
  send({ cmd: 'init', info: { ...info, isNew: false, module: 'legacyd', layer: 'contrib', files: { te: '/t/legacyd.te' }, model: { ...r2.model, provides: [] }, kept: r2.kept, provided: ['legacyd_domtrans'], domains: r2.domains } });
  check(byId.title.textContent === 'Service: legacyd' && find(e => e.attrs.class === 'keptline').length === 1, 'existing module: title, kept statements listed');
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
  const tctx = { has: (n) => idx.defs.has(n), optional: (n) => { const p = layerOf.get(n); return !!p && !/[\\/](kernel|system)[\\/]/.test(p); }, moduleArgs: 2,
    declares: (n) => (((idx.defs.get(n) || [])[0] || {}).declPatterns || []).map(p => p.pattern) };
  const muts = [
    m => { const c = ['sys_chroot', 'kill', 'setuid'].find(x => !m.caps.includes(x)); if (c) m.caps.push(c); },
    m => { m.caps.splice(0, 1); },
    m => { if (!m.self.includes('rlimit')) m.self.push('rlimit'); },
    m => { const t = m.name.replace(/-/g, '_') + '_cache_t'; if (!m.files.some(f => f.type === t)) m.files.push({ kind: 'cache', type: t, paths: [`/var/cache/${m.name}/`], access: 'manage' }); },
    m => { const i = m.files.findIndex(f => f.kind === 'tmp'); if (i >= 0) { const [r] = m.files.splice(i, 1); for (const h of m.helpers) h.files = h.files.filter(x => x.type !== r.type); } },
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
    // Booleans.
    m => { m.booleans.push({ name: m.name.replace(/-/g, '_') + '_e2e_extra', desc: 'Test boolean.', default: false, _new: true, grants: { caps: ['kill'], extra: ['dev_read_sound'], access: ['dbus'], net: { listen: [], connect: [{ proto: 'tcp', port: 'http' }] } } }); },
    m => { const b = m.booleans.find(x => !x.external); if (b) b.default = !b.default; },
    m => { const b = m.booleans.find(x => !x.external); if (b) b.desc = 'Changed description.'; },
    m => { const b = m.booleans.find(x => !x.external); if (b) m.booleans.splice(m.booleans.indexOf(b), 1); },
    m => { const b = m.booleans[0]; if (b && !b.grants.caps.includes('kill')) b.grants.caps.push('kill'); },
    m => { for (const b of m.booleans) for (const k of ['extra', 'access', 'caps', 'self']) if (b.grants[k].length) { b.grants[k].splice(0, 1); return; } },
    // Helper domains.
    m => { m.helpers.push({ name: m.name.replace(/-/g, '_') + '_e2e_helper', exec: [`/usr/libexec/${m.name}-e2e-helper`], signal: true, _new: true, files: m.files.filter(x => x.kind !== 'unit' && x.kind !== 'initrc').slice(0, 1).map(x => ({ type: x.type, access: 'read' })),
      self: ['fifo'], caps: ['setuid'], net: { listen: [], connect: [{ proto: 'tcp', port: 'http' }] }, access: ['syslog'], extra: ['dev_read_sound'] }); },
    m => { if (m.helpers.length) m.helpers.splice(0, 1); },
    m => { const h = m.helpers[0]; if (!h) return; if (!h.caps.includes('kill')) h.caps.push('kill'); h.signal = !h.signal; if (h.extra.length) h.extra.splice(0, 1); },
    m => { const h = m.helpers[0]; if (!h) return; const x = h.files[0]; if (x) x.access = x.access === 'read' ? 'manage' : 'read'; else { const t = m.files.find(r => r.kind === 'config' || r.kind === 'state'); if (t) h.files.push({ type: t.type, access: 'read' }); } },
    m => { if (m.booleans.some(b => b.name === 'use_nfs_home_dirs')) return; m.booleans.push({ name: 'use_nfs_home_dirs', external: true, grants: { access: ['mail'], extra: [], caps: [], self: [], net: { listen: [], connect: [] } } }); },
    // Logins.
    // (interfaces an added option calls read back as part of it, as in the form)
    m => { for (const a of ['loginpgm', 'sessions', 'loginrecords']) if (!m.access.includes(a)) m.access.push(a); m.extra = m.extra.filter(n => !['auth_login_pgm_domain', 'userdom_spec_domtrans_all_users', 'userdom_signal_all_users', 'auth_rw_login_records'].includes(n)); },
    m => { const i = m.access.findIndex(a => ['loginpgm', 'sessions', 'ttys', 'ptys', 'loginrecords', 'lastlog', 'usercontexts'].includes(a)); if (i >= 0) m.access.splice(i, 1); },
    m => { m.loginPty = !m.loginPty; },
  ];
  const bnorm = (m) => (m.booleans || []).filter(b => !b.external || Object.values(b.grants).some(v => (Array.isArray(v) ? v.length : v.listen.length + v.connect.length)))
    .map(b => [b.name, !!b.external, b.external ? null : !!b.default, b.external ? null : b.desc, JSON.stringify(grantsNorm(b.grants))]).sort((a, b) => a[0].localeCompare(b[0]));
  const tnorm = (m) => JSON.stringify([m.files.map(f => [f.kind, f.type, f.access, [...f.paths].sort()]).sort(), [...m.self].sort(), [...m.caps].sort(),
    m.net.listen.map(x => x.proto + x.port).sort(), m.net.connect.map(x => x.proto + x.port).sort(), [...m.access].sort(), [...m.extra].sort(), m.permissive, [...m.exec].sort(), bnorm(m),
    (m.helpers || []).map(h => [svc.helperNames(m, h).H, !!h.signal, [...h.exec].sort(), h.files.map(x => x.type + x.access).sort(), JSON.stringify(grantsNorm(h))]).sort(),
    !!m.loginPty, JSON.stringify(m.entries || []), JSON.stringify(m.declaredBy || null)]);
  let mods = 0, same = 0, edits = 0, good = 0, doms = 0, viaTemplate = 0, otherEntry = 0;
  const bad = [];
  for (const f of idx.files.values()) {
    if (!f.path.endsWith('.te') || !/modules/.test(f.path)) continue;
    const te = fs.readFileSync(f.path, 'utf8');
    if (!/\binit_(ranged_)?(daemon_|system_)?domain\(/.test(te)) continue;
    const base = f.path.slice(0, -3);
    const rd = (p) => (fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '');
    const texts = { te, if: rd(base + '.if'), fc: rd(base + '.fc') };
    const first = svc.recognize(texts, tctx, {});
    if (first.error) continue;
    mods++;
    // Every domain init starts, not only the module's main one.
    for (const dom of first.domains.map(x => x.domain)) {
    const r = svc.recognize(texts, tctx, { domain: dom });
    if (r.error) continue;
    doms++;
    if (r.model.declaredBy) viaTemplate++;
    if ((r.model.entries || []).some(e => e.name !== 'init_daemon_domain')) otherEntry++;
    const o = svc.plan(JSON.parse(JSON.stringify(r.model)), tctx, texts);
    if (o.te === texts.te && o.if === texts.if && o.fc === texts.fc) same++; else bad.push(`unchanged ${f.path} ${dom}`);
    for (const [i, mut] of muts.entries()) {
      edits++;
      const m = JSON.parse(JSON.stringify(r.model));
      mut(m);
      const out2 = svc.plan(m, tctx, texts);
      const r2 = svc.recognize(out2, tctx, { domain: m.domain });
      const again = svc.plan(JSON.parse(JSON.stringify(m)), tctx, out2);
      if (!r2.error && tnorm(r2.model) === tnorm(m) && again.te === out2.te && again.fc === out2.fc) good++;
      else bad.push(`edit ${i} ${f.path} ${dom}`);
    }
    }
  }
  check(mods > 0 && same === doms, `${root}: ${same} of ${doms} domains in ${mods} service modules unchanged by a no-op edit (${otherEntry} started by init_system_domain/init_domain/ranged variants, ${viaTemplate} declared by a template)`, bad.filter(b => b.startsWith('unchanged')).slice(0, 10));
  check(good === edits, `${root}: ${good} of ${edits} edits read back as the edited model and are idempotent`, bad.filter(b => b.startsWith('edit')).slice(0, 10));
}
