'use strict';
// The tighten report (server/tighten.js), any OS: broad and risky grants of a
// service model ranked with the form change that narrows each, the cost of an
// interface from its expansion, and a tight module that gets no rows.
//   node test/tighten-test.js
const T = require('../server/tighten');
const svc = require('../server/service');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};
const ctx = { has: () => true, optional: () => true, moduleArgs: 2, moduleExists: () => false, typeExists: () => false, boolExists: () => false };
const catalog = svc.catalog(ctx);
const ids = (r) => r.rows.map(x => x.id);

// 1. A tight module: nothing to say.
const tight = { ...svc.newModel(), name: 'tightd', caps: ['net_bind_service'], self: ['fifo', 'signal'], access: ['syslog', 'locale', 'nsswitch'], extra: ['dev_read_urand', 'miscfiles_read_generic_certs'],
  files: [{ kind: 'unit', paths: ['/usr/lib/systemd/system/tightd.service'], access: 'none' }, { kind: 'config', paths: ['/etc/tightd/'], access: 'read' }, { kind: 'log', paths: ['/var/log/tightd/'], access: 'append' }, { kind: 'state', paths: ['/var/lib/tightd/'], access: 'manage' }] };
let r = T.report(tight, { domain: 'tightd_t', catalog, grants: new Map([['dev_read_urand', { cost: 3, types: 1, writes: false, broadest: 'allow tightd_t urandom_device_t:chr_file { read open getattr };' }]]), kept: [] });
check(r.rows.length === 0 && r.summary.high === 0 && /Nothing broad or risky/.test(r.notes[0]), 'a tight module: no rows, said so', r);

// 2. A loose one.
const loose = { ...svc.newModel(), name: 'loosed', permissive: true, caps: ['sys_admin', 'dac_override', 'net_admin', 'setuid', 'chown', 'net_bind_service'], self: ['fifo', 'execmem'], access: ['syslog', 'bin', 'kmod', 'etcfiles', 'sessions'],
  extra: ['files_read_all_files', 'domain_read_all_domains_state', 'unconfined_domain', 'corenet_tcp_connect_all_ports', 'auth_read_shadow', 'dev_read_urand', 'apache_read_config', 'kernel_rw_all_sysctls'],
  files: [{ kind: 'unit', paths: ['/usr/lib/systemd/system/loosed.service'], access: 'manage' }, { kind: 'config', type: 'loosed_conf_t', paths: ['/etc/loosed/'], access: 'manage' }, { kind: 'log', paths: ['/var/log/loosed/'], access: 'manage' }, { kind: 'state', paths: ['/var/lib/loosed/'], access: 'manage' }],
  booleans: [{ name: 'loosed_can_network', default: true, external: false, grants: { net: { connect: [{ proto: 'tcp', port: 'http' }] } } }, { name: 'loosed_off', default: false, grants: { caps: ['sys_time'] } }, { name: 'loosed_empty', default: true, grants: {} }] };
const grants = new Map([
  ['apache_read_config', { cost: 12, types: 4, writes: false, broadest: 'allow loosed_t httpd_config_t:file { read open getattr };' }],
  ['dev_read_urand', { cost: 3, types: 1, writes: false, broadest: null }],
  ['files_read_all_files', { cost: 1900, types: 1900, writes: false, broadest: 'allow loosed_t file_type:file { read open getattr };' }],
  ['domain_read_all_domains_state', { cost: 1200, types: 600, writes: false, broadest: 'allow loosed_t domain:file { read open getattr };' }],
]);
const kept = [
  { text: 'dontaudit loosed_t self:capability sys_tty_config;', l: 40 },
  { text: 'dontaudit loosed_t init_t:unix_stream_socket { read write };', l: 41 },
  { text: 'allow loosed_t file_type:dir { read write add_name };', l: 50 },
  { text: 'allow loosed_t domain:process getattr;', l: 51 },
  { text: 'allow loosed_t other_exec_t:file entrypoint;', l: 52 },
  { text: 'allow loosed_t loosed_conf_t:file read;', l: 53 },
  { text: 'allow other_t loosed_t:process signal;', l: 54 },
];
r = T.report(loose, { domain: 'loosed_t', catalog, grants, kept });
const byId = Object.fromEntries(r.rows.map(x => [x.id, x]));
check(r.rows[0].id === 'permissive' && r.rows[0].severity === 'high' && r.rows[0].fix.op === 'permissive' && r.rows.every((x, i) => i === 0 || T.SEV[x.severity] <= T.SEV[r.rows[i - 1].severity]), 'permissive first; rows sorted by severity', r.rows.map(x => `${x.severity} ${x.id}`));
check(byId.sys_admin && byId.sys_admin.severity === 'high' && /nearly root/.test(byId.sys_admin.text) && byId.sys_admin.fix.op === 'cap' && byId.dac_override.severity === 'high' && byId.net_admin.severity === 'medium' && byId.setuid.severity === 'low' && !byId.chown && !byId.net_bind_service,
  'capabilities: sys_admin and dac_override high, net_admin medium, setuid low; chown and net_bind_service not listed', ids(r));
check(byId.execmem && byId.execmem.kind === 'self' && byId.execmem.severity === 'medium' && byId.execmem.fix.self === 'execmem', 'self: execmem');
check(byId.bin && byId.bin.kind === 'access' && byId.bin.severity === 'medium' && /Run ordinary programs/.test(byId.bin.title) && byId.kmod.severity === 'high' && byId.sessions.severity === 'high' && byId.etcfiles.severity === 'low' && !byId.syslog, 'access groups: bin medium, kmod and sessions high, etcfiles low; syslog not listed');
check(byId['file:0'] && byId['file:0'].severity === 'high' && byId['file:0'].fix.access === 'none' && byId['file:1'].fix.access === 'read' && /loosed_conf_t/.test(byId['file:1'].title) && byId['file:2'].fix.access === 'append' && /create and append/.test(byId['file:2'].fix.label) && !byId['file:3'],
  'files: a manageable unit file high → label only; config manage → read; log manage → append; state manage is fine', [byId['file:0'], byId['file:1'], byId['file:2']].map(x => x && x.title));
check(byId.files_read_all_files && byId.files_read_all_files.severity === 'high' && /every file on the system/.test(byId.files_read_all_files.title) && /1900 types/.test(byId.files_read_all_files.text) && /Narrower: the service/.test(byId.files_read_all_files.text) && byId.files_read_all_files.fix.op === 'extra',
  'files_read_all_files: broad by name, with the type count from its expansion and the narrower choice', byId.files_read_all_files);
check(byId.unconfined_domain.severity === 'high' && byId.auth_read_shadow.severity === 'high' && byId.corenet_tcp_connect_all_ports.severity === 'medium' && byId.kernel_rw_all_sysctls.severity === 'medium' && byId.domain_read_all_domains_state.severity === 'high',
  'unconfined, shadow and all-domains high; all ports and all sysctls medium', ['unconfined_domain', 'auth_read_shadow', 'corenet_tcp_connect_all_ports', 'kernel_rw_all_sysctls', 'domain_read_all_domains_state'].map(n => byId[n] && byId[n].severity));
check(!byId.apache_read_config && !byId.dev_read_urand, 'named, cheap interfaces are not listed');
check(byId.loosed_can_network && byId.loosed_can_network.severity === 'low' && byId.loosed_can_network.fix.op === 'boolDefault' && !byId.loosed_off && !byId.loosed_empty, 'a boolean on by default that grants something: low; off or empty ones not listed');
check(byId.dontaudit && byId.dontaudit.severity === 'low' && /2 dontaudit rules/.test(byId.dontaudit.title) && byId.dontaudit.line === 40 && byId.dontaudit.fix === null, 'kept dontaudit rules: one low row with the first line');
check(byId['line:50'] && byId['line:50'].severity === 'high' && /file_type/.test(byId['line:50'].title) && /writes or executes/.test(byId['line:50'].text) && byId['line:51'].severity === 'high' && /every process/.test(byId['line:51'].title) && byId['line:52'].severity === 'medium' && /Another entrypoint/.test(byId['line:52'].title) && !byId['line:53'] && !byId['line:54'],
  'kept allow rules: on file_type (writes) high, on domain high, a second entrypoint medium; own types and others\' rules not listed', ids(r));
check(r.summary.high >= 8 && r.summary.medium >= 6 && r.summary.low >= 3 && r.rows.every(x => x.title && x.text && x.severity && x.kind), `summary ${JSON.stringify(r.summary)}; every row has kind, title, text`);
r = T.report({ ...loose, extra: ['files_read_all_files', 'some_unknown_iface'] }, { domain: 'loosed_t', catalog, kept: [] });
check(byIdOf(r, 'files_read_all_files') && !byIdOf(r, 'some_unknown_iface') && r.notes.some(n => /Build the tree/.test(n)), 'without expansions: broad ones by name only, and a note to build');
r = T.report({ ...tight, extra: ['mystery_iface'] }, { domain: 'tightd_t', catalog, grants: new Map([['mystery_iface', { cost: 6000, types: 1200, writes: true, broadest: 'allow tightd_t file_type:file { write };' }]]), kept: [] });
check(byIdOf(r, 'mystery_iface') && byIdOf(r, 'mystery_iface').severity === 'high' && /1200 types reached, with writes/.test(byIdOf(r, 'mystery_iface').title), 'an interface broad by its expansion alone: listed by cost');

// 3. The cost of an expansion.
const sizeOf = (t) => ({ file_type: 1900, domain: 600, etc_t: 1, my_t: 1 })[t] || 1;
let c = T.costOf([{ src: ['loosed_t'], tgt: ['file_type'], cls: ['file'], perms: ['read', 'open', 'getattr'], text: 'A' }, { src: ['loosed_t'], tgt: ['etc_t'], cls: ['file'], perms: ['write'], text: 'B' }, { src: ['other_t'], tgt: ['domain'], cls: ['process'], perms: ['ptrace'], text: 'C' }], [], 'loosed_t', sizeOf);
check(c.cost === 1903 && c.types === 1900 && c.writes && c.broadest === 'A', 'costOf: reads of an attribute count its size, writes weigh more, other domains\' rules are not ours', c);
c = T.costOf([{ src: ['loosed_attr'], tgt: ['domain'], cls: ['process'], perms: ['ptrace'], text: 'D' }], ['loosed_attr'], 'loosed_t', sizeOf);
check(c.cost === 1800 && c.writes && c.broadest === 'D', 'costOf: rules on an attribute the domain gained count (ptrace weighs 3)', c);
check(T.costOf([], [], 'x_t', sizeOf).cost === 0, 'costOf: nothing');

function byIdOf(rep, id) { return rep.rows.find(x => x.id === id); }
console.log(failures ? `\n${failures} tighten checks FAILED` : '\nall tighten checks passed');
process.exit(failures ? 1 : 0);
