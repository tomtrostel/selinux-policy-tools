// Learn from a permissive run (server/learn.js): the denials of a service in
// its new domain mapped onto the service editor's model. Any OS, in npm test.
const L = require('../server/learn');
const denials = require('../server/denials');
const svc = require('../server/service');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

// The audit records of a permissive run of svctest_t.
const avc = (perms, s, t, c, extra = '') => `type=AVC msg=audit(1700000000.000:1): avc:  denied  { ${perms} } for  pid=1 comm="svctest"${extra} scontext=system_u:system_r:${s}:s0 tcontext=system_u:object_r:${t}:s0 tclass=${c} permissive=1`;
const LOG = [
  avc('net_bind_service', 'svctest_t', 'svctest_t', 'capability'),
  avc('sys_admin', 'svctest_t', 'svctest_t', 'capability'),
  avc('name_bind', 'svctest_t', 'http_port_t', 'tcp_socket'),
  avc('name_connect', 'svctest_t', 'mysqld_port_t', 'tcp_socket'),
  avc('name_bind', 'svctest_t', 'unreserved_port_t', 'tcp_socket'),
  avc('name_bind', 'svctest_t', 'odd_port_t', 'udp_socket'),
  avc('create bind', 'svctest_t', 'svctest_t', 'tcp_socket'),
  avc('node_bind', 'svctest_t', 'node_t', 'tcp_socket'),
  avc('write create', 'svctest_t', 'svctest_conf_t', 'file', ' name="x.conf"'),
  avc('read', 'svctest_t', 'svctest_log_t', 'file'),
  avc('append', 'svctest_t', 'svctest_log_t', 'file'),
  avc('write', 'svctest_t', 'var_lib_t', 'file', ' path="/var/lib/svctest/db/state" name="state"'),
  avc('add_name', 'svctest_t', 'var_lib_t', 'dir', ' path="/var/lib/svctest/db" name="db"'),
  avc('read open', 'svctest_t', 'var_log_t', 'file', ' path="/var/log/svctest.log" name="svctest.log"'),
  avc('getattr', 'svctest_t', 'etc_t', 'file', ' name="hosts"'),
  avc('read', 'svctest_t', 'shadow_t', 'file'),
  avc('signal', 'svctest_t', 'svctest_t', 'process'),
  avc('setsched', 'svctest_t', 'svctest_t', 'process'),
  avc('read write', 'svctest_t', 'svctest_t', 'fifo_file'),
  avc('transition', 'svctest_t', 'bin_t', 'process'),
  avc('read', 'svctest_t', 'random_device_t', 'chr_file'),
  avc('read', 'sshd_t', 'svctest_conf_t', 'file'),
  avc('read', 'svctest_t', 'default_t', 'file'),
  'type=SELINUX_ERR msg=audit(1700000000.000:9): op=security_bounded_transition seresult=denied oldcontext=system_u:system_r:svctest_t:s0 newcontext=system_u:system_r:svctest_helper_t:s0',
].join('\n');
const groups = denials.groupDenials(denials.parseDenials(LOG));
check(groups.length === 21, `${groups.length} denial groups parsed (same source, target and class merged)`, groups.map(g => g.key));

const model = { ...svc.newModel(), name: 'svctest', exec: ['/usr/sbin/svctest'],
  files: [{ kind: 'unit', paths: ['/usr/lib/systemd/system/svctest.service'], access: 'none' }, { kind: 'config', paths: ['/etc/svctest/'], access: 'read' }, { kind: 'log', paths: ['/var/log/svctest/'], access: 'none' }],
  self: ['fifo'], caps: [], net: { listen: [], connect: [] }, access: ['syslog'], extra: [] };
const has = (n) => !/^corenet_tcp_bind_all_unreserved_ports$/.test(n) || true;
const ctx = { has, optional: () => true, condSafe: () => true, declares: () => [] };
const cat = svc.catalog(ctx);
const accessByCall = new Map();
for (const g of cat.access) for (const it of g.items) for (const c of it.calls) accessByCall.set(c, it.id);
const suggestions = new Map([
  [groups.find(g => g.target === 'etc_t').key, { list: [{ name: 'files_read_etc_files', covers: true }] }],
  [groups.find(g => g.target === 'random_device_t').key, { list: [{ name: 'dev_read_rand', covers: true }] }],
  [groups.find(g => g.target === 'shadow_t').key, { list: [{ name: 'auth_read_shadow', covers: true }] }],
  [groups.find(g => g.target === 'default_t').key, { list: [{ name: 'files_read_default_files', covers: false }], partial: true }],
]);
const opts = {
  domain: 'svctest_t', execType: 'svctest_exec_t', fileKinds: cat.fileKinds, fileTypeOf: (row) => svc.fileType(model, row, ctx),
  isGeneric: (t) => denials.GENERIC_TYPES.has(t), portStem: (t) => ({ http_port_t: 'http', mysqld_port_t: 'mysqld' })[t] || null,
  has, interfaces: new Set(['files_read_etc_files', 'dev_read_rand', 'auth_read_shadow', 'corenet_tcp_bind_all_unreserved_ports']), accessByCall, accessLabel: (id) => id,
  capNames: new Set(svc.CAPS.map(c => c[0])), suggestions,
};
const r = L.learn(model, groups, opts);
const m = r.model;
const by = (t, c) => r.report.find(x => x.target === t && x.tclass === c && x.source === 'svctest_t');
check(m.caps.join() === 'net_bind_service,sys_admin' && by('svctest_t', 'capability').action === 'cap', 'capabilities ticked', m.caps);
check(m.net.listen.some(x => x.proto === 'tcp' && x.port === 'http') && m.net.connect.some(x => x.proto === 'tcp' && x.port === 'mysqld'), 'name_bind → listen http, name_connect → connect mysqld', m.net);
check(m.extra.includes('corenet_tcp_bind_all_unreserved_ports') && by('unreserved_port_t', 'tcp_socket').action === 'extra', 'unreserved ports: the interface, with a note to narrow it');
check(by('odd_port_t', 'udp_socket').action === 'unmapped' && /not a port type/.test(by('odd_port_t', 'udp_socket').text), 'an unknown port type: left to add by hand', by('odd_port_t', 'udp_socket'));
check(by('svctest_t', 'tcp_socket').action === 'covered' && by('node_t', 'tcp_socket').action === 'covered', 'its own socket and node_bind: covered by the port entries');
check(m.files[1].access === 'manage' && by('svctest_conf_t', 'file').action === 'file' && /raised to "manage"/.test(by('svctest_conf_t', 'file').text), 'write to its config type: access raised to manage', m.files[1]);
check(m.files[2].access === 'append' && r.report.filter(x => x.target === 'svctest_log_t').every(x => x.action === 'file' || x.action === 'covered'), 'read then append on its log type: append (covers read)', { row: m.files[2], rep: r.report.filter(x => x.target === 'svctest_log_t') });
const state = m.files.find(f => f.kind === 'state');
check(state && state.paths.join() === '/var/lib/svctest/' && state.access === 'manage' && r.report.filter(x => x.target === 'var_lib_t').every(x => x.action === 'label'), 'var_lib_t under /var/lib/svctest/: a state file type of its own, manage', { state, rep: r.report.filter(x => x.target === 'var_lib_t') });
check(m.files[2].paths.includes('/var/log/svctest.log') && by('var_log_t', 'file').action === 'label' && /labeled with the service's log type/.test(by('var_log_t', 'file').text), '/var/log/svctest.log joins the log type', m.files[2]);
check(m.access.includes('etcfiles') && by('etc_t', 'file').action === 'access' && m.access.includes('random') && by('random_device_t', 'chr_file').action === 'access', 'suggested interfaces that are access groups: ticked (etcfiles, random)', m.access);
check(m.extra.includes('auth_read_shadow') && by('shadow_t', 'file').action === 'extra', 'a suggested interface outside the groups: added as an extra call');
check(by('default_t', 'file').action === 'unmapped' && /generic label/.test(by('default_t', 'file').text) && by('default_t', 'file').rule === 'allow svctest_t default_t:file { read };', 'a generic label without a path: give the files a type (rule shown)', by('default_t', 'file'));
check(m.self.includes('signal') && m.self.includes('sched') && by('svctest_t', 'process').action === 'self' && by('svctest_t', 'fifo_file').action === 'covered', 'self: signal and sched ticked; fifo already there', { self: m.self, fifo: by('svctest_t', 'fifo_file') });
check(by('bin_t', 'process').action === 'unmapped' && /helper program/.test(by('bin_t', 'process').text), 'a domain transition: a helper, by hand');
check(r.report.find(x => x.source === 'sshd_t').action === 'skipped' && r.report.find(x => x.target === 'svctest_helper_t').action === 'skipped', 'another domain\'s denial and a SELINUX_ERR: left out');
check(r.stats.mapped + r.stats.unmapped + r.stats.skipped === r.report.length && r.stats.skipped === 2 && r.stats.unmapped === 3, `stats: ${JSON.stringify(r.stats)}`, r.report.filter(x => x.action === 'unmapped').map(x => x.text));
check(model.caps.length === 0 && model.files[1].access === 'read', 'the model given is not changed (a copy comes back)');
// A file under /etc that is not the service's own (no NAME in the path): not labeled, left to the interfaces.
const hosts = denials.groupDenials(denials.parseDenials(avc('read open', 'svctest_t', 'etc_t', 'file', ' path="/etc/hosts" name="hosts"')));
const rh = L.learn(model, hosts, { ...opts, suggestions: new Map([[hosts[0].key, { list: [{ name: 'files_read_etc_files', covers: true }] }]]) });
check(rh.report[0].action === 'access' && rh.model.files.length === model.files.length, '/etc/hosts (etc_t): not the service\'s own file, so the interface (etcfiles), no new type', rh.report[0]);
// Already allowed and custom rows.
const confG = groups.find(g => g.target === 'svctest_conf_t' && g.source === 'svctest_t');
const r2 = L.learn({ ...model, files: [{ kind: 'config', paths: ['/etc/svctest/'], access: 'custom' }] }, [{ ...confG, v: { verdict: 'allowed' } }, confG], opts);
check(r2.report[0].action === 'skipped' && /Already allowed/.test(r2.report[0].text) && r2.report[1].action === 'unmapped' && /custom rules/.test(r2.report[1].text), 'an allowed group is skipped; a custom row is left alone');
check(L.levelFor(['read', 'getattr', 'open'], { access: ['manage', 'read', 'none'] }) === 'read' && L.levelFor(['append', 'open'], { access: ['append', 'manage', 'read', 'none'] }) === 'append' && L.levelFor(['append'], { access: ['manage', 'read', 'none'] }) === 'manage' && L.levelFor(['read'], { access: ['manage', 'none'] }) === 'manage' && L.levelFor(['unlink'], { access: ['manage', 'read', 'none'] }) === 'manage',
  'levelFor: read / append / manage per the kind\'s levels');

if (process.env.DUMP) { for (const x of r.report) console.log('REPORT', x.target, x.tclass, x.perms.join(','), x.action, '|', x.text); console.log('R2', JSON.stringify(r2.report.map(x => [x.action, x.text]))); }
console.log(failures ? `\n${failures} learn checks FAILED` : '\nall learn checks passed');
process.exit(failures ? 1 : 0);
