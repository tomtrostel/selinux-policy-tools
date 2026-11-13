'use strict';
// Prefill the service form from a program on a host (server/prefill.js), any OS:
// the script, its parser on sampled output, and the draft of a model from the
// facts (package files → file kinds, unit → caps/dirs/hardening, sockets → ports,
// D-Bus / cron / xinetd → how it is started, libraries → access groups).
//   node test/prefill-test.js
const P = require('../server/prefill');
const svc = require('../server/service');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

/* ---------- the script ---------- */
const script = P.prefillScript("/usr/sbin/it's");
check(/^E='\/usr\/sbin\/it'\\''s'$/m.test(script) && /^sec exec$/m.test(script) && /rpm -qf/.test(script) && /rpm -ql/.test(script) && /rpm -qc/.test(script) && /systemctl show .*CapabilityBoundingSet/.test(script) && /'\*\.socket'/.test(script) && /ss -ntuHap/.test(script) && /dbus-1\/system-services/.test(script) && /cron\.d/.test(script) && /xinetd\.d/.test(script) && /ldd/.test(script) && /getcap/.test(script) && /semanage port -l -n/.test(script) && /^sec done$/m.test(script),
  'the script: quoted path, every section (exec, package, files, config, units, sockets, ss, dbus, cron, xinetd, libs, filecaps, ports, done)');
check(script.split('\n').filter(l => /ausearch|journalctl|systemctl show/.test(l)).every(l => /<\/dev\/null/.test(l)), 'commands that might read stdin get none (the script arrives on stdin)');

/* ---------- parsing ---------- */
const UNIT = (kv) => Object.entries(kv).map(([k, v]) => `${k}=${v}`).join('\n');
const OUT = `### uid
0
### exec
/usr/sbin/mydaemon\t1
### pkg
mydaemon\tMy daemon does things
### files
d\t/etc/mydaemon
f\t/etc/mydaemon/mydaemon.conf
f\t/etc/mydaemon/keys
f\t/etc/logrotate.d/mydaemon
f\t/etc/sysconfig/mydaemon
f\t/etc/rc.d/init.d/mydaemon
f\t/usr/lib/systemd/system/mydaemon.service
f\t/usr/lib/systemd/system/mydaemon.socket
f\t/usr/sbin/mydaemon
f\t/usr/libexec/mydaemon/helper
d\t/usr/libexec/mydaemon
d\t/usr/share/mydaemon
f\t/usr/share/mydaemon/data.db
d\t/usr/share/man/man8
f\t/usr/share/man/man8/mydaemon.8.gz
d\t/var/lib/mydaemon
d\t/var/log/mydaemon
f\t/var/log/mydaemon.log
d\t/var/cache/mydaemon
d\t/var/spool/mydaemon
-\t/run/mydaemon
l\t/etc/mydaemon/logs
### config
/etc/mydaemon/mydaemon.conf
/etc/logrotate.d/mydaemon
/etc/sysconfig/mydaemon
### units
${UNIT({ Type: 'notify', PIDFile: '/run/mydaemon/mydaemon.pid', MainPID: '4242', BusName: 'org.example.MyDaemon',
  ExecStart: '{ path=/usr/sbin/mydaemon ; argv[]=/usr/sbin/mydaemon -f ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }',
  ExecStartPre: '{ path=/usr/libexec/mydaemon/helper ; argv[]=/usr/libexec/mydaemon/helper check ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 } ; { path=/usr/bin/mkdir ; argv[]=/usr/bin/mkdir -p /run/mydaemon ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }',
  ExecReload: '{ path=/bin/kill ; argv[]=/bin/kill -HUP $MAINPID ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }',
  CapabilityBoundingSet: 'cap_net_bind_service cap_setuid cap_setgid cap_sys_resource', AmbientCapabilities: 'cap_net_bind_service', User: '', Group: '', ReadWritePaths: '/var/lib/mydaemon /srv/export', ReadOnlyPaths: '',
  PrivateTmp: 'yes', NoNewPrivileges: 'yes', RuntimeDirectory: 'mydaemon', StateDirectory: 'mydaemon', CacheDirectory: '', LogsDirectory: 'mydaemon', ConfigurationDirectory: '',
  Id: 'mydaemon.service', TriggeredBy: 'mydaemon.socket', Description: 'My Daemon', ActiveState: 'active', FragmentPath: '/usr/lib/systemd/system/mydaemon.service' })}

${UNIT({ Type: 'simple', PIDFile: '', MainPID: '0', BusName: '', ExecStart: '{ path=/usr/sbin/other ; argv[]=/usr/sbin/other ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }',
  CapabilityBoundingSet: '18446744073709551615', AmbientCapabilities: '', User: 'other', Group: '', ReadWritePaths: '', ReadOnlyPaths: '', PrivateTmp: 'no', NoNewPrivileges: 'no',
  RuntimeDirectory: '', StateDirectory: '', CacheDirectory: '', LogsDirectory: '', ConfigurationDirectory: '', Id: 'other.service', TriggeredBy: '', Description: 'Other', ActiveState: 'inactive', FragmentPath: '/usr/lib/systemd/system/other.service' })}
### sockets
Id=mydaemon.socket
Listen=[::]:8443 (Stream) ; 0.0.0.0:5353 (Datagram) ; /run/mydaemon/sock (Stream)
FragmentPath=/usr/lib/systemd/system/mydaemon.socket
Triggers=mydaemon.service

Id=sshd.socket
Listen=[::]:22 (Stream)
FragmentPath=/usr/lib/systemd/system/sshd.socket
Triggers=sshd.service
### ss
tcp   LISTEN 0      128          0.0.0.0:80         0.0.0.0:*     users:(("mydaemon",pid=4242,fd=5))
tcp   LISTEN 0      128             [::]:4567          [::]:*     users:(("mydaemon",pid=4242,fd=6))
udp   UNCONN 0      0            0.0.0.0:323        0.0.0.0:*     users:(("chronyd",pid=777,fd=4))
tcp   ESTAB  0      0        10.0.0.5:51234      10.0.0.9:3306  users:(("mydaemon",pid=4243,fd=9))
tcp   ESTAB  0      0        10.0.0.5:51235      10.0.0.9:9999  users:(("mydaemon",pid=4243,fd=10))
tcp   ESTAB  0      0        10.0.0.5:51236      10.0.0.9:443   users:(("curl",pid=9000,fd=3))
### ps
4242 1 root /usr/sbin/mydaemon -f
4243 4242 mydaemon /usr/sbin/mydaemon -f
777 1 chrony /usr/sbin/chronyd -F 2
### dbus
/usr/share/dbus-1/system-services/org.example.MyDaemon.service\torg.example.MyDaemon
### cron
/etc/cron.d/mydaemon
### xinetd
### libs
libpam.so.0
libssl.so.3
libkrb5.so.3
libldap.so.2
libc.so.6
/lib64/ld-linux-x86-64.so.2
### filecaps
/usr/sbin/mydaemon cap_sys_time=ep
### stat
root 755 system_u:object_r:bin_t:s0
### ports
http_port_t                    tcp      80, 81, 443, 488, 8008, 8009, 8443, 9000
mysqld_port_t                  tcp      1186, 3306, 63132-63164
mdns_port_t                    udp      5353
### done
`;

const f = P.parsePrefill(OUT);
check(f.uid === 0 && f.exec === '/usr/sbin/mydaemon' && f.exists && f.pkg.name === 'mydaemon' && f.pkg.summary === 'My daemon does things' && f.done, 'parse: uid, exec, package, done', f.pkg);
check(f.files.length === 22 && f.files.find(x => x.path === '/etc/mydaemon').kind === 'd' && f.files.find(x => x.path === '/run/mydaemon').kind === '-' && f.files.find(x => x.path === '/etc/mydaemon/logs').kind === 'l' && f.config.size === 3, 'parse: files with kinds, config files');
const u = f.units.find(x => x.id === 'mydaemon.service');
check(f.units.length === 2 && u.execStart.length === 1 && u.execStart[0].path === '/usr/sbin/mydaemon' && u.execStart[0].argv === '/usr/sbin/mydaemon -f' && u.execPre.map(e => e.path).join() === '/usr/libexec/mydaemon/helper,/usr/bin/mkdir' && u.execReload[0].path === '/bin/kill',
  'parse: units with every Exec* entry', u);
check(u.mainPid === 4242 && u.busName === 'org.example.MyDaemon' && u.pidFile === '/run/mydaemon/mydaemon.pid' && u.runtimeDir.join() === 'mydaemon' && u.stateDir.join() === 'mydaemon' && u.logsDir.join() === 'mydaemon' && u.rwPaths.join() === '/var/lib/mydaemon,/srv/export' && u.privateTmp && u.nnp && u.triggeredBy.join() === 'mydaemon.socket',
  'parse: unit directories, PIDFile, bus name, hardening', u);
check(u.bounding.join() === 'net_bind_service,setuid,setgid,sys_resource' && u.ambient.join() === 'net_bind_service' && f.units[1].bounding === null && f.units[1].ambient.length === 0 && f.units[1].user === 'other',
  'parse: capability sets (explicit list → names; the unlimited number → null)');
check(P.capSet('cap_chown cap_dac_override ' + Array.from({ length: 40 }, (_, i) => `cap_x${i}`).join(' ')) === null && P.capSet('~cap_sys_admin') === null && P.capSet('') === null, 'capSet: everything listed, ~set and empty are not explicit');
const su = f.socketUnits.find(x => x.id === 'mydaemon.socket');
check(f.socketUnits.length === 2 && su.listen.length === 3 && su.listen[0].port === 8443 && su.listen[0].proto === 'tcp' && su.listen[1].port === 5353 && su.listen[1].proto === 'udp' && su.listen[2].port === null && su.triggers.join() === 'mydaemon.service', 'parse: socket units with their Listen entries', su);
check(f.sockets.length === 6 && f.sockets[0].state === 'LISTEN' && f.sockets[0].port === 80 && f.sockets[0].pids.join() === '4242' && f.sockets[3].state === 'ESTAB' && f.sockets[3].peerPort === 3306 && f.sockets[3].peerAddr === '10.0.0.9' && f.sockets[2].proto === 'udp' && f.sockets[2].port === 323,
  'parse: ss sockets (listening, udp unconnected, established with the peer)', f.sockets[3]);
check(f.processes.length === 3 && f.processes[1].ppid === 4242 && f.processes[1].user === 'mydaemon' && f.dbus[0].name === 'org.example.MyDaemon' && f.cron.join() === '/etc/cron.d/mydaemon' && f.xinetd.length === 0 && f.libs.length === 6 && f.fileCaps.join() === 'sys_time' && f.label === 'system_u:object_r:bin_t:s0',
  'parse: processes, dbus, cron, libs, file capabilities, label');
check(f.ports.length === 3 && f.ports[0].name === 'http' && f.ports[0].nums.length === 8 && f.ports[1].nums.some(n => n.port === '63132-63164'), 'parse: semanage port list with ranges', f.ports);
check(P.parsePrefill('### uid\n1000\n### exec\n/usr/sbin/nothing\t0\n### pkg\n### done\n').exists === false && !P.parsePrefill('### uid\n0\n').done, 'parse: a missing program, a cut-off output');

/* ---------- the draft ---------- */
const ctx = { has: () => true, optional: () => true, moduleArgs: 2, moduleExists: (n) => n === 'taken', typeExists: () => false, boolExists: () => false };
const cat = svc.catalog(ctx);
const opts = (extra = {}) => ({ fileKinds: cat.fileKinds, ports: [{ name: 'http', nums: [{ proto: 'tcp', port: '80' }, { proto: 'tcp', port: '443' }] }, { name: 'mysqld', nums: [{ proto: 'tcp', port: '3306' }] }, { name: 'mdns', nums: [{ proto: 'udp', port: '5353' }] }],
  has: () => true, capNames: new Set(svc.CAPS.map(c => c[0])), moduleExists: ctx.moduleExists, name: '', ...extra });
let r = P.draft(f, svc.newModel(), opts());
const m = r.model;
const paths = (kind) => (m.files.find(x => x.kind === kind) || { paths: [] }).paths.slice().sort();
const access = (kind) => (m.files.find(x => x.kind === kind) || {}).access;
check(m.name === 'mydaemon' && m.summary === 'My Daemon' && r.report.find(x => x.field === 'summary').from === 'unit mydaemon.service', 'name from the unit, summary from its Description', { name: m.name, summary: m.summary });
check(m.exec.join() === '/usr/sbin/mydaemon,/usr/libexec/mydaemon/helper' && r.notes.some(n => /ExecStartPre runs \/usr\/bin\/mkdir/.test(n)) && !m.exec.includes('/bin/kill'), 'programs: the daemon and the package\'s helper; mkdir and kill noted, not added', { exec: m.exec, notes: r.notes });
check(paths('config').join() === '/etc/mydaemon/' && access('config') === 'read', 'config: the package\'s /etc/mydaemon/ (read); logrotate and sysconfig files left alone', paths('config'));
check(paths('state').join() === '/var/lib/mydaemon/' && access('state') === 'manage' && paths('log').join() === '/var/log/mydaemon.log,/var/log/mydaemon/' && access('log') === 'append' && paths('cache').join() === '/var/cache/mydaemon/' && paths('spool').join() === '/var/spool/mydaemon/',
  'state, log (dir and file), cache, spool from the package', m.files);
check(paths('runtime').join() === '/run/mydaemon/' && r.report.some(x => x.field === 'files' && /Runtime files: \/run\/mydaemon\//.test(x.text) && /RuntimeDirectory|unit mydaemon.service/.test(x.from)), 'runtime: /run/mydaemon/ from the unit (RuntimeDirectory, PIDFile), the default placeholder replaced', paths('runtime'));
check(paths('unit').join() === '/usr/lib/systemd/system/mydaemon.service,/usr/lib/systemd/system/mydaemon.socket' && paths('initrc').join() === '/etc/rc.d/init.d/mydaemon' && access('initrc') === 'none', 'unit file (and the socket unit), init script labeled only', { unit: paths('unit'), initrc: paths('initrc') });
check(r.notes.some(n => /ReadWritePaths=\/srv\/export/.test(n)) && !m.files.some(x => x.paths.some(p => p.startsWith('/srv'))), '/srv/export (ReadWritePaths, no kind) noted, not labeled');
check(r.notes.some(n => /generic labels.*\/usr\/libexec\/mydaemon, \/usr\/share\/mydaemon/.test(n)), 'package directories without a kind listed as left alone', r.notes);
const listen = m.net.listen.map(x => `${x.proto} ${x.port}`).sort(), connect = m.net.connect.map(x => `${x.proto} ${x.port}`).sort();
check(listen.join('|') === 'tcp http|tcp mydaemon|udp mdns' && m.ports.length === 1 && m.ports[0].name === '' && m.ports[0].nums.map(n => `${n.proto} ${n.port}`).sort().join('|') === 'tcp 4567|tcp 8443',
  'listens: http (80 and 8443 → http_port_t), mdns (socket unit), 4567 and the socket unit\'s 8443… no: 8443 is http; 4567 has no type → a port type of its own', { listen, ports: m.ports });
check(connect.join('|') === 'tcp mysqld' && r.notes.some(n => /Connects to tcp port 9999/.test(n)) && !connect.some(x => /443/.test(x)), 'connects: mysqld from the established connection of its child; 9999 noted; curl\'s connection not its own', { connect, notes: r.notes });
check(m.caps.slice().sort().join() === 'net_bind_service,setgid,setuid,sys_resource,sys_time' && r.report.some(x => x.field === 'caps' && /sys_time/.test(x.text) && x.from === 'getcap') && r.report.some(x => /CapabilityBoundingSet/.test(x.from)),
  'capabilities: file capability, ambient, the unit\'s small bounding set', m.caps);
check(m.access.includes('nnp') && m.access.includes('dbus') && m.access.includes('pam') && m.access.includes('kerberos') && m.access.includes('nsswitch') && m.access.includes('certs') && m.access.includes('urandom') && m.access.includes('syslog') && m.access.includes('locale'),
  'access: NoNewPrivileges, D-Bus (bus name), PAM, Kerberos, nsswitch (LDAP), certificates + urandom (OpenSSL); the defaults kept', m.access);
check(m.entries.map(e => e.name).join() === 'init_daemon_domain,dbus_system_domain,cron_system_entry' && r.report.some(x => x.field === 'starts' && /D-Bus activation \(org.example.MyDaemon\)/.test(x.text)) && r.report.some(x => x.field === 'starts' && /cron/.test(x.text) && x.from === '/etc/cron.d/mydaemon'),
  'started by systemd, also D-Bus activation and cron', m.entries);
check(r.notes.some(n => /PrivateTmp/.test(n)) && r.notes.some(n => /runs as root with every capability/.test(n)) === false && m.self.join() === 'fifo' && m.permissive === false && m.provides.join() === 'domtrans,admin', 'notes about PrivateTmp; self and provides untouched', r.notes);
check(r.report.every(x => x.field && x.text && x.from) && new Set(r.report.map(x => x.field)).size >= 7, `report: ${r.report.length} rows, each with field, text and source`);

// Nothing already set is removed; a chosen name is kept; an existing module is noted.
const pre = { ...svc.newModel(), name: 'chosen', summary: 'Mine', exec: ['/usr/sbin/mydaemon', '/usr/sbin/extra'], caps: ['chown'], access: ['syslog'], files: [{ kind: 'config', paths: ['/etc/elsewhere/'], access: 'manage' }] };
r = P.draft(f, pre, opts({ name: 'chosen' }));
check(r.model.name === 'chosen' && r.model.summary === 'Mine' && r.model.exec.join() === '/usr/sbin/mydaemon,/usr/sbin/extra,/usr/libexec/mydaemon/helper' && r.model.caps.includes('chown') && r.model.files.find(x => x.kind === 'config').paths.join() === '/etc/elsewhere/,/etc/mydaemon/' && r.model.files.find(x => x.kind === 'config').access === 'manage',
  'an edited form keeps everything it had; the facts are added', r.model.files);
r = P.draft(f, svc.newModel(), opts({ moduleExists: (n) => n === 'mydaemon' }));
check(r.model.name === '' && r.notes.some(n => /A module named mydaemon exists/.test(n)), 'the only name is taken by a module: left empty, said so', r.notes);
r = P.draft({ ...f, pkg: null, files: [], units: [{ ...u, id: 'svc-x.service', bounding: null, ambient: [] }] }, svc.newModel(), opts());
check(r.model.name === 'svc_x' && r.model.caps.join() === 'net_bind_service,sys_time' && r.notes.some(n => /runs as root with every capability/.test(n)), 'no package: the unit names it; an unlimited bounding set is a note; net_bind_service from the low port, sys_time from getcap', { name: r.model.name, caps: r.model.caps });
r = P.draft({ ...f, units: [{ ...u, bounding: ['chown', 'dac_override', 'dac_read_search', 'fowner', 'fsetid', 'setgid', 'setuid', 'setpcap', 'net_bind_service', 'net_admin', 'net_raw'] }] }, svc.newModel(), opts());
check(r.model.caps.slice().sort().join() === 'net_bind_service,sys_time' && r.notes.some(n => /keeps 11 capabilities/.test(n)), `a bounding set over ${P.MAX_BOUNDING} is not ticked blindly`, r.model.caps);
r = P.draft({ ...f, units: [{ ...u, user: 'svc' }] }, svc.newModel(), opts());
check(r.notes.some(n => /runs as svc: systemd switches the user/.test(n)) && !r.report.some(x => /below 1024/.test(x.text)), 'User= set: no setuid note, net_bind_service not implied by the low port (the ambient one still is)');

// xinetd instead of a unit; the host's semanage ports when the policy has none (standalone module).
const fx = { ...f, units: [], socketUnits: [], dbus: [], cron: [], xinetd: ['/etc/xinetd.d/mydaemon'], sockets: [] };
r = P.draft(fx, svc.newModel(), opts());
check(r.model.entries.map(e => e.name).join() === 'inetd_tcp_service_domain' && r.report.some(x => x.field === 'starts' && /xinetd/.test(x.text)) && !r.model.access.includes('nnp') && r.model.access.includes('pam'), 'xinetd: started by inetd instead of systemd', r.model.entries);
r = P.draft(f, svc.newModel(), opts({ ports: [] }));
check(r.model.net.listen.some(x => x.port === 'http' && x.proto === 'tcp') && r.model.net.connect.some(x => x.port === 'mysqld') && r.model.net.listen.some(x => x.port === 'mdns'), 'without the policy\'s ports (standalone), the host\'s semanage list names the port types', r.model.net);
r = P.draft({ ...f, ports: [] }, svc.newModel(), opts({ ports: [], has: (n) => n !== 'dbus_system_domain' }));
check(r.model.ports.length === 1 && r.model.ports[0].nums.length === 4 && r.model.net.listen.every(x => x.port === 'mydaemon') && !r.model.entries.some(e => e.name === 'dbus_system_domain') && r.model.access.includes('dbus'),
  'no port types at all: every port becomes the service\'s own port type; an interface the policy lacks is not used', { ports: r.model.ports, entries: r.model.entries });
r = P.draft(P.parsePrefill('### uid\n0\n### exec\n/usr/sbin/nothing\t0\n### done\n'), svc.newModel(), opts());
check(r.report.length === 0 && r.notes.join() === '/usr/sbin/nothing does not exist on the host.', 'a program that is not there: one note, nothing filled in');
r = P.draft({ ...f, uid: 1000, done: false }, svc.newModel(), opts());
check(r.notes.some(n => /Not root on the host/.test(n)) && r.notes.some(n => /did not run to its end/.test(n)), 'not root and a cut-off output are said');
check(P.sameProgram('chrony', 'chronyd') && P.sameProgram('httpd', 'httpd') && P.sameProgram('mydaemon.service', 'mydaemon') && !P.sameProgram('ab', 'abc') && !P.sameProgram('mysql', 'mariadb'), 'sameProgram: prefixes of 3+ letters');

console.log(failures ? `\n${failures} prefill checks FAILED` : '\nall prefill checks passed');
process.exit(failures ? 1 : 0);
