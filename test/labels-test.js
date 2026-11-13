'use strict';
// Labeling coverage for a module (server/labels.js), any OS: the script, its
// parser on sampled output, and the assessment (package files under generic
// labels → file kinds; files on disk disagreeing with the policy; missing paths).
//   node test/labels-test.js
const L = require('../server/labels');
const svc = require('../server/service');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

const script = L.coverageScript(['/usr/sbin/mydaemon', "/usr/libexec/it's"], ['/var/lib/mydaemon', '/etc/mydaemon'], ['/var/lib/mydaemon', '/etc/mydaemon.conf', 'bad\npath']);
check(/rpm -qf/.test(script) && /rpm -ql/.test(script) && /stat -c %C/.test(script) && /restorecon -nv -R '\/var\/lib\/mydaemon' '\/etc\/mydaemon'/.test(script) && /'\/usr\/libexec\/it'\\''s'/.test(script) && !/bad/.test(script) && /^sec done$/m.test(script),
  'the script: packages, files with labels, restorecon dry run over the dirs, existence; paths quoted, a bad one dropped');
check(!/restorecon/.test(L.coverageScript(['/usr/sbin/x'], [], []).split('sec restorecon')[1].split('sec exist')[0]), 'no directories: no restorecon');

const OUT = `### uid
0
### pkgs
/usr/sbin/mydaemon\tmydaemon
/usr/libexec/other\t
### files
mydaemon\td\tsystem_u:object_r:etc_t:s0\t/etc/mydaemon
mydaemon\tf\tsystem_u:object_r:mydaemon_conf_t:s0\t/etc/mydaemon/mydaemon.conf
mydaemon\tf\tsystem_u:object_r:etc_t:s0\t/etc/mydaemon/extra.conf
mydaemon\tf\tsystem_u:object_r:etc_t:s0\t/etc/logrotate.d/mydaemon
mydaemon\tf\tsystem_u:object_r:systemd_unit_file_t:s0\t/usr/lib/systemd/system/mydaemon.service
mydaemon\tf\tsystem_u:object_r:bin_t:s0\t/usr/sbin/mydaemon
mydaemon\tf\tsystem_u:object_r:bin_t:s0\t/usr/libexec/mydaemon/helper
mydaemon\td\tsystem_u:object_r:usr_t:s0\t/usr/share/mydaemon
mydaemon\tf\tsystem_u:object_r:man_t:s0\t/usr/share/man/man8/mydaemon.8.gz
mydaemon\td\tsystem_u:object_r:var_lib_t:s0\t/var/lib/mydaemon
mydaemon\td\tsystem_u:object_r:var_lib_t:s0\t/var/lib/mydaemon/cache
mydaemon\tf\tsystem_u:object_r:var_t:s0\t/var/lib/mydaemon/state.db
mydaemon\td\tsystem_u:object_r:mydaemon_log_t:s0\t/var/log/mydaemon
mydaemon\tf\tsystem_u:object_r:var_log_t:s0\t/var/log/mydaemon/old.log
mydaemon\td\tsystem_u:object_r:var_spool_t:s0\t/var/spool/mydaemon
mydaemon\td\tsystem_u:object_r:srv_t:s0\t/srv/mydaemon
mydaemon\tl\tsystem_u:object_r:etc_t:s0\t/etc/mydaemon/logs
mydaemon\tf\tsystem_u:object_r:httpd_config_t:s0\t/etc/httpd/conf.d/mydaemon.conf
### restorecon
/var/lib/mydaemon/state.db from system_u:object_r:var_t:s0 to system_u:object_r:mydaemon_var_lib_t:s0
/var/log/mydaemon/old.log from system_u:object_r:var_log_t:s0 to system_u:object_r:mydaemon_log_t:s0
### exist
/var/lib/mydaemon\t1
/etc/mydaemon.conf\t0
/run/mydaemon\t0
### done
`;
const f = L.parseCoverage(OUT);
check(f.uid === 0 && f.pkgs.get('/usr/sbin/mydaemon') === 'mydaemon' && f.pkgs.get('/usr/libexec/other') === null && f.files.length === 18 && f.files[1].label === 'mydaemon_conf_t' && f.files[0].kind === 'd' && f.done, 'parse: packages, files with kind and label type', { pkgs: [...f.pkgs], n: f.files.length });
check(f.relabel.length === 2 && f.relabel[0].path === '/var/lib/mydaemon/state.db' && f.relabel[0].from === 'var_t' && f.relabel[0].to === 'mydaemon_var_lib_t', 'parse: restorecon dry-run lines', f.relabel);
check(f.exist.get('/var/lib/mydaemon') === true && f.exist.get('/etc/mydaemon.conf') === false && f.exist.size === 3, 'parse: existence');

// The policy's labels (what the tree's file contexts say).
const expected = new Map([
  ['/etc/mydaemon', 'etc_t'], ['/etc/mydaemon/mydaemon.conf', 'mydaemon_conf_t'], ['/etc/mydaemon/extra.conf', 'etc_t'], ['/etc/logrotate.d/mydaemon', 'etc_t'],
  ['/usr/lib/systemd/system/mydaemon.service', 'systemd_unit_file_t'], ['/usr/sbin/mydaemon', 'mydaemon_exec_t'], ['/usr/libexec/mydaemon/helper', 'bin_t'], ['/usr/share/mydaemon', 'usr_t'],
  ['/var/lib/mydaemon', 'mydaemon_var_lib_t'], ['/var/lib/mydaemon/cache', 'mydaemon_var_lib_t'], ['/var/lib/mydaemon/state.db', 'mydaemon_var_lib_t'],
  ['/var/log/mydaemon', 'mydaemon_log_t'], ['/var/log/mydaemon/old.log', 'mydaemon_log_t'], ['/var/spool/mydaemon', 'var_spool_t'], ['/srv/mydaemon', 'srv_t'], ['/etc/httpd/conf.d/mydaemon.conf', 'httpd_config_t'],
]);
const ctx = { has: () => true, optional: () => true, moduleArgs: 2, moduleExists: () => false, typeExists: () => false, boolExists: () => false };
const kinds = svc.catalog(ctx).fileKinds;
const r = L.assess(f, { name: 'mydaemon', kinds, moduleTypes: new Set(['mydaemon_t', 'mydaemon_exec_t', 'mydaemon_conf_t', 'mydaemon_var_lib_t', 'mydaemon_log_t']), expected, programs: ['/usr/sbin/mydaemon'],
  modelPaths: [{ path: '/var/lib/mydaemon/', kind: 'state' }, { path: '/etc/mydaemon.conf', kind: 'config' }, { path: '/run/mydaemon/', kind: 'runtime' }] });
const gen = Object.fromEntries(r.generic.map(g => [g.suggest.path, g]));
check(Object.keys(gen).sort().join(' ') === '/etc/mydaemon/ /srv/mydaemon/ /usr/lib/systemd/system/mydaemon.service /var/spool/mydaemon/', 'generic: the config dir (etc_t, with its extra.conf), the unit file, the spool dir, /srv/mydaemon; not the covered, skipped or others\' files', Object.keys(gen));
check(gen['/etc/mydaemon/'].suggest.kind === 'config' && gen['/etc/mydaemon/'].files.length === 2 && gen['/etc/mydaemon/'].label === 'Configuration' && gen['/usr/lib/systemd/system/mydaemon.service'].suggest.kind === 'unit' && gen['/var/spool/mydaemon/'].suggest.kind === 'spool' && gen['/srv/mydaemon/'].suggest.kind === 'other',
  'each with the file kind that would label it (the directory stands for its files)', r.generic.map(g => [g.suggest, g.files]));
check(r.disagree.map(d => d.path).join() === '/var/lib/mydaemon,/var/lib/mydaemon/cache,/var/lib/mydaemon/state.db,/var/log/mydaemon/old.log' && r.disagree[2].from === 'var_t' && r.disagree[2].to === 'mydaemon_var_lib_t' && r.disagree[0].from === 'var_lib_t',
  'disagree: files whose label on disk differs from the policy (the state dir and its files, the old log; package files and restorecon agree, each listed once)', r.disagree);
check(r.missing.length === 2 && r.missing.map(m => m.path).join() === '/etc/mydaemon.conf,/run/mydaemon/' && r.missing[1].kind === 'runtime', 'missing: the module\'s paths that do not exist on the host (directory form kept)', r.missing);
check(r.covered === 6 && r.skipped >= 3 && !r.notes.length, `covered ${r.covered}, skipped ${r.skipped}, no notes as root`, r.notes);
const r2 = L.assess({ ...f, uid: 1000, files: [], done: false }, { name: 'mydaemon', kinds, moduleTypes: new Set(), expected: new Map(), programs: ['/usr/sbin/mydaemon'], modelPaths: [] });
check(r2.generic.length === 0 && r2.notes.length === 3 && /No package owns \/usr\/sbin\/mydaemon/.test(r2.notes[0]) && /Not root/.test(r2.notes[1]) && /did not run to its end/.test(r2.notes[2]), 'no package, not root, cut off: three notes');
check(L.kindFor({ path: '/etc/mydaemon/x.conf', kind: 'f' }, 'mydaemon', kinds).path === '/etc/mydaemon/' && L.kindFor({ path: '/etc/mydaemon.conf', kind: 'f' }, 'mydaemon', kinds).path === '/etc/mydaemon.conf' && L.kindFor({ path: '/var/log/mydaemon.log', kind: 'f' }, 'mydaemon', kinds).kind === 'log' && L.kindFor({ path: '/etc/sysconfig/mydaemon', kind: 'f' }, 'mydaemon', kinds) === null && L.kindFor({ path: '/var/lib/other', kind: 'd' }, 'mydaemon', kinds) === null,
  'kindFor: a file in the program\'s dir → the dir; a file named after it → itself; sysconfig and other programs\' dirs → nothing');
check(L.kindFor({ path: '/etc/chrony.keys', kind: 'f' }, ['chronyd', 'chrony'], kinds).kind === 'config' && L.kindFor({ path: '/etc/chrony.keys', kind: 'f' }, 'chronyd', kinds).kind === 'config' && L.kindFor({ path: '/var/lib/chrony/drift', kind: 'f' }, 'chronyd', kinds).path === '/var/lib/chrony/',
  'kindFor: the package name counts too, and a file\'s extension does not hide it (chrony.keys is chronyd\'s)');

console.log(failures ? `\n${failures} labels checks FAILED` : '\nall labels checks passed');
process.exit(failures ? 1 : 0);
