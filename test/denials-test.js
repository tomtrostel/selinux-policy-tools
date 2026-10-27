// Denial assistant: audit record parsing, event joining, grouping and verdicts
// (server/denials.js), and the webview against a fake DOM. Any OS.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const d = require('../server/denials');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

/* ---------- parsing ---------- */

// audit.log / ausearch --raw: one event with SYSCALL, CWD, PATH (relative name), hex proctitle, RHEL ENRICHED suffix.
const RAW = `type=AVC msg=audit(1728650000.123:4521): avc:  denied  { read } for  pid=1234 comm="httpd" name="index.html" dev="dm-0" ino=393217 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0
type=SYSCALL msg=audit(1728650000.123:4521): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=55d0 a2=80000 a3=0 items=1 ppid=1 pid=1234 auid=4294967295 uid=48 gid=48 euid=48 suid=48 fsuid=48 egid=48 sgid=48 fsgid=48 tty=(none) ses=4294967295 comm="httpd" exe="/usr/sbin/httpd" subj=system_u:system_r:httpd_t:s0 key=(null)\x1dARCH=x86_64 SYSCALL=openat AUID="unset" UID="apache"
type=CWD msg=audit(1728650000.123:4521): cwd="/var/www"
type=PATH msg=audit(1728650000.123:4521): item=0 name="html/index.html" inode=393217 dev=fd:00 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PROCTITLE msg=audit(1728650000.123:4521): proctitle=2F7573722F7362696E2F6874747064002D44464F524547524F554E44
type=AVC msg=audit(1728650001.500:4522): avc:  denied  { read open } for  pid=1234 comm="httpd" path=2F7661722F7777772F68746D6C2F6D7920706167652E68746D6C dev="dm-0" ino=393218 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0
type=AVC msg=audit(1728650002.000:4523): avc:  denied  { name_connect } for  pid=1234 comm="httpd" dest=8080 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:http_cache_port_t:s0 tclass=tcp_socket permissive=1
type=AVC msg=audit(1728650003.000:4524): avc:  granted  { setsecparam } for  pid=1 comm="x" scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:security_t:s0 tclass=security
`;
let ds = d.parseDenials(RAW);
check(ds.length === 3, `raw: 3 denials (granted ignored): ${ds.length}`);
check(ds[0].path === '/var/www/html/index.html' && ds[0].exe === '/usr/sbin/httpd' && ds[0].comm === 'httpd', 'raw: PATH name joined with CWD, exe from SYSCALL', ds[0]);
check(ds[1].path === '/var/www/html/my page.html', 'raw: hex-encoded path decoded', ds[1].path);
check(ds[2].permissive && ds[2].tclass === 'tcp_socket' && ds[2].scontext.type === 'httpd_t' && ds[2].tcontext.level === 's0', 'raw: permissive flag, contexts parsed');
check(ds[0].at === 1728650000000, 'raw: event time');

// ausearch -i: interpreted, " : " after the stamp, unquoted values, records in reverse order.
const INTERP = `----
type=PROCTITLE msg=audit(10/11/2026 14:33:20.123:4600) : proctitle=/usr/sbin/myd -f
type=PATH msg=audit(10/11/2026 14:33:20.123:4600) : item=1 name=/etc/myd/myd.conf inode=12 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:etc_t:s0 nametype=NORMAL
type=PATH msg=audit(10/11/2026 14:33:20.123:4600) : item=0 name=/etc/myd/ inode=11 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:etc_t:s0 nametype=PARENT
type=CWD msg=audit(10/11/2026 14:33:20.123:4600) : cwd=/
type=SYSCALL msg=audit(10/11/2026 14:33:20.123:4600) : arch=x86_64 syscall=openat success=no exit=EACCES(Permission denied) a0=AT_FDCWD items=2 ppid=1 pid=77 auid=unset uid=root comm=myd exe=/usr/sbin/myd subj=system_u:system_r:myd_t:s0 key=(null)
type=AVC msg=audit(10/11/2026 14:33:20.123:4600) : avc:  denied  { write } for  pid=77 comm=myd name=myd.conf dev="dm-0" ino=12 scontext=system_u:system_r:myd_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0
`;
ds = d.parseDenials(INTERP);
check(ds.length === 1 && ds[0].path === '/etc/myd/myd.conf' && ds[0].exe === '/usr/sbin/myd' && ds[0].at === Date.parse('10/11/2026 14:33:20'), 'ausearch -i: interpreted records joined (NORMAL item, not PARENT)', ds[0]);

// Kernel/journal lines and a USER_AVC (D-Bus / systemd) with the AVC inside msg='…'.
const KERN = `Oct 11 14:40:01 melody kernel: audit: type=1400 audit(1728650401.010:4700): avc:  denied  { search } for  pid=900 comm="chronyd" name="foo" dev="tmpfs" ino=5 scontext=system_u:system_r:chronyd_t:s0 tcontext=system_u:object_r:var_run_t:s0 tclass=dir permissive=0
type=USER_AVC msg=audit(1728650402.000:4701): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 msg='avc:  denied  { status } for auid=n/a uid=0 gid=0 path="/usr/lib/systemd/system/myd.service" cmdline="systemctl status myd" function="mac_selinux_filter" scontext=system_u:system_r:myd_t:s0 tcontext=system_u:object_r:systemd_unit_file_t:s0 tclass=service permissive=0  exe="/usr/lib/systemd/systemd" sauid=0 hostname=? addr=? terminal=?'
type=SELINUX_ERR msg=audit(1728650403.000:4702): op=security_compute_sid invalid_context="system_u:system_r:myd_t:s0" scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:myd_exec_t:s0 tclass=process
avc:  denied  { getattr } for  pid=3 comm="cat" path="/srv/x" dev="sda1" ino=9 scontext=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 tcontext=system_u:object_r:default_t:s0 tclass=file permissive=0
`;
ds = d.parseDenials(KERN);
check(ds.length === 4, `kernel/journal/user_avc/selinux_err/bare: 4 records: ${ds.map(x => x.kind).join(',')}`);
check(ds[0].kind === 'avc' && ds[0].tclass === 'dir' && ds[0].event === '1728650401:4700', 'kernel line: type=1400 is an AVC, event id read');
check(ds[1].kind === 'user_avc' && ds[1].path === '/usr/lib/systemd/system/myd.service' && ds[1].exe === '/usr/lib/systemd/systemd' && ds[1].tclass === 'service', 'USER_AVC: fields from inside msg=\'…\'', ds[1]);
check(ds[2].kind === 'error' && ds[2].op === 'security_compute_sid' && ds[2].invalid === 'system_u:system_r:myd_t:s0', 'SELINUX_ERR kept as an error');
check(ds[3].scontext.level === 's0-s0:c0.c1023' && ds[3].path === '/srv/x', 'bare avc line; MLS level with colons');

/* ---------- grouping ---------- */

const groups = d.groupDenials(d.parseDenials(RAW + KERN + RAW.replace(/:452(\d)\)/g, ':462$1)')));
const home = groups.find(g => g.target === 'user_home_t');
check(home && home.count === 4 && home.perms.join(' ') === 'read open' && home.paths.length === 2 && !home.permissive && home.enforcing, 'grouped by source/target/class: counts events, merges perms and paths', home);
const port = groups.find(g => g.tclass === 'tcp_socket');
check(port && port.permissive && port.count === 2, 'all-permissive group marked permissive');
check(groups[0] === home, 'most frequent group first');
check(groups.some(g => g.kind === 'error'), 'errors grouped separately');

/* ---------- verdicts ---------- */

const g = (o) => ({ kind: 'deny', source: 'httpd_t', target: 'user_home_t', tclass: 'file', perms: ['read'], paths: [], ops: [], permissive: false, userspace: false, ...o });
const P = 'targeted';
let v = d.verdict(g({ paths: ['/var/www/html/index.html'] }), { perms: { read: { status: 'missing' } } }, [{ path: '/var/www/html/index.html', expected: 'httpd_sys_content_t', current: 'user_home_t' }], P);
check(v.verdict === 'label' && /restorecon -v \/var\/www\/html\/index\.html/.test(v.fixes[0].command) && /httpd_sys_content_t/.test(v.detail), 'wrong label beats a missing rule: restorecon', v);
v = d.verdict(g({ paths: ['/var/www/html/index.html'] }), null, [{ path: '/var/www/html/index.html', expected: 'httpd_sys_content_t', current: 'httpd_sys_content_t' }], P);
check(v.verdict === 'label' && !v.fixes.length && v.notes.some(n => /relabeled since/.test(n)), 'already relabeled: no fix, says so');
v = d.verdict(g({ paths: ['/var/www/html/a b'] }), null, [{ path: '/var/www/html/a b', expected: 'httpd_sys_content_t', current: null }], P);
check(v.fixes[0].command === "restorecon -v '/var/www/html/a b'", 'paths quoted for the shell');
v = d.verdict(g({ perms: ['create'], tclass: 'file', paths: ['/run/myd/x.pid'], target: 'var_run_t' }), null, [{ path: '/run/myd/x.pid', expected: 'myd_runtime_t', current: null }], P);
check(v.verdict === 'label' && /type transition/.test(v.detail), 'create with a different expected type: directory label or type transition');
v = d.verdict(g({ paths: ['/var/www/html/index.html'] }), { perms: { read: { status: 'boolean', options: [{ httpd_read_user_content: true }] } } }, [{ path: '/var/www/html/index.html', expected: 'user_home_t', current: 'user_home_t' }], P);
check(v.verdict === 'boolean' && v.fixes[0].command === 'setsebool -P httpd_read_user_content on', 'matching label + boolean → setsebool', v);
v = d.verdict(g({ perms: ['read', 'getattr'] }), { perms: { read: { status: 'boolean', options: [{ a_bool: true }, { b_bool: true }] }, getattr: { status: 'boolean', options: [{ b_bool: true }] } } }, null, P);
check(v.verdict === 'boolean' && v.fixes[0].command === 'setsebool -P b_bool on', 'boolean covering every permission chosen', v.fixes);
v = d.verdict(g({ perms: ['read', 'write'] }), { perms: { read: { status: 'boolean', options: [{ a_bool: true }] }, write: { status: 'missing' } } }, null, P);
check(v.verdict === 'missing' && v.notes.some(n => /a_bool/.test(n)), 'partly boolean, partly missing → missing, boolean noted');
v = d.verdict(g({}), { perms: { read: { status: 'allowed', rules: [{ rt: 'allow', s: 'httpd_t', t: 'user_home_t', c: 'file', perms: ['read'] }] } } }, null, P);
check(v.verdict === 'allowed' && v.rules.length === 1 && /constraint/.test(v.detail), 'already allowed: explains reload/constraint');
v = d.verdict(g({ target: 'default_t', paths: ['/srv/x'] }), { perms: { read: { status: 'missing' } } }, [{ path: '/srv/x', expected: 'default_t', current: 'default_t' }], P);
check(v.verdict === 'generic' && /type of their own/.test(v.detail), 'generic type: give files a type of their own');
v = d.verdict(g({ target: 'default_t', tclass: 'tcp_socket' }), { perms: { read: { status: 'missing' } } }, null, P);
check(v.verdict === 'missing', 'generic only for file classes');
v = d.verdict(g({ perms: ['read', 'open'] }), { perms: { read: { status: 'missing' }, open: { status: 'missing' } } }, null, P);
check(v.verdict === 'missing' && v.needed === 'allow httpd_t user_home_t:file { read open };' && /interface/.test(v.detail), 'missing rule: needed access shown, interface advised', v);
v = d.verdict(g({ source: 'myd_t', target: 'myd_t', tclass: 'capability', perms: ['net_admin'] }), { perms: { net_admin: { status: 'missing' } } }, null, P);
check(v.needed === 'allow myd_t self:capability { net_admin };', 'self for same source and target');
v = d.verdict(g({ source: 'nope_t' }), { unknown: ['nope_t'] }, null, P);
check(v.verdict === 'unknown' && /different policy/.test(v.detail), 'unknown type: from a different policy');
v = d.verdict(g({ permissive: true }), { perms: { read: { status: 'missing' } }, permissiveDomain: true }, null, P);
check(v.notes.length === 2, 'permissive mode and permissive domain noted');
v = d.verdict({ ...g({}), kind: 'error', ops: ['security_compute_sid'], target: 'myd_exec_t', tclass: 'process' }, null, null, P);
check(v.verdict === 'error', 'SELinux error verdict');

/* ---------- SELINUX_ERR: refused at run time though the policy compiles ---------- */
{
  const log = [
    'type=AVC msg=audit(1728650500.000:4800): avc:  denied  { nnp_transition } for  pid=900 comm="sshd" scontext=system_u:system_r:sshd_t:s0-s0:c0.c1023 tcontext=ro_u:ro_r:ro_t:s0 tclass=process2 permissive=0',
    'type=SELINUX_ERR msg=audit(1728650500.000:4800): op=security_bounded_transition seresult=denied oldcontext=system_u:system_r:sshd_t:s0-s0:c0.c1023 newcontext=ro_u:ro_r:ro_t:s0',
    'type=SYSCALL msg=audit(1728650500.000:4800): arch=c000003e syscall=59 success=no exit=-1 pid=900 comm="sshd" exe="/usr/sbin/sshd"',
    'type=SELINUX_ERR msg=audit(1728650501.000:4801): security_compute_sid:  invalid context staff_u:staff_r:passwd_t:s0 for scontext=staff_u:staff_r:staff_t:s0 tcontext=system_u:object_r:passwd_exec_t:s0 tclass=process',
    'type=SELINUX_ERR msg=audit(1728650502.000:4802): op=security_compute_av reason=bounds scontext=system_u:system_r:web_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file perms=read,open',
  ].join('\n');
  const recs = d.parseDenials(log);
  const bt = recs.find(x => x.op === 'security_bounded_transition');
  check(recs.length === 4 && bt && bt.scontext.type === 'sshd_t' && bt.tcontext.type === 'ro_t' && bt.tclass === 'process' && bt.exe === '/usr/sbin/sshd', 'bounded transition: oldcontext → newcontext as source → target, with the program', recs);
  const cs = recs.find(x => x.op === 'security_compute_sid');
  check(cs && cs.invalid === 'staff_u:staff_r:passwd_t:s0' && cs.tcontext.type === 'passwd_exec_t', 'older "invalid context X for" wording read too', cs);
  const ca = recs.find(x => x.op === 'security_compute_av');
  check(ca && ca.reason === 'bounds' && ca.perms.join() === 'read,open', 'typebounds mask: reason and permissions', ca);
  const gs = d.groupDenials(recs);
  const gb = gs.find(x => x.kind === 'error' && x.tclass === 'process' && x.target === 'ro_t');
  v = d.verdict(gb, { err: { nnp: { process2: true, bounded: false, nnp_transition: { status: 'missing' }, nosuid_transition: { status: 'missing' }, nnpTo: [{ name: 'login_userdomain', attribute: true }], attrs: ['userdomain'] } } }, null, P);
  check(v.verdict === 'nnp' && /NoNewPrivileges/.test(v.detail) && v.need.tclass === 'process2' && v.need.source === 'sshd_t' && v.need.target === 'ro_t' && v.attrs.join() === 'login_userdomain'
    && v.needed === 'allow sshd_t ro_t:process2 { nnp_transition nosuid_transition };', 'bounded transition: NoNewPrivileges/nosuid verdict, the need, the attribute that has it', v);
  v = d.verdict(gb, { err: { nnp: { process2: true, bounded: false, nnp_transition: { status: 'allowed' }, nosuid_transition: { status: 'missing' } } } }, null, P);
  check(v.verdict === 'allowed', 'bounded transition the build now allows: allowed (a fix shows as resolved)', v);
  const gc = gs.find(x => x.kind === 'error' && x.target === 'passwd_exec_t');
  v = d.verdict(gc, { err: { valid: { ok: false, reasons: [{ kind: 'roletype', text: "role staff_r isn't authorized for passwd_t" }] } } }, null, P);
  check(v.verdict === 'invalid' && /staff_r isn't authorized for passwd_t/.test(v.detail) && v.role.role === 'staff_r' && v.role.type === 'passwd_t' && v.needed === 'role staff_r types passwd_t;', 'invalid computed context: the reason and the role to authorize', v);
  v = d.verdict(gc, { err: { valid: { ok: true, reasons: [] } } }, null, P);
  check(v.verdict === 'allowed', 'a context the build accepts now: allowed');
  const ga = gs.find(x => x.kind === 'error' && x.target === 'shadow_t');
  v = d.verdict(ga, { err: { bounds: { parent: 'httpd_t', masked: [] } } }, null, P);
  check(v.verdict === 'bounds' && /bounded by httpd_t/.test(v.detail) && v.need.source === 'httpd_t' && v.needed === 'allow httpd_t shadow_t:file { read open };', 'typebounds mask: the parent needs the access', v);
  const gn = gs.find(x => x.kind === 'deny' && x.tclass === 'process2');
  v = d.verdict(gn, { perms: { nnp_transition: { status: 'missing' } } }, null, P);
  check(v.verdict === 'missing' && v.notes.some(n => /NoNewPrivileges/.test(n)), 'the nnp_transition AVC itself: missing rule, explained', v);
}

/* ---------- interface suggestions ---------- */

const PROBE = `policy_module(zzprobe, 1.0.0)
##### begin files_rw_etc_files(myd_t) depth: 1
	require { type etc_t; class file { read write }; }
	allow myd_t etc_t:file { open { getattr read write append ioctl lock } };
##### begin files_search_etc(myd_t) depth: 2
	allow myd_t etc_t:dir { getattr search open };
##### end files_search_etc(myd_t) depth: 1
##### end files_rw_etc_files(myd_t) depth: 0
##### begin files_manage_etc_files(myd_t) depth: 1
	allow myd_t etc_t:dir { getattr search open read write add_name remove_name };
	allow myd_t etc_t:file { create open getattr setattr read write append rename link unlink ioctl lock };
##### end files_manage_etc_files(myd_t) depth: 0
##### begin files_manage_config_files(myd_t) depth: 1
	allow myd_t configfile:file { create open getattr setattr read write append rename link unlink ioctl lock };
##### end files_manage_config_files(myd_t) depth: 0
##### begin files_dontaudit_write_etc_files(myd_t) depth: 1
	dontaudit myd_t etc_t:file write;
##### end files_dontaudit_write_etc_files(myd_t) depth: 0
##### begin etc_writer(myd_t) depth: 1
	typeattribute myd_t etc_writer_domain;
##### end etc_writer(myd_t) depth: 0
##### begin files_read_etc_files(myd_t) depth: 1
	allow myd_t etc_t:file { open getattr read };
	if (allow_etc_write) {
	allow myd_t etc_t:file write;
	}
##### end files_read_etc_files(myd_t) depth: 0
`;
const st = d.probeStatements(PROBE);
check(st.size === 6 && st.get('files_rw_etc_files(myd_t)').length === 2, `probe: one statement list per top-level call: ${[...st.keys()].join(', ')}`);
check(st.get('files_rw_etc_files(myd_t)')[1].nested && !st.get('files_rw_etc_files(myd_t)')[0].nested, 'probe: statements of called interfaces marked nested');
check(st.get('files_rw_etc_files(myd_t)')[0].perms.join(' ') === 'open getattr read write append ioctl lock', 'probe: nested permission sets flattened');
check(st.get('files_read_etc_files(myd_t)')[1].cond, 'probe: rules in if blocks are conditional');
const cand = (name, extra = {}) => ({ name, call: `${name}(myd_t)`, module: 'files', owner: true, off: false, summary: '', loc: null, ...extra });
const types = { etc_t: { attr: false, size: 1, attrs: ['configfile', 'file_type'] }, configfile: { attr: true, size: 300 } };
const ranked = d.rankInterfaces({ domain: 'myd_t', target: 'etc_t', tclass: 'file', perms: ['write'] },
  ['files_rw_etc_files', 'files_manage_etc_files', 'files_manage_config_files', 'files_dontaudit_write_etc_files', 'etc_writer', 'files_read_etc_files'].map(n => cand(n, n === 'etc_writer' ? { module: 'other', owner: false } : {})),
  st, types, { etc_writer_domain: [{ rt: 'allow', s: 'etc_writer_domain', t: 'etc_t', c: 'file', perms: ['write', 'append'], cond: '' }] });
check(ranked.map(x => x.name).join(' ') === 'etc_writer files_rw_etc_files files_manage_etc_files files_manage_config_files',
  `ranked narrowest first; dontaudit and conditional-only interfaces left out: ${ranked.map(x => `${x.name}(${x.extra})`).join(' ')}`);
check(ranked[0].attrs.join() === 'etc_writer_domain', 'rights through an added attribute count (its rules in the policy)');
check(ranked.find(x => x.name === 'files_manage_config_files').broad && !ranked.find(x => x.name === 'files_rw_etc_files').broad, 'interfaces far broader than the best are flagged');
check(/configfile \(300 types\) file: /.test(ranked.find(x => x.name === 'files_manage_config_files').grants[0]), `grants summary names the attribute and its size: ${ranked.find(x => x.name === 'files_manage_config_files').grants[0]}`);
check(ranked.find(x => x.name === 'files_manage_etc_files').extra > ranked.find(x => x.name === 'files_rw_etc_files').extra, 'create/unlink weigh more than reads');
const part = d.rankInterfaces({ domain: 'myd_t', target: 'etc_t', tclass: 'file', perms: ['write', 'execute'] }, [cand('files_rw_etc_files')], st, types);
check(part.length === 1 && !part[0].covers && part[0].missing.join() === 'execute', 'partial cover reported with what it lacks');

/* ---------- phase 4: domains, constraints, pairs, new interfaces ---------- */

const ug = (o) => g({ source: 'unconfined_service_t', target: 'etc_t', exes: ['/usr/sbin/myd'], ...o });
v = d.verdict(ug({}), { perms: { read: { status: 'allowed' } }, transition: { exe: '/usr/sbin/myd', expected: 'myd_exec_t', current: 'bin_t', domains: ['myd_t'], generic: false } }, null, P);
check(v.verdict === 'transition' && /wrong label/.test(v.title) && v.fixes[0].command === 'restorecon -v /usr/sbin/myd', 'program with the wrong label: relabel, not rules', v);
v = d.verdict(ug({}), { perms: { read: { status: 'missing' } }, transition: { exe: '/usr/sbin/myd', expected: 'myd_exec_t', current: 'myd_exec_t', domains: ['myd_t'], generic: false } }, null, P);
check(v.verdict === 'transition' && v.title === 'Not running in myd_t' && /started without the transition/.test(v.detail) && !v.fixes.length, 'labeled right but not in its domain: how it was started', v);
v = d.verdict(ug({ source: 'unconfined_t' }), { perms: {}, transition: { exe: '/usr/sbin/myd', expected: 'myd_exec_t', current: 'myd_exec_t', domains: ['myd_t'], generic: false } }, null, P);
check(/login shell/.test(v.detail) && /systemctl start/.test(v.detail), 'started from a shell: start it as a service');
v = d.verdict(ug({}), { perms: {}, transition: { exe: '/usr/sbin/myd', expected: 'myd_exec_t', current: null, domains: ['myd_t'], generic: false } }, null, P);
check(/ls -Z/.test(v.detail) && /restorecon/.test(v.fixes[0].command), 'current label unknown: suggests checking and relabeling');
v = d.verdict(ug({ exes: ['/opt/x/run'] }), { perms: { read: { status: 'missing' } }, transition: { exe: '/opt/x/run', expected: 'usr_t', current: 'usr_t', domains: [], generic: true } }, null, P);
check(v.verdict === 'transition' && v.title === 'No policy for this program' && v.fixes[0].action.cmd === 'newService' && v.fixes[0].action.exec === '/opt/x/run', 'no policy for the program: offers a new service policy', v);

const mcs = [{ kind: 'mlsconstrain', perms: ['read'], text: 'h1 dom h2 or ( t1 != mcs_constrained_type )', leaves: [{ text: 'h1 dom h2', ok: false, a: 's0:c1.c2', b: 's0:c3.c4' }, { text: 't1 != { mcs_constrained_type }', ok: false, a: 'svirt_t' }] }];
v = d.verdict(g({ source: 'svirt_t', target: 'svirt_image_t', scontext: 'system_u:system_r:svirt_t:s0:c1,c2', tcontext: 'system_u:object_r:svirt_image_t:s0:c3,c4', paths: ['/var/lib/libvirt/images/a.img'] }),
  { perms: { read: { status: 'allowed', rules: [] } }, constraints: mcs }, null, P);
check(v.verdict === 'constraint' && /MCS\/MLS/.test(v.title) && /s0:c1,c2/.test(v.detail) && /h1 dom h2/.test(v.detail) && v.fixes[0].command === 'chcon -l s0:c1,c2 /var/lib/libvirt/images/a.img', 'MCS constraint: explained, chcon -l offered', v);
v = d.verdict(g({ scontext: 'staff_u:staff_r:staff_t:s0', tcontext: 'user_u:object_r:user_home_t:s0', paths: ['/home/a/x'] }),
  { perms: { read: { status: 'allowed' } }, constraints: [{ kind: 'constrain', perms: ['read'], text: 'u1 == u2 or t1 == ubac_exempt', leaves: [{ text: 'u1 == u2', ok: false, a: 'staff_u', b: 'user_u' }] }] }, null, P);
check(v.verdict === 'constraint' && /UBAC/.test(v.title) && v.fixes[0].command === 'chcon -u staff_u /home/a/x', 'UBAC constraint: SELinux users differ, chcon -u offered');
v = d.verdict(g({}), { perms: { read: { status: 'allowed' } }, constraints: [] }, null, P);
check(v.verdict === 'allowed', 'no failing constraint: already allowed');

// Pairs when no single interface covers it.
const st2 = d.probeStatements(`##### begin a_read(myd_t) depth: 1
	allow myd_t x_t:file { read open };
##### end a_read(myd_t) depth: 0
##### begin b_write(myd_t) depth: 1
	allow myd_t x_t:file { write };
##### end b_write(myd_t) depth: 0
##### begin c_append(myd_t) depth: 1
	allow myd_t x_t:file { write append create unlink };
##### end c_append(myd_t) depth: 0
`);
const pr = d.rankInterfaces({ domain: 'myd_t', target: 'x_t', tclass: 'file', perms: ['read', 'write'] }, ['a_read', 'b_write', 'c_append'].map(n => cand(n)), st2, { x_t: { attr: false, size: 1, attrs: [] } });
check(!pr.some(x => x.covers) && pr.combos.length === 2 && pr.combos[0].items.map(x => x.name).sort().join() === 'a_read,b_write', `no single cover: the narrowest pair first (${pr.combos.map(c => c.items.map(x => x.name).join('+')).join(', ')})`);
const one = d.rankInterfaces({ domain: 'myd_t', target: 'x_t', tclass: 'file', perms: ['write'] }, ['b_write', 'c_append'].map(n => cand(n)), st2, { x_t: { attr: false, size: 1, attrs: [] } });
check(one.combos.length === 0, 'no pairs when one interface covers it');

// Only reading was denied: interfaces that can also change things rank lower.
const st3 = d.probeStatements(`##### begin manage_x(myd_t) depth: 1
	allow myd_t x_t:file { create open getattr read write unlink };
##### end manage_x(myd_t) depth: 0
##### begin read_some(myd_t) depth: 1
	allow myd_t some_types:file { read open getattr };
##### end read_some(myd_t) depth: 0
##### begin read_many(myd_t) depth: 1
	allow myd_t many_types:file { read open getattr };
##### end read_many(myd_t) depth: 0
`);
const ty3 = { x_t: { attr: false, size: 1, attrs: ['some_types', 'many_types'] }, some_types: { attr: true, size: 30 }, many_types: { attr: true, size: 900 } };
let ro = d.rankInterfaces({ domain: 'myd_t', target: 'x_t', tclass: 'file', perms: ['read', 'open'] }, ['manage_x', 'read_some'].map(n => cand(n)), st3, ty3);
check(ro[0].name === 'read_some' && ro[1].name === 'manage_x' && ro[1].writes && !ro[0].writes, `read-only denial: a read-only interface over 30 types first, the one that also writes the type second (${ro.map(x => `${x.name} ${x.extra}${x.writes ? ' writes' : ''}`).join(', ')})`);
ro = d.rankInterfaces({ domain: 'myd_t', target: 'x_t', tclass: 'file', perms: ['read', 'open'] }, ['manage_x', 'read_many'].map(n => cand(n)), st3, ty3);
check(ro[0].name === 'manage_x', `... but reading 900 types is broader still (${ro.map(x => `${x.name} ${x.extra}`).join(', ')})`);
ro = d.rankInterfaces({ domain: 'myd_t', target: 'x_t', tclass: 'file', perms: ['write'] }, ['manage_x', 'read_some'].map(n => cand(n)), st3, ty3);
check(ro.length === 1 && ro[0].name === 'manage_x' && ro[0].writes, 'a write denial: no read-only penalty (it still creates and deletes, which is noted)');

// A new interface for the owner module.
let ni = d.newInterfaceText({ module: 'notesd', target: 'notesd_var_lib_t', tclass: 'file', perms: ['read', 'open'] });
check(ni.name === 'notesd_read_var_lib_files' && /interface\(`notesd_read_var_lib_files',`/.test(ni.text) && /gen_require\(`\n\t\ttype notesd_var_lib_t;\n\t'\)/.test(ni.text) && /allow \$1 notesd_var_lib_t:file \{ read open \};/.test(ni.text) && /## <param name="domain">/.test(ni.text),
  'new interface: refpolicy name, doc, gen_require, the exact rule', ni.text);
check(d.newInterfaceText({ module: 'notesd', target: 'notesd_var_lib_t', tclass: 'dir', perms: ['add_name', 'write'] }).name === 'notesd_manage_var_lib_dirs'
  && d.newInterfaceText({ module: 'notesd', target: 'notesd_log_t', tclass: 'file', perms: ['write'] }).name === 'notesd_rw_log_files'
  && d.newInterfaceText({ module: 'syslogd', target: 'syslogd_t', tclass: 'unix_dgram_socket', perms: ['sendto'] }).name === 'syslogd_sendto_unix_dgram_sockets'
  && d.newInterfaceText({ module: 'notesd', target: 'notesd_log_t', tclass: 'file', perms: ['write'] }, n => n === 'notesd_rw_log_files').name === 'notesd_rw_log_files_2', 'names: manage / rw / a permission for other classes; taken names get a suffix');

/* ---------- writing the fix ---------- */

const TE = `policy_module(myd, 1.0.0)

type myd_t;
type myd_exec_t;
init_daemon_domain(myd_t, myd_exec_t)

type myd_data_t;
files_type(myd_data_t)

########################################
#
# myd local policy
#

allow myd_t self:process signal;
allow myd_t myd_data_t:file read_file_perms;

files_read_etc_files(myd_t)
logging_send_syslog_msg(myd_t)

optional_policy(\`
	apache_read_sys_content(myd_t)
')

optional_policy(\`
	dbus_system_bus_client(myd_t)
')
`;
const linesAfter = (r, n = 3) => r.text.split('\n').slice(r.line - 1, r.line + n).join('|');
let fx = d.insertFix(TE, { domain: 'myd_t', call: 'kernel_read_system_state(myd_t)', optional: false });
check(linesAfter(fx) === 'files_read_etc_files(myd_t)|kernel_read_system_state(myd_t)|logging_send_syslog_msg(myd_t)|', 'call inserted among the domain\'s calls in alphabetical order', linesAfter(fx));
check(fx.text.split('\n').length === TE.split('\n').length + 1, 'only one line added');
fx = d.insertFix(TE, { domain: 'myd_t', call: 'apache_search_sys_content(myd_t)', optional: true, module: 'apache' });
check(/apache_read_sys_content\(myd_t\)\n\tapache_search_sys_content\(myd_t\)\n'\)/.test(fx.text), 'optional call joins the module\'s existing optional_policy block');
fx = d.insertFix(TE, { domain: 'myd_t', call: 'cron_system_entry(myd_t)', optional: true, module: 'cron' });
check(/apache_read_sys_content\(myd_t\)\n'\)\n\noptional_policy\(`\n\tcron_system_entry\(myd_t\)\n'\)\n\noptional_policy\(`\n\tdbus/.test(fx.text), 'new optional block between apache and dbus, blank lines around it', fx.text.slice(-200));
fx = d.insertFix(TE, { domain: 'myd_t', call: 'abrt_stream_connect(myd_t)', optional: true, module: 'abrt' });
check(/logging_send_syslog_msg\(myd_t\)\n\noptional_policy\(`\n\tabrt_stream_connect\(myd_t\)\n'\)\n\noptional_policy\(`\n\tapache/.test(fx.text), 'new optional block before the first one');
fx = d.insertFix(TE, { domain: 'myd_t', call: 'zebra_read_config(myd_t)', optional: true, module: 'zebra' });
check(/dbus_system_bus_client\(myd_t\)\n'\)\n\noptional_policy\(`\n\tzebra_read_config\(myd_t\)\n'\)\n$/.test(fx.text), 'new optional block after the last one');
fx = d.insertFix(TE, { domain: 'myd_t', rule: 'allow myd_t myd_data_t:file { write };' });
check(linesAfter(fx, 1) === 'allow myd_t myd_data_t:file read_file_perms;|allow myd_t myd_data_t:file { write };', 'own rule after the domain\'s last allow rule');
check(d.insertFix(TE, { domain: 'myd_t', call: 'files_read_etc_files(myd_t)' }).already && d.insertFix(TE, { domain: 'myd_t', call: 'apache_read_sys_content(myd_t)', optional: true }).already, 'calls already there (top level or optional) are reported');
fx = d.insertFix(TE.replace(/\n/g, '\r\n'), { domain: 'myd_t', call: 'kernel_read_system_state(myd_t)' });
check(!/[^\r]\n/.test(fx.text), 'CRLF files stay CRLF');
const bare = 'policy_module(x, 1.0)\n\ntype x_t;\nallow x_t self:process signal;\n';
fx = d.insertFix(bare, { domain: 'x_t', call: 'files_read_etc_files(x_t)' });
check(fx.text === 'policy_module(x, 1.0)\n\ntype x_t;\nallow x_t self:process signal;\n\nfiles_read_etc_files(x_t)\n', 'module without calls or header: after its rules', fx.text);
const lm = d.localModuleText('local_httpd', 'httpd_t', 'files_rw_etc_files(httpd_t)');
check(/^policy_module\(local_httpd, 1\.0\.0\)/.test(lm) && /gen_require\(`\n\ttype httpd_t;\n'\)/.test(lm) && /\nfiles_rw_etc_files\(httpd_t\)\n$/.test(lm), 'local module: requires the domain, adds the call');

/* ---------- webview ---------- */

class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this._text = ''; this.checked = false; this.hidden = false; this.open = false; this.nodeType = 1; this.disabled = false; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set className(v) { this.attrs.class = v; } get className() { return this.attrs.class || ''; }
  append(...cs) { for (let c of cs) { if (typeof c === 'string') c = text(c); this.children.push(c); c.parent = this; } }
  replaceChildren(...cs) { this.children = []; this._text = ''; this.append(...cs); }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'open') this.open = true; }
  addEventListener(ev, f) { (this.listeners[ev] = this.listeners[ev] || []).push(f); }
  fire(ev) { for (const f of this.listeners[ev] || []) f({ target: this, currentTarget: this, preventDefault() {}, stopPropagation() {} }); }
  all(pred, out = []) { for (const c of this.children) { if (c.tag && pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
}
const text = (s) => ({ nodeType: 3, textContent: s });
const byId = {};
for (const id of ['list', 'status', 'against', 'log', 'analyze', 'host', 'since', 'openFile', 'title']) byId[id] = new El(id);
const posted = [];
const winListeners = [];
const wctx = {
  setTimeout, clearTimeout,
  acquireVsCodeApi: () => ({ postMessage: (m) => posted.push(JSON.parse(JSON.stringify(m))), getState: () => null, setState: () => {} }),
  document: { getElementById: (id) => byId[id], createElement: (tag) => new El(tag), createTextNode: text },
  window: { addEventListener: (ev, f) => winListeners.push(f) },
};
vm.createContext(wctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/denials.js'), 'utf8'), wctx);
const send = (data) => winListeners.forEach(f => f({ data }));
const last = (cmd) => [...posted].reverse().find(m => m.cmd === cmd);
const find = (pred) => byId.list.all(pred);

check(posted[0] && posted[0].cmd === 'ready', 'webview asks for data when loaded');
send({ cmd: 'policies', policies: [{ id: 'installed:targeted', label: 'Installed targeted policy (running here)', active: true }, { id: 'build', label: 'Last build of rhel9', build: true }] });
check(byId.against.children.length === 2 && byId.against.value === 'installed:targeted', 'policy picker filled, running policy selected');
byId.log.value = RAW; byId.analyze.fire('click');
check(last('analyze') && last('analyze').text === RAW && last('analyze').against === 'installed:targeted', 'Analyze sends the log and the policy');
const result = {
  policy: { id: 'installed:targeted', label: 'Installed targeted policy' }, count: 3, notes: ['1 line could not be read.'],
  groups: [
    { key: 'a', kind: 'deny', source: 'httpd_t', target: 'user_home_t', tclass: 'file', perms: ['read', 'open'], count: 2, comms: ['httpd'], exes: ['/usr/sbin/httpd'], paths: ['/var/www/html/index.html'], labels: [{ path: '/var/www/html/index.html', expected: 'httpd_sys_content_t', current: 'user_home_t' }],
      srcLoc: { p: '/t/apache.te', l: 3, c: 5, m: 'apache' }, tgtLoc: null, first: 1728650000000, last: 1728650001500,
      v: { verdict: 'label', title: 'Wrong label', detail: 'The file has a different label.\n/var/www/html/index.html: …', fixes: [{ text: 'Relabel it', command: 'restorecon -v /var/www/html/index.html' }], notes: [] } },
    { key: 'b', kind: 'deny', source: 'httpd_t', target: 'http_cache_port_t', tclass: 'tcp_socket', perms: ['name_connect'], count: 1, comms: ['httpd'], exes: [], paths: [], labels: [], permissive: true,
      v: { verdict: 'boolean', title: 'Allowed under a boolean that is off', detail: '…', fixes: [{ text: 'Set it', command: 'setsebool -P httpd_can_network_relay on' }], rules: [{ rt: 'allow', s: 'httpd_t', t: 'http_cache_port_t', c: 'tcp_socket', perms: ['name_connect'], cond: 'httpd_can_network_relay:true' }], notes: ['Logged in permissive mode.'] } },
    { key: 'c', kind: 'deny', source: 'myd_t', target: 'etc_t', tclass: 'file', perms: ['write'], count: 1, comms: [], exes: [], paths: [], labels: [],
      v: { verdict: 'missing', title: 'Missing rule', detail: '…', fixes: [], needed: 'allow myd_t etc_t:file { write };', notes: [] },
      suggest: { list: [
        { name: 'files_rw_etc_files', module: 'files', owner: true, covers: true, missing: [], extra: 16, grants: ['etc_t dir: search getattr open'], attrs: [], summary: 'Read and write generic files in /etc.', loc: { p: '/t/files.if', l: 9, c: 0 } },
        { name: 'files_manage_config_files', module: 'files', owner: true, covers: true, missing: [], extra: 6579, broad: true, grants: ['configfile (300 types) file: create unlink write'], attrs: [], summary: '', loc: { p: '/t/files.if', l: 99, c: 0 } }] } },
    { key: 'd', kind: 'deny', source: 'myd_t', target: 'myd_data_t', tclass: 'file', perms: ['write'], count: 1, comms: [], exes: [], paths: [], labels: [],
      v: { verdict: 'missing', title: 'Missing rule', detail: '…', fixes: [], needed: 'allow myd_t myd_data_t:file { write };', notes: [] },
      suggest: { own: true, module: 'myd', rule: 'allow myd_t myd_data_t:file { write };' } },
  ],
};
send({ cmd: 'result', result });
const cards = find(e => (e.attrs.class || '').split(' ').includes('group'));
check(cards.length === 4, `one card per group: ${cards.length}`);
check(/Wrong label/.test(cards[0].textContent) && /httpd_t/.test(cards[0].textContent) && /2×/.test(cards[0].textContent), 'card header: verdict, types, count');
check(/1 line could not be read/.test(byId.list.textContent), 'notes shown');
check(/3 denials in 4 groups/.test(byId.status.textContent), `status: ${byId.status.textContent}`);
const btn = (card, t) => card.all(e => e.tag === 'button' && e.textContent === t)[0];
btn(cards[0], 'Send to terminal').fire('click');
check(last('run') && last('run').command === 'sudo restorecon -v /var/www/html/index.html', 'fix sent to the terminal with sudo');
btn(cards[1], 'Copy').fire('click');
check(last('copy') && last('copy').text === 'setsebool -P httpd_can_network_relay on', 'fix copied');
check(/when httpd_can_network_relay]/.test(cards[1].textContent) && /permissive/.test(cards[1].textContent), 'allowing rule with its condition, notes');
check(/allow myd_t etc_t:file \{ write \};/.test(cards[2].textContent), 'missing rule: needed access shown');
const ifaces = cards[2].all(e => e.attrs.class === 'iface');
check(ifaces.length === 2 && /narrowest/.test(ifaces[0].textContent) && /owner/.test(ifaces[0].textContent) && /broad/.test(ifaces[1].textContent) && /configfile \(300 types\)/.test(ifaces[1].textContent), 'suggested interfaces: narrowest, owner, broad, what else they grant');
btn(ifaces[0], 'files_rw_etc_files(myd_t)').fire('click');
check(last('open') && last('open').loc.p === '/t/files.if', 'interface opens its definition');
btn(ifaces[0], 'Copy').fire('click');
check(last('copy').text === 'files_rw_etc_files(myd_t)', 'interface call copied');
// Add to module: plan, apply, verify against the build.
btn(ifaces[0], 'Add to module…').fire('click');
check(last('fix') && last('fix').call === 'files_rw_etc_files(myd_t)' && last('fix').domain === 'myd_t' && last('fix').key === 'c', 'Add to module asks for a plan');
send({ cmd: 'fixPlan', key: 'c', plan: { path: '/t/myd.te', exists: true, line: 20, inserted: ['files_rw_etc_files(myd_t)'], optional: false, text: 'x' } });
let card3 = () => find(e => (e.attrs.class || '').split(' ').includes('group'))[2];
check(/Adds to \/t\/myd\.te at line 21/.test(card3().textContent) && /files_rw_etc_files\(myd_t\)/.test(card3().all(e => e.tag === 'pre')[0].textContent), 'the plan shows the file, line and inserted text');
btn(card3(), 'Apply').fire('click');
check(last('applyFix') && last('applyFix').plan.path === '/t/myd.te', 'Apply sends the plan');
send({ cmd: 'applied', key: 'c', path: '/t/myd.te' });
check(/Checking it against your build/.test(card3().textContent), 'applied: waiting for the build');
const nAnalyze = posted.filter(m => m.cmd === 'analyze').length;
send({ cmd: 'built', ok: true });
check(posted.filter(m => m.cmd === 'analyze').length === nAnalyze + 1 && last('analyze').against === 'build', 'after the build: analyzed again against the build');
send({ cmd: 'result', result: { ...result, policy: { id: 'build', label: 'Last build of t' }, groups: result.groups.map(g => (g.key === 'c' ? { ...g, v: { ...g.v, verdict: 'allowed', title: 'Already allowed' }, suggest: null } : g)) } });
check(/Resolved: your build now allows this \(Last build of t\)/.test(card3().textContent), 'resolved by the build');
btn(cards[3] || find(e => (e.attrs.class || '').split(' ').includes('group'))[3], 'Add to module…').fire('click');
check(last('fix').rule === 'allow myd_t myd_data_t:file { write };', 'own rule: Add to module sends the rule');
send({ cmd: 'fixPlan', key: 'd', plan: { already: true, message: 'myd.te already has it' } });
check(/already has it/.test(find(e => (e.attrs.class || '').split(' ').includes('group'))[3].textContent), 'already there: said so');
send({ cmd: 'fixPlan', key: 'd', plan: { path: '/t/myd.te', exists: true, line: 3, inserted: ['allow myd_t myd_data_t:file { write };'], text: 'y' } });
send({ cmd: 'applied', key: 'd', path: '/t/myd.te' });
send({ cmd: 'built', ok: false });
check(/The build failed/.test(find(e => (e.attrs.class || '').split(' ').includes('group'))[3].textContent), 'failed build reported on the fix');
check(/a rule in module myd/.test(find(e => (e.attrs.class || '').split(' ').includes('group'))[3].textContent) && /allow myd_t myd_data_t:file/.test(cards[3].textContent), "own types: a rule in the domain's module");
btn(cards[0], 'httpd_t').fire('click');
check(last('open') && last('open').loc.p === '/t/apache.te', 'type links open the declaration');
check(!btn(cards[0], 'user_home_t'), 'no link for a type without a source location');
byId.host.fire('click');
check(last('ausearch') && last('ausearch').since === byId.since.value, 'Read from this host asks for ausearch');
byId.openFile.fire('click');
check(last('openFile'), 'Open log file');
byId.against.value = 'build'; byId.against.fire('change');
check(last('analyze').against === 'build', 'changing the policy analyzes again');
send({ cmd: 'log', text: 'x avc:  denied', source: 'this host' });
check(byId.log.value === 'x avc:  denied' && last('analyze').text === 'x avc:  denied', 'a log from the host fills the box and is analyzed');
const untitled = [byId.analyze, byId.host, byId.openFile, byId.against, byId.since].filter(e => !e.attrs.title).map(e => e.tag);
check(!untitled.length, 'every control has hover help', untitled);

// Phase 4 cards: no policy for a program (New Service…), a constraint, pairs, a new interface.
send({ cmd: 'result', result: { policy: { id: 'build', label: 'Last build' }, count: 4, notes: [], groups: [
  { key: 'p1', kind: 'deny', source: 'unconfined_service_t', target: 'etc_t', tclass: 'file', perms: ['write'], count: 1, comms: [], exes: ['/opt/x/run'], paths: [], labels: [],
    v: { verdict: 'transition', title: 'No policy for this program', detail: '…', fixes: [{ text: 'Create a service policy for this program', action: { cmd: 'newService', exec: '/opt/x/run' } }], notes: [] } },
  { key: 'p2', kind: 'deny', source: 'svirt_t', target: 'svirt_image_t', tclass: 'file', perms: ['read'], count: 1, comms: [], exes: [], paths: [], labels: [],
    v: { verdict: 'constraint', title: 'Denied by MCS/MLS levels', detail: 'h1 dom h2 …', fixes: [{ text: 'Give the file the categories', command: 'chcon -l s0:c1,c2 /x' }], notes: [] } },
  { key: 'p3', kind: 'deny', source: 'myd_t', target: 'x_t', tclass: 'file', perms: ['read', 'write'], count: 1, comms: [], exes: [], paths: [], labels: [],
    v: { verdict: 'missing', title: 'Missing rule', detail: '…', fixes: [], needed: 'allow myd_t x_t:file { read write };', notes: [] },
    suggest: { list: [], partial: true, combos: [{ items: [{ name: 'a_read', grants: [], loc: { p: '/t/a.if', l: 1, c: 0 } }, { name: 'b_write', grants: ['x_t file: write'], loc: { p: '/t/b.if', l: 2, c: 0 } }], extra: 3 }] } },
  { key: 'p4', kind: 'deny', source: 'httpd_t', target: 'ntpd_extra_t', tclass: 'file', perms: ['read'], count: 1, comms: [], exes: [], paths: [], labels: [],
    v: { verdict: 'missing', title: 'Missing rule', detail: '…', fixes: [], needed: 'allow httpd_t ntpd_extra_t:file { read };', notes: [] },
    suggest: { list: [], note: 'No interface mentions ntpd_extra_t.', newIface: { module: 'ntp', name: 'ntp_read_ntpd_extra_files', summary: 'Read ntpd extra files (ntpd_extra_t).', call: 'ntp_read_ntpd_extra_files(httpd_t)', ifPath: '/t/ntp.if', rule: 'allow httpd_t ntpd_extra_t:file { read };' } } },
] } });
const pc = find(e => (e.attrs.class || '').split(' ').includes('group'));
check(pc.length === 4 && /DOMAIN|domain/.test(pc[0].textContent) && /constraint/i.test(pc[1].textContent), 'transition and constraint cards with their badges');
btn(pc[0], 'New Service…').fire('click');
check(last('newService') && last('newService').exec === '/opt/x/run', 'No policy for this program: New Service… for the program');
check(/Together they cover it/.test(pc[2].textContent) && /narrowest pair/.test(pc[2].textContent), 'pairs listed when no single interface covers it');
btn(pc[2], 'Add to module…').fire('click');
check(last('fix').calls && last('fix').calls.join() === 'a_read(myd_t),b_write(myd_t)', 'Add to module for a pair sends both calls');
check(/a new interface in ntp/.test(pc[3].textContent) && /ntp_read_ntpd_extra_files\(httpd_t\)/.test(pc[3].textContent), 'nothing grants it: a new interface in the owner module');
btn(pc[3], 'Add to module…').fire('click');
check(last('fix').newInterface && last('fix').newInterface.target === 'ntpd_extra_t' && last('fix').newInterface.perms.join() === 'read', 'Add to module for a new interface sends what it must grant');
send({ cmd: 'fixPlan', key: 'p4', plan: { path: '/t/apache.te', exists: true, line: 9, inserted: ['optional_policy(`', '\tntp_read_ntpd_extra_files(httpd_t)', "')"], optional: true, text: 'x',
  also: [{ path: '/t/ntp.if', exists: true, line: 40, inserted: ['interface(`ntp_read_ntpd_extra_files\',`'], what: 'new interface ntp_read_ntpd_extra_files' }] } });
const p4 = find(e => (e.attrs.class || '').split(' ').includes('group'))[3];
check(/\/t\/ntp\.if/.test(p4.textContent) && /new interface ntp_read_ntpd_extra_files/.test(p4.textContent) && /and adds to/.test(p4.textContent) && /\/t\/apache\.te/.test(p4.textContent), 'the plan shows both files');

// Login programs' own refusals (no audit record): parsed from journal / secure lines, not from audit records.
const refs = d.loginRefusals([
  'Oct 26 10:01:02 ricardo sshd[4242]: pam_selinux(sshd:session): Unable to get valid context for rouser',
  'Oct 26 10:01:09 ricardo sshd[4250]: pam_selinux(sshd:session): Unable to get valid context for rouser',
  'Oct 26 10:02:00 ricardo sshd[99]: error: ssh_selinux_getctxbyname: Failed to get default SELinux security context for bob (in enforcing mode)',
  'Oct 26 10:03:00 ricardo crond[77]: (carol) ERROR (failed to change SELinux context)',
  'Oct 26 10:04:00 ricardo login[5]: pam_selinux(login:session): Unable to get valid context for dave',
  'Oct 26 10:05:00 ricardo systemd[1]: pam_selinux(systemd-user:session): Unable to get valid context for erin',
  'type=USER_AVC msg=audit(1729000000.1:5): pid=1 msg=\'pam_selinux(sshd:session): Unable to get valid context for nobody\'',
].join('\n'));
const R = (login) => refs.find(x => x.login === login) || {};
check(refs.length === 5 && R('rouser').count === 2 && R('rouser').source === 'sshd_t' && R('bob').source === 'sshd_t' && R('carol').source === 'crond_t' && R('dave').source === 'local_login_t' && R('erin').source === 'init_t' && !R('nobody').login,
  'login refusals: pam_selinux, sshd and crond messages, by login program and login (audit records left to the AVC parser)', refs);
send({ cmd: 'result', result: { policy: { id: 'build', label: 'Last build' }, count: 0, notes: [], groups: [],
  refusals: [{ ...R('rouser'), mapped: { login: 'rouser', user: 'ro_u', l: 2 }, problems: [{ kind: 'nocontext2', severity: 'error', text: 'rouser (ro_u) can\'t log in by ssh on RHEL 8 …', file: '/t/config/appconfig-mcs/seusers', l: 2 }] }] } });
check(/1 login refusal/.test(byId.status.textContent), 'status counts login refusals when there are no denials', byId.status.textContent);
const rc = find(e => (e.attrs.class || '').split(' ').includes('group'))[0];
check(rc && /no audit record/.test(rc.textContent) && /sshd found no valid context for rouser/.test(rc.textContent) && /×2/.test(rc.textContent) && /can't log in by ssh on RHEL 8/.test(rc.textContent) && /seusers:3/.test(rc.textContent),
  'a refusal card: no audit record, what the login check finds for that login, its seusers line', rc && rc.textContent);
btn(rc, 'Open Check Login Contexts').fire('click');
check(last('command') && last('command').id === 'selinux.checkLoginContexts', 'the card opens Check Login Contexts');

console.log(failures ? `\n${failures} check(s) failed` : '\nall denial checks passed');
process.exit(failures ? 1 : 0);
