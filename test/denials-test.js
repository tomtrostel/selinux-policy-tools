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
      v: { verdict: 'missing', title: 'Missing rule', detail: '…', fixes: [], needed: 'allow myd_t etc_t:file { write };', notes: [] } },
  ],
};
send({ cmd: 'result', result });
const cards = find(e => (e.attrs.class || '').split(' ').includes('group'));
check(cards.length === 3, `one card per group: ${cards.length}`);
check(/Wrong label/.test(cards[0].textContent) && /httpd_t/.test(cards[0].textContent) && /2×/.test(cards[0].textContent), 'card header: verdict, types, count');
check(/1 line could not be read/.test(byId.list.textContent), 'notes shown');
check(/3 denials in 3 groups/.test(byId.status.textContent), `status: ${byId.status.textContent}`);
const btn = (card, t) => card.all(e => e.tag === 'button' && e.textContent === t)[0];
btn(cards[0], 'Send to terminal').fire('click');
check(last('run') && last('run').command === 'sudo restorecon -v /var/www/html/index.html', 'fix sent to the terminal with sudo');
btn(cards[1], 'Copy').fire('click');
check(last('copy') && last('copy').text === 'setsebool -P httpd_can_network_relay on', 'fix copied');
check(/when httpd_can_network_relay]/.test(cards[1].textContent) && /permissive/.test(cards[1].textContent), 'allowing rule with its condition, notes');
check(/allow myd_t etc_t:file \{ write \};/.test(cards[2].textContent), 'missing rule: needed access shown');
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

console.log(failures ? `\n${failures} check(s) failed` : '\nall denial checks passed');
process.exit(failures ? 1 : 0);
