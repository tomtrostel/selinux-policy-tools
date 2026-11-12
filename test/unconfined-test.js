// What runs unconfined on a host (server/unconfined.js): the parsers over real
// command output, the rows and verdicts, what init_t gets per label, and the
// Unconfined Programs webview against a fake DOM. Any OS, in npm test.
const U = require('../server/unconfined');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

// 1. Parsers, on output sampled from a Rocky 9 host.
const PS = [
  '      1       0 root     system_u:system_r:init_t:s0     systemd         /usr/lib/systemd/systemd --switched-root --system --deserialize 31 rhgb',
  '      2       0 root     system_u:system_r:kernel_t:s0   kthreadd        [kthreadd]',
  '    988       1 chrony   system_u:system_r:chronyd_t:s0  chronyd         /usr/sbin/chronyd -F 2',
  '   1150       1 root     system_u:system_r:sshd_t:s0     sshd            sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups',
  '   1201       1 root     system_u:system_r:unconfined_service_t:s0 agent  /opt/vendor/agent --daemon',
  '   1300    1150 ttrostel unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 bash -bash',
  '   1400       1 pcp      system_u:system_r:pcp_pmcd_t:s0 pmcd            /usr/libexec/pcp/bin/pmcd --foreground',
  '   1500       1 root     -                               noctx           /usr/sbin/noctx',
].join('\n');
const ps = U.parsePs(PS);
check(ps.length === 7 && !ps.some(p => p.comm === 'kthreadd'), 'parsePs: kernel threads left out', ps.map(p => p.comm));
const sshd = ps.find(p => p.pid === 1150);
check(sshd && sshd.ppid === 1 && sshd.user === 'root' && sshd.type === 'sshd_t' && sshd.argv0 === 'sshd:' && ps.find(p => p.pid === 988).argv0 === '/usr/sbin/chronyd' && ps.find(p => p.pid === 1300).type === 'unconfined_t' && ps.find(p => p.pid === 1500).type === null,
  'parsePs: pid, ppid, user, type from the label, argv0 (sshd rewrites its argv; a "-" label is none)', sshd);

const UNITS = [
  'MainPID=1150', 'ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $OPTIONS ; ignore_errors=no ; start_time=[Sat 2026-11-07 06:48:23 EST] ; stop_time=[n/a] ; pid=1150 ; code=(null) ; status=0/0 }',
  'User=', 'NoNewPrivileges=no', 'Id=sshd.service', 'ActiveState=active', 'SubState=running', 'FragmentPath=/usr/lib/systemd/system/sshd.service', '',
  'MainPID=0', 'ExecStart={ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 } ; { path=/opt/vendor/agent ; argv[]=/opt/vendor/agent --daemon ; ignore_errors=no }',
  'User=vendor', 'NoNewPrivileges=yes', 'Id=vendor-agent.service', 'ActiveState=inactive', 'SubState=dead', 'FragmentPath=/etc/systemd/system/vendor-agent.service', '',
  'MainPID=0', 'ExecStart=', 'User=', 'NoNewPrivileges=no', 'Id=systemd-oomd.service', 'ActiveState=inactive', 'SubState=dead', 'FragmentPath=/usr/lib/systemd/system/systemd-oomd.service', '',
].join('\n');
const units = U.parseUnits(UNITS);
check(units.length === 3 && units[0].id === 'sshd.service' && units[0].exec.join() === '/usr/sbin/sshd' && units[0].mainPid === 1150 && units[0].active === 'active' && units[0].sub === 'running' && !units[0].nnp,
  'parseUnits: blocks → id, ExecStart path, MainPID, states', units[0]);
check(units[1].exec.join() === '/usr/bin/true,/opt/vendor/agent' && units[1].user === 'vendor' && units[1].nnp && units[2].exec.length === 0, 'parseUnits: several ExecStart commands, User=, NoNewPrivileges, none', units.slice(1));

const SS = [
  'udp UNCONN 0      0      127.0.0.1:323  0.0.0.0:*',
  'tcp LISTEN 0      128      0.0.0.0:22   0.0.0.0:*    users:(("sshd",pid=1150,fd=3))',
  'tcp LISTEN 0      128         [::]:22      [::]:*    users:(("sshd",pid=1150,fd=4))',
  'tcp LISTEN 0      4096   127.0.0.1:44321 0.0.0.0:*   users:(("pmcd",pid=1400,fd=0),("pmcd",pid=1401,fd=0))',
].join('\n');
const ss = U.parseSs(SS);
check(ss.length === 4 && ss[0].proto === 'udp' && ss[0].port === 323 && !ss[0].pids.length && ss[1].pids.join() === '1150' && ss[2].addr === '::' && ss[3].pids.join() === '1400,1401',
  'parseSs: proto, address, port, pids (several, or none without root)', ss);

// 2. What init_t gets per label.
const startsAs = U.startsAsFrom([
  { target: 'sshd_t', entrypoints: ['sshd_exec_t'], auto: ['sshd_exec_t'] },
  { target: 'chronyd_t', entrypoints: ['chronyd_exec_t'], auto: ['chronyd_exec_t'] },
  { target: 'unconfined_service_t', entrypoints: ['bin_t', 'usr_t'], auto: ['bin_t'] },
  { target: 'pcp_pmcd_t', entrypoints: ['pcp_pmcd_exec_t'], auto: [] },
], (t) => ({ shell_exec_t: { execute: true, noTrans: true }, usr_t: { execute: true, noTrans: true }, odd_exec_t: { execute: false, noTrans: false } })[t] || null);
check(startsAs('sshd_exec_t').domain === 'sshd_t' && startsAs('sshd_exec_t').how === 'auto' && startsAs('bin_t').domain === 'unconfined_service_t', 'startsAs: a type_transition from init_t');
check(startsAs('shell_exec_t').domain === 'init_t' && startsAs('shell_exec_t').how === 'stays' && startsAs('usr_t').how === 'stays', 'startsAs: execute_no_trans → stays init_t (an entrypoint without a type_transition too)');
check(startsAs('pcp_pmcd_exec_t').domain === null && startsAs('pcp_pmcd_exec_t').how === 'manual' && startsAs('pcp_pmcd_exec_t').manual === 'pcp_pmcd_t', 'startsAs: an entrypoint only setexec reaches');
check(startsAs('odd_exec_t').how === 'none' && startsAs('nolabel_t').how === 'none', 'startsAs: init_t can\'t run it at all');

// 3. Rows and verdicts (the running targeted policy: unconfined_service_t confines nothing).
const LABELS = { '/usr/sbin/sshd': 'sshd_exec_t', '/usr/sbin/chronyd': 'chronyd_exec_t', '/opt/vendor/agent': 'bin_t', '/usr/bin/true': 'bin_t', '/usr/libexec/pcp/bin/pmcd': 'pcp_pmcd_exec_t', '/usr/sbin/noctx': 'bin_t' };
const facts = {
  processes: ps, units, sockets: ss,
  labelOf: (p) => LABELS[p] || null,
  startsAs,
  unconfined: new Set(['unconfined_service_t', 'unconfined_t', 'initrc_t', 'init_t', 'kernel_t']),
  exists: (p) => p !== '/opt/vendor/agent',
  realpath: (p) => (p === '/usr/sbin/sshd' ? '/usr/sbin/sshd' : p),
  pkgOf: (p) => ({ '/usr/sbin/sshd': 'openssh-server', '/usr/sbin/chronyd': 'chrony', '/usr/bin/true': 'coreutils' })[p] || null,
};
const r = U.assemble(facts);
const by = Object.fromEntries(r.rows.map(x => [x.real, x]));
check(r.rows.length === 6 && !by['/usr/lib/systemd/systemd'] && !by['-bash'], `assemble: ${r.rows.length} programs (systemd itself and the login shell left out)`, r.rows.map(x => x.real));
check(by['/usr/sbin/sshd'] && by['/usr/sbin/sshd'].verdict === 'confined' && by['/usr/sbin/sshd'].hostDomains.join() === 'sshd_t' && by['/usr/sbin/sshd'].policyDomain === 'sshd_t' && by['/usr/sbin/sshd'].units[0].id === 'sshd.service' && by['/usr/sbin/sshd'].pkg === 'openssh-server'
  && by['/usr/sbin/sshd'].listens.map(l => `${l.proto} ${l.port}`).join() === 'tcp 22' && by['/usr/sbin/sshd'].running && !by['/usr/sbin/sshd'].differs,
  'sshd: confined, sshd.service, openssh-server, tcp 22 (two sockets, one port)', by['/usr/sbin/sshd']);
check(by['/opt/vendor/agent'] && by['/opt/vendor/agent'].verdict === 'unconfined' && by['/opt/vendor/agent'].generic && by['/opt/vendor/agent'].hostDomains.join() === 'unconfined_service_t' && by['/opt/vendor/agent'].policyDomain === 'unconfined_service_t'
  && by['/opt/vendor/agent'].units[0].id === 'vendor-agent.service' && by['/opt/vendor/agent'].units[0].nnp && by['/opt/vendor/agent'].pids.join() === '1201' && !by['/opt/vendor/agent'].exists,
  'the vendor agent: unconfined (bin_t, generic), its unit (inactive now, NoNewPrivileges) and its process matched', by['/opt/vendor/agent']);
check(by['/usr/bin/true'] && by['/usr/bin/true'].verdict === 'unconfined' && !by['/usr/bin/true'].running && by['/usr/bin/true'].policyDomain === 'unconfined_service_t', '/usr/bin/true from the same unit: would run unconfined, not running');
check(by['/usr/sbin/chronyd'] && by['/usr/sbin/chronyd'].verdict === 'confined' && by['/usr/sbin/chronyd'].units.length === 0 && by['/usr/sbin/chronyd'].users.join() === 'chrony', 'chronyd: a process systemd started with no unit listed, confined');
check(by['/usr/libexec/pcp/bin/pmcd'] && by['/usr/libexec/pcp/bin/pmcd'].verdict === 'confined' && by['/usr/libexec/pcp/bin/pmcd'].how === 'manual' && by['/usr/libexec/pcp/bin/pmcd'].listens[0].port === 44321, 'pmcd: confined here (the host says pcp_pmcd_t), the policy only via setexec; its port');
check(by['/usr/sbin/noctx'] && by['/usr/sbin/noctx'].verdict === 'unconfined' && by['/usr/sbin/noctx'].hostDomains.length === 0 && by['/usr/sbin/noctx'].policyDomain === 'unconfined_service_t', 'a process without a label (ps -): judged by the policy');
check(r.rows[0].verdict === 'unconfined' && r.rows.findIndex(x => x.verdict === 'confined') > r.rows.filter(x => x.verdict === 'unconfined').length - 1 && r.summary.unconfined === 3 && r.summary.confined === 3 && r.summary.listening === 0 && r.summary.notRunning === 1,
  'order: unconfined first; summary', r.summary);
check(r.unconfined.join() === 'init_t,initrc_t,kernel_t,unconfined_service_t,unconfined_t', 'the domains that confine nothing, listed');

// A lockdown policy (CLIP: no unconfined domains, no chronyd module): sshd confined, chronyd can't start, the agent would stay in init_t.
const clipStarts = U.startsAsFrom([{ target: 'sshd_t', entrypoints: ['sshd_exec_t'], auto: ['sshd_exec_t'] }], (t) => (t === 'bin_t' ? { execute: true, noTrans: true } : { execute: false, noTrans: false }));
const r2 = U.assemble({ ...facts, startsAs: clipStarts, unconfined: new Set(['init_t', 'initrc_t', 'kernel_t']), labelOf: (p) => ({ ...LABELS, '/usr/sbin/chronyd': 'bin_t', '/opt/vendor/agent': 'odd_t' })[p] || null });
const by2 = Object.fromEntries(r2.rows.map(x => [x.real, x]));
check(by2['/usr/sbin/sshd'].verdict === 'confined' && by2['/usr/sbin/chronyd'].verdict === 'confined' && by2['/usr/sbin/chronyd'].policyDomain === 'init_t' && by2['/usr/sbin/chronyd'].differs && by2['/usr/sbin/chronyd'].hostDomains.join() === 'chronyd_t',
  'another policy: chronyd (bin_t there) would stay in init_t; found as a process, not a unit, it keeps the host\'s domain for the verdict and shows the difference', by2['/usr/sbin/chronyd']);
check(by2['/opt/vendor/agent'].verdict === 'nostart' && by2['/opt/vendor/agent'].how === 'none' && by2['/opt/vendor/agent'].differs && by2['/usr/libexec/pcp/bin/pmcd'].verdict === 'confined' && by2['/usr/libexec/pcp/bin/pmcd'].differs && by2['/usr/libexec/pcp/bin/pmcd'].how === 'none' && r2.summary.nostart === 1,
  'a label init_t may not run at all: the policy can\'t start the agent (a unit); pmcd, a process on its own, keeps its verdict with the difference shown', { agent: by2['/opt/vendor/agent'], pmcd: by2['/usr/libexec/pcp/bin/pmcd'], summary: r2.summary });
// A user's session processes are not services: a system_u check.
const r3 = U.assemble({ ...facts, processes: [...ps, { pid: 4058, ppid: 1, user: 'alice', ctx: 'unconfined_u:unconfined_r:unconfined_t:s0', seuser: 'unconfined_u', type: 'unconfined_t', comm: 'pipewire', args: '/usr/bin/pipewire', argv0: '/usr/bin/pipewire' }],
  units: [...units, { id: 'user@1000.service', exec: ['/usr/lib/systemd/systemd'], mainPid: 0, active: 'active', sub: 'running', user: '', nnp: false }] });
check(!r3.rows.some(x => x.real === '/usr/bin/pipewire') && !r3.rows.some(x => x.real === '/usr/lib/systemd/systemd') && r3.rows.length === r.rows.length, 'a login\'s pipewire (unconfined_u) and user@1000.service are left out: sessions, not services', r3.rows.map(x => x.real));
// ExecStart with a bare program name (systemd's PATH): resolved, or left out when not found.
const r4 = U.assemble({ ...facts, units: [...units, { id: 'systemd-boot-update.service', exec: ['bootctl'], mainPid: 0, active: 'active', sub: 'exited', user: '', nnp: false }, { id: 'odd.service', exec: ['nosuchprog'], mainPid: 0, active: 'inactive', sub: 'dead', user: '', nnp: false }],
  which: (n) => (n === 'bootctl' ? '/usr/bin/bootctl' : null) });
check(r4.rows.some(x => x.real === '/usr/bin/bootctl' && x.units[0].id === 'systemd-boot-update.service') && !r4.rows.some(x => !x.real.startsWith('/')), 'ExecStart=bootctl: resolved on PATH; an unknown name is left out', r4.rows.map(x => x.real));

// 4. The webview.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this._text = ''; this.nodeType = 1; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set className(v) { this.attrs.class = v; } get className() { return this.attrs.class || ''; }
  append(...cs) { for (let c of cs) { if (typeof c === 'string') c = { nodeType: 3, textContent: c }; this.children.push(c); } }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'value') this.value = String(v); }
  addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
  fire(ev) { for (const fn of this.listeners[ev] || []) fn({ target: this }); }
  all(pred, out = []) { for (const c of this.children) { if (c.tag && pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
}
const byId = {};
for (const id of ['main', 'status', 'against', 'refresh']) byId[id] = new El(id);
const posted = [], winListeners = [];
const wctx = {
  acquireVsCodeApi: () => ({ postMessage: (msg) => posted.push(JSON.parse(JSON.stringify(msg))) }),
  document: { getElementById: (id) => byId[id], createElement: (tag) => new El(tag), createTextNode: (s) => ({ nodeType: 3, textContent: s }) },
  window: { addEventListener: (ev, fn) => winListeners.push(fn) },
};
vm.createContext(wctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/unconfined.js'), 'utf8'), wctx);
const send = (data) => winListeners.forEach(fn => fn({ data }));
check(posted[0] && posted[0].cmd === 'load' && /Looking at this host/.test(byId.status.textContent), 'webview: asks at once');
const policies = [{ id: 'installed:targeted', label: 'Installed targeted policy (running here)', active: true }, { id: 'build', label: 'Last build of clip', build: true }];
send({ cmd: 'result', key: posted[0].key, result: { ...r, policies, policy: policies[0], locs: { sshd_t: { p: '/src/ssh.te', l: 10, c: 5 } }, host: { hostname: 'melody', processes: 7, units: 3, limits: ['Listening ports are known only for root'] } } });
let page = byId.main.textContent;
check(/3 programs run unconfined/.test(page) && /3 confined programs/.test(page) && /melody: 3 services, 7 processes/.test(page) && /Installed targeted policy/.test(page), 'webview: the verdict line', page.slice(0, 600));
check(/Run unconfined/.test(page) && /\/opt\/vendor\/agent/.test(page) && /vendor-agent\.service \(inactive\)/.test(page) && /generic/.test(page) && /openssh-server/.test(page) && /tcp 22/.test(page), 'webview: the groups, units with state, generic labels, packages, ports', page.slice(0, 1500));
check(/Listening ports are known only for root/.test(page) && /confine nothing in this policy: init_t, initrc_t/.test(page), 'webview: the host\'s limits and the unconfined set');
const ns = byId.main.all(e => e.tag === 'button' && e.textContent === 'New Service…');
ns[0].fire('click');
check(ns.length === 6 && posted[posted.length - 1].cmd === 'newService' && posted[posted.length - 1].exec === r.rows[0].real, 'webview: New Service… opens the editor with the program (the first row: an unconfined one)', posted[posted.length - 1]);
byId.main.all(e => e.tag === 'button' && e.textContent === '/usr/sbin/sshd')[0].fire('click');
check(posted[posted.length - 1].cmd === 'lookUp' && posted[posted.length - 1].path === '/usr/sbin/sshd', 'webview: the program name looks it up in File Labels');
byId.main.all(e => e.tag === 'button' && e.textContent === 'sshd_t')[0].fire('click');
check(posted[posted.length - 1].cmd === 'open' && posted[posted.length - 1].loc.p === '/src/ssh.te', 'webview: a domain with a known declaration opens it');
const input = byId.main.all(e => e.tag === 'input')[0];
input.value = 'chrony';
input.fire('input');
page = byId.main.textContent;
check(/1 of 3/.test(page) && /chronyd/.test(page) && !/\/usr\/sbin\/sshd/.test(page), 'webview: the filter narrows every group', page.slice(0, 800));
input.value = '';
input.fire('input');
check(/3 of 3|Run unconfined3These/.test(byId.main.textContent) || /\/usr\/sbin\/sshd/.test(byId.main.textContent), 'webview: clearing the filter shows every row again');
send({ cmd: 'built', ok: true });
check(posted[posted.length - 1].cmd !== 'load', 'webview: a build does not reload while an installed policy is shown');
byId.against.value = 'build';
byId.against.fire('change');
check(posted[posted.length - 1].cmd === 'load' && posted[posted.length - 1].against === 'build', 'webview: picking the build asks again');
send({ cmd: 'result', key: posted[posted.length - 1].key, result: { ...r2, policies, policy: policies[1], locs: {}, host: { hostname: 'melody', processes: 7, units: 3, limits: [] } } });
page = byId.main.textContent;
check(/The policy can't start them/.test(page) && /can't start it/.test(page) && /policy: init_t/.test(page), 'webview: the build: a program it can\'t start, one that would stay in init_t', page.slice(0, 1200));
send({ cmd: 'error', text: 'boom' });
check(/boom/.test(byId.main.textContent), 'webview: an error is shown');

console.log(failures ? `\n${failures} unconfined checks FAILED` : '\nall unconfined checks passed');
process.exit(failures ? 1 : 0);
