'use strict';
// Prefill the service form from a program on a host, over LSP on a Linux host
// with the toolchain: a copy of a tree (default: CLIP for RHEL 9) is opened,
// /usr/sbin/chronyd and /usr/sbin/sshd are looked at on this host (as the
// user: no ports); the drafted chrony model clashes with the tree's chronyd
// module on its paths (the plan says so); with chronyd removed from the copy
// the draft is named chronyd, plans cleanly and the tree builds with it;
// then, with a root target (TARGET + TARGET_PASS_FILE, as in target-e2e),
// the programs are looked at on the target, with their ports.
//   node test/prefill-e2e.js [tree-dir]
//   TARGET=root@localhost TARGET_PASS_FILE=/path/0600file node test/prefill-e2e.js
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { tempDir } = require('./tmpdirs');
const { detectToolchain } = require('../server/build');
const { clipArgs } = require('./clip-args');

const tc = detectToolchain(null);
if (process.platform !== 'linux' || !tc.ok) { console.log(`SKIP: ${tc.reason || 'needs Linux'}`); process.exit(0); }
const src = path.resolve(process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy'));
if (!fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP: no tree at ${src}`); process.exit(0); }
const TARGET = process.env.TARGET || null;
const PASS_FILE = process.env.TARGET_PASS_FILE || null;

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
const ws = tempDir('selinux-prefill-e2e-');
cp.execFileSync('cp', ['-a', src + '/.', ws]);
fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
let doneIndex, indexed = new Promise(r => (doneIndex = r));
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(p.stats); });
for (const n of ['textDocument/publishDiagnostics', 'selinux/build', 'selinux/checks', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged', 'selinux/loginsChanged', 'selinux/targetsChanged']) conn.onNotification(n, () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
const req = (m, p) => conn.sendRequest(m, p || {});
const paths = (m, kind) => (m.files.find(x => x.kind === kind) || { paths: [] }).paths.slice().sort();
const show = (r) => { for (const x of r.report) console.log(`     ${x.field.padEnd(8)} ${x.text} — ${x.from}`); for (const n of r.notes) console.log(`     note: ${n}`); };

(async () => {
  await req('initialize', { processId: null, rootUri: uri(ws), capabilities: {}, initializationOptions: { build: { tree: { makeArgs: clipArgs(src) } } } });
  conn.sendNotification('initialized', {});
  await indexed;
  const info = await req('selinux/serviceInfo', { prefill: { exec: '/usr/sbin/chronyd', host: '' } });
  check(info.isNew && info.prefill && info.prefill.exec === '/usr/sbin/chronyd' && info.prefill.host === '' && info.model.exec.join() === '/usr/sbin/chronyd', 'serviceInfo with a prefill: the program is in the model and echoed for the form to look at');

  // 1. Refusals.
  let r = await req('selinux/servicePrefill', { exec: 'chronyd', host: '' });
  check(r.error && /absolute path/.test(r.error), 'a relative program path is refused', r);
  r = await req('selinux/servicePrefill', { exec: '/usr/sbin/no-such-program-here', host: '', model: info.model });
  check(!r.error && r.report.length === 0 && r.notes.some(n => /does not exist on the host/.test(n)) && r.facts.exists === false, 'a program that is not there: nothing filled in, said so', r);
  r = await req('selinux/servicePrefill', { exec: '/usr/sbin/chronyd', host: 'root@nowhere', model: info.model });
  check(r.error && /not connected/.test(r.error), 'an unconnected target is refused', r);

  // 2. chronyd on this host, as the user.
  let t0 = Date.now();
  r = await req('selinux/servicePrefill', { exec: '/usr/sbin/chronyd', host: '', model: info.model });
  check(!r.error && r.model && r.facts.pkg && r.facts.pkg.name === 'chrony' && r.facts.units.join() === 'chronyd.service', `chronyd looked at on this host in ${Date.now() - t0} ms: package ${r.facts.pkg && r.facts.pkg.name}, unit ${r.facts.units}`, r.error || r.facts);
  show(r);
  const m = r.model;
  const taken = r.notes.find(n => /module named chronyd exists/.test(n));
  check(m.name === 'chrony' && taken, 'name: chronyd is a module of the tree already (said), so the package name chrony', { name: m.name, notes: r.notes });
  check(m.summary === 'NTP client/server' && m.exec.join() === '/usr/sbin/chronyd', 'summary from the unit, the program', { summary: m.summary, exec: m.exec });
  check(paths(m, 'config').join() === '/etc/chrony.conf,/etc/chrony.keys' && paths(m, 'state').join() === '/var/lib/chrony/' && paths(m, 'log').join() === '/var/log/chrony/' && paths(m, 'runtime').join() === '/run/chrony/' && paths(m, 'unit').join() === '/usr/lib/systemd/system/chronyd.service',
    'files: config (chrony.conf, chrony.keys; not logrotate/sysconfig), state, log, runtime (PIDFile), the unit file', m.files);
  check(!m.net.listen.length && r.notes.some(n => /Not root on the host/.test(n)) && r.facts.root === false, 'as the user: no ports seen, said so');
  check(m.access.includes('certs') && m.access.includes('syslog') && m.access.includes('locale'), 'access: certificates (gnutls), the defaults kept', m.access);
  // Its paths are chronyd's already: the plan refuses (setfiles would).
  let plan = await req('selinux/servicePlan', { model: m, module: null, where: info.defaultLayer });
  const clashes = (plan.problems || []).filter(p => /labeled \w+ by .*chronyd\.fc:\d+ already/.test(p));
  check(clashes.length >= 4 && clashes.some(p => /\/etc\/chrony\\\.conf is labeled chronyd_conf_t by/.test(p)) && clashes.some(p => /\/usr\/sbin\/chronyd is labeled chronyd_exec_t/.test(p)), `the plan refuses: ${clashes.length} paths chronyd.fc labels already`, plan.problems);
  // Without chronyd's .te and .fc in the tree (a program no module labels; its .if stays: ntp.te calls
  // chronyd_enabledisable, and m4 leaves an unknown macro as a syntax error): the draft plans cleanly and builds.
  for (const f of ['te', 'fc']) fs.rmSync(path.join(ws, 'policy/modules/services', `chronyd.${f}`));
  const confPath = path.join(ws, 'policy/modules.conf');
  // Off, not gone: the interfaces of off modules are still in all_interfaces.conf (ntp.te's optional call).
  fs.writeFileSync(confPath, fs.readFileSync(confPath, 'utf8').replace(/^chronyd = module$/m, 'chronyd = off'));
  indexed = new Promise(res => (doneIndex = res));
  await req('selinux/reindex');
  await indexed;
  r = await req('selinux/servicePrefill', { exec: '/usr/sbin/chronyd', host: '', model: info.model });
  const nm = r.model.name;
  check(!r.error && (nm === 'chronyd' || nm === 'chrony'), `with no chronyd module in the tree the draft is named ${nm}`, { name: r.model.name, notes: r.notes });
  const m2 = r.model;
  plan = await req('selinux/servicePlan', { model: m2, module: null, where: info.defaultLayer });
  const blocking = (plan.problems || []).filter(p => !/^Note:/.test(p));
  const isTe = (f) => f.path.endsWith(`/${nm}.te`), isFc = (f) => f.path.endsWith(`/${nm}.fc`);
  check(!blocking.length && plan.files.some(isTe), `the drafted ${nm} model plans without problems`, plan.problems);
  // The .if is not written when chronyd's own stays (its interfaces are what ntp.te calls).
  for (const f of plan.files) if (f.changed && !(nm === 'chronyd' && f.kind === 'if')) fs.writeFileSync(f.path, f.text);
  const te = plan.files.find(isTe).text;
  check(new RegExp(`${nm}_conf_t`).test(te) && new RegExp(`${nm}_var_lib_t`).test(te) && new RegExp(`${nm}_log_t`).test(te) && new RegExp(`init_daemon_domain\\(${nm}_t, ${nm}_exec_t\\)`).test(te) && new RegExp(`miscfiles_read_generic_certs\\(${nm}_t\\)`).test(te), 'the .te has the file types, the entry and the certificate call', te.slice(0, 1200));
  const fc = plan.files.find(isFc).text;
  check(new RegExp(`/etc/chrony\\\\\\.conf\\s+--\\s+gen_context\\(system_u:object_r:${nm}_conf_t`).test(fc) && new RegExp(`/var/lib/chrony\\(/\\.\\*\\)\\?\\s+gen_context\\(system_u:object_r:${nm}_var_lib_t`).test(fc) && new RegExp(`chronyd\\\\\\.service\\s+--\\s+gen_context\\(system_u:object_r:${nm}_unit`).test(fc), 'the .fc labels the files found', fc);
  indexed = new Promise(res => (doneIndex = res));
  await req('selinux/reindex');
  t0 = Date.now();
  const b1 = await req('selinux/build', { uri: uri(plan.files.find(isTe).path) });
  check(b1 && b1.ok, `the tree builds with the drafted ${nm} module (${((Date.now() - t0) / 1000).toFixed(0)} s)`, b1 && (b1.unavailable || { diags: (b1.diagnostics || []).filter(d => d.severity === 'error').slice(0, 5), log: (b1.log || '').slice(-1500) }));

  // 3. sshd: libraries say PAM, Kerberos, nsswitch; config /etc/ssh/.
  r = await req('selinux/servicePrefill', { exec: '/usr/sbin/sshd', host: '', model: { ...info.model, exec: ['/usr/sbin/sshd'], name: '' } });
  check(!r.error && r.facts.pkg && /^openssh/.test(r.facts.pkg.name) && r.facts.units.includes('sshd.service'), `sshd: package ${r.facts.pkg && r.facts.pkg.name}, units ${r.facts.units}`, r.error || r.facts);
  show(r);
  const libs = cp.execFileSync('ldd', ['/usr/sbin/sshd']).toString();
  check(r.model.access.includes('pam') && r.model.access.includes('kerberos') === /libkrb5\.so/.test(libs) && r.model.access.includes('nsswitch') === /libldap|libsss_nss_idmap/.test(libs) && paths(r.model, 'config').join() === '/etc/ssh/' && r.model.exec.includes('/usr/sbin/sshd'),
    `sshd: PAM${/libkrb5\.so/.test(libs) ? ', Kerberos' : ''} from its libraries; /etc/ssh/ as configuration`, { access: r.model.access, files: r.model.files, exec: r.model.exec });
  check(r.model.name === 'openssh' || r.model.name === 'sshd' || r.model.name === '' , `name: ${JSON.stringify(r.model.name)} (ssh is a module of the tree)`, r.notes);

  // 4. On a root target: ports.
  if (!TARGET || !PASS_FILE) console.log('SKIP target part: no TARGET / TARGET_PASS_FILE');
  else {
    const password = fs.readFileSync(PASS_FILE, 'utf8').replace(/\r?\n$/, '');
    const c = await req('selinux/targetConnect', { spec: TARGET, password });
    check(!c.error && c.state === 'connected' && c.facts.root, `connected to ${TARGET} as root`, c.error || c);
    if (!c.error) {
      t0 = Date.now();
      r = await req('selinux/servicePrefill', { exec: '/usr/sbin/chronyd', host: c.id, model: info.model });
      check(!r.error && r.facts.host === c.id && r.facts.root === true, `chronyd looked at on ${c.id} as root in ${Date.now() - t0} ms`, r.error || r.facts);
      show(r);
      const lis = (r.model.net.listen || []).map(x => `${x.proto} ${x.port}`).sort();
      const running = r.facts.units.length && !r.notes.some(n => /No systemd unit runs/.test(n));
      check(!running || lis.includes('udp chronyd') || lis.includes('udp ntp') || r.notes.some(n => /no port type/.test(n)) || r.model.ports.length, `ports as root: ${lis.join(', ') || 'none'} (chronyd's command port 323 is chronyd_port_t upstream)`, { listen: lis, ports: r.model.ports, notes: r.notes });
      check(!r.notes.some(n => /Not root/.test(n)), 'no "not root" note on the target');
      r = await req('selinux/servicePrefill', { exec: '/usr/sbin/sshd', host: c.id, model: { ...info.model, exec: ['/usr/sbin/sshd'], name: '' } });
      show(r);
      const l2 = (r.model.net.listen || []).map(x => `${x.proto} ${x.port}`);
      check(!r.error && l2.includes('tcp ssh') && r.model.caps.includes('net_bind_service'), `sshd on ${c.id}: listens on tcp ssh (port 22), net_bind_service`, { listen: l2, caps: r.model.caps });
      await req('selinux/targetDisconnect', { id: c.id });
    }
  }
  proc.kill();
  console.log(failures ? `\n${failures} prefill e2e checks FAILED` : '\nall prefill e2e checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
