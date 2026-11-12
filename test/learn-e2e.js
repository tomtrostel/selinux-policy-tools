// Learn from a permissive run, over LSP on a Linux host with the toolchain: a
// copy of a tree (default: CLIP for RHEL 9) is built, a new service model gets
// the denials of a (synthetic) permissive run of its domain, and the form's
// settings come back filled: file access levels, a new state type, ports,
// capabilities, self permissions, access groups and interfaces ranked against
// the build; the planned module then builds with the tree.
//   node test/learn-e2e.js [tree-dir]
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

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
const ws = tempDir('selinux-learn-e2e-');
cp.execFileSync('cp', ['-a', src + '/.', ws]);
fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
let doneIndex, indexed = new Promise(r => (doneIndex = r));
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(p.stats); });
for (const n of ['textDocument/publishDiagnostics', 'selinux/build', 'selinux/checks', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged', 'selinux/loginsChanged']) conn.onNotification(n, () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();

const avc = (perms, t, c, extra = '') => `type=AVC msg=audit(1700000000.000:${Math.floor(Math.random() * 1e6)}): avc:  denied  { ${perms} } for  pid=1 comm="learnd"${extra} scontext=system_u:system_r:learnd_t:s0 tcontext=system_u:object_r:${t}:s0 tclass=${c} permissive=1`;
const LOG = [
  avc('net_bind_service', 'learnd_t', 'capability'),
  avc('name_bind', 'http_port_t', 'tcp_socket'),
  avc('name_connect', 'mysqld_port_t', 'tcp_socket'),
  avc('create bind listen', 'learnd_t', 'tcp_socket'),
  avc('node_bind', 'node_t', 'tcp_socket'),
  avc('write create', 'learnd_conf_t', 'file', ' name="x.conf"'),
  avc('write', 'var_lib_t', 'file', ' path="/var/lib/learnd/state" name="state"'),
  avc('read open getattr', 'etc_t', 'file', ' path="/etc/hosts" name="hosts"'),
  avc('read open', 'cert_t', 'file', ' path="/etc/pki/tls/certs/ca-bundle.crt" name="ca-bundle.crt"'),
  avc('signal', 'learnd_t', 'process'),
  avc('read write', 'learnd_t', 'fifo_file'),
  avc('getattr', 'default_t', 'file'),
].join('\n');

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {}, initializationOptions: { build: { tree: { makeArgs: clipArgs(src) } } } });
  conn.sendNotification('initialized', {});
  await indexed;
  let t0 = Date.now();
  const b0 = await conn.sendRequest('selinux/build', { uri: uri(ws) });
  check(b0 && b0.ok, `tree build (${((Date.now() - t0) / 1000).toFixed(0)} s)`, b0 && b0.diagnostics && b0.diagnostics.slice(0, 3));
  const info = await conn.sendRequest('selinux/serviceInfo', {});
  const model = { ...info.model, name: 'learnd', summary: 'Learn test daemon', exec: ['/usr/sbin/learnd'],
    files: [{ kind: 'unit', paths: ['/usr/lib/systemd/system/learnd.service'], access: 'none' }, { kind: 'config', paths: ['/etc/learnd/'], access: 'read' }],
    self: ['fifo'], caps: [], net: { listen: [], connect: [] }, access: ['syslog'], extra: [] };
  // 1. Refusals: no name, no records of the domain.
  let r = await conn.sendRequest('selinux/serviceLearn', { text: LOG, model: { ...model, name: '' } });
  check(r.error && /name first/.test(r.error), 'no module name: refused', r);
  r = await conn.sendRequest('selinux/serviceLearn', { text: LOG.replace(/learnd_t/g, 'other_t'), model });
  check(r.error && /None of the \d+ denial groups has learnd_t/.test(r.error), 'denials of another domain: refused with the count', r);
  // 2. The run.
  t0 = Date.now();
  r = await conn.sendRequest('selinux/serviceLearn', { text: LOG, model });
  check(!r.error && r.model && r.groups === 12 && r.stats, `learned from ${r.groups} groups (${r.records} records) in ${Date.now() - t0} ms: ${JSON.stringify(r.stats)}`, r.error || r.notes);
  const m = r.model;
  const by = (t, c) => r.report.find(x => x.target === t && x.tclass === c);
  for (const x of r.report) console.log(`     ${x.action.padEnd(8)} ${x.target}:${x.tclass} { ${x.perms.join(' ')} } — ${x.text.slice(0, 110)}`);
  check(m.caps.includes('net_bind_service') && m.net.listen.some(x => x.port === 'http') && m.net.connect.some(x => x.port === 'mysqld') && by('learnd_t', 'tcp_socket').action === 'covered' && by('node_t', 'tcp_socket').action === 'covered',
    'capability, http listen, mysqld connect; own socket and node covered', { caps: m.caps, net: m.net });
  check(m.files.find(f => f.kind === 'config').access === 'manage' && m.files.some(f => f.kind === 'state' && f.paths.join() === '/var/lib/learnd/' && f.access === 'manage'),
    'config raised to manage; /var/lib/learnd/ gets a state type', m.files);
  const etc = by('etc_t', 'file'), cert = by('cert_t', 'file');
  check(etc && (etc.action === 'access' || etc.action === 'extra') && /files_(read|getattr)_etc/.test(etc.call || '') && (etc.action !== 'access' || m.access.includes(etc.access)),
    `/etc/hosts: ranked against the build → ${etc && etc.call} (${etc && etc.action})`, etc);
  check(cert && ['access', 'extra'].includes(cert.action) && /cert/.test(cert.call || '') && (cert.action !== 'extra' || m.extra.includes(cert.call)) && (cert.action !== 'access' || m.access.includes(cert.access)), `cert_t: ${cert && cert.call} (${cert && cert.action})`, cert);
  check(m.self.includes('signal') && by('learnd_t', 'fifo_file').action === 'covered' && by('default_t', 'file').action === 'unmapped' && /generic label/.test(by('default_t', 'file').text), 'signal ticked, fifo covered, default_t left to label by hand');
  // 3. The planned module builds with the tree.
  const plan = await conn.sendRequest('selinux/servicePlan', { model: m, module: null, where: info.defaultLayer });
  const blocking = (plan.problems || []).filter(p => !/^Note:/.test(p));
  check(!blocking.length && plan.files.some(f => /learnd\.te$/.test(f.path)), 'the learned model plans without problems', plan.problems);
  for (const f of plan.files) if (f.changed) fs.writeFileSync(f.path, f.text);
  const te = plan.files.find(f => /learnd\.te$/.test(f.path)).text;
  check(/corenet_tcp_bind_http_port\(learnd_t\)/.test(te) && /corenet_tcp_connect_mysqld_port\(learnd_t\)/.test(te) && /net_bind_service/.test(te) && /learnd_var_lib_t/.test(te) && /manage_files_pattern\(learnd_t, learnd_conf_t/.test(te),
    'the .te has the port calls, the capability, the state type and config management', te.slice(0, 1500));
  indexed = new Promise(r => (doneIndex = r));
  await conn.sendRequest('selinux/reindex');
  t0 = Date.now();
  const b1 = await conn.sendRequest('selinux/build', { uri: uri(plan.files.find(f => /learnd\.te$/.test(f.path)).path) });
  check(b1 && b1.ok, `the tree builds with learnd (${((Date.now() - t0) / 1000).toFixed(0)} s)`, b1 && (b1.unavailable || { diags: (b1.diagnostics || []).filter(d => d.severity === 'error').slice(0, 5), log: (b1.log || '').slice(-1500) }));
  proc.kill();
  console.log(failures ? `\n${failures} learn e2e checks FAILED` : '\nall learn e2e checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
