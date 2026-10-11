// Service editor end to end over LSP on a copy of a policy tree, with real builds:
// create a new service module (every kind of setting), build the tree, read it
// back; edit an existing service, build, read it back; a removal the .if still
// needs is refused.
//   node test/service-e2e.js [tree-dir] [spec [variant]]
// Default: the CLIP clone on melody with CLIP's make arguments; with a spec
// (RHEL), its settings, overlays copied so modules.conf edits stay in the copy.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain } = require('../server/build');

const tc = detectToolchain(null);
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }
const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');
if (!fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP: no refpolicy tree at ${src}`); process.exit(0); }
const specArg = process.argv[3];
const variant = process.argv[4] || 'targeted';
const CLIP_SEPARATE = 'ssh rhsmcertd oddjob rtkit aide postfix usbguard fapolicyd rngd logadm auditadm secadm sasl rpcbind rpc gssproxy kerberos certmonger pcscd apcupsd nut postgresql mysql apache bind openvpn samba ntp xserver accountsd colord geoclue gnome wm telepathy bluetooth devicekit';
const CLIP_ARGS = ['NAME=mcs', 'TYPE=mcs', 'DISTRO=redhat', 'UBAC=y', 'DIRECT_INITRC=n', 'MONOLITHIC=n', 'POLY=y', 'UNK_PERMS=deny',
  'MLS_CATS=1024', 'MCS_CATS=1024', 'SEMOD_EXP=/usr/bin/semodule_expand', `APPS_MODS=${CLIP_SEPARATE}`];

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-service-e2e-'));
cp.execFileSync('cp', ['-a', src + '/.', ws]);
fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
let spec = null;
if (specArg) {
  const sdir = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-service-spec-'));
  cp.execFileSync('cp', ['-a', path.dirname(path.resolve(specArg)) + '/.', sdir]);
  spec = path.join(sdir, path.basename(specArg));
}

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
const diags = {};
let doneIndex, indexed = new Promise(r => (doneIndex = r));
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(p.stats); });
conn.onNotification('window/logMessage', () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + (typeof extra === 'string' ? extra : JSON.stringify(extra, null, 1)).slice(0, 2500).replace(/\n/g, '\n     ')); }
};
const norm = (m) => JSON.stringify([m.files.map(f => [f.kind, f.type, f.access, [...f.paths].sort()]).sort(), [...m.self].sort(), [...m.caps].sort(),
  m.net.listen.map(x => x.proto + x.port).sort(), m.net.connect.map(x => x.proto + x.port).sort(), [...m.access].sort(), [...m.extra].sort(), m.permissive, [...m.exec].sort()]);
const errors = (r) => Object.entries(diags).flatMap(([u, ds]) => ds.filter(d => d.severity === 1).map(d => `${path.basename(URI.parse(u).fsPath)}:${d.range.start.line + 1} ${d.message}`));
const write = async (plan) => {
  for (const f of plan.files) if (f.changed) fs.writeFileSync(f.path, f.text);
  indexed = new Promise(r => (doneIndex = r));
  await conn.sendRequest('selinux/reindex');
};
const build = async (te) => {
  const r = await conn.sendRequest('selinux/build', { uri: uri(te) });
  return r;
};

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {}, initializationOptions: { build: { tree: { makeArgs: specArg ? [] : CLIP_ARGS } } } });
  conn.sendNotification('initialized', {});
  let stats = await indexed;
  check(stats.buildMode === 'tree', `tree detected (${stats.modules} modules)`);
  if (spec) {
    const sc = await conn.sendRequest('selinux/specBuildConfig', { specPath: spec });
    const cfg = sc.configs.find(c => c.variant === variant);
    indexed = new Promise(r => (doneIndex = r));
    conn.sendNotification('workspace/didChangeConfiguration', { settings: { selinux: { build: { tree: { makeArgs: cfg.makeArgs, files: cfg.files } } } } });
    await indexed;
    console.log(`     settings from ${path.basename(spec)} (${variant})`);
  }

  // 1. A new service.
  const info = await conn.sendRequest('selinux/serviceInfo', {});
  check(info.isNew && info.layers && info.ports.some(p => p.name === 'http' && /tcp 80/.test(p.nums)) && info.interfaces.length > 500,
    `new-service info: ${info.catalog.fileKinds.length} file kinds, ${info.ports.length} port types, ${info.interfaces.length} interfaces, layers ${info.layers.join(' ')}`);
  const has = (id) => info.catalog.access.some(g => g.items.some(i => i.id === id));
  const model = info.model;
  Object.assign(model, { name: 'svctest', summary: 'Service editor test daemon', exec: ['/usr/bin/svctest', '/usr/libexec/svctest-helper'] });
  model.files.push({ kind: 'state', paths: ['/var/lib/%/'], access: 'manage' }, { kind: 'log', paths: ['/var/log/%/'], access: 'append' },
    { kind: 'config', paths: ['/etc/%/', '/etc/%.conf'], access: 'read' }, { kind: 'tmp', paths: [], access: 'manage' }, { kind: 'cache', paths: ['/var/cache/%/'], access: 'manage' });
  model.caps = ['setuid', 'setgid', 'net_bind_service'];
  model.self.push('unixstream', 'signal');
  model.net.listen.push({ proto: 'tcp', port: 'http' });
  model.net.connect.push({ proto: 'tcp', port: 'postgresql' }, { proto: 'udp', port: 'all' });
  model.access.push(...['nsswitch', 'sysstate', 'urandom', 'dbus', 'mail', 'certs'].filter(has));
  model.extra.push('files_read_usr_files');
  model.provides = info.catalog.provides.map(p => p.id);
  let plan = await conn.sendRequest('selinux/servicePlan', { model, module: null, where: info.defaultLayer });
  const blocking = (p) => (p.problems || []).filter(x => !x.startsWith('Note:'));
  check(!blocking(plan).length && plan.files.filter(f => f.changed).length >= 3, `plan: ${plan.files.map(f => `${path.basename(f.path)}${f.exists ? ' (edit)' : ' (new)'}`).join(', ')}`, plan.problems);
  const conf = plan.files.find(f => f.kind === 'conf');
  check(conf && /^svctest = module$/m.test(conf.text), `modules.conf gets "svctest = module" (${conf && path.basename(conf.path)})`);
  await write(plan);
  const te = plan.files.find(f => f.kind === 'te').path;
  let r = await build(te);
  check(r.ok && r.validated, `tree with the new module builds and links (${(r.ms / 1000).toFixed(1)} s, ${r.packages} packages)`, { log: r.log && r.log.slice(-2500), errors: errors() });
  check(r.workDir && fs.existsSync(path.join(r.workDir, 'svctest.pp')), 'svctest.pp built');
  const back = await conn.sendRequest('selinux/serviceInfo', { module: 'svctest' });
  check(!back.unavailable && norm(back.model) === norm({ ...model, files: model.files.map(f => ({ ...f, type: `svctest${info.catalog.fileKinds.find(k => k.id === f.kind).suffix}`, paths: f.paths.map(p => p.replace(/%/g, 'svctest')) })), exec: model.exec }) &&
    back.kept.length === 0 && back.model.provides.length === model.provides.length, 'the new module reads back as created (nothing unmodelled)', back.unavailable || { got: norm(back.model), kept: back.kept });

  // 2. Edit an existing, enabled service.
  const list = await conn.sendRequest('selinux/serviceList');
  const name = ['ntp', 'rpcbind', 'chronyd', 'cron'].find(n => list.modules.some(m => m.module === n));
  const ex = await conn.sendRequest('selinux/serviceInfo', { module: name });
  const m = JSON.parse(JSON.stringify(ex.model));
  const changes = [];
  const cap = ['sys_chroot', 'kill', 'fowner'].find(c => !m.caps.includes(c)); m.caps.push(cap); changes.push(`+cap ${cap}`);
  m.files.push({ kind: 'cache', type: '', paths: [`/var/cache/${name}-e2e/`], access: 'manage' }); changes.push('+cache files');
  if (!m.net.listen.some(x => x.port === 'http')) { m.net.listen.push({ proto: 'tcp', port: 'http' }); changes.push('+listen http'); }
  if (has('dbus') && !m.access.includes('dbus')) { m.access.push('dbus'); changes.push('+dbus'); }
  if (m.access.length > 1) { changes.push(`-${m.access[0]}`); m.access.splice(0, 1); }
  if (!m.extra.includes('files_read_usr_files')) { m.extra.push('files_read_usr_files'); changes.push('+files_read_usr_files'); }
  const tmp = m.files.findIndex(f => f.kind === 'tmp');
  plan = await conn.sendRequest('selinux/servicePlan', { model: m, module: name });
  check(!blocking(plan).length, `${name}: edit planned (${changes.join(', ')})`, plan.problems);
  const teFile = plan.files.find(f => f.kind === 'te');
  const removed = teFile.diff.filter(x => x[0] === '-' && x[1].trim()).length;
  check(teFile.changed && removed <= 3, `${name}.te: ${teFile.diff.filter(x => x[0] === '+').length} lines added, ${removed} removed`, teFile.diff.filter(x => x[0] !== ' '));
  await write(plan);
  r = await build(teFile.path);
  check(r.ok && r.validated, `tree with the edited ${name} builds and links (${(r.ms / 1000).toFixed(1)} s)`, { log: r.log && r.log.slice(-2500), errors: errors() });
  const ex2 = await conn.sendRequest('selinux/serviceInfo', { module: name });
  const want = { ...m, files: m.files.map(f => (f.type ? f : { ...f, type: `${name}_cache_t` })) };
  check(norm(ex2.model) === norm(want) && ex2.kept.length === ex.kept.length, `${name} reads back as edited; ${ex.kept.length} unmodelled statements kept`, { got: norm(ex2.model), want: norm(want) });

  // 3. Removing a file type the .if still uses is refused.
  const used = ex2.model.files.find(f => f.access !== 'none' && fs.readFileSync(ex2.files.if, 'utf8').includes(f.type));
  if (used) {
    const m3 = JSON.parse(JSON.stringify(ex2.model));
    m3.files = m3.files.filter(f => f.type !== used.type);
    plan = await conn.sendRequest('selinux/servicePlan', { model: m3, module: name });
    check(blocking(plan).some(p => p.includes(used.type) && /still used/.test(p)), `removing ${used.type} (used in ${name}.if) is refused: ${blocking(plan)[0]}`);
  }
  if (tmp < 0) console.log(`     (${name} has no tmp files)`);

  await conn.sendRequest('shutdown');
  conn.sendNotification('exit');
  await sleep(300);
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });

  // 4. Standalone module (devel headers): a new service in a folder of the workspace, built with the devel Makefile.
  if (fs.existsSync('/usr/share/selinux/devel/Makefile')) await standalone();
  if (spec) fs.rmSync(path.dirname(spec), { recursive: true, force: true });
  console.log(failures ? `\n${failures} check(s) failed` : '\nall service e2e checks passed');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });

async function standalone() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-service-devel-'));
  const p2 = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const c2 = rpc.createMessageConnection(new rpc.StreamMessageReader(p2.stdout), new rpc.StreamMessageWriter(p2.stdin));
  let done, ready = new Promise(r => (done = r));
  c2.onNotification('selinux/indexing', p => { if (p.state === 'done') done(p.stats); });
  c2.onNotification('window/logMessage', () => {});
  c2.onNotification('textDocument/publishDiagnostics', () => {});
  c2.listen();
  await c2.sendRequest('initialize', { processId: null, rootUri: uri(dir), capabilities: {} });
  c2.sendNotification('initialized', {});
  const st = await ready;
  const info = await c2.sendRequest('selinux/serviceInfo', {});
  check(st.buildMode === 'module' && info.isNew && info.mode === 'module' && !info.layers, `standalone workspace: new service in a folder (${info.interfaces.length} interfaces from the devel headers)`, info.unavailable);
  const model = info.model;
  Object.assign(model, { name: 'develsvc', summary: 'Standalone test daemon' });
  model.files.push({ kind: 'state', paths: ['/var/lib/%/'], access: 'manage' });
  model.net.listen.push({ proto: 'tcp', port: 'http' });
  model.access.push('nsswitch', 'dbus');
  const plan = await c2.sendRequest('selinux/servicePlan', { model, module: null, where: null });
  check(plan.files.length === 3 && plan.files.every(f => path.dirname(f.path) === path.join(dir, 'develsvc')), `files go to ${path.join(path.basename(dir), 'develsvc')}/`, plan.files.map(f => f.path));
  fs.mkdirSync(path.join(dir, 'develsvc'));
  for (const f of plan.files) fs.writeFileSync(f.path, f.text);
  ready = new Promise(r => (done = r));
  await c2.sendRequest('selinux/reindex');
  const r = await c2.sendRequest('selinux/build', { uri: uri(path.join(dir, 'develsvc', 'develsvc.te')) });
  check(r.ok, `standalone module builds against the devel headers (${r.ms} ms)`, r.log && r.log.slice(-2000));
  const back = await c2.sendRequest('selinux/serviceInfo', { module: 'develsvc' });
  check(!back.unavailable && back.kept.length === 0 && back.model.net.listen.length === 1, 'reads back from the folder');
  await c2.sendRequest('shutdown');
  c2.sendNotification('exit');
  await sleep(200);
  p2.kill();
  fs.rmSync(dir, { recursive: true, force: true });
}
