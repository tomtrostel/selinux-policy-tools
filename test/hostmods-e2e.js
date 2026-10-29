// Host Changes over LSP on a Linux host: a semanage export compared with the
// running targeted policy and with a tree build; the no-root read; and each
// fixable change written into a copy of the tree, rebuilt, and found in the
// policy afterwards.
//   node test/hostmods-e2e.js [tree-dir]
// Needs Linux running the targeted policy with python3-setools; the tree part
// also the build toolchain. Skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const { tempDir } = require('./tmpdirs');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { installedPolicies, detectToolchain } = require('../server/build');
const { clipArgs } = require('./clip-args');

const installed = installedPolicies().find(p => p.active);
if (process.platform !== 'linux' || !installed || installed.name !== 'targeted') { console.log('SKIP: needs Linux running the targeted policy'); process.exit(0); }
const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
const sleep = ms => new Promise(r => setTimeout(r, ms));

function start(ws, initOptions = {}) {
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let doneIndex;
  const indexed = new Promise(r => (doneIndex = r));
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
  for (const n of ['textDocument/publishDiagnostics', 'selinux/checks', 'selinux/build', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged']) conn.onNotification(n, () => {});
  conn.listen();
  return { proc, conn, async init() {
    await conn.sendRequest('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: initOptions });
    conn.sendNotification('initialized', {});
    await indexed;
  } };
}

// As semanage export writes it.
const EXPORT = [
  'boolean -D', 'login -D', 'interface -D', 'user -D', 'port -D', 'node -D', 'fcontext -D', 'module -D', 'ibendport -D', 'ibpkey -D', 'permissive -D',
  'boolean -m -1 httpd_can_network_connect',
  "login -a -s staff_u -r 's0-s0:c0.c1023' alice",
  "user -a -L s0 -r s0 -R 'nosuch_r' bad_u",
  "port -a -t http_port_t -r 's0' -p tcp 80",
  "port -a -t http_port_t -r 's0' -p tcp 12345",
  "port -a -t http_port_t -r 's0' -p tcp 8080",
  "fcontext -a -f a -t httpd_sys_content_t -r 's0' '/srv/hostweb(/.*)?'",
  "fcontext -a -f f -t bin_t '/usr/bin/rpm'",
  "fcontext -a -f a -t nosuch_t '/opt/broken(/.*)?'",
  'fcontext -a -e / /var/chroot/web',
  'permissive -a httpd_t',
  '#### modules',
  '100 abrt pp',
  '400 mylocal pp',
  '',
].join('\n');

(async () => {
  // 1. The running targeted policy.
  const ws = tempDir('selinux-hostmods-e2e-');
  fs.writeFileSync(path.join(ws, 'readme.txt'), 'empty workspace\n');
  const a = start(ws);
  await a.init();
  let t0 = Date.now();
  const r = await a.conn.sendRequest('selinux/hostChanges', { text: EXPORT });
  console.log(`  compared in ${Date.now() - t0} ms with ${r.policy && r.policy.label}`);
  const it = (pred) => (r.items || []).find(pred) || {};
  check(!r.error && r.policy && r.policy.active && r.containsLocal && r.items.length === 12 && r.modulesListed, `running policy: 12 changes, noted that it contains its own local changes (${r.items && r.items.length})`, r.error || r.items && r.items.map(x => x.text));
  check(it(x => x.kind === 'port' && x.low === 80).state === 'present' && it(x => x.kind === 'port' && x.low === 12345).state === 'local' && it(x => x.kind === 'port' && x.low === 8080).state === 'override',
    `ports: tcp 80 present, 12345 only on the host, 8080 overrides (${it(x => x.kind === 'port' && x.low === 8080).note})`);
  check(it(x => x.kind === 'boolean').state === 'override' && /defaults to off/.test(it(x => x.kind === 'boolean').note), 'boolean turned on: overrides the default');
  check(it(x => x.kind === 'fcontext' && /hostweb/.test(x.spec)).state === 'local' && it(x => x.kind === 'fcontext' && x.spec === '/usr/bin/rpm').state === 'override' && /rpm_exec_t/.test(it(x => x.kind === 'fcontext' && x.spec === '/usr/bin/rpm').note),
    `file contexts: a new path local; /usr/bin/rpm overrides (${it(x => x.spec === '/usr/bin/rpm').note})`);
  check(it(x => /broken/.test(x.spec || '')).state === 'broken' && it(x => x.kind === 'user').state === 'broken', 'a missing type, a missing role: broken');
  check(it(x => x.kind === 'permissive').severity === 'warn' && it(x => x.kind === 'local-module').name === 'mylocal', 'permissive domain flagged; a module added by hand listed');
  check(it(x => x.kind === 'login').state === 'local' || it(x => x.kind === 'login').state === 'present', `login alice → staff_u: ${it(x => x.kind === 'login').state}`);
  check((r.items || []).every(x => !x.fixable), 'against an installed policy nothing is written into sources');
  const loc = await a.conn.sendRequest('selinux/hostChangesLocal');
  check(!loc.error && loc.partial && /^# Read without root/.test(loc.text), 'without root: file_contexts.local, .subs and changed booleans as export lines', loc.error || loc.text.slice(0, 200));
  const rl = await a.conn.sendRequest('selinux/hostChanges', { text: loc.text });
  check(!rl.error && (rl.items.length > 0 || /No local changes/.test(rl.note || '')), `the no-root read compares (${rl.items ? rl.items.length : 0} changes)`, rl.error);
  a.proc.kill();

  // 2. A tree build: compare, write the fixable changes into a copy, rebuild, compare again.
  const tc = detectToolchain(null);
  if (!tc.ok || !fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP tree part: ${tc.ok ? `no tree at ${src}` : tc.reason}`); return finish(); }
  const tw = tempDir('selinux-hostmods-tree-');
  cp.execFileSync('cp', ['-a', src + '/.', tw]);
  fs.rmSync(path.join(tw, 'tmp'), { recursive: true, force: true });
  const conf = path.join(tw, 'policy/modules.conf');
  const confText = fs.readFileSync(conf, 'utf8');
  // A loadable module to turn off: the first "= module" line not forced on by APPS_MODS.
  const apps = new Set(((clipArgs(src).find(x => x.startsWith('APPS_MODS=')) || '').slice(10).match(/\S+/g)) || []);
  const offMod = (confText.match(/^(\w+) = module$/gm) || []).map(l => l.split(' ')[0]).find(m => !apps.has(m) && !['cron', 'logging', 'unconfined'].includes(m));
  const TREE_EXPORT = EXPORT.replace('#### modules', `module -d ${offMod}\n#### modules`);
  const b = start(tw, { build: { tree: { makeArgs: clipArgs(src) } } });
  await b.init();
  t0 = Date.now();
  const res = await b.conn.sendRequest('selinux/build', { uri: URI.file(tw).toString() });
  check(res && res.ok, `tree build (${Date.now() - t0} ms)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  const r2 = await b.conn.sendRequest('selinux/hostChanges', { text: TREE_EXPORT, against: 'build' });
  const it2 = (pred) => (r2.items || []).find(pred) || {};
  check(!r2.error && r2.policy && r2.policy.build && !r2.containsLocal, 'compared with the build', r2.error);
  const fixable = (r2.items || []).filter(x => x.fixable);
  console.log(`  fixable: ${fixable.map(x => `${x.kind} ${x.text} [${x.state}]`).join('; ')}`);
  for (const [kind, pred] of [['fcontext', x => /hostweb/.test(x.spec || '')], ['port', x => x.kind === 'port' && x.low === 12345], ['boolean', x => x.kind === 'boolean'], ['login', x => x.kind === 'login'], ['equivalence', x => x.kind === 'equivalence'], ['module-disabled', x => x.kind === 'module-disabled']]) {
    const x = it2(pred);
    check(x.fixable, `${kind} (${x.text}): can be written into the tree (${x.state})`, x);
  }
  check(!it2(x => x.kind === 'permissive').fixable && /^permissive httpd_t;/.test(it2(x => x.kind === 'permissive').snippet || '') && !it2(x => x.kind === 'local-module').fixable, 'permissive and added modules: a line to copy, nothing written');
  // Write each fix as the client would (plan → file), then rebuild.
  const written = [];
  for (const x of fixable.filter(y => y.state !== 'present' && y.state !== 'redundant')) {
    const plan = await b.conn.sendRequest('selinux/hostChangeFix', { item: x, against: 'build' });
    if (plan.error || plan.already) { check(false, `fix for ${x.text}`, plan); continue; }
    check(plan.text.split('\n')[plan.line] !== undefined && plan.inserted.length === 1 && plan.text.includes(plan.inserted[0]), `${x.kind}${x.state === 'override' ? ' (override)' : ''}: the edit puts "${plan.inserted[0].slice(0, 70)}" into ${path.relative(tw, plan.path)}`);
    if (x.kind === 'fcontext' && x.state === 'override') check(/rpm\.fc$/.test(plan.path), 'a file context override edits the policy\'s own line (rpm.fc), not the new type\'s module', plan.path);
    fs.mkdirSync(path.dirname(plan.path), { recursive: true });
    fs.writeFileSync(plan.path, plan.text);
    written.push(plan.path);
    b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: URI.file(plan.path).toString(), type: 2 }] });
  }
  const again = await b.conn.sendRequest('selinux/hostChangeFix', { item: it2(x => /hostweb/.test(x.spec || '')), against: 'build' });
  check(again.already, 'writing the same change twice: the file has it already');
  await sleep(1500);
  t0 = Date.now();
  const res2 = await b.conn.sendRequest('selinux/build', { uri: URI.file(tw).toString() });
  check(res2 && res2.ok, `the tree with the host's changes builds (${Date.now() - t0} ms)`, res2 && res2.diagnostics && res2.diagnostics.slice(0, 5));
  const r3 = await b.conn.sendRequest('selinux/hostChanges', { text: TREE_EXPORT, against: 'build' });
  const it3 = (pred) => (r3.items || []).find(pred) || {};
  check(it3(x => /hostweb/.test(x.spec || '')).state === 'present', `after the rebuild: the file context is in the policy (${it3(x => /hostweb/.test(x.spec || '')).note})`);
  check(it3(x => x.kind === 'port' && x.low === 12345).state === 'present', `the port is in the policy (${it3(x => x.kind === 'port' && x.low === 12345).note})`);
  check(it3(x => x.kind === 'boolean').state === 'redundant', `the boolean's default is now on (${it3(x => x.kind === 'boolean').note})`);
  check(it3(x => x.kind === 'login').state === 'present' && it3(x => x.kind === 'equivalence').state === 'present', 'the login and the equivalence are in the policy');
  check(it3(x => x.kind === 'module-disabled').state === 'present', `${offMod} is off in the policy too (${it3(x => x.kind === 'module-disabled').note})`);
  check(it3(x => x.kind === 'port' && x.low === 8080).state === 'present', `the overriding port moved to http_port_t (${it3(x => x.kind === 'port' && x.low === 8080).note})`);
  check(it3(x => x.kind === 'fcontext' && x.spec === '/usr/bin/rpm').state === 'present', `/usr/bin/rpm's own line now says bin_t (${it3(x => x.spec === '/usr/bin/rpm').note})`);
  b.proc.kill();
  fs.rmSync(tw, { recursive: true, force: true });
  finish();
})().catch((e) => { console.error(e); process.exit(1); });

function finish() {
  console.log(failures ? `\n${failures} check(s) failed` : '\nall host changes e2e checks passed');
  process.exit(failures ? 1 : 0);
}
