// Login contexts over LSP on a Linux host: the running policy's logins all get
// a context; then on a copy of a tree (default: CLIP for RHEL 9) after a
// build, the problems are diagnostics on the seusers / contexts file lines, and
// editing those files on disk updates them without a rebuild.
//   node test/loginctx-e2e.js [tree-dir]
// Needs Linux running the targeted policy with python3-setools; the tree part
// also the build toolchain. Skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
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
const until = async (cond, ms = 20000) => { for (const end = Date.now() + ms; !cond() && Date.now() < end;) await sleep(200); return cond(); };

function start(ws, initOptions = {}) {
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let doneIndex;
  const indexed = new Promise(r => (doneIndex = r));
  const diags = {};
  const s = { proc, conn, diags };
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
  conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
  for (const n of ['selinux/build', 'selinux/checks', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged']) conn.onNotification(n, () => {});
  conn.listen();
  s.init = async () => {
    await conn.sendRequest('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: initOptions });
    conn.sendNotification('initialized', {});
    await indexed;
  };
  return s;
}

(async () => {
  // 1. The running targeted policy: every real login gets a context.
  const ws0 = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-loginctx-e2e-'));
  fs.writeFileSync(path.join(ws0, 'readme.txt'), 'empty workspace\n');
  const a = start(ws0);
  await a.init();
  let t0 = Date.now();
  const run = await a.conn.sendRequest('selinux/loginContexts', {});
  check(!run.error && run.policy && run.policy.active && run.mappings.some(m => m.login === '__default__') && !run.problems.some(p => p.severity !== 'info'),
    `running ${installed.name}: ${run.mappings && run.mappings.length} seusers lines, no errors or warnings (${run.problems && run.problems.length} notes, ${Date.now() - t0} ms)`, run.error || run.problems);
  const dflt = run.mappings && run.mappings.find(m => m.login === '__default__');
  const ssh = dflt && dflt.ways.find(w => w.source === 'sshd_t');
  check(ssh && ssh.works3 && ssh.works2 && /:\w+_r:\w+_t:/.test(ssh.v3.ctx), `__default__ over ssh gets ${ssh && ssh.v3 && ssh.v3.ctx} on RHEL 9+ and ${ssh && ssh.v2 && ssh.v2.ctx} on RHEL 8`, ssh);
  a.proc.kill();

  // 2. A tree build.
  const tc = detectToolchain(null);
  if (!tc.ok || !fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP tree part: ${tc.reason || `no tree at ${src}`}`); return finish(); }
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-loginctx-e2e-tree-'));
  cp.execFileSync('cp', ['-a', src + '/.', ws]);
  fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
  const args = clipArgs(src);
  const type = (args.find(x => /^TYPE=/.test(x)) || 'TYPE=mcs').slice(5);
  const app = path.join(ws, 'config', `appconfig-${type}`);
  const seusersPath = path.join(app, 'seusers');
  const seUri = URI.file(seusersPath).toString();
  const b = start(ws, { build: { tree: { makeArgs: args } } });
  await b.init();
  t0 = Date.now();
  const res = await b.conn.sendRequest('selinux/build', { uri: URI.file(ws).toString() });
  check(res && res.ok, `tree build (${((Date.now() - t0) / 1000).toFixed(0)} s)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  const rep = await b.conn.sendRequest('selinux/loginContexts', { against: 'build' });
  check(!rep.error && rep.policy.build && rep.mappings.some(m => m.login === 'root') && rep.policy.configDir === app, `build: ${rep.mappings && rep.mappings.length} logins checked from ${rep.policy && path.relative(ws, rep.policy.configDir)}`, rep.error || rep.policy);
  for (const p of (rep.problems || []).filter(x => x.severity !== 'info')) console.log(`     ${p.severity}: ${p.text.slice(0, 200)}`);
  const onSeusers = (rep.problems || []).filter(p => p.file === seusersPath);
  await until(() => (b.diags[seUri] || []).length >= onSeusers.length);
  const ds = (b.diags[seUri] || []).filter(d => d.source === 'selinux-logins');
  check(ds.length === onSeusers.length && onSeusers.every(p => ds.some(d => d.range.start.line === p.l && d.code === p.kind)), `after the build: ${ds.length} diagnostic(s) on seusers, one per problem there`, { ds, onSeusers });

  // 3. seusers edited on disk: a login mapped to a user the policy lacks, and a range it rejects.
  const seOrig = fs.readFileSync(seusersPath, 'utf8');
  const lines = seOrig.replace(/\n*$/, '\n').split('\n');
  fs.writeFileSync(seusersPath, `${seOrig.replace(/\n*$/, '\n')}ghost:nosuch_u:s0\nbob:staff_u:s0:c5000\n`);
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: seUri, type: 2 }] });
  const ghostL = lines.length - 1, bobL = lines.length;
  const has = (code, l) => (b.diags[seUri] || []).some(d => d.code === code && d.range.start.line === l);
  await until(() => has('nouser', ghostL) && has('range', bobL));
  const g = (b.diags[seUri] || []).find(d => d.code === 'nouser');
  check(has('nouser', ghostL) && /ghost is mapped to nosuch_u, which this policy doesn't have/.test(g.message) && g.severity === 1, 'seusers edited: a login mapped to a missing user is an error on its line, without a rebuild', b.diags[seUri]);
  check(has('range', bobL), 'a range the policy rejects (c5000 of 1024 categories) on its line');

  // 4. A contexts file of staff_u (__default__ in CLIP) whose first console entry it can't have.
  const def = rep.mappings.find(m => m.login === '__default__');
  const U = def ? def.user : 'staff_u';
  const own = path.join(app, `${U}_default_contexts`);
  const ownUri = URI.file(own).toString();
  const ownOrig = fs.existsSync(own) ? fs.readFileSync(own, 'utf8') : null;
  const con = def && def.ways.find(w => w.source === 'local_login_t' && w.works3);
  const role = (con && con.v3.ctx.split(':')[1]) || 'staff_r';
  const dom = (con && con.v3.ctx.split(':')[2]) || 'staff_t';
  fs.writeFileSync(own, `system_r:local_login_t:s0\t${role}:nosuch_t:s0 ${role}:${dom}:s0\n${ownOrig || ''}`);
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: ownUri, type: ownOrig == null ? 1 : 2 }] });
  await until(() => (b.diags[ownUri] || []).some(d => d.code === 'skipped'));
  const sk = (b.diags[ownUri] || []).find(d => d.code === 'skipped');
  check(sk && sk.range.start.line === 0 && sk.severity === 3 && new RegExp(`lands in ${U}:${role}:${dom}:.*, not ${U}:${role}:nosuch_t`).test(sk.message) && /there is no type nosuch_t/.test(sk.message),
    `${path.basename(own)} edited: the entry ${U} can't have is passed over, an info on that line`, b.diags[ownUri]);

  // 5. Both files restored: back to what the build had.
  fs.writeFileSync(seusersPath, seOrig);
  if (ownOrig == null) fs.rmSync(own); else fs.writeFileSync(own, ownOrig);
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: seUri, type: 2 }, { uri: ownUri, type: ownOrig == null ? 3 : 2 }] });
  await until(() => !has('nouser', ghostL) && !(b.diags[ownUri] || []).length);
  check(!has('nouser', ghostL) && !has('range', bobL) && !(b.diags[ownUri] || []).length && (b.diags[seUri] || []).length === ds.length, 'restored: the added problems are gone, the build\'s own remain');
  b.proc.kill();
  finish();
})().catch((e) => { console.log(`FAIL ${e.stack}`); process.exit(1); });

function finish() {
  console.log(failures ? `\n${failures} check(s) failed` : '\nall login context e2e checks passed');
  process.exit(failures ? 1 : 0);
}
