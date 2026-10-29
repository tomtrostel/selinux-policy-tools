// Context files over LSP on a Linux host: the running policy's context files all
// load; then on a copy of a tree (default: CLIP for RHEL 9) the problems after a
// build are diagnostics on the lines that cause them: an invalid context and a
// duplicate path in a module's .fc (where `make validate` fails), an x_contexts
// entry edited on disk (no rebuild), and a home-directory line genhomedircon
// would leave out for a user whose prefix is one of its roles.
//   node test/ctxfiles-e2e.js [tree-dir]
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
  // 1. The running targeted policy: everything loads (notes at most).
  const ws0 = tempDir('selinux-ctxfiles-e2e-');
  fs.writeFileSync(path.join(ws0, 'readme.txt'), 'empty workspace\n');
  const a = start(ws0);
  await a.init();
  let t0 = Date.now();
  const run = await a.conn.sendRequest('selinux/contextFiles', {});
  check(!run.error && run.policy && run.policy.active && run.fc && run.fc.main.count > 1000 && !run.problems.some(p => p.severity !== 'info'),
    `running ${installed.name}: ${run.fc && run.fc.main.count} file_contexts lines, ${run.fc && run.fc.homedirs.count} home lines, ${run.files && run.files.filter(f => f.exists).length} context files, no errors or warnings (${run.problems && run.problems.length} notes, ${Date.now() - t0} ms)`, run.error || run.problems);
  check(run.files && run.files.find(f => f.name === 'x_contexts').exists && run.files.find(f => f.name === 'media').exists && run.fc.associateChecked > 1000, 'the application files are read from contexts/ (media from contexts/files/), every type checked for associate');
  a.proc.kill();

  // 2. A tree build.
  const tc = detectToolchain(null);
  if (!tc.ok || !fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP tree part: ${tc.reason || `no tree at ${src}`}`); return finish(); }
  const ws = tempDir('selinux-ctxfiles-e2e-tree-');
  cp.execFileSync('cp', ['-a', src + '/.', ws]);
  fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
  const args = clipArgs(src);
  const type = (args.find(x => /^TYPE=/.test(x)) || 'TYPE=mcs').slice(5);
  const app = path.join(ws, 'config', `appconfig-${type}`);
  const b = start(ws, { build: { tree: { makeArgs: args } } });
  await b.init();
  const buildTree = async () => { const t = Date.now(); const r = await b.conn.sendRequest('selinux/build', { uri: URI.file(ws).toString() }); return { r, s: ((Date.now() - t) / 1000).toFixed(0) }; };
  let { r: res, s } = await buildTree();
  check(res && res.ok, `tree build (${s} s)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  const rep = await b.conn.sendRequest('selinux/contextFiles', { against: 'build' });
  check(!rep.error && rep.policy.build && rep.fc.build && rep.fc.templates > 10 && rep.homes.length >= 2 && rep.homes.every(h => h.dropped === 0) && !rep.problems.some(p => p.severity === 'error'),
    `build: ${rep.fc && rep.fc.main.count} file-context lines, ${rep.fc && rep.fc.templates} home templates written for ${rep.homes && rep.homes.map(h => h.user).join(', ')}, no errors`, rep.error || rep.problems.filter(p => p.severity === 'error'));
  for (const p of (rep.problems || []).filter(x => x.severity !== 'info')) console.log(`     ${p.severity}: ${p.text.slice(0, 200)}`);
  const ctx = (uri) => (b.diags[uri] || []).filter(d => d.source === 'selinux-contexts');

  // 3. A module's .fc with an invalid context and a duplicate path: make validate fails; the lines are flagged.
  const fcPath = path.join(ws, 'policy', 'modules', 'system', 'logging.fc');
  const fcUri = URI.file(fcPath).toString();
  const fcOrig = fs.readFileSync(fcPath, 'utf8');
  const dupSpec = (/^(\/\S+)\s+--\s+gen_context/m.exec(fcOrig) || [])[1];
  const added = `/opt/ctxtest\t--\tgen_context(system_u:object_r:ctxtest_nosuch_t,s0)\n${dupSpec}\t--\tgen_context(system_u:object_r:etc_t,s0)\n`;
  fs.writeFileSync(fcPath, fcOrig.replace(/\n*$/, '\n') + added);
  const badL = fcOrig.replace(/\n*$/, '\n').split('\n').length - 1;
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: fcUri, type: 2 }] });
  ({ r: res, s } = await buildTree());
  check(res && !res.ok, `rebuilt with the bad lines: make validate fails (${s} s)`);
  await until(() => ctx(fcUri).length >= 2);
  const inv = ctx(fcUri).find(d => d.code === 'fc-main'), dup = ctx(fcUri).find(d => d.code === 'fc-duplicate');
  check(inv && inv.range.start.line === badL && inv.severity === 1 && /there is no type ctxtest_nosuch_t/.test(inv.message) && /make validate/.test(inv.message),
    'an invalid context: an error on its .fc line, saying make validate rejects it', ctx(fcUri));
  check(dup && dup.range.start.line === badL + 1 && /Multiple different specifications/.test(dup.message) && dup.relatedInformation && dup.relatedInformation[0].location.uri === fcUri,
    `${dupSpec} labeled twice: an error on the second line, pointing at the first`, dup);
  fs.writeFileSync(fcPath, fcOrig);
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: fcUri, type: 2 }] });
  ({ r: res, s } = await buildTree());
  await until(() => !ctx(fcUri).length);
  check(res && res.ok && !ctx(fcUri).length, `restored and rebuilt: the .fc lines are clean again (${s} s)`);

  // 4. x_contexts edited on disk: checked again without a rebuild.
  const xPath = path.join(app, 'x_contexts');
  const xUri = URI.file(xPath).toString();
  const xOrig = fs.readFileSync(xPath, 'utf8');
  const xL = xOrig.replace(/\n*$/, '\n').split('\n').length - 1;
  fs.writeFileSync(xPath, `${xOrig.replace(/\n*$/, '\n')}property CTXTEST\tsystem_u:object_r:ctxtest_xproperty_t:s0\n`);
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: xUri, type: 2 }] });
  await until(() => ctx(xUri).some(d => d.range.start.line === xL));
  const xd = ctx(xUri).find(d => d.range.start.line === xL);
  const xserver = rep.files.find(f => f.name === 'x_contexts');
  check(xd && /there is no type ctxtest_xproperty_t/.test(xd.message) && xd.range.start.character === 'property CTXTEST\t'.length && (xserver.unused ? xd.severity === 3 : xd.severity === 1),
    `x_contexts edited: the entry is flagged on its context without a rebuild (${xserver.unused ? 'info: no X server in this policy' : 'error'})`, ctx(xUri));
  fs.writeFileSync(xPath, xOrig);
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: xUri, type: 2 }] });
  await until(() => !ctx(xUri).some(d => d.range.start.line === xL));
  check(!ctx(xUri).some(d => d.range.start.line === xL), 'restored: gone again');

  // 5. A login mapped to a user whose prefix is one of its roles: genhomedircon drops its home lines.
  const usersPath = path.join(ws, 'policy', 'users');
  const usersOrig = fs.readFileSync(usersPath, 'utf8');
  const seusersPath = path.join(app, 'seusers');
  const seUri = URI.file(seusersPath).toString();
  const seOrig = fs.readFileSync(seusersPath, 'utf8');
  const staff = /^gen_user\(staff_u,\s*\w+,/m.exec(usersOrig);
  fs.writeFileSync(usersPath, `${usersOrig.replace(/\n*$/, '\n')}gen_user(ctxtest_u, staff_r, staff_r, s0, s0)\n`);
  fs.writeFileSync(seusersPath, `${seOrig.replace(/\n*$/, '\n')}ctxtester:ctxtest_u:s0\n`);
  const seL = seOrig.replace(/\n*$/, '\n').split('\n').length - 1;
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: URI.file(usersPath).toString(), type: 2 }, { uri: seUri, type: 2 }] });
  ({ r: res, s } = await buildTree());
  check(staff && res && res.ok, `a user ctxtest_u with prefix staff_r (its role) added and built (${s} s)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  await until(() => (b.diags[seUri] || []).some(d => d.code === 'homedir'));
  const hd = (b.diags[seUri] || []).find(d => d.code === 'homedir');
  check(hd && hd.range.start.line === seL && hd.severity === 2 && /leaves \d+ of \d+ home-directory lines out for ctxtester \(ctxtest_u\)/.test(hd.message) && /prefix staff_r is also one of its roles/.test(hd.message)
    && (hd.relatedInformation || []).some(x => /\.fc$/.test(URI.parse(x.location.uri).fsPath)), 'genhomedircon: the login\'s seusers line says its home lines are left out and why, with the template lines', b.diags[seUri]);
  check((b.diags[seUri] || []).every(d => d.source === 'selinux-contexts' || d.source === 'selinux-logins'), 'seusers carries both reports\' diagnostics side by side');
  fs.writeFileSync(usersPath, usersOrig);
  fs.writeFileSync(seusersPath, seOrig);
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: URI.file(usersPath).toString(), type: 2 }, { uri: seUri, type: 2 }] });
  ({ r: res, s } = await buildTree());
  await until(() => !(b.diags[seUri] || []).some(d => d.code === 'homedir'));
  check(res && res.ok && !(b.diags[seUri] || []).some(d => d.code === 'homedir'), `restored and rebuilt: no home lines left out (${s} s)`);
  b.proc.kill();
  finish();
})().catch((e) => { console.log(`FAIL ${e.stack}`); process.exit(1); });

function finish() {
  console.log(failures ? `\n${failures} check(s) failed` : '\nall context file e2e checks passed');
  process.exit(failures ? 1 : 0);
}
