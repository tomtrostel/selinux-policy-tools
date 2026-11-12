// Booleans over LSP on a Linux host: the running policy's booleans (values,
// what they switch), then a tree build (default: a copy of CLIP for RHEL 9)
// with its sources' declarations and booleans.conf; a boolean set in
// booleans.conf through selinux/booleanSet, rebuilt, comes back changed.
//   node test/booleans-e2e.js [tree-dir]
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { tempDir } = require('./tmpdirs');
const { installedPolicies, detectToolchain } = require('../server/build');
const { clipArgs } = require('./clip-args');

const installed = installedPolicies().find(p => p.active);
if (process.platform !== 'linux' || !installed) { console.log('SKIP: needs Linux running an SELinux policy'); process.exit(0); }
const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
function start(ws, initOptions = {}) {
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let doneIndex;
  const indexed = new Promise(r => (doneIndex = r));
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
  for (const n of ['textDocument/publishDiagnostics', 'selinux/build', 'selinux/checks', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged', 'selinux/loginsChanged']) conn.onNotification(n, () => {});
  conn.listen();
  return { proc, conn, init: async () => { await conn.sendRequest('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: initOptions }); conn.sendNotification('initialized', {}); await indexed; } };
}
const finish = () => { console.log(failures ? `\n${failures} booleans e2e checks FAILED` : '\nall booleans e2e checks passed'); process.exit(failures ? 1 : 0); };

(async () => {
  // 1. The running policy.
  const ws0 = tempDir('selinux-booleans-e2e-');
  fs.writeFileSync(path.join(ws0, 'readme.txt'), 'empty workspace\n');
  const a = start(ws0);
  await a.init();
  let t0 = Date.now();
  const r = await a.conn.sendRequest('selinux/booleans', {});
  check(!r.error && r.rows && r.rows.length > 100 && r.policy && r.policy.active && !r.conf.editable, `running ${installed.name}: ${r.rows && r.rows.length} booleans (${Date.now() - t0} ms)`, r.error || r.summary);
  const getsebool = (n) => { try { return /-->\s+on/.test(cp.execFileSync('getsebool', [n], { encoding: 'utf8' })); } catch { return null; } };
  const sample = (r.rows || []).filter(x => x.running != null).slice(0, 40);
  const agree = sample.filter(x => getsebool(x.name) === x.running).length;
  check(sample.length && agree === sample.length, `running values agree with getsebool for ${agree} of ${sample.length} sampled booleans`, sample.filter(x => getsebool(x.name) !== x.running).slice(0, 3).map(x => x.name));
  const ssh = (r.rows || []).find(x => x.name === 'ssh_sysadm_login');
  check(ssh && ssh.inPolicy && ssh.compiled != null && ssh.running != null && ssh.on && ssh.on.count > 0 && ssh.on.domains.includes('sshd_t') && ssh.declared === false,
    `ssh_sysadm_login: compiled ${ssh && ssh.compiled}, running ${ssh && ssh.running}, switches ${ssh && ssh.on.count} rules for ${ssh && ssh.on.domains.join(',')}`, ssh);
  check((r.rows || []).every(x => ['boolean', 'object'].includes(typeof x.effective) && x.effective !== null) && r.summary.on + r.summary.off === r.summary.total, 'every row has an effective value; the summary adds up', r.summary);
  const changed = (r.rows || []).filter(x => x.changed);
  console.log(`     changed on this host: ${changed.slice(0, 8).map(x => `${x.name}=${x.running ? 'on' : 'off'}`).join(', ') || 'none'}`);
  a.proc.kill();

  // 2. A tree build: declarations, booleans.conf, setting one.
  const tc = detectToolchain(null);
  if (!tc.ok || !fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP tree part: ${tc.reason || `no tree at ${src}`}`); return finish(); }
  const ws = tempDir('selinux-booleans-e2e-tree-');
  cp.execFileSync('cp', ['-a', src + '/.', ws]);
  fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
  const b = start(ws, { build: { tree: { makeArgs: clipArgs(src) } } });
  await b.init();
  t0 = Date.now();
  let res = await b.conn.sendRequest('selinux/build', { uri: URI.file(ws).toString() });
  check(res && res.ok, `tree build (${((Date.now() - t0) / 1000).toFixed(0)} s)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  const r2 = await b.conn.sendRequest('selinux/booleans', { against: 'build' });
  check(!r2.error && r2.policy && r2.policy.build && r2.rows.length > 50 && r2.conf.editable && /booleans\.conf$/.test(r2.conf.path || ''), `against the build: ${r2.rows && r2.rows.length} booleans, booleans.conf ${r2.conf && r2.conf.path}`, r2.error || r2.conf);
  const declared = (r2.rows || []).filter(x => x.declared && x.inPolicy);
  const oddLoc = declared.filter(x => !(x.loc && /\.te(\.in)?$/.test(x.loc.p) && x.loc.p.startsWith(ws)));
  const noDefault = declared.filter(x => x.source == null);
  // Booleans a template declares (allow_httpd_$1_script_anon_write) have no default of their own on the pattern.
  check(declared.length > 50 && !oddLoc.length && declared.some(x => x.desc) && noDefault.length < 10 && noDefault.every(x => /_script_/.test(x.name)), `${declared.length} declared in the tree's sources with their location, description and default (${noDefault.length} template-generated without one)`, { oddLoc: oddLoc.slice(0, 3).map(x => [x.name, x.loc]), noDefault: noDefault.slice(0, 5).map(x => x.name) });
  // CLIP's booleans.conf names booleans of modules that are off too: only the compiled ones can follow it.
  const fromConf = (r2.rows || []).filter(x => x.conf != null && x.inPolicy);
  const disagree = fromConf.filter(x => x.compiled !== x.conf);
  check(fromConf.length > 5 && !disagree.length, `booleans.conf sets ${fromConf.length} of the compiled booleans; the compiled defaults follow it (${(r2.rows || []).filter(x => x.conf != null && !x.inPolicy).length} named there are not in the policy)`, disagree.slice(0, 4).map(x => [x.name, x.conf, x.compiled, x.source]));
  // Set one that booleans.conf doesn't name yet, away from its declared default.
  const pick = declared.find(x => x.conf == null && x.source != null && x.on && x.on.count > 0);
  check(pick, `a declared boolean to set: ${pick && pick.name} (declared ${pick && (pick.source ? 'on' : 'off')})`);
  const plan = await b.conn.sendRequest('selinux/booleanSet', { name: pick.name, value: !pick.source });
  check(plan && plan.path === r2.conf.path && plan.inserted[0] === `${pick.name} = ${!pick.source ? 'true' : 'false'}` && typeof plan.line === 'number', 'booleanSet: a plan for booleans.conf', plan);
  fs.writeFileSync(plan.path, plan.text);
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: URI.file(plan.path).toString(), type: 2 }] });
  await new Promise(r => setTimeout(r, 800));
  t0 = Date.now();
  res = await b.conn.sendRequest('selinux/build', { uri: URI.file(ws).toString() });
  check(res && res.ok, `rebuilt with ${pick.name} = ${!pick.source} (${((Date.now() - t0) / 1000).toFixed(0)} s)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  const r3 = await b.conn.sendRequest('selinux/booleans', { against: 'build' });
  const after = (r3.rows || []).find(x => x.name === pick.name);
  check(after && after.conf === !pick.source && after.compiled === !pick.source && after.changed && after.effective === !pick.source, `${pick.name}: booleans.conf and the compiled default now ${!pick.source ? 'on' : 'off'}, marked changed`, after);
  const again = await b.conn.sendRequest('selinux/booleanSet', { name: pick.name, value: !pick.source });
  check(again && again.already, 'setting it again: already so');
  b.proc.kill();
  finish();
})().catch((e) => { console.error(e); process.exit(1); });
