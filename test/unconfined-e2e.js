// What runs unconfined on this host, over LSP on a Linux host running the
// targeted policy: the running policy's view (sshd confined in sshd_t with its
// unit, package and port; every row judged), then a tree build's view (default:
// a copy of CLIP for RHEL 9): what the lockdown would do to this host's
// services.
//   node test/unconfined-e2e.js [tree-dir]
// Needs Linux with python3-setools; the tree part also the build toolchain.
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
const finish = () => { console.log(failures ? `\n${failures} unconfined e2e checks FAILED` : '\nall unconfined e2e checks passed'); process.exit(failures ? 1 : 0); };

(async () => {
  // 1. The running policy.
  const ws0 = tempDir('selinux-unconfined-e2e-');
  fs.writeFileSync(path.join(ws0, 'readme.txt'), 'empty workspace\n');
  const a = start(ws0);
  await a.init();
  let t0 = Date.now();
  const r = await a.conn.sendRequest('selinux/unconfined', {});
  check(!r.error && r.rows && r.rows.length > 10 && r.policy && r.policy.active && r.host && r.host.units > 10 && r.host.processes > 20,
    `running ${installed.name}: ${r.rows && r.rows.length} programs from ${r.host && r.host.units} services and ${r.host && r.host.processes} processes (${Date.now() - t0} ms)`, r.error || r.host);
  const sshd = (r.rows || []).find(x => x.real === '/usr/sbin/sshd');
  check(sshd && sshd.type === 'sshd_exec_t' && sshd.hostDomains.includes('sshd_t') && sshd.policyDomain === 'sshd_t' && sshd.verdict === 'confined' && sshd.units.some(u => u.id === 'sshd.service' && u.active === 'active') && /openssh/.test(sshd.pkg || '') && sshd.running,
    'sshd: sshd_exec_t → sshd_t here and in the policy, sshd.service active, package openssh-server', sshd);
  const odd = (r.rows || []).filter(x => !(['unconfined', 'confined', 'nostart', 'unknown'].includes(x.verdict) && x.real.startsWith('/') && Array.isArray(x.units) && Array.isArray(x.listens)));
  check(!odd.length, 'every row has a verdict, a path, units and ports', odd.slice(0, 3));
  const sessions = (r.rows || []).filter(x => x.units.some(u => /^user@/.test(u.id)) || (!x.units.length && x.users.some(u => /^\d{4,}$|^[a-z]+\+$/.test(u))));
  check(!sessions.length && (r.rows || []).every(x => x.users.every(u => !u.endsWith('+'))), 'no login sessions among the rows (user@ units); user names not cut short by ps', sessions.slice(0, 4).map(x => ({ real: x.real, users: x.users, units: x.units.map(u => u.id) })));
  check(r.summary && r.summary.rows === r.rows.length && r.summary.unconfined + r.summary.confined + r.summary.nostart <= r.rows.length && r.unconfined.includes('unconfined_service_t') && r.unconfined.length > 5,
    `summary: ${r.summary && r.summary.unconfined} unconfined, ${r.summary && r.summary.confined} confined, ${r.summary && r.summary.nostart} can't start, ${r.summary && r.summary.notRunning} not running; ${r.unconfined && r.unconfined.length} domains confine nothing`, r.summary);
  const unc = (r.rows || []).filter(x => x.verdict === 'unconfined');
  for (const x of unc.slice(0, 6)) console.log(`     unconfined: ${x.real} (${x.type || 'no label'}) runs as ${x.hostDomains.join(',') || '-'}, policy ${x.policyDomain || x.how}; ${x.units.map(u => u.id).join(' ') || `pid ${x.pids.join(',')}`}`);
  check(unc.every(x => (x.hostDomains[0] && r.unconfined.includes(x.hostDomains[0])) || (x.policyDomain && r.unconfined.includes(x.policyDomain))), 'each unconfined row runs (or would run) in one of those domains');
  check(r.rows.findIndex(x => x.verdict === 'confined') >= unc.length || !unc.length, 'unconfined rows come first');
  check(r.locs && r.locs.sshd_t === undefined || typeof r.locs.sshd_t === 'object', 'locs: a map (empty without tree sources)');
  a.proc.kill();

  // 2. A tree build: what the lockdown would do to this host's services.
  const tc = detectToolchain(null);
  if (!tc.ok || !fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP tree part: ${tc.reason || `no tree at ${src}`}`); return finish(); }
  const ws = tempDir('selinux-unconfined-e2e-tree-');
  cp.execFileSync('cp', ['-a', src + '/.', ws]);
  fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
  const b = start(ws, { build: { tree: { makeArgs: clipArgs(src) } } });
  await b.init();
  t0 = Date.now();
  const res = await b.conn.sendRequest('selinux/build', { uri: URI.file(ws).toString() });
  check(res && res.ok, `tree build (${((Date.now() - t0) / 1000).toFixed(0)} s)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  t0 = Date.now();
  const r2 = await b.conn.sendRequest('selinux/unconfined', { against: 'build' });
  // (The processes are read again by a new server: a few may have come or gone since.)
  const shared = (r2.rows || []).filter(x => r.rows.some(y => y.real === x.real)).length;
  check(!r2.error && r2.policy && r2.policy.build && shared >= Math.min(r.rows.length, r2.rows.length) * 0.8, `against the build: the same programs judged by it (${r2.rows && r2.rows.length}, ${shared} in common; ${Date.now() - t0} ms)`, r2.error || { rows: r2.rows && r2.rows.length, was: r.rows.length });
  const sshd2 = (r2.rows || []).find(x => x.real === '/usr/sbin/sshd');
  check(sshd2 && sshd2.type === 'sshd_exec_t' && sshd2.policyDomain === 'sshd_t' && sshd2.verdict === 'confined' && r2.locs && r2.locs.sshd_t && /ssh\.te$/.test(r2.locs.sshd_t.p), 'sshd: sshd_t in the build too, its declaration located in the tree', sshd2 && { ...sshd2, loc: r2.locs && r2.locs.sshd_t });
  const changed = (r2.rows || []).filter(x => x.differs);
  for (const x of changed.slice(0, 8)) console.log(`     ${x.real}: here ${x.hostDomains.join(',') || '-'} (${x.type || 'no label'}), under the build ${x.policyDomain || `${x.how}`} → ${x.verdict}`);
  check(changed.length > 0 && changed.every(x => x.policyDomain !== x.hostDomains[0]), `${changed.length} programs would run differently under the build (chronyd, pcp, … have no module in CLIP)`, changed.slice(0, 3));
  // CLIP has no unconfined_service_t: a service with a bin_t program lands in initrc_t / init_t (its type_transition from init_t), or can't start.
  check(!(r2.unconfined || []).includes('unconfined_service_t') && changed.some(x => x.verdict === 'nostart' || (x.verdict === 'unconfined' && x.units.length && r2.unconfined.includes(x.policyDomain))),
    `no unconfined_service_t in the build: this host's services without a CLIP module would run in ${[...new Set(changed.map(x => x.policyDomain || 'nothing'))].join('/')} (${r2.summary.nostart} can't start, ${r2.summary.unconfined} unconfined)`, r2.summary);
  b.proc.kill();
  finish();
})().catch((e) => { console.error(e); process.exit(1); });
