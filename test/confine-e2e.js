'use strict';
// The confinement checklist end to end, over LSP on a Linux host that runs the
// same policy as the build (default: the RHEL 9 tree with its spec's settings →
// the targeted policy, the target root@localhost) for chronyd, which runs here:
// the steps without a target, with the target (pushed state, running in
// chronyd_t, denials since today), the domain made permissive, exercise
// commands run on the target, enforce and verify, and the steps after it.
//   TARGET=root@localhost TARGET_PASS_FILE=/path/0600file node test/confine-e2e.js [tree] [spec] [variant]
// Nothing is left changed on the target: the domain is enforced again at the
// end (as it was), a pushed module is rolled back.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { tempDir } = require('./tmpdirs');
const { installedPolicies, detectToolchain } = require('../server/build');

const installed = installedPolicies().find(p => p.active);
if (process.platform !== 'linux' || !installed) { console.log('SKIP: needs Linux running an SELinux policy'); process.exit(0); }
const TARGET = process.env.TARGET || 'root@localhost';
const PASS_FILE = process.env.TARGET_PASS_FILE || null;
if (!PASS_FILE) { console.log('SKIP: TARGET_PASS_FILE (root on the target) needed'); process.exit(0); }
const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/rhel9');
const spec = process.argv[3] || path.join(os.homedir(), 'sepol-test/srpm/selinux-policy.spec');
const variant = process.argv[4] || 'targeted';
const tc = detectToolchain(null);
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }
if (!fs.existsSync(path.join(src, 'Rules.modular')) || !fs.existsSync(spec)) { console.log(`SKIP: need a tree at ${src} and a spec at ${spec}`); process.exit(0); }
if (!fs.existsSync('/usr/sbin/chronyd')) { console.log('SKIP: chronyd is not installed here'); process.exit(0); }

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
const password = fs.readFileSync(PASS_FILE, 'utf8').replace(/\r?\n$/, '');
const by = (r) => Object.fromEntries((r.steps || []).map(s => [s.id, s]));
const states = (r) => (r.steps || []).map(s => `${s.id}:${s.state}`).join(' ');
const show = (r) => { for (const s of r.steps || []) console.log(`     ${s.state.padEnd(7)} ${s.title}: ${s.text}`); };

(async () => {
  const ws = tempDir('selinux-confine-e2e-');
  cp.execFileSync('cp', ['-a', src + '/.', ws]);
  fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let doneIndex, indexed = new Promise(r => (doneIndex = r));
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
  for (const n of ['textDocument/publishDiagnostics', 'selinux/build', 'selinux/checks', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged', 'selinux/loginsChanged', 'selinux/targetsChanged']) conn.onNotification(n, () => {});
  conn.listen();
  const req = (m, p) => conn.sendRequest(m, p || {});
  await req('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: { trusted: true } });
  conn.sendNotification('initialized', {});
  await indexed;
  const sc = await req('selinux/specBuildConfig', { specPath: spec });
  const cfg = sc.configs && sc.configs.find(c => c.variant === variant);
  check(cfg && cfg.makeArgs.some(x => x === `NAME=${installed.name}`), `the spec's ${variant} settings build the ${installed.name} policy (this host runs it)`, sc.error);
  if (!cfg) process.exit(1);
  indexed = new Promise(r => (doneIndex = r));
  conn.sendNotification('workspace/didChangeConfiguration', { settings: { selinux: { build: { tree: { makeArgs: cfg.makeArgs, files: cfg.files } } } } });
  await indexed;
  const finish = async () => { proc.kill(); console.log(failures ? `\n${failures} confine e2e checks FAILED` : '\nall confine e2e checks passed'); process.exit(failures ? 1 : 0); };

  // 1. Before any build or target.
  let r = await req('selinux/confineStatus', { module: 'chronyd', target: null, since: 'today' });
  check(r.module && r.module.domain === 'chronyd_t' && r.module.layer === 'contrib' && !r.module.standalone && states(r) === 'module:done build:todo target:todo push:skip permissive:skip running:skip exercise:skip denials:skip verify:skip', 'chronyd before a build: written; build and connect next', states(r));
  r = await req('selinux/confineStatus', { module: 'nosuchmodule', target: null });
  check(r.module === null && by(r).module.state === 'todo' && /New Service/.test(by(r).module.text), 'an unknown module: the first step says to create it');
  let t0 = Date.now();
  let res = await req('selinux/build', { uri: URI.file(ws).toString() });
  check(res && res.ok && res.packages > 300, `tree build (${((Date.now() - t0) / 1000).toFixed(0)} s, ${res && res.packages} packages)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  if (!res || !res.ok) return finish();
  r = await req('selinux/confineStatus', { module: 'chronyd', target: null });
  check(by(r).build.state === 'done' && /Tree build ok/.test(by(r).build.text) && by(r).target.state === 'todo', 'built: the target is next', states(r));

  // 2. With the target.
  const c = await req('selinux/targetConnect', { spec: TARGET, password });
  check(!c.error && c.facts && c.facts.root && c.facts.policy.name === installed.name, `connected to ${TARGET} as root (${c.label})`, c.error);
  if (c.error) return finish();
  const id = c.id;
  const wasPermissive = (c.facts.permissive || []).includes('chronyd_t');
  t0 = Date.now();
  r = await req('selinux/confineStatus', { module: 'chronyd', target: id, since: 'today' });
  show(r);
  check(r.target && r.target.id === id && r.target.root && by(r).target.state === 'done', `status with the target in ${((Date.now() - t0) / 1000).toFixed(1)} s`, r.target);
  check(r.push && !r.push.error && ['same', 'differs'].includes(r.push.state) && by(r).push.state === (r.push.state === 'same' ? 'done' : 'todo'), `push state: the build's chronyd is ${r.push.state} on the target`, r.push);
  const running = r.services.some(s => s.pids.length);
  check(r.services.length >= 1 && r.services.some(s => s.real === '/usr/sbin/chronyd') && r.units.includes('chronyd.service') && r.programs.includes('/usr/sbin/chronyd'), 'chronyd found on the target: its program, unit', r.services);
  if (running) check(by(r).running.state === 'done' && /in chronyd_t/.test(by(r).running.text) && /chronyd\.service/.test(by(r).running.text), 'running in chronyd_t', by(r).running);
  else console.log('     (chronyd is not running here; the running step is judged later, after the restart)');
  check(by(r).permissive.state === (wasPermissive ? 'done' : 'todo') && by(r).exercise.state === 'todo' && r.denials && !r.denials.error && typeof r.denials.count === 'number' && by(r).denials.state === (r.denials.count ? 'todo' : 'done'), `permissive ${wasPermissive ? 'already' : 'not yet'}; exercise next; ${r.denials.count} denials of chronyd_t today`, { p: by(r).permissive, d: r.denials });
  let pushed = false;
  if (r.push.state !== 'same') {
    const p = await req('selinux/targetPush', { id, modules: ['chronyd'] });
    check(p.ok, 'chronyd pushed so the target runs this build', p.error || p.failed);
    pushed = p.ok;
    r = await req('selinux/confineStatus', { module: 'chronyd', target: id, since: 'push' });
    check(by(r).push.state === 'done' && r.denials.since === 'the last push', 'after the push: the same; denials since the last push', { push: by(r).push, d: r.denials });
  }

  // 3. Permissive for the test run; exercise.
  if (!wasPermissive) {
    const pm = await req('selinux/targetPermissive', { id, domain: 'chronyd_t', on: true });
    check(pm.ok && pm.permissive.includes('chronyd_t'), 'chronyd_t made permissive on the target', pm);
  }
  r = await req('selinux/confineStatus', { module: 'chronyd', target: id, since: 'today' });
  check(by(r).permissive.state === 'done' && /chronyd_t is permissive on/.test(by(r).permissive.text) && by(r).verify.state === 'todo' && /Enforce chronyd_t/.test(by(r).verify.text), 'permissive: done; verify says to enforce', { p: by(r).permissive, v: by(r).verify });
  const ex = await req('selinux/confineExercise', { target: id, commands: ['# a comment', 'chronyc tracking', 'systemctl is-active chronyd.service', 'false', ''] });
  check(!ex.error && ex.ran.length === 3 && ex.ran[0].cmd === 'chronyc tracking' && ex.ran[0].code === 0 && /Reference ID|Stratum|506 Cannot talk/.test(ex.ran[0].out) && ex.ran[1].out.trim() === (running ? 'active' : ex.ran[1].out.trim()) && ex.ran[2].code === 1 && ex.ran.every(x => typeof x.ms === 'number'),
    'exercise: 3 commands ran on the target (comment and blank skipped), chronyc answered, false failed', ex.error || ex.ran);
  r = await req('selinux/confineStatus', { module: 'chronyd', target: id, since: 'today', exercise: ex });
  check(by(r).exercise.state === 'bad' && /1 command failed on .*: false \(exit 1\)/.test(by(r).exercise.text), 'the failed command shows in the exercise step', by(r).exercise);
  check((await req('selinux/confineExercise', { target: id, commands: ['#'] })).error && (await req('selinux/confineExercise', { target: 'root@nowhere', commands: ['true'] })).error, 'no commands / an unconnected target: errors');

  // 4. Enforce and verify.
  t0 = Date.now();
  const v = await req('selinux/confineVerify', { module: 'chronyd', target: id, units: ['chronyd.service'], commands: ['chronyc tracking', 'systemctl is-active chronyd.service'], programs: ['/usr/sbin/chronyd'] });
  console.log(`     verdict: ${v.verdict && v.verdict.text}`);
  for (const p of (v.verdict && v.verdict.problems) || []) console.log(`     - ${p}`);
  check(!v.error && v.enforce && v.enforce.ok && v.restart && v.restart.ok && v.restart.units.length === 1 && v.restart.units[0].state === 'active' && v.exercise.length === 2 && v.exercise.every(x => x.code === 0) && v.denials && !v.denials.error && v.running && v.running.pids.length >= 1 && v.running.domains.join() === 'chronyd_t',
    `enforce and verify in ${((Date.now() - t0) / 1000).toFixed(1)} s: enforced, chronyd.service restarted and active, 2 commands ran, chronyd runs as chronyd_t`, v.error || { enforce: v.enforce, restart: v.restart, exercise: v.exercise.map(x => [x.cmd, x.code]), running: v.running, denials: v.denials });
  check(v.ok === (v.denials.count === 0) && v.verdict && (v.ok ? /enforced on .*: chronyd\.service restarted and active, 2 commands ran, nothing denied/.test(v.verdict.text) : v.verdict.problems.some(p => /denials of chronyd_t while enforcing/.test(p))), `verdict ok=${v.ok} (${v.denials.count} denials while enforcing)`, v.verdict);
  r = await req('selinux/confineStatus', { module: 'chronyd', target: id, since: 'verify', exercise: { ran: v.exercise, at: Date.now() } });
  show(r);
  check(r.denials && r.denials.since === 'the last verify' && by(r).permissive.state === 'todo' && by(r).running.state === 'done' && by(r).exercise.state === 'done' && (!v.ok || (by(r).verify.state === 'done' && by(r).denials.state === 'done')), 'after verifying, since the last verify: enforced (permissive is open again), running in its domain, exercised; verified when nothing was denied', states(r));
  const vb = await req('selinux/targetDenials', { id: 'root@nowhere', since: 'verify' });
  check(vb.error, 'denials since the last verify need the target');
  check(!(await req('selinux/confineVerify', { module: 'chronyd', target: 'root@nowhere' })).ok && /not a service module/.test((await req('selinux/confineVerify', { module: 'nosuch', target: id })).error), 'verify refusals: unconnected target, unknown module');

  // 5. Leave the target as it was.
  if (wasPermissive) await req('selinux/targetPermissive', { id, domain: 'chronyd_t', on: true });
  if (pushed) { const rb = await req('selinux/targetRollback', { id }); check(rb.ok, 'the pushed chronyd rolled back', rb.error || rb.failed); await req('selinux/targetRun', { id, command: `rm -rf ${rb.dir || ''} /root/selinux-policy-tools/push-*` }); }
  await req('selinux/targetDisconnect', { id });
  await finish();
})().catch((e) => { console.error(e); process.exit(1); });
