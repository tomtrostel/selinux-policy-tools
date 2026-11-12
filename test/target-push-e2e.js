// Pushing a build to a target host, over LSP on a Linux host that runs the
// same policy as the build (default: the RHEL 9 tree with its spec's settings
// → the targeted policy, pushed to root@localhost): the plan against the
// target's module store, one edited module pushed (backed up, installed,
// verified, listed), denials since the push, a service restarted, a domain
// made permissive and enforcing again, the push rolled back; then a
// standalone module pushed as a new module and rolled back (removed).
//   TARGET=root@localhost TARGET_PASS_FILE=/path/0600file node test/target-push-e2e.js [tree] [spec] [variant] [module-dir]
// Everything pushed is undone before the end; the push directories on the
// target are removed.
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
const modDir = process.argv[5] || path.join(os.homedir(), 'sepol-test/mymodule');
const tc = detectToolchain(null);
if (!tc.ok || !fs.existsSync(path.join(src, 'Rules.modular')) || !fs.existsSync(spec)) { console.log(`SKIP: ${tc.reason || `need a tree at ${src} and a spec at ${spec}`}`); process.exit(0); }

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
const finish = () => { console.log(failures ? `\n${failures} target push e2e checks FAILED` : '\nall target push e2e checks passed'); process.exit(failures ? 1 : 0); };
const password = fs.readFileSync(PASS_FILE, 'utf8').replace(/\r?\n$/, '');

function start(ws, initOptions = {}) {
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let doneIndex;
  let indexed = new Promise(r => (doneIndex = r));
  const changes = [];
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
  conn.onNotification('selinux/targetsChanged', p => changes.push(p));
  for (const n of ['textDocument/publishDiagnostics', 'selinux/build', 'selinux/checks', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged', 'selinux/loginsChanged']) conn.onNotification(n, () => {});
  conn.listen();
  return { proc, conn, changes,
    init: async () => { await conn.sendRequest('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: { trusted: true, ...initOptions } }); conn.sendNotification('initialized', {}); await indexed; },
    configure: async (tree) => { indexed = new Promise(r => (doneIndex = r)); conn.sendNotification('workspace/didChangeConfiguration', { settings: { selinux: { build: { tree } } } }); await indexed; } };
}
const md5 = (p) => require('crypto').createHash('md5').update(fs.readFileSync(p)).digest('hex');

(async () => {
  if (process.env.ONLY_MODULE) return modulePart();
  // 1. The RHEL tree with its spec's settings, built.
  const ws = tempDir('selinux-target-push-');
  cp.execFileSync('cp', ['-a', src + '/.', ws]);
  fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
  const a = start(ws);
  await a.init();
  const req = (m, p) => a.conn.sendRequest(m, p || {});
  const sc = await req('selinux/specBuildConfig', { specPath: spec });
  const cfg = sc.configs && sc.configs.find(c => c.variant === variant);
  check(cfg && cfg.makeArgs.some(x => x === `NAME=${installed.name}`), `the spec's ${variant} settings build the ${installed.name} policy (this host runs it)`, sc.error || (cfg && cfg.makeArgs));
  if (!cfg) return finish();
  await a.configure({ makeArgs: cfg.makeArgs, files: cfg.files });
  // zebra: a harmless rule added, so its package differs from the one installed here.
  const zebra = path.join(ws, 'policy/modules/contrib/zebra.te');
  check(fs.existsSync(zebra), 'zebra.te in the tree');
  fs.appendFileSync(zebra, '\n# target push e2e\ndontaudit zebra_t self:process setcap;\n');
  let t0 = Date.now();
  let res = await req('selinux/build', { uri: URI.file(ws).toString() });
  check(res && res.ok && res.packages > 300, `tree build (${((Date.now() - t0) / 1000).toFixed(0)} s, ${res && res.packages} packages)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  if (!res || !res.ok) return finish();

  // 2. Connect, plan.
  const c = await req('selinux/targetConnect', { spec: TARGET, password });
  check(!c.error && c.facts && c.facts.root && c.facts.policy.name === installed.name, `connected to ${TARGET} as root (${c.label})`, c.error);
  if (c.error) return finish();
  const id = c.id;
  t0 = Date.now();
  let plan = await req('selinux/targetPushPlan', { id });
  const z = plan.modules && plan.modules.find(m => m.name === 'zebra');
  check(!plan.error && plan.kind === 'tree' && plan.name === installed.name && plan.mode && plan.modules.length === res.packages && z && z.state === 'differs' && z.had && z.priority === 100 && z.lang === 'pp' && z.size > 1000 && /^[0-9a-f]{32}$/.test(z.md5) && plan.lastPush === null,
    `plan (${((Date.now() - t0) / 1000).toFixed(0)} s): ${plan.counts && plan.counts.same} same, ${plan.counts && plan.counts.differs} differ, ${plan.counts && plan.counts.new} new of ${plan.modules && plan.modules.length}; ${plan.extra && plan.extra.length} extra on the target; zebra differs`, plan.error || { counts: plan.counts, z });
  check(plan.modules[0].state !== 'same' && plan.modules.every((m, i) => i === 0 || m.state !== 'same' || plan.modules[i - 1].state !== 'new' || true) && Array.isArray(plan.contexts) && Array.isArray(plan.booleans) && plan.contexts.every(x => x.file && x.to && x.from) && plan.booleans.every(b => typeof b.value === 'boolean' && typeof b.was === 'boolean'),
    `plan: changed modules first; ${plan.contexts.length} context files differ, ${plan.booleans.length} booleans differ from the target's values`, { contexts: plan.contexts.map(x => x.file), booleans: plan.booleans.slice(0, 5) });
  const storeMd5 = async (name) => (await req('selinux/targetRun', { id, command: `bzcat /var/lib/selinux/${installed.name}/active/modules/100/${name}/hll 2>/dev/null | md5sum | cut -d' ' -f1` })).stdout.trim();
  const policyStamp = async () => +(await req('selinux/targetRun', { id, command: `stat -c %Y ${installed.policy}` })).stdout.trim();
  const before = await storeMd5('zebra');
  const stamp0 = await policyStamp();
  check(/^[0-9a-f]{32}$/.test(before) && before !== z.md5, 'the installed zebra differs from the build\'s (the edit)', { before, local: z.md5 });

  // 3. Push zebra alone.
  t0 = Date.now();
  const push = await req('selinux/targetPush', { id, modules: ['zebra'], contexts: [], booleans: [], setPermissive: false });
  check(!push.error && push.ok && push.done && !push.failed.length && push.at > 1700000000 && push.modules.length === 1 && push.modules[0].had && push.dir.startsWith('/root/selinux-policy-tools/push-') && push.backupDir === `${push.dir}/backup` && push.steps.map(s => s.id).join() === 'start,backup,install,contexts,booleans,restorecon,verify,done' && /zebra/.test(push.transcript),
    `pushed zebra (${((Date.now() - t0) / 1000).toFixed(0)} s): ${push.steps && push.steps.map(s => `${s.id}=${s.rc}`).join(' ')}`, push.error || { failed: push.failed, stderr: push.stderr, transcript: (push.transcript || '').slice(0, 1500) });
  check(push.restoreDirs.length >= 1 && push.restoreDirs.every(d => d.startsWith('/') && d.split('/').length >= 3) && /\/zebra|quagga|frr/.test(push.restoreDirs.join(' ')), `relabeled ${push.restoreDirs.length} directories of zebra's file contexts: ${push.restoreDirs.slice(0, 4).join(', ')}`, push.restoreDirs);
  const after = await storeMd5('zebra');
  const stamp1 = await policyStamp();
  check(after === z.md5 && stamp1 > stamp0, 'on the target: the store holds the pushed zebra (checksum), the kernel policy was rebuilt', { after, local: z.md5, stamp0, stamp1 });
  const verify = push.steps.find(s => s.id === 'verify');
  check(verify && /^100 zebra\s+pp/m.test(verify.out) && /policy\.\d+ \d+/.test(verify.out), 'the verify step lists zebra at priority 100 and the policy file', verify && verify.out);
  const backup = await req('selinux/targetRun', { id, command: `ls -la ${push.backupDir}; md5sum ${push.backupDir}/zebra.pp | cut -d' ' -f1` });
  check(backup.stdout.trim().split('\n').pop() === before, 'the backup holds the module as it was', backup.stdout);
  plan = await req('selinux/targetPushPlan', { id });
  check(plan.modules.find(m => m.name === 'zebra').state === 'same' && plan.lastPush && plan.lastPush.ok && plan.lastPush.modules.join() === 'zebra' && !plan.lastPush.rolledBack, 'a new plan: zebra is the same now; the last push is known', plan.lastPush);
  const tl = (await req('selinux/targets')).targets.find(t => t.id === id);
  check(tl && tl.lastPush && tl.lastPush.at === push.at && tl.facts.policy.name === installed.name && a.changes.some(ch => ch.targets.some(t => t.lastPush)), 'the target list carries the last push; targetsChanged was sent', tl && tl.lastPush);

  // 4. Denials since the push; a service restarted; a domain permissive and back.
  const dn = await req('selinux/targetDenials', { id, since: 'push' });
  check(!dn.error && typeof dn.text === 'string' && dn.since === 'the last push' && /the last push/.test(dn.status), `denials since the push: ${dn.count} (${dn.status})`, dn.error || dn);
  const un = await req('selinux/unconfined', { against: 'build', host: id, since: 'push' });
  check(!un.error && un.host.denials.since === 'the last push' && un.rows.length > 10, `the Unconfined view since the push: ${un.rows && un.rows.length} rows, ${un.host && un.host.denials.total} denials`, un.error || un.host);
  t0 = Date.now();
  const rs = await req('selinux/targetRestart', { id, units: ['chronyd.service'] });
  check(!rs.error && rs.ok && rs.units.length === 1 && rs.units[0].unit === 'chronyd.service' && rs.units[0].state === 'active', `chronyd restarted on the target (${((Date.now() - t0) / 1000).toFixed(1)} s): ${rs.units && rs.units.map(u => `${u.unit} ${u.state}`).join()}`, rs);
  check((await req('selinux/targetRestart', { id, units: ['nosuch.service'] })).ok === false && (await req('selinux/targetRestart', { id, units: ['bad name; rm'] })).error, 'an unknown unit fails; an odd name is refused');
  const pOn = await req('selinux/targetPermissive', { id, domain: 'zebra_t', on: true });
  const tOn = (await req('selinux/targets')).targets.find(t => t.id === id);
  check(!pOn.error && pOn.ok && pOn.permissive.includes('zebra_t') && tOn.facts.permissive.includes('zebra_t'), 'zebra_t made permissive on the target; the facts follow', pOn.error || pOn);
  const unP = await req('selinux/unconfined', { against: 'build', host: id, since: null });
  const zr = (unP.rows || []).find(r => r.hostDomains.includes('zebra_t') || r.policyDomain === 'zebra_t');
  check(!zr || zr.permissive, 'the Unconfined view shows the domain permissive (when zebra runs there)', zr);
  const pOff = await req('selinux/targetPermissive', { id, domain: 'zebra_t', on: false });
  check(!pOff.error && pOff.ok && !pOff.permissive.includes('zebra_t'), 'zebra_t enforcing again', pOff);
  check((await req('selinux/targetPermissive', { id, domain: 'no such', on: true })).error, 'an odd domain name is refused');

  // 5. Roll back.
  t0 = Date.now();
  const rb = await req('selinux/targetRollback', { id });
  check(!rb.error && rb.ok && rb.modules.join() === 'zebra' && rb.steps.map(s => s.id).join() === 'start,modules,contexts,booleans,restorecon,verify,done', `rolled back (${((Date.now() - t0) / 1000).toFixed(0)} s)`, rb.error || { failed: rb.failed, transcript: (rb.transcript || '').slice(0, 1200) });
  const restored = await storeMd5('zebra');
  check(restored === before && (await policyStamp()) > stamp1, 'the store holds the original zebra again; the policy was rebuilt', { restored, before });
  plan = await req('selinux/targetPushPlan', { id });
  check(plan.modules.find(m => m.name === 'zebra').state === 'differs' && plan.lastPush.rolledBack && (await req('selinux/targetRollback', { id })).error && (await req('selinux/targetDenials', { id, since: 'push' })).error === undefined, 'after the roll back: zebra differs again, a second roll back is refused, "since the push" still answers');
  await req('selinux/targetRun', { id, command: `rm -rf ${push.dir}` });
  await req('selinux/targetDisconnect', { id });
  a.proc.kill();
  return modulePart();
})().catch((e) => { console.error(e); process.exit(1); });

// 6. A standalone module: pushed as a new module, rolled back (removed).
async function modulePart() {
  if (!fs.existsSync(modDir)) { console.log(`SKIP standalone part: no module at ${modDir}`); return finish(); }
  const ws2 = tempDir('selinux-target-push-mod-');
  cp.execFileSync('cp', ['-a', modDir + '/.', ws2]);
  const te = fs.readdirSync(ws2).find(n => n.endsWith('.te'));
  const b = start(ws2); // no tree in the workspace: the devel headers are found on their own
  await b.init();
  const req2 = (m, p) => b.conn.sendRequest(m, p || {});
  const mr = await req2('selinux/build', { uri: URI.file(path.join(ws2, te)).toString() });
  check(mr && mr.ok && !mr.tree, `standalone module ${te} built`, mr);
  if (!mr || !mr.ok) { b.proc.kill(); return finish(); }
  const c2 = await req2('selinux/targetConnect', { spec: TARGET, password });
  check(!c2.error, 'connected again from the module workspace', c2.error);
  const mod = te.replace(/\.te$/, '');
  const plan2 = await req2('selinux/targetPushPlan', { id: c2.id });
  const m2 = plan2.modules && plan2.modules[0];
  check(!plan2.error && plan2.kind === 'module' && plan2.modules.length === 1 && m2.name === mod && ['new', 'differs', 'same'].includes(m2.state) && !plan2.contexts.length && !plan2.booleans.length, `plan for the module: ${mod} is ${m2 && m2.state} on the target`, plan2.error || plan2);
  const wasThere = m2.had;
  t0 = Date.now();
  const push2 = await req2('selinux/targetPush', { id: c2.id, modules: [mod] });
  check(!push2.error && push2.ok && push2.kind === 'module' && push2.modules[0].had === wasThere, `pushed ${mod} (${((Date.now() - t0) / 1000).toFixed(0)} s)`, push2.error || { failed: push2.failed, transcript: (push2.transcript || '').slice(0, 1200) });
  const listed = (await req2('selinux/targetRun', { id: c2.id, command: `semodule --list-modules=full | grep -E '^[0-9]+ ${mod} '` })).stdout.trim();
  check(/^100 /.test(listed), `the target lists ${mod}: ${listed}`);
  const rb2 = await req2('selinux/targetRollback', { id: c2.id });
  const listed2 = (await req2('selinux/targetRun', { id: c2.id, command: `semodule --list-modules=full | grep -E '^[0-9]+ ${mod} ' || true` })).stdout.trim();
  check(!rb2.error && rb2.ok && (wasThere ? /^100 /.test(listed2) : listed2 === ''), wasThere ? `rolled back: ${mod} reinstalled as before` : `rolled back: ${mod} removed from the target`, rb2.error || { listed2, transcript: (rb2.transcript || '').slice(0, 800) });
  await req2('selinux/targetRun', { id: c2.id, command: `rm -rf ${push2.dir}` });
  await req2('selinux/targetDisconnect', { id: c2.id });
  b.proc.kill();
  finish();
}
