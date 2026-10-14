// Wrapped programs end to end over LSP on a copy of a policy tree, with real
// builds: a chroot on this host, two programs (one with a domain of its own,
// one without), the module written into the tree, built, its checks run on
// the build, the compiled transitions and labels looked at; read back, edited
// with a hand-written line kept; then the same as a standalone module built
// against the devel headers and packaged (make rpm).
//   node test/wrapper-e2e.js [tree-dir] [spec [variant]]
// Default: the CLIP clone on melody with CLIP's make arguments.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain } = require('../server/build');
const { clipArgs } = require('./clip-args');

const tc = detectToolchain(null);
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }
const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');
if (!fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP: no refpolicy tree at ${src}`); process.exit(0); }
const specArg = process.argv[3];
const variant = process.argv[4] || 'targeted';
const CLIP_ARGS = clipArgs(src);
// Programs every RHEL-like host has: one with a domain of its own, one without.
const PROG = '/usr/sbin/setfiles', PLAIN = '/usr/bin/ls';

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-wrapper-e2e-'));
cp.execFileSync('cp', ['-a', src + '/.', ws]);
fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
let spec = null;
if (specArg) {
  const sdir = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-wrapper-spec-'));
  cp.execFileSync('cp', ['-a', path.dirname(path.resolve(specArg)) + '/.', sdir]);
  spec = path.join(sdir, path.basename(specArg));
}
// A small chroot: /etc and a library directory, no copies yet.
const chroot = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-wrapper-chroot-'));
fs.mkdirSync(path.join(chroot, 'etc'));
fs.mkdirSync(path.join(chroot, 'usr/lib64'), { recursive: true });

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
const diags = {};
let summary = null;
let doneIndex, indexed = new Promise(r => (doneIndex = r));
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(p.stats); });
conn.onNotification('selinux/checks', s => { summary = s; });
for (const n of ['window/logMessage', 'selinux/build', 'selinux/inactiveRanges', 'selinux/inactiveChanged']) conn.onNotification(n, () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + (typeof extra === 'string' ? extra : JSON.stringify(extra, null, 1)).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
// Build errors (the checks file reports check results, looked at separately).
const errors = () => Object.entries(diags).filter(([u]) => !u.endsWith('selinux.checks')).flatMap(([u, ds]) => ds.filter(d => d.severity === 1).map(d => `${path.basename(URI.parse(u).fsPath)}:${d.range.start.line + 1} ${d.message}`));
const blocking = (p) => (p.problems || []).filter(x => !x.startsWith('Note:'));
const write = async (plan) => {
  for (const f of plan.files) if (f.changed) { fs.mkdirSync(path.dirname(f.path), { recursive: true }); fs.writeFileSync(f.path, f.text); }
  indexed = new Promise(r => (doneIndex = r));
  await conn.sendRequest('selinux/reindex');
  await indexed;
};
const sh = (cmd, args, opts = {}) => cp.spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 64 << 20, ...opts });

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {}, initializationOptions: { build: { tree: { makeArgs: specArg ? [] : CLIP_ARGS } } } });
  conn.sendNotification('initialized', {});
  await indexed;
  if (spec) {
    const sc = await conn.sendRequest('selinux/specBuildConfig', { specPath: spec });
    const cfg = sc.configs.find(c => c.variant === variant);
    indexed = new Promise(r => (doneIndex = r));
    conn.sendNotification('workspace/didChangeConfiguration', { settings: { selinux: { build: { tree: { makeArgs: cfg.makeArgs, files: cfg.files } } } } });
    await indexed;
    console.log(`     settings from ${path.basename(spec)} (${variant})`);
  }
  // The programs are looked up in the tree's build.
  let t0 = Date.now();
  const b0 = await conn.sendRequest('selinux/build', { uri: uri(ws) });
  check(b0.ok, `the tree builds (${Date.now() - t0} ms)`, errors().slice(0, 5));

  // 1. What the form offers.
  const info = await conn.sendRequest('selinux/wrapperInfo', {});
  const ro = info.users.find(u => u.role === 'user_r') || info.users.find(u => u.role === 'staff_r');
  check(!info.unavailable && ro && !info.users.some(u => u.domain === 'nope_t') && info.defaults.length === 4 && info.layers.includes(info.defaultLayer), `users who may run wrappers: ${info.users.map(u => u.role).join(' ')}; layer ${info.defaultLayer}`, info.unavailable || info);

  // 2. The programs: their label, domain, the rules on their own file, what the chroot lacks.
  const look = await conn.sendRequest('selinux/wrapperProgram', { path: PROG, chroot });
  const sc = look.candidates && look.candidates.find(c => c.domain === look.target);
  check(!look.error && look.origType === 'setfiles_exec_t' && look.target === 'setfiles_t' && /^policycoreutils/.test(look.pkg || ''), `${PROG}: ${look.origType} → ${look.target}, package ${look.pkg}`, look);
  console.log(`     rules on its own file: ${JSON.stringify(sc && sc.selfRules)}; starts on its own: ${(sc && sc.auto.map(a => a.domain).join(' ')) || 'nothing'}`);
  check(look.chrootExists && look.libs && look.libs.total > 0 && look.libs.missing.length === look.libs.total && look.needsCount.present >= 1 && look.needs.some(n => !n.present) && !look.needs[0].present,
    `in the chroot: ${look.libs && look.libs.missing.length} of ${look.libs && look.libs.total} libraries missing; ${look.needsCount && look.needsCount.present} of ${look.needsCount && look.needsCount.total} paths its domain uses present (missing listed first)`, look.needsCount);
  const lookPlain = await conn.sendRequest('selinux/wrapperProgram', { path: PLAIN, chroot });
  check(!lookPlain.error && lookPlain.origType === 'bin_t' && lookPlain.target === '' && lookPlain.generic, `${PLAIN}: ${lookPlain.origType}, no domain of its own`, lookPlain);
  const bad = await conn.sendRequest('selinux/wrapperProgram', { path: '/usr/bin/no-such-program', chroot });
  check(/isn't on this host/.test(bad.error || ''), 'a missing program is refused');

  // 3. A new module in the tree.
  const prog = (l, stem) => ({ stem, original: l.path, wrapper: path.basename(l.path), copy: `${path.basename(l.path)}.real`, pkg: l.pkg, origType: l.origType, target: l.target,
    roles: l.target ? (l.candidates.find(c => c.domain === l.target).auto.map(a => a.domain)) : [], selfRules: l.target ? l.candidates.find(c => c.domain === l.target).selfRules : [], ifaces: info.defaults.slice() });
  // The chroot's users: a group mapped to the SELinux user of that role in the tree's seusers.
  const seusersP = path.join(ws, 'config', 'appconfig-mcs', 'seusers');
  fs.appendFileSync(seusersP, `%rousers:${ro.role.replace(/_r$/, '_u')}:s0\n`);
  const model = { name: 'wrapt', summary: 'Programs the chroot users may run', version: '1.0.0', chroot, likeRoot: true, protectedDir: '/.wrapt', wrapperDir: '/opt/wrapt/bin', role: ro.role, domain: ro.domain, logins: '%rousers',
    programs: [prog(look, 'setfiles'), prog(lookPlain, 'ls')] };
  let plan = await conn.sendRequest('selinux/wrapperPlan', { model, where: info.defaultLayer });
  const kinds = plan.files.map(f => f.kind).sort().join();
  check(!blocking(plan).length && kinds === 'checks,conf,fc,if,subs,te', `plan: ${kinds}`, plan.problems);
  check(plan.problems.some(p => /ls has no domain of its own/.test(p)) && plan.commands.some(c => /semanage fcontext -a -e \//.test(c)) && plan.commands.some(c => c.includes(`cp -p '${PROG}'`)), 'notes and the setup commands for each system', plan);
  const subs = plan.files.find(f => f.kind === 'subs');
  check(subs.text.split('\n').includes(`${chroot} /`), 'the chroot is labeled like / (file_contexts.subs_dist)');
  const cf = plan.files.find(f => f.kind === 'checks');
  check(cf.text.includes(`never ${ro.domain} may { execute read getattr } wrapt_setfiles_real_exec_t wrapt_ls_real_exec_t:file`) && cf.text.includes('never login %rousers reaches setfiles_t except through wrapt_setfiles_t'), 'checks written', cf.text);
  const taken = await conn.sendRequest('selinux/wrapperPlan', { model: { ...model, protectedDir: '/etc', wrapperDir: '/usr/bin' }, where: info.defaultLayer });
  check(blocking(taken).some(p => /\/etc exists on the host too/.test(p)) && blocking(taken).some(p => /\/usr\/bin\/ls exists on the host too/.test(p)), 'paths the host has are refused (the equivalence would relabel them)', taken.problems);
  await write(plan);
  t0 = Date.now();
  summary = null;
  const b1 = await conn.sendRequest('selinux/build', { uri: uri(plan.files.find(f => f.kind === 'te').path) });
  check(b1.ok && !errors().length, `the tree builds with the module (${Date.now() - t0} ms)`, errors().slice(0, 8));
  for (let i = 0; i < 300 && !(summary && summary.failed !== undefined && !summary.note); i++) await sleep(200);
  const checksUri = uri(cf.path);
  const lines = cf.text.split('\n');
  const ours = (diags[checksUri] || []).filter(d => /wrapt|reaches setfiles_t/.test(lines[d.range.start.line] || ''));
  const access = ours.filter(d => /may/.test(lines[d.range.start.line]));
  check(summary && access.length === 0, `${ro.domain} can't execute the copies or list the protected directory: ${JSON.stringify(summary)}`, ours.map(d => `${lines[d.range.start.line]}: ${d.message}`));
  // Reaching setfiles_t through the wrapper doesn't count; another way in is reported (on CLIP staff_t reaches it via newrole_t as sysadm_r).
  const reach = ours.find(d => /reaches/.test(lines[d.range.start.line]));
  check(!reach || (/without going through wrapt_setfiles_t/.test(reach.message) && !/→ wrapt_setfiles_t/.test(reach.message)), `reaches … except through the wrapper: ${reach ? reach.message : 'holds'}`, reach);

  // 4. The compiled policy.
  const bin = path.join(b1.workDir, 'tmp', 'policy.bin');
  const tt = sh('sesearch', ['-T', '-s', 'wrapt_setfiles_t', '-t', 'wrapt_setfiles_real_exec_t', '-c', 'process', bin]).stdout;
  check(/type_transition wrapt_setfiles_t wrapt_setfiles_real_exec_t:process setfiles_t;/.test(tt), 'the wrapper enters setfiles_t through the copy', tt);
  const ex = sh('sesearch', ['-A', '-t', 'wrapt_setfiles_real_exec_t', '-c', 'file', '-p', 'execute', bin]).stdout.trim().split('\n').filter(Boolean);
  check(ex.length >= 1 && ex.every(l => !l.startsWith(`allow ${ro.domain} `)) && ex.some(l => /^allow wrapt_setfiles_t /.test(l)), `who may execute the copy: ${ex.map(l => l.split(' ')[1]).join(', ')}`, ex);
  const ep = sh('sesearch', ['-A', '-t', 'wrapt_setfiles_real_exec_t', '-c', 'file', '-p', 'entrypoint', bin]).stdout.trim().split('\n').filter(Boolean);
  check(ep.length === 1 && /^allow setfiles_t /.test(ep[0]), 'only setfiles_t is entered through it', ep);
  const role = sh('seinfo', ['-r', ro.role, '-x', bin]).stdout;
  check(/wrapt_setfiles_t/.test(role) && /setfiles_t/.test(role), `${ro.role} has the wrapper and setfiles_t`);
  // Labels inside the chroot, as the build gives them (through the tree's equivalence).
  const etcPasswd = ((await conn.sendRequest('selinux/fileLabel', { path: '/etc/passwd', mode: 'file' })).policies.find(x => x.id === 'build') || {}).type;
  for (const [p, t] of [[`${chroot}/.wrapt/setfiles.real`, 'wrapt_setfiles_real_exec_t'], [`${chroot}/.wrapt`, 'wrapt_protected_t'], [`${chroot}/opt/wrapt/bin/setfiles`, 'wrapt_setfiles_exec_t'], [`${chroot}/etc/passwd`, etcPasswd]]) {
    const r = await conn.sendRequest('selinux/fileLabel', { path: p, mode: p.endsWith('.wrapt') ? 'dir' : 'file' });
    const b = r.policies.find(x => x.id === 'build') || {};
    check(b.type === t, `${p.replace(chroot, 'CHROOT')} → ${b.type} (looked up as ${b.key})`, b);
  }

  // 5. Read back and edit.
  const mod = await conn.sendRequest('selinux/wrapperInfo', { module: 'wrapt' });
  const same = JSON.stringify(mod.model.programs.map(p => [p.stem, p.target, p.roles, p.selfRules, p.ifaces, p.pkg])) === JSON.stringify(model.programs.map(p => [p.stem, p.target, p.roles, p.selfRules, p.ifaces, p.pkg || null]));
  check(!mod.unavailable && !mod.isNew && mod.model.chroot === chroot && same, 'read back: the same model', mod.unavailable || mod.model);
  plan = await conn.sendRequest('selinux/wrapperPlan', { model: mod.model, module: 'wrapt' });
  check(!blocking(plan).length && plan.files.length === 0, 'no-op: no changes', plan.files.map(f => f.path));
  const teP = path.join(ws, 'policy/modules', info.defaultLayer, 'wrapt.te');
  fs.appendFileSync(teP, `\n# mine\ndontaudit ${ro.domain} wrapt_protected_t:dir getattr;\n`);
  await write({ files: [] });
  const m2 = (await conn.sendRequest('selinux/wrapperInfo', { module: 'wrapt' })).model;
  m2.programs = m2.programs.filter(p => p.stem !== 'ls');
  plan = await conn.sendRequest('selinux/wrapperPlan', { model: m2, module: 'wrapt' });
  const te2 = (plan.files.find(f => f.kind === 'te') || {}).text || '';
  check(!blocking(plan).length && !/wrapt_ls/.test(te2) && te2.split('Local additions')[1] && te2.split('Local additions')[1].includes(`dontaudit ${ro.domain} wrapt_protected_t:dir getattr;`)
    && plan.files.some(f => f.kind === 'checks' && !/wrapt_ls/.test(f.text)) && plan.files.some(f => f.kind === 'fc'), 'edit: ls removed (module, file contexts, checks); the hand-written line kept', plan.files.map(f => f.kind));
  await write(plan);
  const b2 = await conn.sendRequest('selinux/build', { uri: uri(teP) });
  check(b2.ok && !errors().length, 'the edited module builds', errors().slice(0, 5));

  // 6. Standalone: the module and its package.
  const sa = await conn.sendRequest('selinux/wrapperInfo', { standalone: true });
  if (!sa.standalone) console.log('SKIP standalone part: no devel headers on this host');
  else {
    const hostLook = await conn.sendRequest('selinux/wrapperProgram', { path: PROG, chroot, standalone: true });
    check(hostLook.target === 'setfiles_t' && /^Installed/.test(hostLook.policy), `standalone: looked up in ${hostLook.policy}: ${hostLook.target}`, hostLook);
    const smodel = { ...model, name: 'wrapsa', protectedDir: '/.wrapsa', wrapperDir: '/opt/wrapsa/bin', programs: [prog(hostLook, 'setfiles')] };
    const splan = await conn.sendRequest('selinux/wrapperPlan', { model: smodel, standalone: true, license: 'MIT' });
    const sk = splan.files.map(f => f.kind).sort().join();
    check(!blocking(splan).length && sk === 'checks,fc,if,make,spec,te', `standalone plan: ${sk}`, splan.problems);
    const specF = splan.files.find(f => f.kind === 'spec');
    check(/semanage fcontext -a -e \/ /.test(specF.text) && /%triggerin -- policycoreutils/.test(specF.text) && !splan.commands, 'the spec labels the chroot, copies, and refreshes with a trigger');
    await write(splan);
    const sdir = path.dirname(specF.path);
    const sb = await conn.sendRequest('selinux/build', { uri: uri(path.join(sdir, 'wrapsa.te')) });
    check(sb.ok, 'the standalone module builds against the devel headers', sb.diagnostics && sb.diagnostics.slice(0, 5));
    const rpm = sh('make', ['-C', sdir, 'rpm']);
    const built = (rpm.stdout.match(/\S+wrapsa-selinux-\S+\.rpm/) || [])[0];
    check(rpm.status === 0 && built, `make rpm: ${built ? path.basename(built) : rpm.stderr.slice(-400)}`);
    if (built) {
      const scripts = sh('rpm', ['-qp', '--scripts', built]).stdout;
      const trig = sh('rpm', ['-qp', '--triggers', built]).stdout;
      check(scripts.includes(`cp -p '${PROG}' '${chroot}/.wrapsa/setfiles.real'`) && /semanage fcontext -d -e \//.test(scripts) && /triggerin scriptlet[^\n]*policycoreutils/.test(trig), 'the package\'s scripts and trigger', { scripts: scripts.slice(0, 1500), trig });
    }
    // Adding a program rewrites the spec's blocks only.
    const smod = await conn.sendRequest('selinux/wrapperInfo', { module: 'wrapsa' });
    const lookSa2 = await conn.sendRequest('selinux/wrapperProgram', { path: '/usr/sbin/load_policy', chroot, standalone: true });
    smod.model.programs.push(prog(lookSa2, 'load_policy'));
    const splan2 = await conn.sendRequest('selinux/wrapperPlan', { model: smod.model, module: 'wrapsa' });
    const spec2 = splan2.files.find(f => f.kind === 'spec');
    check(!blocking(splan2).length && spec2 && /load_policy\.real/.test(spec2.text) && spec2.diff.filter(d => d[0] !== ' ').every(d => /load_policy|triggerin|refresh|^\s*$/.test(d[1])),
      `adding ${lookSa2.target || '?'}: only the spec's wrapped-programs blocks change`, spec2 && spec2.diff.filter(d => d[0] !== ' '));
  }

  await conn.sendRequest('shutdown');
  conn.sendNotification('exit');
  await sleep(300);
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  fs.rmSync(chroot, { recursive: true, force: true });
  if (spec) fs.rmSync(path.dirname(spec), { recursive: true, force: true });
  console.log(failures ? `\n${failures} check(s) failed` : '\nall wrapper e2e checks passed');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); process.exit(1); });
