// User editor end to end over LSP on a copy of a policy tree, with real builds:
// a new login user (ssh + console, sudo, may switch to sysadm_r) and a confined
// admin role entered from staff_r, written, built, and checked with the logins
// report of the build (where the login lands, what it reaches).
//   node test/user-e2e.js [tree-dir] [spec [variant]]
// Default: the CLIP clone on melody with CLIP's make arguments; with a spec
// (RHEL), its settings, the spec's directory copied so users-<variant> edits stay in the copy.
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

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-user-e2e-'));
cp.execFileSync('cp', ['-a', src + '/.', ws]);
fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
let spec = null;
if (specArg) {
  const sdir = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-user-spec-'));
  cp.execFileSync('cp', ['-a', path.dirname(path.resolve(specArg)) + '/.', sdir]);
  spec = path.join(sdir, path.basename(specArg));
}

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
const diags = {};
let doneIndex, indexed = new Promise(r => (doneIndex = r));
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(p.stats); });
for (const n of ['window/logMessage', 'selinux/build', 'selinux/checks', 'selinux/inactiveRanges', 'selinux/inactiveChanged']) conn.onNotification(n, () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + (typeof extra === 'string' ? extra : JSON.stringify(extra, null, 1)).slice(0, 2500).replace(/\n/g, '\n     ')); }
};
const errors = () => Object.entries(diags).flatMap(([u, ds]) => ds.filter(d => d.severity === 1 && !/^selinux-(logins|contexts)$/.test(d.source)).map(d => `${path.basename(URI.parse(u).fsPath)}:${d.range.start.line + 1} ${d.message}`));
const blocking = (p) => (p.problems || []).filter(x => !x.startsWith('Note:'));
const write = async (plan) => {
  for (const f of plan.files) if (f.changed) { fs.mkdirSync(path.dirname(f.path), { recursive: true }); fs.writeFileSync(f.path, f.text); }
  indexed = new Promise(r => (doneIndex = r));
  await conn.sendRequest('selinux/reindex');
  await indexed;
};
const readSource0 = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } };
const diffOf = (f) => f.diff.filter(x => x[0] !== ' ').map(x => x.join(' '));

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

  // 1. What the editor offers in this tree.
  const info = await conn.sendRequest('selinux/userInfo');
  check(!info.unavailable, 'user editor available', info.unavailable);
  const kinds = info.catalog.kinds.map(k => k.id);
  check(['unpriv', 'admin', 'confined'].every(k => kinds.includes(k)), `kinds: ${kinds.join(', ')} (confined via ${info.catalog.kinds.find(k => k.id === 'confined').template})`);
  const calls = info.catalog.roleCalls;
  check(calls.some(c => c.n === 'sudo_role_template' && c.g === 'login') && calls.some(c => c.g === 'admin') && calls.some(c => c.g === 'apps'),
    `role calls: ${calls.length} (${['login', 'admin', 'apps', 'run'].map(g => `${g} ${calls.filter(c => c.g === g).length}`).join(', ')})`);
  const sys = info.catalog.roles.find(r => r.role === 'sysadm_r'), staff = info.catalog.roles.find(r => r.role === 'staff_r');
  check(sys && sys.change && staff && staff.changeTo, `roles: sysadm_r via ${sys && sys.change}, staff_r may change to others via ${staff && staff.changeTo}`);
  check(info.catalog.ways.some(w => w.id === 'ssh') && info.users.includes('staff_u'), `ways: ${info.catalog.ways.map(w => w.id).join(', ')}; users: ${info.users.join(', ')}`);
  console.log(`     users file ${path.relative(ws, info.usersFile)}, prefix default ${info.prefixDefault}`);

  // 2. A new login user: ssh and console, sudo and the ssh client, may switch to sysadm_r.
  const m = info.model;
  Object.assign(m, { name: 'opsusr', summary: 'Operators', logins: [{ login: 'alice', range: '' }, { login: '%opsgroup', range: '' }],
    roleCalls: ['sudo_role_template', 'ssh_role_template'], switchTo: ['sysadm_r'], extra: ['logging_send_syslog_msg'] });
  let plan = await conn.sendRequest('selinux/userPlan', { model: m });
  check(!blocking(plan).length, `plan: ${plan.files.map(f => `${path.basename(f.path)}${f.exists ? ' (edit)' : ' (new)'}`).join(', ')}`, plan.problems);
  const F = (k) => plan.files.find(f => f.kind === k);
  check(F('te') && /^role opsusr_r;$/m.test(F('te').text) && new RegExp(`^${info.catalog.kinds.find(k => k.id === 'unpriv').template}\\(opsusr\\)$`, 'm').test(F('te').text), '.te declares the role and calls the unpriv template');
  check(F('users') && diffOf(F('users')).some(l => /^\+ gen_user\(opsusr_u, \w+, opsusr_r sysadm_r, s0, s0\)$/.test(l)), `users file gets the gen_user line (${F('users') && path.relative(ws, F('users').path)})`, F('users') && diffOf(F('users')));
  check(F('seusers') && diffOf(F('seusers')).join('|') === '+ alice:opsusr_u|+ %opsgroup:opsusr_u', 'seusers gets alice and %opsgroup, before __default__', F('seusers') && diffOf(F('seusers')));
  check(F('contexts') && /^system_r:sshd_t:s0\t\topsusr_r:opsusr_t:s0$/m.test(F('contexts').text) && /^opsusr_r:opsusr_sudo_t:s0\t\topsusr_r:opsusr_t:s0 sysadm_r:sysadm_t:s0$/m.test(F('contexts').text),
    'its contexts file: ssh lands in opsusr_t; after sudo, its own context or sysadm', F('contexts') && F('contexts').text);
  check(F('conf') && /^opsusr = module$/m.test(F('conf').text), 'modules.conf gets "opsusr = module"');
  const taken = await conn.sendRequest('selinux/userPlan', { model: { ...m, logins: [{ login: 'root', range: '' }] } });
  check(blocking(taken).some(p => /root is already mapped/.test(p)), `a login mapped to another user is refused: ${blocking(taken)[0]}`);
  const dup = await conn.sendRequest('selinux/userPlan', { model: { ...m, name: 'staff' } });
  check(blocking(dup).some(p => /staff_r already exists|staff_t is already declared|staff already exists/.test(p)), `an existing role name is refused: ${blocking(dup)[0]}`);
  await write(plan);

  // 3. A confined admin role entered from staff_r, which staff_u gets, administering logs.
  const info2 = await conn.sendRequest('selinux/userInfo');
  const m2 = info2.model;
  const admin = info2.catalog.roleCalls.find(c => c.n === 'logging_admin') || info2.catalog.roleCalls.find(c => c.g === 'admin');
  Object.assign(m2, { name: 'logops', summary: 'Log operators', user: { kind: 'confined' }, logins: [], ways: [], enteredFrom: ['staff_r'], grantUsers: ['staff_u'], roleCalls: [admin.n] });
  let plan2 = await conn.sendRequest('selinux/userPlan', { model: m2 });
  check(!blocking(plan2).length, `confined role plan (administers via ${admin.n})`, plan2.problems);
  const users2 = plan2.files.find(f => f.kind === 'users');
  check(users2 && diffOf(users2).some(l => /^\+ gen_user\(staff_u, \w+, staff_r .*logops_r/.test(l)), 'staff_u gets logops_r in its gen_user line', users2 && diffOf(users2));
  check(!plan2.files.some(f => f.kind === 'seusers') && /staff_role_change_to\(logops_r\)/.test(plan2.files.find(f => f.kind === 'te').text), 'no logins of its own; staff_r may change to it');
  await write(plan2);

  // 4. Build, then the logins report of the build.
  const te = plan.files.find(f => f.kind === 'te').path;
  const r = await conn.sendRequest('selinux/build', { uri: uri(te) });
  check(r.ok && r.validated, `tree with both users builds and links (${(r.ms / 1000).toFixed(1)} s)`, { log: r.log && r.log.slice(-2500), errors: errors() });
  const rep = await conn.sendRequest('selinux/logins', { against: 'build' });
  const U = (n) => (rep.users || []).find(u => u.name === n);
  const ops = U('opsusr_u');
  check(ops && ops.roles.join(' ') === 'opsusr_r sysadm_r', `opsusr_u in the built policy with roles ${ops && ops.roles.join(' ')}`, rep.error || (rep.users || []).map(u => u.name));
  check(ops && ops.logins.map(l => (l.group ? `%${l.login}` : l.login)).sort().join() === '%opsgroup,alice', 'its logins: alice, %opsgroup');
  const ssh = ops && ops.entries.find(e => e.source === 'sshd_t');
  check(ssh && ssh.contexts.length === 1 && ssh.contexts[0].type === 'opsusr_t', 'ssh lands in opsusr_t (its own contexts file)', ops && ops.entries);
  const reach = ops && await conn.sendRequest('selinux/loginReach', { against: 'build', user: 'opsusr_u', starts: [{ role: 'opsusr_r', type: 'opsusr_t' }] });
  const viaSudo = reach && reach.domains.find(d => d.name === 'opsusr_sudo_t'), sysadm = reach && reach.domains.find(d => d.name === 'sysadm_t');
  check(viaSudo && sysadm && sysadm.role === 'sysadm_r', `reaches its sudo domain and sysadm_t: ${sysadm && sysadm.path.map(s => s.text).join(' ; ')}`, reach && reach.domains.slice(0, 20));
  const st = U('staff_u');
  check(st && st.roles.includes('logops_r'), 'staff_u has logops_r in the built policy', st && st.roles);
  const sreach = await conn.sendRequest('selinux/loginReach', { against: 'build', user: 'staff_u', starts: [{ role: 'staff_r', type: 'staff_t' }] });
  const lo = sreach.domains && sreach.domains.find(d => d.name === 'logops_t');
  check(lo && lo.role === 'logops_r', `staff_u reaches logops_t: ${lo && lo.path.map(s => s.text).join(' ; ')}`, sreach.error || (sreach.domains || []).length);

  // 5. Editing an existing user: staff (CLIP and RHEL both have it).
  const list = await conn.sendRequest('selinux/userList');
  check(['staff', 'sysadm'].every(x => list.modules.some(m => m.module === x)) && list.modules.some(m => m.module === 'opsusr'), `user modules: ${list.modules.map(m => m.module).join(' ')}`);
  const si = await conn.sendRequest('selinux/userInfo', { module: 'staff' });
  check(!si.unavailable && !si.isNew && si.model.name === 'staff' && si.model.user.kind === 'unpriv', `staff read back: ${si.unavailable || `${si.model.roleCalls.length} role calls, switches to ${si.model.switchTo.join(' ')}, ways ${si.model.ways.join(' ')}, ${si.kept.length} kept`}`);
  check(si.model.switchTo.includes('sysadm_r') && si.model.roleCalls.includes('sudo_role_template') && si.model.enteredFrom.length === 0, 'staff switches to sysadm_r and has sudo');
  let sp = await conn.sendRequest('selinux/userPlan', { model: si.model, module: 'staff' });
  check(!blocking(sp).length && sp.files.length === 0, 'a no-op edit changes no file', sp.files.map(f => f.path));
  const sm = JSON.parse(JSON.stringify(si.model));
  sm.caps.push(['sys_nice', 'kill', 'dac_read_search'].find(c => !sm.caps.includes(c)));
  const rc = si.catalog.roleCalls.find(c => c.g === 'run' && !sm.roleCalls.includes(c.n));
  sm.roleCalls.push(rc.n);
  sm.ways = sm.ways.filter(w => w !== 'console');
  sp = await conn.sendRequest('selinux/userPlan', { model: sm, module: 'staff' });
  check(!blocking(sp).length, `edit: ${sp.files.map(f => `${path.basename(f.path)} ${diffOf(f).length} line(s)`).join(', ')} (+ ${rc.n})`, sp.problems);
  const ste = sp.files.find(f => f.kind === 'te');
  check(ste && diffOf(ste).every(l => l.startsWith('+')) && diffOf(ste).length <= 8 && diffOf(ste).some(l => l.includes(rc.n)), 'staff.te: lines added only', ste && diffOf(ste));
  const cons = sp.files.filter(f => f.kind === 'contexts' || f.kind === 'defaults');
  check(si.model.ways.includes('console') ? cons.length && cons.every(f => diffOf(f).every(l => /local_login_t/.test(l))) : true, `console logins taken away: ${cons.map(f => path.basename(f.path)).join(', ')}`, cons.map(diffOf));
  await write(sp);
  const r2 = await conn.sendRequest('selinux/build', { uri: uri(ste.path) });
  check(r2.ok && r2.validated, `tree with the edited staff builds and links (${(r2.ms / 1000).toFixed(1)} s)`, { log: r2.log && r2.log.slice(-2500), errors: errors() });
  const back = await conn.sendRequest('selinux/userInfo', { module: 'staff' });
  check(back.model.roleCalls.includes(rc.n) && !back.model.ways.includes('console') && back.model.caps.length === sm.caps.length, 'staff reads back as edited');
  const rep2 = await conn.sendRequest('selinux/logins', { against: 'build' });
  const st2 = (rep2.users || []).find(u => u.name === 'staff_u');
  check(st2 && !st2.entries.some(e => e.source === 'local_login_t' && e.contexts.some(c => c.type === 'staff_t')), 'the build\'s logins report: staff_u no longer lands in staff_t on the console', st2 && st2.entries);

  // 5b. Changing an existing user's kind. A user written as a restricted desktop user where the
  // X template can't link (CLIP: xserver off, so xdm_t is missing) is switched to the terminal kind.
  const kx = info.catalog.kinds.find(k => k.id === 'restricted_x'), kr = info.catalog.kinds.find(k => k.id === 'restricted');
  // xserver is built when modules.conf or the build's APPS_MODS (CLIP's make arguments) turn it on.
  const confOn = /^xserver = (base|module)$/m.test(readSource0(path.join(ws, 'policy', 'modules.conf')));
  const appsOn = (specArg ? [] : CLIP_ARGS).some(a => /^APPS_MODS=/.test(a) && a.split(/[=\s]+/).includes('xserver'));
  const xOff = !confOn && !appsOn;
  if (kx && kr) {
    check(xOff ? /needs xdm_t, which only the xserver module/.test(kx.blocked) : !kx.blocked, `restricted desktop kind ${kx.blocked ? `blocked: ${kx.blocked}` : `available (xserver on${appsOn ? ' through APPS_MODS' : ''})`}`, kx);
    const ni = await conn.sendRequest('selinux/userInfo');
    const xm = { ...ni.model, name: 'rokind', summary: 'Read-only jail users', logins: [], ways: ['ssh'], user: { kind: 'restricted' } };
    const xp = await conn.sendRequest('selinux/userPlan', { model: xm });
    check(!blocking(xp).length, 'a new terminal user rokind', xp.problems);
    // Written with the X template, as the editor did before kinds could be changed or were checked.
    const xte = xp.files.find(f => f.kind === 'te');
    xte.text = xte.text.replace(`${kr.template}(rokind)`, `${kx.template}(rokind)`);
    await write(xp);
    const xi = await conn.sendRequest('selinux/userInfo', { module: 'rokind' });
    check(xi.model && xi.model.user.kind === 'restricted_x', `read back as ${xi.model && xi.model.user.kind}`, xi.unavailable);
    if (xOff) {
      const p0 = await conn.sendRequest('selinux/userPlan', { model: xi.model, module: 'rokind' });
      check(p0.files.length === 0 && (p0.problems || []).some(x => /^Note: .*xdm_t.*won't link/.test(x)), 'as it is: a note that it won\'t link', p0.problems);
    }
    const sw = JSON.parse(JSON.stringify(xi.model));
    sw.user.kind = 'restricted';
    const p1 = await conn.sendRequest('selinux/userPlan', { model: sw, module: 'rokind' });
    const t1 = p1.files.find(f => f.kind === 'te');
    check(!blocking(p1).length && t1 && diffOf(t1).join('|') === `- ${kx.template}(rokind)|+ ${kr.template}(rokind)` && p1.files.length === 1,
      `kind changed: ${t1 && diffOf(t1).join(' ; ')}`, { problems: p1.problems, files: p1.files.map(f => [f.path, diffOf(f)]) });
    await write(p1);
    const r3 = await conn.sendRequest('selinux/build', { uri: uri(t1.path) });
    check(r3.ok && r3.validated, `tree with rokind as a terminal user builds and links (${(r3.ms / 1000).toFixed(1)} s)`, { log: r3.log && r3.log.slice(-2500), errors: errors() });
    const ki = await conn.sendRequest('selinux/userInfo', { module: 'rokind' });
    check(ki.model.user.kind === 'restricted', 'reads back as a restricted terminal user');
  } else console.log('     (no restricted kinds in this tree: 5b skipped)');

  // 6. A standalone user (built against this host's devel headers, packaged as an RPM).
  const sai = await conn.sendRequest('selinux/userInfo', { standalone: true });
  if (!sai.standalone) console.log(`SKIP standalone part: ${sai.unavailable || 'no devel headers'}`);
  else {
    const sudoT = sai.catalog.roleCalls.find(c => c.n === 'sudo_role_template');
    check(sudoT && sai.users.includes('staff_u') && sai.licenses && sai.licenses.default, `standalone info: ${sai.catalog.roleCalls.length} role calls from the devel headers, host users ${sai.users.join(' ')}`);
    const sm2 = sai.model;
    Object.assign(sm2, { name: 'sadev', summary: 'Standalone test user', logins: [{ login: 'bob', range: '' }, { login: '%sadevs', range: 's0' }], ways: ['ssh'],
      roleCalls: ['sudo_role_template'], switchTo: ['sysadm_r'], grantUsers: ['staff_u'] });
    const macro = await conn.sendRequest('selinux/userPlan', { model: { ...sm2, range: 's0 - mls_systemhigh' }, standalone: true, license: 'MIT' });
    check(blocking(macro).some(p => /literal level/.test(p)), `an m4 macro in the range is refused standalone: ${blocking(macro)[0]}`);
    let sp2 = await conn.sendRequest('selinux/userPlan', { model: sm2, standalone: true, license: 'MIT' });
    check(!blocking(sp2).length, `standalone plan: ${sp2.files.map(f => path.basename(f.path)).join(', ')}`, sp2.problems);
    const S2 = (k) => sp2.files.find(f => f.kind === k);
    check(S2('te') && /sudo_role_template\(sadev, sadev_r, sadev_t\)/.test(S2('te').text), 'the sudo call in the host\'s (RHEL) form, from its devel headers', S2('te') && S2('te').text);
    check(!sp2.files.some(f => ['users', 'kernel', 'seusers', 'conf'].includes(f.kind)) && S2('contexts') && /system_r:sshd_t:s0\t\tsadev_r:sadev_t:s0/.test(S2('contexts').text), 'no tree files; its contexts file next to the module');
    const spec = S2('spec') && S2('spec').text;
    check(spec && /^semanage user -a -R 'sadev_r sysadm_r' -L 's0' -r 's0' -P 'user' sadev_u /m.test(spec) && /semanage login -a -s sadev_u 'bob'/.test(spec) && /'%%sadevs'/.test(spec) && /semanage user -m -R "\$r sadev_r" staff_u/.test(spec) && /contexts\/users\/sadev_u/.test(spec),
      'spec: semanage user and logins (%group escaped), staff_u gets the role, the contexts file installed', spec && spec.split('\n').filter(l => /semanage|contexts/.test(l)));
    await write(sp2);
    const dir = path.dirname(S2('te').path);
    const rb = await conn.sendRequest('selinux/build', { uri: uri(S2('te').path) });
    check(rb.ok, `the standalone module builds against the devel headers (${rb.ms} ms)`, rb.log && rb.log.slice(-1500));
    let rpmOut = '';
    try { rpmOut = cp.execFileSync('make', ['-C', dir, 'rpm'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { rpmOut = String(e.stdout || '') + String(e.stderr || ''); }
    const rpm = (rpmOut.match(/\S+sadev-selinux-[^\s/]+\.rpm/g) || []).pop();
    check(rpm && fs.existsSync(rpm), `make rpm: ${rpm ? path.basename(rpm) : rpmOut.slice(-800)}`);
    if (rpm) {
      const scripts = cp.execFileSync('rpm', ['-qp', '--scripts', rpm], { encoding: 'utf8' });
      const list = cp.execFileSync('rpm', ['-qpl', rpm], { encoding: 'utf8' });
      check(/semanage user -a -R 'sadev_r sysadm_r'/.test(scripts) && /semanage login -a -s sadev_u -r 's0' '%sadevs'/.test(scripts) && /semanage user -d sadev_u/.test(scripts) && /printf "%s "/.test(scripts),
        'RPM scripts: user and logins created, removed on erase (rpm expanded %% to %)', scripts.split('\n').filter(l => /semanage/.test(l)).slice(0, 8));
      check(/\/etc\/selinux\/targeted\/contexts\/users\/sadev_u/.test(list) && /sadev\.pp\.bz2/.test(list), 'RPM files: the module and contexts/users/sadev_u');
    }
    // Read back: the module, its contexts file, and the spec's settings.
    const sl = await conn.sendRequest('selinux/userList');
    check(sl.modules.some(m => m.module === 'sadev' && m.standalone), 'listed as a standalone user module');
    const sb = await conn.sendRequest('selinux/userInfo', { module: 'sadev' });
    check(!sb.unavailable && sb.model.standalone && sb.model.roleCalls.includes('sudo_role_template') && sb.model.switchTo.includes('sysadm_r') && sb.model.ways.join() === 'ssh'
      && sb.model.logins.map(l => l.login).join() === 'bob,%sadevs' && sb.model.grantUsers.join() === 'staff_u', 'read back: role calls, switch, ways, and from the spec its logins and staff_u', sb.unavailable || sb.model);
    let ep = await conn.sendRequest('selinux/userPlan', { model: sb.model, module: 'sadev' });
    check(!blocking(ep).length && !ep.files.length, 'a no-op edit changes no file', ep.files.map(f => f.path));
    const em = JSON.parse(JSON.stringify(sb.model));
    em.caps.push('kill'); em.ways.push('console');
    ep = await conn.sendRequest('selinux/userPlan', { model: em, module: 'sadev' });
    check(!blocking(ep).length && ep.files.map(f => f.kind).sort().join() === 'contexts,te', `an edit changes the .te and its contexts file only: ${ep.files.map(f => path.basename(f.path)).join(', ')}`, ep.problems);
    const lm = JSON.parse(JSON.stringify(sb.model));
    lm.logins.push({ login: 'carol', range: '' });
    ep = await conn.sendRequest('selinux/userPlan', { model: lm, module: 'sadev' });
    check((ep.problems || []).some(p => /%post of .*sadev-selinux\.spec/.test(p)), 'logins of a standalone user: pointed to the spec');
  }

  // 7. Previews of what a user would reach (nothing written).
  const pi = await conn.sendRequest('selinux/userInfo');
  const am = pi.model;
  Object.assign(am, { name: 'autouser', summary: 'Automation account', ways: ['ssh', 'cron'], roleCalls: ['sudo_role_template', 'cron_role'].filter(n => pi.catalog.roleCalls.some(c => c.n === n)),
    switchTo: ['logops_r'], logins: [{ login: 'ansible', range: '' }] });
  let pv = await conn.sendRequest('selinux/userPreview', { model: am });
  check(!pv.error && pv.ways.some(w => w.source === 'sshd_t' && w.contexts[0].type === 'autouser_t') && pv.roles.join(' ') === 'autouser_r logops_r',
    `new tree user preview (${pv.buildMs && (pv.buildMs / 1000).toFixed(1)} s): ssh lands in autouser_t, roles ${pv.roles}`, pv.error || pv);
  check(!pv.error && pv.reached > 1 && !fs.existsSync(path.join(ws, 'policy/modules/roles/autouser.te')), `it reaches ${pv.reached} domains; nothing written`);
  const sv = await conn.sendRequest('selinux/userInfo', { module: 'staff' });
  const nm = JSON.parse(JSON.stringify(sv.model));
  nm.roleCalls = nm.roleCalls.filter(n => n !== 'sudo_role_template');
  pv = await conn.sendRequest('selinux/userPreview', { model: nm, module: 'staff' });
  check(!pv.error && pv.before && pv.lost.includes('staff_sudo_t') && pv.reached < pv.before.reached, `staff without sudo: reaches ${pv.reached} (was ${pv.before && pv.before.reached}), loses ${(pv.lost || []).slice(0, 5).join(' ')}`, pv.error || pv);
  check(!readSource0(path.join(ws, 'policy/modules/roles/staff.te')).includes('#preview'), 'staff.te untouched');
  if (sai.standalone) {
    const sp = JSON.parse(JSON.stringify(sai.model));
    Object.assign(sp, { name: 'sapre', ways: ['ssh'], roleCalls: ['sudo_role_template'], switchTo: ['sysadm_r'], logins: [], grantUsers: [] });
    pv = await conn.sendRequest('selinux/userPreview', { model: sp, standalone: true, license: 'MIT' });
    check(!pv.error && pv.standalone && pv.roles.join(' ') === 'sapre_r sysadm_r' && pv.ways.some(w => w.contexts[0].type === 'sapre_t'),
      `standalone preview (linked with the installed policy, ${pv.buildMs} ms): roles ${pv.roles}, ssh lands in sapre_t`, pv.error || pv);
    const sys = pv.abilities && pv.abilities.length;
    check(!pv.error && pv.reached > 1, `it reaches ${pv.reached} domains, ${sys} risky abilit${sys === 1 ? 'y' : 'ies'} (${(pv.abilities || []).map(a => `${a.id}@${a.domain}`).join(', ')})`);
  }

  proc.kill();
  console.log(failures ? `${failures} FAILED` : 'all passed');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); process.exit(1); });
