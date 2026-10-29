// Logins view over LSP on a Linux host: the installed targeted policy (this
// host's seusers, contexts and accounts) and a tree build (default: the CLIP
// clone on melody, whose __default__ login maps to staff_u).
//   node test/logins-e2e.js [tree-dir]
// Needs Linux running the targeted policy and python3-setools; the tree part
// also the build toolchain. Skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const { tempDir } = require('./tmpdirs');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { installedPolicies } = require('../server/build');
const { clipArgs } = require('./clip-args');

const installed = installedPolicies().find(p => p.active);
if (process.platform !== 'linux' || !installed || installed.name !== 'targeted') { console.log('SKIP: needs Linux running the targeted policy'); process.exit(0); }
const treeDir = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');
const VERBOSE = process.env.VERBOSE;
const CLIP_ARGS = clipArgs(treeDir);

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
  for (const n of ['textDocument/publishDiagnostics', 'selinux/checks', 'selinux/build', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged']) conn.onNotification(n, () => {});
  conn.listen();
  return { proc, conn, async init() {
    await conn.sendRequest('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: initOptions });
    conn.sendNotification('initialized', {});
    await indexed;
  } };
}

const pathText = (p) => (p || []).map(s => s.text).join(' ; ');

(async () => {
  // 1. This host's running targeted policy.
  const ws = tempDir('selinux-logins-e2e-');
  fs.writeFileSync(path.join(ws, 'readme.txt'), 'empty workspace\n');
  const a = start(ws);
  await a.init();
  let t0 = Date.now();
  const rep = await a.conn.sendRequest('selinux/logins', {});
  console.log(`  report in ${Date.now() - t0} ms against ${rep.policy && rep.policy.label}`);
  if (VERBOSE) console.log(JSON.stringify(rep, null, 1).slice(0, 20000));
  check(!rep.error && rep.policy && rep.policy.host, 'installed running policy, host accounts apply', rep.error || rep.policy);
  const U = (n) => (rep.users || []).find(u => u.name === n);
  const unc = U('unconfined_u');
  check(unc && unc.logins.some(l => l.login === '__default__') && unc.logins.some(l => l.login === 'root'), 'unconfined_u has root and __default__', unc && unc.logins);
  check(unc && unc.abilities.some(x => x.id === 'unconfined') && unc.abilities.some(x => x.id === 'loadPolicy'), 'unconfined_u: runs unconfined, can load policy', unc && unc.abilities);
  check(rep.mappings.some(m => m.login === '__default__' && m.notes.some(n => /unconfined_u/.test(n.text))), '__default__ → unconfined_u is noted');
  const staff = U('staff_u');
  const ssh = staff && staff.entries.find(e => e.source === 'sshd_t');
  check(ssh && ssh.contexts[0] && ssh.contexts[0].type === 'staff_t', 'staff_u over ssh lands in staff_t', staff && staff.entries);
  const user = U('user_u');
  check(user && user.reached > 10 && user.reached < staff.reached, `user_u reaches fewer domains (${user && user.reached}) than staff_u (${staff && staff.reached})`);
  check(user && !user.roles.includes('sysadm_r'), 'user_u has no sysadm_r');
  for (const u of rep.users || []) console.log(`  ${u.name}: ${u.roles.join(' ')} · reaches ${u.reached} · ${u.abilities.map(x => `${x.id}@${x.domain}`).join(', ')}`);
  check(rep.accounts && rep.accounts.people.some(p => p.name === 'root') && rep.accounts.services.some(s => s.name === 'daemon' && !s.canLogin), 'accounts: root among people, daemon a service account without a login', rep.accounts);
  const st = staff && staff.entries.find(e => e.source === 'sshd_t');
  const starts = st ? st.contexts : [];
  t0 = Date.now();
  // Its own contexts file lets ssh choose sysadm_r:sysadm_t directly; from staff_t it takes newrole or sudo.
  check(starts.some(c => c.type === 'sysadm_t'), 'staff_u over ssh may also choose sysadm_t', starts);
  const reach = await a.conn.sendRequest('selinux/loginReach', { user: 'staff_u', starts: [{ role: 'staff_r', type: 'staff_t' }] });
  const sys = reach.domains && reach.domains.find(d => d.name === 'sysadm_t');
  check(sys && sys.role === 'sysadm_r' && sys.path.length >= 1, `staff_u reaches sysadm_t as sysadm_r: ${pathText(sys && sys.path)}`, sys);
  const can = await a.conn.sendRequest('selinux/loginCan', { user: 'user_u', starts: [{ role: 'user_r', type: 'user_t' }], path: '/etc/shadow', tclass: 'file', perms: ['read'] });
  check(can.target === 'shadow_t' && can.resolved, '/etc/shadow resolves to shadow_t', can);
  console.log(`  user_u read /etc/shadow: ${can.can ? `yes, as ${can.domain}: ${pathText(can.path)}` : 'no'} (${Date.now() - t0} ms)`);
  const no = await a.conn.sendRequest('selinux/loginCan', { user: 'guest_u', starts: [{ role: 'guest_r', type: 'guest_t' }], target: 'security_t', tclass: 'security', perms: ['load_policy'] });
  check(no.can === false, 'guest_u cannot load policy', no);
  const bad = await a.conn.sendRequest('selinux/loginCan', { user: 'user_u', starts: [{ role: 'user_r', type: 'user_t' }], target: 'nope_t', tclass: 'file', perms: ['read'] });
  check(/not a type/.test(bad.error || ''), 'unknown type reported', bad);
  a.proc.kill();

  // 2. A tree build.
  if (!fs.existsSync(path.join(treeDir, 'Rules.modular'))) { console.log(`SKIP tree part: no tree at ${treeDir}`); }
  else {
    const b = start(treeDir, { build: { tree: { makeArgs: CLIP_ARGS } } });
    await b.init();
    t0 = Date.now();
    const res = await b.conn.sendRequest('selinux/build', { uri: URI.file(treeDir).toString() });
    console.log(`  tree build ${res && res.ok ? 'ok' : 'failed'} in ${Date.now() - t0} ms`);
    const tr = await b.conn.sendRequest('selinux/logins', { against: 'build' });
    if (VERBOSE) console.log(JSON.stringify(tr, null, 1).slice(0, 20000));
    check(!tr.error && tr.policy.id === 'build' && !tr.policy.host, 'tree build report (not this host)', tr.error || tr.policy);
    const TU = (n) => (tr.users || []).find(u => u.name === n);
    const cs = TU('staff_u');
    check(cs && cs.logins.some(l => l.login === '__default__'), 'CLIP: __default__ → staff_u', cs && cs.logins);
    check(tr.mappings.some(m => m.login === '__default__' && m.notes.some(n => /admin role/.test(n.text))), 'CLIP: __default__ gets a user with an admin role (noted)', tr.mappings);
    check(cs && cs.loc && /users$/.test(cs.loc.p), 'staff_u located at its gen_user line', cs && cs.loc);
    check(tr.accounts === null, 'no host accounts for a tree build');
    for (const u of tr.users || []) console.log(`  ${u.name}: ${u.roles.join(' ')} · reaches ${u.reached} · ${u.abilities.map(x => `${x.id}@${x.domain}`).join(', ')}`);
    b.proc.kill();
  }
  console.log(failures ? `${failures} FAILED` : 'all passed');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
