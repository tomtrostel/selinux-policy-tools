// Several policy trees in one workspace (CLIP and RHEL 10 side by side): one
// is active at a time (indexed, built, shown), each with its own build
// settings (selinux.build.trees); switching moves everything over.
//   node test/multi-tree-e2e.js [clip-tree] [rhel10-tree] [rhel10-spec-dir]
// Needs Linux with the build toolchain and both trees; skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain } = require('../server/build');

const tc = detectToolchain(null);
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }
const CLIP_SRC = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');
const R10_SRC = process.argv[3] || path.join(os.homedir(), 'sepol-test/rhel10');
const SPEC10 = process.argv[4] || path.join(os.homedir(), 'sepol-test/srpm10');
if (![CLIP_SRC, R10_SRC].every(t => fs.existsSync(path.join(t, 'Rules.modular'))) || !fs.existsSync(path.join(SPEC10, 'modules-dropped.lst'))) {
  console.log('SKIP: need the CLIP and RHEL 10 trees and the RHEL 10 spec directory'); process.exit(0);
}

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-multi-e2e-'));
const CLIP = path.join(ws, 'clip'), R10 = path.join(ws, 'rhel10');
for (const [s, d] of [[CLIP_SRC, CLIP], [R10_SRC, R10]]) { cp.execFileSync('cp', ['-a', s, d]); fs.rmSync(path.join(d, 'tmp'), { recursive: true, force: true }); }
const CLIP_SEPARATE = 'ssh rhsmcertd oddjob rtkit aide postfix usbguard fapolicyd rngd logadm auditadm secadm sasl rpcbind rpc gssproxy kerberos certmonger pcscd apcupsd nut postgresql mysql apache bind openvpn samba ntp xserver accountsd colord geoclue gnome wm telepathy bluetooth devicekit';
const trees = {
  clip: { makeArgs: ['NAME=mcs', 'TYPE=mcs', 'DISTRO=redhat', 'UBAC=y', 'DIRECT_INITRC=n', 'MONOLITHIC=n', 'POLY=y', 'UNK_PERMS=deny', 'MLS_CATS=1024', 'MCS_CATS=1024', `APPS_MODS=${CLIP_SEPARATE}`] },
  rhel10: {
    makeArgs: ['DISTRO=redhat', 'UBAC=n', 'DIRECT_INITRC=n', 'MONOLITHIC=n', 'MLS_CATS=1024', 'MCS_CATS=1024', 'UNK_PERMS=allow', 'NAME=targeted', 'TYPE=mcs'],
    files: {
      'policy/booleans.conf': ['dist/targeted/booleans.conf'],
      'policy/users': ['dist/targeted/users'],
      'policy/modules.conf': [{ from: 'dist/targeted/modules.conf', disable: [path.join(SPEC10, 'modules-dropped.lst')] }],
    },
  },
};

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
const diags = {};
let stats = null, flags = null;
let doneIndex;
const indexed = new Promise(r => (doneIndex = r));
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') { stats = p.stats; doneIndex(); } });
conn.onNotification('selinux/inactiveChanged', p => { flags = p.flags; });
conn.onNotification('window/logMessage', () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 1500).replace(/\n/g, '\n     ')); }
};
const LOG_C = path.join(CLIP, 'policy/modules/system/logging.te'), LOG_R = path.join(R10, 'policy/modules/system/logging.te');
const defOf = async (file, word) => {
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const l = lines.findIndex(x => new RegExp(`\\b${word}\\b`).test(x) && !/^\s*#/.test(x));
  return conn.sendRequest('textDocument/definition', { textDocument: { uri: uri(file) }, position: { line: l, character: lines[l].search(new RegExp(`\\b${word}\\b`)) + 1 } });
};
const under = (locs, root) => locs.length > 0 && locs.every(d => URI.parse(d.uri).fsPath.startsWith(root + path.sep));

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {}, initializationOptions: { build: { trees } } });
  conn.sendNotification('initialized', {});
  await indexed;

  // 1. Both trees found; one active (the first, without a choice).
  check(stats.trees.length === 2 && stats.trees.map(t => t.name).join(',') === 'clip,rhel10' && stats.tree === CLIP,
    `trees: ${stats.trees.map(t => `${t.name}${t.active ? '*' : ''}`).join(', ')}`, stats.trees);
  for (const f of [LOG_C, LOG_R]) conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(f), languageId: 'selinux', version: 1, text: fs.readFileSync(f, 'utf8') } });
  await sleep(1500);
  let d = await defOf(LOG_C, 'syslogd_t');
  check(under(d, CLIP), `definition of syslogd_t stays in the active tree (${d.map(x => path.relative(ws, URI.parse(x.uri).fsPath)).join(', ')})`, d);
  const hint = (diags[uri(LOG_R)] || []);
  check(hint.length === 1 && hint[0].code === 'inactive-tree' && /policy tree rhel10, but clip is the one being worked on/.test(hint[0].message),
    `a file of the inactive tree gets a hint, no analysis: ${hint.map(x => x.message.slice(0, 80)).join(' | ')}`, hint);
  for (let i = 0; i < 40 && !flags; i++) await sleep(250);
  check(flags && /enable_mcs/.test(flags) && /enable_ubac/.test(flags), `m4 flags from clip's settings: ${flags}`);

  // 2. Building: the active tree with its own settings; a file of the other tree isn't built.
  let r = await conn.sendRequest('selinux/build', { uri: uri(LOG_C) });
  check(r.ok && r.packages > 80 && r.packages < 120, `clip builds with its settings (${r.packages} packages, ${(r.ms / 1000).toFixed(1)} s)`, { ...r, log: r.log && r.log.slice(-800) });
  r = await conn.sendRequest('selinux/build', { uri: uri(LOG_R) });
  check(r.unavailable && /outside the policy tree/.test(r.unavailable), `rhel10 file while clip is active: "${r.unavailable}"`, r);

  // 3. Switch to rhel10: index, flags, hint and builds follow.
  flags = null;
  const sw = await conn.sendRequest('selinux/selectTree', { root: R10 });
  await sleep(1500);
  check(sw.ok && stats.tree === R10 && stats.trees.find(t => t.active).name === 'rhel10', `switched to ${sw.name}`, sw);
  d = await defOf(LOG_R, 'syslogd_t');
  check(under(d, R10), `definition of syslogd_t now in rhel10 (${d.map(x => path.relative(ws, URI.parse(x.uri).fsPath)).join(', ')})`, d);
  check(!(diags[uri(LOG_R)] || []).some(x => x.code === 'inactive-tree') && (diags[uri(LOG_C)] || []).some(x => x.code === 'inactive-tree'),
    'the hint moved to the clip file');
  for (let i = 0; i < 40 && !flags; i++) await sleep(250);
  check(flags && /enable_mcs/.test(flags) && !/enable_ubac/.test(flags), `m4 flags from rhel10's settings (UBAC=n): ${flags}`);
  r = await conn.sendRequest('selinux/build', { uri: uri(LOG_R) });
  check(r.ok && r.validated && r.packages > 400, `rhel10 builds with its settings (${r.packages} packages, ${(r.ms / 1000).toFixed(1)} s)`, { ...r, log: r.log && r.log.slice(-800) });
  const m = await conn.sendRequest('selinux/policyModel');
  check(!m.unavailable && m.tree === R10 && m.types.length > 4000, `Compiled Policy view shows rhel10 (${m.types && m.types.length} types)`, m.unavailable);

  // 4. Back to clip: its last build is still there (per-tree build results).
  await conn.sendRequest('selinux/selectTree', { root: CLIP });
  await sleep(1000);
  const m2 = await conn.sendRequest('selinux/policyModel');
  check(!m2.unavailable && m2.tree === CLIP && m2.types.length < 3000, `back on clip: its build is shown without rebuilding (${m2.types && m2.types.length} types)`, m2.unavailable);
  const tr = await conn.sendRequest('selinux/trees');
  check(tr.active === CLIP && tr.trees.every(t => t.key === t.name), `selinux/trees: ${tr.trees.map(t => `${t.key}${t.active ? '*' : ''}`).join(', ')}`, tr);

  await conn.sendRequest('shutdown');
  const exited = new Promise(res => proc.on('exit', res));
  conn.sendNotification('exit');
  await Promise.race([exited, sleep(5000)]);
  console.log(failures ? `\n${failures} check(s) failed` : '\nall multi-tree checks passed');
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); fs.rmSync(ws, { recursive: true, force: true }); process.exit(1); });
