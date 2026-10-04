// "What did this change grant": compare the working tree's build with HEAD.
// Copies a refpolicy tree (default: CLIP for RHEL 9 on the test host) into a
// fresh git repository, edits a module in an unsaved buffer, and checks the
// policy diff and its source tracing. Usage:
//   node test/diff-e2e.js [tree-dir] [makeArgs.json]
// Needs Linux with make, m4, checkpolicy, policycoreutils-devel, setools and git; skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain } = require('../server/build');

const tc = detectToolchain(null);
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }
const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');
if (!fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP: no refpolicy tree at ${src}`); process.exit(0); }
const CLIP_SEPARATE = 'ssh rhsmcertd oddjob rtkit aide postfix usbguard fapolicyd rngd logadm auditadm secadm sasl rpcbind rpc gssproxy kerberos certmonger pcscd apcupsd nut postgresql mysql apache bind openvpn samba ntp xserver accountsd colord geoclue gnome wm telepathy bluetooth devicekit';
const makeArgs = process.argv[3] ? JSON.parse(fs.readFileSync(process.argv[3], 'utf8')) :
  ['NAME=mcs', 'TYPE=mcs', 'DISTRO=redhat', 'UBAC=y', 'DIRECT_INITRC=n', 'MONOLITHIC=n', 'POLY=y', 'UNK_PERMS=deny',
    'MLS_CATS=1024', 'MCS_CATS=1024', 'SEMOD_EXP=/usr/bin/semodule_expand', `APPS_MODS=${CLIP_SEPARATE}`];

// The tree lives in a subdirectory of the repository, like CLIP's.
const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-diff-e2e-'));
const ws = path.join(repo, 'policy-src');
cp.execFileSync('cp', ['-a', src + '/.', ws]);
fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
const g = (...a) => cp.execFileSync('git', a, { cwd: repo, stdio: 'pipe' });
g('init', '-q'); g('add', '-A'); g('-c', 'user.name=t', '-c', 'user.email=t@e', 'commit', '-q', '-m', 'baseline');
const LOGGING = path.join(ws, 'policy/modules/system/logging.te');
const ORIG = fs.readFileSync(LOGGING, 'utf8');
const PROC_LINE = 'allow syslogd_t self:process { getcap setcap signal_perms setpgid setrlimit getsched setsched };';
const EDITED = ORIG.replace(PROC_LINE, 'allow syslogd_t self:process { getcap setcap signal_perms setpgid setrlimit };')
  + '\nauth_read_shadow(syslogd_t)\nfiles_manage_etc_files(syslogd_t)\n';

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
let doneIndex;
const indexed = new Promise(r => (doneIndex = r));
const states = [];
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
conn.onNotification('selinux/build', p => states.push(p.state));
conn.onNotification('textDocument/publishDiagnostics', () => {});
conn.onNotification('window/logMessage', () => {});
conn.onNotification('selinux/inactiveChanged', () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2000).replace(/\n/g, '\n     ')); }
};
const rel = (p) => path.relative(ws, p);
const lineOf = (text, needle) => text.split('\n').findIndex(l => l.includes(needle));

(async () => {
  if (!PROC_LINE || EDITED === ORIG + '\nauth_read_shadow(syslogd_t)\nfiles_manage_etc_files(syslogd_t)\n') { console.log('SKIP: logging.te no longer has the expected line'); process.exit(0); }
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {}, initializationOptions: { build: { tree: { makeArgs } } } });
  conn.sendNotification('initialized', {});
  await indexed;

  // 1. No edits: the working tree compiles to exactly HEAD's policy.
  let d = await conn.sendRequest('selinux/policyDiff');
  check(!d.unavailable && d.ruleCount === 0 && !d.membership.length, `unchanged tree: no policy difference (${d.ms && (d.ms.total / 1000).toFixed(1)} s incl. HEAD build)`, d.unavailable || d.rules);
  check(states.includes('baseline') && d.head && d.head.subject === 'baseline', 'HEAD baseline built from the commit', { states, head: d.head });

  // 2. Edit in an unsaved buffer, build, compare.
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(LOGGING), languageId: 'selinux', version: 1, text: EDITED } });
  await sleep(400);
  const b = await conn.sendRequest('selinux/build', { uri: uri(LOGGING) });
  check(b.ok, 'edited tree builds');
  d = await conn.sendRequest('selinux/policyDiff');
  const R = (s, t, c) => d.rules.find(r => r.s === s && r.t === t && r.c === c && r.rt === 'allow');
  check(!d.unavailable && d.ruleCount === 5, `5 rule changes (${d.ms && (d.ms.total / 1000).toFixed(1)} s with cached HEAD build)`, d.unavailable || d.rules && d.rules.map(r => `${r.kind} ${r.s} ${r.t}:${r.c} +${r.add} -${r.del}`));
  const shadow = R('syslogd_t', 'shadow_t', 'file');
  const auth = lineOf(EDITED, 'auth_read_shadow(syslogd_t)'), files = lineOf(EDITED, 'files_manage_etc_files(syslogd_t)');
  check(shadow && shadow.kind === 'added' && shadow.addFrom.origins[0].path === LOGGING && shadow.addFrom.origins[0].line === auth && /auth_read_shadow/.test(shadow.addFrom.origins[0].via),
    `+ shadow_t:file traced to logging.te:${auth + 1} via auth_read_shadow`, shadow && shadow.addFrom);
  check(R('syslogd_t', 'shadow_history_t', 'file') && R('syslogd_t', 'shadow_history_t', 'file').addFrom.origins[0].line === auth, '+ shadow_history_t:file (a side effect of auth_read_shadow) traced to the same line');
  const etc = R('syslogd_t', 'etc_t', 'dir');
  check(etc && etc.kind === 'modified' && etc.add.includes('write') && etc.addFrom.origins[0].line === files, `~ etc_t:dir +write traced to logging.te:${files + 1} via files_manage_etc_files`, etc && etc.addFrom);
  const pr = R('syslogd_t', 'syslogd_t', 'process');
  const procLine = lineOf(ORIG, PROC_LINE);
  check(pr && pr.del.join() === 'getsched,setsched' && pr.delFrom.origins[0].head && pr.delFrom.origins[0].line === procLine && rel(pr.delFrom.origins[0].real) === 'policy/modules/system/logging.te',
    `- process getsched setsched traced to HEAD logging.te:${procLine + 1}`, pr && pr.delFrom);
  const mem = d.membership.find(m => m.type === 'syslogd_t');
  check(mem && mem.added.includes('can_read_shadow_passwords') && mem.addFrom[0].origins.some(o => o.line === auth),
    'syslogd_t joined can_read_shadow_passwords, traced to the auth_read_shadow line', mem);

  // 2b. The Changes since HEAD view, driven with a stub vscode module.
  const Module = require('module');
  const stub = {
    EventEmitter: class { constructor() { this.event = () => {}; } fire() {} },
    TreeItem: class { constructor(label, state) { this.label = label; this.collapsibleState = state; } },
    ThemeIcon: class { constructor(id) { this.id = id; } }, ThemeColor: class { constructor(id) { this.id = id; } },
    TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
    workspace: { asRelativePath: (p) => path.relative(ws, p) },
  };
  const load = Module._load;
  Module._load = function (req, ...rest) { return req === 'vscode' ? stub : req === 'vscode-languageclient/node' ? { LanguageClient: class {}, TransportKind: {} } : load.call(this, req, ...rest); };
  const { ChangesView } = require('../client/extension');
  Module._load = load;
  const view = new ChangesView(async () => d);
  await view.compare();
  const top = await view.getChildren();
  const kid = async (n, re) => (await view.getChildren(n)).find(k => re.test(k.item.label));
  check(/^vs HEAD [0-9a-f]{7}$/.test(top[0].item.label) && top.some(n => n.item.label === 'Rules') && top.some(n => n.item.label === 'Attribute membership'),
    `view: ${top.map(n => n.item.label).join(' | ')}`);
  const rulesBySrc = await kid(top.find(n => n.item.label === 'Rules'), /^syslogd_t$/);
  const ruleNodes = await view.getChildren(rulesBySrc);
  const shadowNode = ruleNodes.find(n => /shadow_t:file$/.test(n.item.label));
  const shadowOrigins = await view.getChildren(shadowNode);
  check(ruleNodes.length === 5 && shadowNode.item.description.startsWith('+') && shadowOrigins[0].item.label === `policy/modules/system/logging.te:${auth + 1}` && /auth_read_shadow/.test(shadowOrigins[0].item.description) && shadowOrigins[0].item.command.arguments[0] === LOGGING,
    `view: syslogd_t › allow syslogd_t shadow_t:file › ${shadowOrigins[0] && shadowOrigins[0].item.label} (${shadowOrigins[0] && shadowOrigins[0].item.description})`);
  const procNode = ruleNodes.find(n => /syslogd_t:process$/.test(n.item.label));
  const procOrigins = await view.getChildren(procNode);
  check(/−getsched −setsched/.test(procNode.item.description) && /\(HEAD\)$/.test(procOrigins[0].item.label) && fs.existsSync(procOrigins[0].item.command.arguments[0]),
    `view: removed permissions point at the HEAD copy (${procOrigins[0] && procOrigins[0].item.label})`);

  // 3. A change with no effect on the compiled policy.
  conn.sendNotification('textDocument/didChange', { textDocument: { uri: uri(LOGGING), version: 2 }, contentChanges: [{ text: ORIG + '\nallow syslogd_t self:capability sys_ptrace;\n' }] });
  await sleep(400);
  await conn.sendRequest('selinux/build', { uri: uri(LOGGING) });
  d = await conn.sendRequest('selinux/policyDiff');
  check(!d.unavailable && d.ruleCount === 0, 'a rule that is already granted: no effective change', d.rules && d.rules.length);
  await view.compare();
  const top3 = await view.getChildren();
  check(top3.some(n => /^No effective policy change/.test(n.item.label)), 'view says "No effective policy change"', top3.map(n => n.item.label));

  const area = path.dirname((await conn.sendRequest('selinux/build', { uri: uri(LOGGING) })).workDir);
  const inArea = fs.readdirSync(area);
  check(inArea.some(n => /^head-/.test(n)) && inArea.some(n => /^tree-/.test(n)), `HEAD export and both trees live in this server's scratch area (${inArea.join(', ')})`);
  await conn.sendRequest('shutdown');
  const exited = new Promise(res => proc.on('exit', res));
  conn.sendNotification('exit');
  await Promise.race([exited, sleep(5000)]);
  check(!fs.existsSync(area), 'the whole scratch area is removed on server exit');
  console.log(failures ? `\n${failures} check(s) failed` : '\nall diff checks passed');
  proc.kill();
  fs.rmSync(repo, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); fs.rmSync(repo, { recursive: true, force: true }); process.exit(1); });
