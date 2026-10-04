// Full source-tree build test: drives the server over stdio LSP against a copy
// of a refpolicy tree (default: CLIP for RHEL 9 on the test host) built with
// the tree's own Makefile. Usage:
//   node test/build-tree-e2e.js [tree-dir] [makeArgs.json]
// Needs Linux with make, m4, checkpolicy and policycoreutils-devel; skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain } = require('../server/build');

const tc = detectToolchain(null);
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }

const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');
if (!fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP: no refpolicy tree at ${src}`); process.exit(0); }
// CLIP's RPM build arguments (packages/selinux-policy/Makefile + selinux-policy.spec).
const CLIP_SEPARATE = 'ssh rhsmcertd oddjob rtkit aide postfix usbguard fapolicyd rngd logadm auditadm secadm sasl rpcbind rpc gssproxy kerberos certmonger pcscd apcupsd nut postgresql mysql apache bind openvpn samba ntp xserver accountsd colord geoclue gnome wm telepathy bluetooth devicekit';
const makeArgs = process.argv[3] ? JSON.parse(fs.readFileSync(process.argv[3], 'utf8')) :
  ['NAME=mcs', 'TYPE=mcs', 'DISTRO=redhat', 'UBAC=y', 'DIRECT_INITRC=n', 'MONOLITHIC=n', 'POLY=y', 'UNK_PERMS=deny',
    'MLS_CATS=1024', 'MCS_CATS=1024', 'SEMOD_EXP=/usr/bin/semodule_expand', `APPS_MODS=${CLIP_SEPARATE}`];

// Work on a copy so the test can edit files freely.
const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-tree-e2e-'));
cp.execFileSync('cp', ['-a', src + '/.', ws]);
fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
const P = (rel) => path.join(ws, rel);
const LOGGING = P('policy/modules/system/logging.te'), FILES = P('policy/modules/kernel/files.te');
const ORIG = { [LOGGING]: fs.readFileSync(LOGGING, 'utf8'), [FILES]: fs.readFileSync(FILES, 'utf8') };

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
const diags = {};
const waiters = [];
let stats, doneIndex;
const indexed = new Promise(r => (doneIndex = r));
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') { stats = p.stats; doneIndex(); } });
conn.onNotification('selinux/build', p => { if (p.state === 'done') waiters.splice(0).forEach(w => w(p)); });
conn.onNotification('window/logMessage', () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
const sleep = ms => new Promise(r => setTimeout(r, ms));
const nextBuild = () => new Promise(r => waiters.push(r));

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 1500).replace(/\n/g, '\n     ')); }
};
const fmt = (f) => (diags[uri(f)] || []).map(d => `${d.range.start.line + 1}:${d.range.start.character} [${d.source}] ${d.message}`);
const versions = {};
const open = (f) => { versions[f] = 1; conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(f), languageId: 'selinux', version: 1, text: fs.readFileSync(f, 'utf8') } }); };
// Edits stay unsaved on disk: the build must compile the editor buffer.
const edit = async (f, text) => {
  conn.sendNotification('textDocument/didChange', { textDocument: { uri: uri(f), version: ++versions[f] }, contentChanges: [{ text }] });
  await sleep(400);
};
const save = (f) => { const b = nextBuild(); conn.sendNotification('textDocument/didSave', { textDocument: { uri: uri(f) } }); return b; };
const lineOf = (text, needle) => text.split('\n').findIndex(l => l.includes(needle));
const hover = async (f, text, needle) => {
  const line = lineOf(text, needle);
  const h = await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(f) }, position: { line, character: text.split('\n')[line].indexOf(needle) + 1 } });
  return h ? h.contents.value : '';
};

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {},
    initializationOptions: { build: { tree: { makeArgs } } } });
  conn.sendNotification('initialized', {});
  await indexed;
  check(stats.buildMode === 'tree', `workspace detected as a source tree (${stats.modules} modules)`, stats);
  open(LOGGING); open(FILES);
  await sleep(400);

  // 1. Full build: compile, then link validation.
  let r = await conn.sendRequest('selinux/build', { uri: uri(LOGGING) });
  check(r.ok && r.validated && r.packages > 1 && r.policyBin && fs.existsSync(r.policyBin),
    `full build + validate (${(r.ms / 1000).toFixed(1)} s, ${r.packages} packages)`, { ...r, log: r.log && r.log.slice(-1500) });

  // 2. Compile error in a loadable module, from an unsaved buffer.
  let t = ORIG[LOGGING] + 'allow syslogd_t nosuch_t:file read;\n';
  await edit(LOGGING, t);
  r = await save(LOGGING);
  let d = (diags[uri(LOGGING)] || []).find(x => x.source === 'checkmodule');
  check(!r.ok && !r.validated, 'module compile error fails phase 1 (no link step)', r.ok);
  check(d && d.range.start.line === lineOf(t, 'nosuch_t') && /unknown type nosuch_t/.test(d.message), 'checkmodule error on the right line of logging.te', fmt(LOGGING));
  await edit(LOGGING, ORIG[LOGGING]);

  // 3. Compile error in a base module.
  t = ORIG[FILES] + 'allow var_t nosuch_t:file read;\n';
  await edit(FILES, t);
  r = await save(FILES);
  d = (diags[uri(FILES)] || []).find(x => x.source === 'checkmodule');
  check(!r.ok && d && d.range.start.line === lineOf(t, 'nosuch_t'), 'base module (files.te) error on the right line', fmt(FILES));
  await edit(FILES, ORIG[FILES]);

  // 4. Link error: requiring a type whose module is off in modules.conf.
  t = ORIG[LOGGING] + "gen_require(`\n\ttype squid_t;\n')\nallow syslogd_t squid_t:process signal;\n";
  await edit(LOGGING, t);
  r = await save(LOGGING);
  d = (diags[uri(LOGGING)] || []).find(x => x.source === 'semodule_link');
  check(!r.ok && d && d.range.start.line === lineOf(t, 'type squid_t') && /squid_t/.test(d.message), 'link error placed on the require of squid_t', { ok: r.ok, diags: fmt(LOGGING), log: r.log.slice(-600) });
  await edit(LOGGING, ORIG[LOGGING]);
  r = await save(LOGGING);
  check(r.ok && r.validated && !(diags[uri(LOGGING)] || []).some(x => x.source !== 'selinux'), 'reverted tree builds and validates cleanly', fmt(LOGGING));

  // 5. "Compiles to" hover: a loadable module (tmp/<mod>.tmp) and a base module (base.conf).
  let h = await hover(LOGGING, ORIG[LOGGING], 'init_daemon_domain(syslogd_t');
  check(/Compiles to/.test(h) && /allow syslogd_t syslogd_exec_t:file entrypoint/.test(h), 'hover expansion in a loadable module', h.slice(-500));
  h = await hover(FILES, ORIG[FILES], 'files_mountpoint(var_run_t)');
  check(/Compiles to/.test(h) && /typeattribute var_run_t mountpoint/.test(h), 'hover expansion in a base module', h.slice(-500));

  // 6. Expanded policy: one file's part of base.conf; an off module has none.
  let ex = await conn.sendRequest('selinux/expandedPolicy', { uri: uri(FILES) });
  check(ex.text && /# ──── files\.te:\d+: files_mountpoint\(var_run_t\)/.test(ex.text) && !/logging\.te/.test(ex.text), 'expanded view of files.te shows only files.te', ex.unavailable || ex.text.slice(0, 300));
  ex = await conn.sendRequest('selinux/expandedPolicy', { uri: uri(P('policy/modules/services/squid.te')) });
  check(ex.unavailable && /off in modules\.conf/.test(ex.unavailable), 'expanded view explains a disabled module', ex);

  // 7. Compiled policy model: what the kernel policy contains, with source locations.
  const m = await conn.sendRequest('selinux/policyModel');
  check(!m.unavailable && m.types.length === m.counts.types && m.types.length > 100, `policy model loaded (${m.types && m.types.length} types, ${m.transitions && m.transitions.length} domain transitions)`, m.unavailable);
  if (!m.unavailable) {
    const T = (n) => m.types.find(t => t.name === n);
    const located = m.types.filter(t => t.loc).length;
    check(located / m.types.length > 0.95, `source location for ${located}/${m.types.length} types`, m.types.filter(t => !t.loc).slice(0, 15).map(t => t.name));
    check(T('syslogd_t') && T('syslogd_t').loc && T('syslogd_t').loc.p === LOGGING && T('syslogd_t').loc.m === 'logging', 'syslogd_t located in logging.te (module logging)', T('syslogd_t'));
    check(!T('squid_t'), 'types of disabled modules are absent (squid_t)');
    check(m.types.some(t => t.loc && t.loc.via), 'template-generated types point at the generating call', null);
    const su = m.users.find(u => u.name === 'system_u');
    check(su && su.loc && /policy[\\/]users$/.test(su.loc.p) && su.roles.includes('system_r'), 'system_u located in policy/users with role system_r', su);
    check(m.transitions.some(x => x.result === 'syslogd_t' && x.entry === 'syslogd_exec_t'), 'domain transition into syslogd_t via syslogd_exec_t');
    check(m.bools.filter(b => b.loc).length / m.bools.length > 0.9, `source location for ${m.bools.filter(b => b.loc).length}/${m.bools.length} booleans`, m.bools.filter(b => !b.loc).slice(0, 10).map(b => b.name));

    // 8. The Compiled Policy tree view, driven with a stub vscode module.
    const Module = require('module');
    const stub = {
      EventEmitter: class { constructor() { this.event = () => {}; } fire() {} },
      TreeItem: class { constructor(label, state) { this.label = label; this.collapsibleState = state; } },
      ThemeIcon: class { constructor(id) { this.id = id; } },
      TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
      workspace: { asRelativePath: (p) => p },
    };
    const load = Module._load;
    const lcStub = { LanguageClient: class {}, TransportKind: {} }; // needs a real VS Code; unused by the view
    Module._load = function (req, ...rest) { return req === 'vscode' ? stub : req === 'vscode-languageclient/node' ? lcStub : load.call(this, req, ...rest); };
    const { CompiledPolicyView } = require('../client/extension');
    Module._load = load;
    const view = new CompiledPolicyView(async () => m);
    const roots = await view.getChildren();
    const labels = (ns) => ns.map(n => n.item.label);
    const child = async (n, label) => (await view.getChildren(n)).find(k => k.item.label === label);
    check(['Modules', 'Users', 'Roles', 'Domains', 'Types', 'Attributes', 'Booleans', 'Classes'].every(l => labels(roots).includes(l)), 'view top level: Modules, Users, Roles, Domains, Types, Attributes, Booleans, Classes', labels(roots));
    const logMod = await child(await child(roots[0].item.label === 'Modules' ? roots[0] : roots.find(r => r.item.label === 'Modules'), 'logging'), 'Types');
    const sys = logMod && await child(logMod, 'syslogd_t');
    check(sys && sys.item.command && sys.item.command.arguments[0] === LOGGING, 'Modules › logging › Types › syslogd_t opens logging.te', sys && sys.item);
    const sysKids = sys ? labels(await view.getChildren(sys)) : [];
    check(['Attributes', 'Roles', 'Entered from'].every(l => sysKids.includes(l)), `syslogd_t expands to its relationships (${sysKids.join(', ')})`);
    const entered = sys && await child(sys, 'Entered from');
    const from = entered ? await view.getChildren(entered) : [];
    check(from.length && from.every(n => /^via \w+$/.test(n.item.description)), `"Entered from" lists source domains with entrypoints (${from.slice(0, 3).map(n => `${n.item.label} ${n.item.description}`).join('; ')})`);
    const sysU = await child(await child(roots.find(r => r.item.label === 'Users'), 'system_u'), 'system_r');
    check(sysU && /types/.test(sysU.item.description), 'Users › system_u › system_r (role with its types)', sysU && sysU.item);
    const canon = view.canonical('type', 'syslogd_t');
    check(canon && canon.parent && canon.parent.key === 'types' && canon.item.id === '/types/t:syslogd_t', 'canonical node for reveal: Types › syslogd_t', canon && canon.item.id);
  }

  // 9. Clean shutdown removes the scratch tree.
  const scratch = path.join(os.tmpdir(), 'selinux-policy-tools', 'tree-' + crypto.createHash('sha1').update(ws).digest('hex').slice(0, 12));
  check(fs.existsSync(scratch), 'scratch tree exists while the server runs');
  await conn.sendRequest('shutdown');
  const exited = new Promise(res => proc.on('exit', res));
  conn.sendNotification('exit');
  await Promise.race([exited, sleep(5000)]);
  check(!fs.existsSync(scratch), 'scratch tree removed on server exit');

  console.log(failures ? `\n${failures} check(s) failed` : '\nall tree build checks passed');
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); fs.rmSync(ws, { recursive: true, force: true }); process.exit(1); });
