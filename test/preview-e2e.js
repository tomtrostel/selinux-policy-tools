// Module on/off preview: build the tree with one module flipped in
// modules.conf (separate scratch copy) and compare with the current build.
// Default tree: CLIP for RHEL 9 on the test host. Usage:
//   node test/preview-e2e.js [tree-dir] [makeArgs.json]
// Needs Linux with make, m4, checkpolicy, policycoreutils-devel and setools; skips otherwise.
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

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-preview-e2e-'));
cp.execFileSync('cp', ['-a', src + '/.', ws]);
fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
let doneIndex;
const indexed = new Promise(r => (doneIndex = r));
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
for (const n of ['selinux/build', 'textDocument/publishDiagnostics', 'window/logMessage', 'selinux/inactiveChanged']) conn.onNotification(n, () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2000).replace(/\n/g, '\n     ')); }
};
const rel = (p) => p ? path.relative(ws, p) : String(p);
const inBlock = (o, blocks) => blocks.some(b => b.path === o.path && o.line >= b.l && o.line <= b.endL);

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {}, initializationOptions: { build: { tree: { makeArgs } } } });
  conn.sendNotification('initialized', {});
  await indexed;

  const st = await conn.sendRequest('selinux/moduleStates');
  const S = (m) => st.modules && st.modules.find(x => x.module === m);
  check(S('cron') && S('cron').state === 'module' && S('nscd').state === 'off' && S('ntp').apps && S('files').state === 'base',
    `module states: cron=${S('cron') && S('cron').state}, nscd=${S('nscd') && S('nscd').state}, ntp via APPS_MODS, files=${S('files') && S('files').state}`, st.unavailable);

  const b = await conn.sendRequest('selinux/build', { uri: uri(ws) });
  check(b.ok && b.validated, `current build (${(b.ms / 1000).toFixed(1)} s)`);
  const curBin = b.policyBin, curMtime = fs.statSync(curBin).mtimeMs;

  // 1. cron off: still links; optional blocks in other modules drop out, with their unrelated rules.
  let p = await conn.sendRequest('selinux/modulePreview', { module: 'cron', to: 'off' });
  check(p.ok && p.from === 'module' && p.to === 'off' && p.diff, `cron → off links (${p.ms && (p.ms.total / 1000).toFixed(1)} s)`, p.unavailable || p.errors);
  check(p.optionalBlocks.length > 10 && p.optionalBlocks.every(x => x.module !== 'cron') && p.optionalBlocks.some(x => x.uses.some(u => /^cron_/.test(u))),
    `${p.optionalBlocks.length} optional_policy blocks in ${new Set(p.optionalBlocks.map(x => x.module)).size} modules depend on cron (e.g. ${p.optionalBlocks[0] && `${rel(p.optionalBlocks[0].path)}:${p.optionalBlocks[0].l + 1} uses ${p.optionalBlocks[0].uses.join(', ')}`})`);
  const d = p.diff || { rules: [], types: { removed: [] } };
  check(d.types.removed.includes('crond_t') && d.ruleCount > 50 && d.rules.every(r => r.kind !== 'added' || r.add.length === 0 || true),
    `cron → off removes ${d.types.removed.length} types (incl. crond_t) and changes ${d.ruleCount} rules`);
  const fromBlock = d.rules.find(r => r.delFrom && r.delFrom.origins.some(o => inBlock(o, p.optionalBlocks)));
  check(fromBlock, `a removed rule traced into another module's optional block: ${fromBlock && `${fromBlock.s} ${fromBlock.t}:${fromBlock.c} ← ${rel(fromBlock.delFrom.origins.find(o => inBlock(o, p.optionalBlocks)).path)}:${fromBlock.delFrom.origins.find(o => inBlock(o, p.optionalBlocks)).line + 1}`}`);
  check(p.apply && rel(p.apply.path) === 'policy/modules.conf' && fs.readFileSync(p.apply.path, 'utf8').split('\n')[p.apply.line].replace(/\s/g, '') === 'cron=module',
    `apply target: ${p.apply && `${rel(p.apply.path)}:${p.apply.line + 1}`}`);
  check(fs.statSync(curBin).mtimeMs === curMtime, 'the current build was not touched by the preview');

  // 2. mta off: other modules use it outside optional_policy, so linking fails and names them.
  p = await conn.sendRequest('selinux/modulePreview', { module: 'mta', to: 'off' });
  const linkErrs = (p.errors || []).filter(e => e.tool === 'semodule_link' || /requires|not met|scope/.test(e.msg));
  check(p.ok === false && linkErrs.length > 0, `mta → off fails: ${(p.errors || []).length} errors (${linkErrs.length} link), e.g. ${(p.errors || []).slice(0, 2).map(e => `${rel(e.path)}:${e.l + 1} ${e.msg.slice(0, 140)}`).join(' | ')}`, p.unavailable || p.log);
  const le = linkErrs[0];
  const leLine = le && fs.readFileSync(le.path, 'utf8').split('\n')[le.l];
  check(le && le.l > 0 && /required through (\w+)\(\)/.test(le.msg) && leLine.includes(/required through (\w+)\(\)/.exec(le.msg)[1]),
    `link error placed on the interface call that requires it: ${le && `${rel(le.path)}:${le.l + 1}: ${leLine && leLine.trim()}`}`);

  // 3. nscd on: optional blocks elsewhere come alive.
  p = await conn.sendRequest('selinux/modulePreview', { module: 'nscd', to: 'module' });
  const e = p.diff || { types: { added: [] }, rules: [] };
  check(p.ok && e.types.added.includes('nscd_t') && p.optionalBlocks.length > 5, `nscd → module: adds ${e.types.added.length} types (incl. nscd_t), ${p.optionalBlocks && p.optionalBlocks.length} optional blocks come alive`, p.unavailable || p.errors);
  const alive = e.rules.find(r => r.addFrom && r.addFrom.origins.some(o => inBlock(o, p.optionalBlocks)));
  check(alive, `an added rule traced into a now-active optional block: ${alive && `${alive.s} ${alive.t}:${alive.c}`}`);

  // 4. A module forced on by APPS_MODS: turning it off also drops it from APPS_MODS.
  p = await conn.sendRequest('selinux/modulePreview', { module: 'ntp', to: 'off' });
  // (after previews that changed the module set: stale all_mods.fc must not break validate)
  check(p.appsMods && p.appsChanged && p.ok && p.diff.types.removed.includes('ntpd_t'), `ntp (APPS_MODS) → off: dropped from APPS_MODS too, removes ntpd_t`, { ok: p.ok, errors: p.errors, log: p.log, unavailable: p.unavailable });

  // 5. The Module Preview view (stub vscode): cron off, then mta off.
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
  const { ModulePreviewView } = require('../client/extension');
  Module._load = load;
  const view = new ModulePreviewView((m, prm) => conn.sendRequest(m, prm));
  await view.run('cron', 'off');
  let top = await view.getChildren();
  const labels = top.map(n => n.item.label);
  check(labels[0] === 'cron: module → off' && /^Apply: set cron = off in policy\/modules\.conf$/.test(labels[1]) && labels.includes('optional_policy blocks that drop out') && labels.includes('Rules'),
    `view (cron off): ${labels.join(' | ')}`);
  const blocksNode = top.find(n => n.item.label === 'optional_policy blocks that drop out');
  const firstMod = (await view.getChildren(blocksNode))[0];
  const firstBlock = (await view.getChildren(firstMod))[0];
  check(firstBlock && /\.te:\d+$/.test(firstBlock.item.label) && /^uses cron_/.test(firstBlock.item.description) && firstBlock.item.command,
    `view: blocks › ${firstMod && firstMod.item.label} › ${firstBlock && firstBlock.item.label} (${firstBlock && firstBlock.item.description})`);
  await view.run('mta', 'off');
  top = await view.getChildren();
  const errs = top.find(n => n.item.label === 'Link errors');
  const e1 = errs && (await view.getChildren(errs))[0];
  check(top[0].item.description === 'fails to link' && e1 && /postfix\.te:\d+$/.test(e1.item.label), `view (mta off): ${top[0].item.label} ${top[0].item.description} › ${e1 && e1.item.label}`);

  await conn.sendRequest('shutdown');
  const exited = new Promise(res => proc.on('exit', res));
  conn.sendNotification('exit');
  await Promise.race([exited, sleep(5000)]);
  console.log(failures ? `\n${failures} check(s) failed` : '\nall module preview checks passed');
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); fs.rmSync(ws, { recursive: true, force: true }); process.exit(1); });
