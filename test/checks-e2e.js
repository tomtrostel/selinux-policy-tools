// Property checks (selinux.checks) on a copy of a refpolicy tree (default:
// CLIP for RHEL 9 on the test host): evaluated after a build and on edits,
// reported as diagnostics with related source locations and as code lenses.
//   node test/checks-e2e.js [tree-dir] [makeArgs.json]
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

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-checks-e2e-'));
cp.execFileSync('cp', ['-a', src + '/.', ws]);
fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
const CHECKS = path.join(ws, 'selinux.checks');
const TEXT = [
  '# test checks',
  'never syslogd_t may write shadow_t',                       // 1: holds
  'require syslogd_t may { append create } var_log_t:file',   // 2: holds
  'never syslogd_t may write syslogd_var_run_t',              // 3: fails (its own runtime files; an alias of syslogd_runtime_t in CLIP)
  'require syslogd_t may write shadow_t:file',                // 4: fails (missing)
  'never staff_t reaches sysadm_t',                           // 5: either; if it fails, a path ending at sysadm_t
  'never nosuch_t may read etc_t',                            // 6: unknown type
  'only syslogd_t may',                                       // 7: syntax error
  '',
].join('\n');
fs.writeFileSync(CHECKS, TEXT);

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
let doneIndex;
const indexed = new Promise(r => (doneIndex = r));
const diags = {};
let summary = null;
const buildStarts = [];
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/checks', s => { summary = s; });
conn.onNotification('selinux/build', p => { if (p.state === 'start') buildStarts.push(p); });
for (const n of ['window/logMessage', 'selinux/inactiveChanged']) conn.onNotification(n, () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};
const waitSummary = async (pred, ms = 60000) => { for (let t = 0; t < ms && !(summary && pred(summary)); t += 200) await sleep(200); return summary; };
const onLine = (l) => (diags[uri(CHECKS)] || []).filter(d => d.range.start.line === l);

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {}, initializationOptions: { build: { tree: { makeArgs } } } });
  conn.sendNotification('initialized', {});
  await indexed;
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(CHECKS), languageId: 'selinux-checks', version: 1, text: TEXT } });
  await sleep(800);
  let lenses = await conn.sendRequest('textDocument/codeLens', { textDocument: { uri: uri(CHECKS) } });
  check(lenses.length === 6 && lenses.every(l => /build the policy/.test(l.command.title)), `before a build: ${lenses.length} lenses say "${lenses[0] && lenses[0].command.title}"`);
  check(onLine(7).length === 1 && /Expected permissions/.test(onLine(7)[0].message), 'syntax error reported on its line', onLine(7));

  const b = await conn.sendRequest('selinux/build', { uri: uri(ws) });
  check(b.ok && b.validated, `build (${(b.ms / 1000).toFixed(1)} s)`);
  const s = await waitSummary(x => x.failed !== undefined && !x.note);
  check(s && s.total === 6, `checks evaluated after the build: ${JSON.stringify(s)}`);
  lenses = await conn.sendRequest('textDocument/codeLens', { textDocument: { uri: uri(CHECKS) } });
  const lens = (l) => (lenses.find(x => x.range.start.line === l) || { command: { title: '' } }).command.title;
  check(lens(1) === '✓ holds' && lens(2) === '✓ holds', `holding checks: "${lens(1)}", "${lens(2)}"`);
  check(/^✗ violated by 1 domain/.test(lens(3)) && /^✗ \d+ missing/.test(lens(4)) && /^⚠ unknown type or attribute nosuch_t/.test(lens(6)), `failing checks: "${lens(3)}" / "${lens(4)}" / "${lens(6)}"`);

  const d3 = onLine(3)[0];
  const rel3 = (d3 && d3.relatedInformation) || [];
  check(d3 && /syslogd_t may write syslogd_var_run_t/.test(d3.message) && rel3.some(r => /logging\.te$/.test(URI.parse(r.location.uri).fsPath)),
    `violation traced to source: ${d3 && d3.message.slice(0, 90)} | ${rel3.slice(0, 2).map(r => `${path.relative(ws, URI.parse(r.location.uri).fsPath)}:${r.location.range.start.line + 1} ${r.message.slice(0, 60)}`).join(' | ')}`, d3);
  const d4 = onLine(4)[0];
  check(d4 && /Not allowed: syslogd_t shadow_t:file \{ [^}]*\bwrite\b[^}]*\}/.test(d4.message) && !/add_name|rmdir/.test(d4.message), `require failure (file permissions only): ${d4 && d4.message}`);
  const d5 = onLine(5)[0];
  check(lens(5) === '✓ holds' ? !d5 : (d5 && /^staff_t can reach sysadm_t: staff_t → .* → ?sysadm_t$|^staff_t can reach sysadm_t: staff_t → sysadm_t$/.test(d5.message) && d5.relatedInformation.length > 0),
    `reaches: ${lens(5)}${d5 ? ` — ${d5.message}` : ''}`);
  check(onLine(6).length === 1 && /unknown type or attribute nosuch_t/.test(onLine(6)[0].message), 'unknown type reported');

  // Editing the checks file re-checks against the last build without rebuilding.
  const starts = buildStarts.length;
  summary = null;
  const edited = TEXT.replace('never syslogd_t may write syslogd_var_run_t', 'never syslogd_t may write shadow_t:file');
  conn.sendNotification('textDocument/didChange', { textDocument: { uri: uri(CHECKS), version: 2 }, contentChanges: [{ text: edited }] });
  await waitSummary(x => x.failed !== undefined);
  conn.sendNotification('textDocument/didSave', { textDocument: { uri: uri(CHECKS) } });
  await sleep(1500);
  lenses = await conn.sendRequest('textDocument/codeLens', { textDocument: { uri: uri(CHECKS) } });
  check(lens(3) === '✓ holds' && onLine(3).length === 0 && buildStarts.length === starts, `edit + save: line 4 now "${lens(3)}", no rebuild (${buildStarts.length - starts} builds)`);

  // Completion in the checks file.
  const comp = await conn.sendRequest('textDocument/completion', { textDocument: { uri: uri(CHECKS) }, position: { line: 8, character: 0 } });
  conn.sendNotification('textDocument/didChange', { textDocument: { uri: uri(CHECKS), version: 3 }, contentChanges: [{ text: edited.replace(/\n$/, '\nnever sysl') }] });
  await sleep(200);
  const comp2 = await conn.sendRequest('textDocument/completion', { textDocument: { uri: uri(CHECKS) }, position: { line: 8, character: 10 } });
  check(comp.items.some(i => i.label === 'only') && comp2.items.some(i => i.label === 'syslogd_t'), 'completion: keywords and type names');

  await conn.sendRequest('shutdown');
  const exited = new Promise(res => proc.on('exit', res));
  conn.sendNotification('exit');
  await Promise.race([exited, sleep(5000)]);
  console.log(failures ? `\n${failures} check(s) failed` : '\nall property check tests passed');
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); fs.rmSync(ws, { recursive: true, force: true }); process.exit(1); });
