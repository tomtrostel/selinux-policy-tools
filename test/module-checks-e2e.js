// Property checks for a standalone module: the module is linked with this
// host's installed policy (decompiled to CIL, compiled with semodule -p,
// unprivileged) and the checks file at the workspace root is evaluated on it.
//   node test/module-checks-e2e.js
// Needs Linux with make, m4, checkpolicy, selinux-policy-devel, policycoreutils
// and setools, and an installed policy under /etc/selinux; skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain, installedKernelPolicy } = require('../server/build');

const tc = detectToolchain('/usr/share/selinux/devel/Makefile');
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }
if (!installedKernelPolicy()) { console.log('SKIP: no installed policy under /etc/selinux'); process.exit(0); }

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-modchecks-e2e-'));
const te = path.join(ws, 'demo.te');
const TE = `policy_module(demo, 1.0.0)

type demo_t;
type demo_exec_t;
init_daemon_domain(demo_t, demo_exec_t)

type demo_private_t;

auth_read_shadow(demo_t)
allow demo_t demo_private_t:file { create open write };
`;
fs.writeFileSync(te, TE);
fs.writeFileSync(path.join(ws, 'demo.if'), '## <summary>demo</summary>\n');
fs.writeFileSync(path.join(ws, 'demo.fc'), '/usr/bin/demo\t--\tgen_context(system_u:object_r:demo_exec_t,s0)\n');
const CHECKS = path.join(ws, 'selinux.checks');
const TEXT = [
  'never demo_t may write shadow_t',                 // 0: holds
  'never demo_t may { read } shadow_t:file',         // 1: fails, traced to auth_read_shadow in demo.te
  'never shadow_t flows to demo_private_t',          // 2: fails: shadow_t → demo_t → demo_private_t
  'require demo_t may append demo_private_t:file',   // 3: fails: append missing
  'never sshd_t may read demo_private_t',            // 4: holds (installed types work too)
  '',
].join('\n');
fs.writeFileSync(CHECKS, TEXT);

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
let doneIndex;
const indexed = new Promise(r => (doneIndex = r));
const diags = {};
let summary = null;
const states = [];
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/checks', s => { summary = s; });
conn.onNotification('selinux/build', p => { states.push(p); });
conn.onNotification('window/logMessage', () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};
const waitSummary = async (pred, ms = 120000) => { for (let t = 0; t < ms && !(summary && pred(summary)); t += 200) await sleep(200); return summary; };
const onLine = (l) => (diags[uri(CHECKS)] || []).filter(d => d.range.start.line === l);
const rel = (d) => ((d && d.relatedInformation) || []).map(r => `${path.relative(ws, URI.parse(r.location.uri).fsPath)}:${r.location.range.start.line + 1} ${r.message}`);

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {} });
  conn.sendNotification('initialized', {});
  await indexed;

  const cf = await conn.sendRequest('selinux/checksFile');
  check(cf.path === CHECKS && cf.exists, `checks file of a standalone module: ${cf.path || cf.unavailable}`);
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(CHECKS), languageId: 'selinux-checks', version: 1, text: TEXT } });
  await sleep(800);
  let lenses = await conn.sendRequest('textDocument/codeLens', { textDocument: { uri: uri(CHECKS) } });
  check(lenses.length === 5 && lenses.every(l => /build the module/.test(l.command.title)), `before a build: "${lenses[0] && lenses[0].command.title}"`);

  const b = await conn.sendRequest('selinux/build', { uri: uri(te) });
  check(b.ok, `module builds (${b.ms} ms)`, b);
  const s = await waitSummary(x => x.failed !== undefined && !x.note);
  const linked = states.find(p => p.state === 'linked');
  check(linked && linked.ok, `linked with the installed policy (${linked && (linked.ms / 1000).toFixed(1)} s)`, states.slice(-3));
  check(s && s.total === 5 && s.failed === 3, `checks evaluated: ${JSON.stringify(s)}`);
  lenses = await conn.sendRequest('textDocument/codeLens', { textDocument: { uri: uri(CHECKS) } });
  const lens = (l) => (lenses.find(x => x.range.start.line === l) || { command: { title: '' } }).command.title;
  check(lens(0) === '✓ holds' && lens(4) === '✓ holds', `holding: "${lens(0)}", "${lens(4)}"`);

  const teLine = (needle) => TE.split('\n').findIndex(l => l.includes(needle)) + 1;
  const d1 = onLine(1)[0];
  check(lens(1) === '✗ violated by 1 domain (1 rule)' && d1 && rel(d1).some(r => r.startsWith(`demo.te:${teLine('auth_read_shadow')} `) && /via auth_read_shadow/.test(r)),
    `read of shadow_t traced to demo.te:${teLine('auth_read_shadow')}: "${lens(1)}" | ${rel(d1).slice(0, 2).join(' | ')}`, d1);
  const d2 = onLine(2)[0];
  check(lens(2) === '✗ data flows in 2 steps' && d2 && /shadow_t → demo_t → demo_private_t/.test(d2.message)
    && rel(d2).some(r => r.startsWith(`demo.te:${teLine('allow demo_t demo_private_t')} `) && /demo_t writes/.test(r)),
    `flow through the module: ${d2 && d2.message.slice(0, 80)} | ${rel(d2).join(' | ')}`, d2);
  const d3 = onLine(3)[0];
  check(/^✗ 1 missing/.test(lens(3)) && d3 && /demo_t demo_private_t:file \{ append \}/.test(d3.message), `require: ${d3 && d3.message}`);

  // The Compiled Policy view shows the module linked with the installed policy.
  const m = await conn.sendRequest('selinux/policyModel');
  const demo = m.types && m.types.find(t => t.name === 'demo_t');
  check(!m.unavailable && m.linked && m.linked.module === 'demo' && m.types.length > 1000 && demo && demo.loc && /demo\.te$/.test(demo.loc.p) && demo.attrs.includes('domain'),
    `compiled policy model: ${m.unavailable || `${m.linked && m.linked.module} + ${m.types.length} types; demo_t at ${demo && demo.loc && path.basename(demo.loc.p)}`}`);

  // Editing the module and building again relinks; the read check then holds.
  const fixed = TE.replace('auth_read_shadow(demo_t)\n', '');
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(te), languageId: 'selinux', version: 1, text: TE } });
  conn.sendNotification('textDocument/didChange', { textDocument: { uri: uri(te), version: 2 }, contentChanges: [{ text: fixed }] });
  await sleep(500);
  summary = null;
  const links = states.filter(p => p.state === 'linked').length;
  const b2 = await conn.sendRequest('selinux/build', { uri: uri(te) });
  await waitSummary(x => x.failed !== undefined && !x.note);
  lenses = await conn.sendRequest('textDocument/codeLens', { textDocument: { uri: uri(CHECKS) } });
  // Other paths through the installed policy may remain, but not the direct one.
  const d2b = onLine(2)[0];
  check(b2.ok && states.filter(p => p.state === 'linked').length === links + 1 && lens(1) === '✓ holds' && (lens(2) === '✓ holds' || (d2b && !/shadow_t → demo_t →/.test(d2b.message))),
    `after removing auth_read_shadow: relinked, "${lens(1)}" / "${lens(2)}"${d2b ? ` (${d2b.message.split('. Fix')[0]})` : ''}`);

  await conn.sendRequest('shutdown');
  const exited = new Promise(res => proc.on('exit', res));
  conn.sendNotification('exit');
  await Promise.race([exited, sleep(5000)]);
  console.log(failures ? `\n${failures} check(s) failed` : '\nall standalone module check tests passed');
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); fs.rmSync(ws, { recursive: true, force: true }); process.exit(1); });
