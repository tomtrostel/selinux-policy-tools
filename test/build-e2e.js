// Real-build integration test: drives the server over stdio LSP against a
// standalone module compiled with selinux-policy-devel (m4 + checkmodule).
// Needs Linux with make, m4, checkpolicy and selinux-policy-devel; skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain } = require('../server/build');

const tc = detectToolchain('/usr/share/selinux/devel/Makefile');
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-build-e2e-'));
const dir = path.join(ws, 'policy/modules/local');
fs.mkdirSync(dir, { recursive: true });
const te = path.join(dir, 'myapp.te');
const GOOD = `policy_module(myapp, 1.0.0)

type myapp_t;
type myapp_exec_t;
init_daemon_domain(myapp_t, myapp_exec_t)

type myapp_tmp_t;
files_tmp_file(myapp_tmp_t)

allow myapp_t myapp_tmp_t:file manage_file_perms;
files_tmp_filetrans(myapp_t, myapp_tmp_t, file)
`;
fs.writeFileSync(te, GOOD);
fs.writeFileSync(path.join(dir, 'myapp.if'), '## <summary>myapp</summary>\n');
fs.writeFileSync(path.join(dir, 'myapp.fc'), '/usr/bin/myapp\t--\tgen_context(system_u:object_r:myapp_exec_t,s0)\n');

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
const diags = {};
const waiters = [];
let doneIndex;
const indexed = new Promise(r => (doneIndex = r));
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
conn.onNotification('selinux/build', p => { if (p.state === 'done') waiters.splice(0).forEach(w => w(p)); });
conn.onNotification('window/logMessage', () => {});
conn.listen();
const uri = URI.file(te).toString();
const sleep = ms => new Promise(r => setTimeout(r, ms));
const nextBuild = () => new Promise(r => waiters.push(r));

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).replace(/\n/g, '\n     ')); }
};
const fmt = () => (diags[uri] || []).map(d => `${d.range.start.line + 1}:${d.range.start.character} [${d.source}] ${d.message}`);
let version = 1;
const setText = async (text) => {
  conn.sendNotification('textDocument/didChange', { textDocument: { uri, version: ++version }, contentChanges: [{ text }] });
  fs.writeFileSync(te, text);
  await sleep(400); // let the server's index debounce settle
};
const save = async () => { const b = nextBuild(); conn.sendNotification('textDocument/didSave', { textDocument: { uri } }); return b; };
const hover = async (needle) => {
  const lines = fs.readFileSync(te, 'utf8').split('\n');
  const line = lines.findIndex(l => l.includes(needle));
  const h = await conn.sendRequest('textDocument/hover', { textDocument: { uri }, position: { line, character: lines[line].indexOf(needle) + 1 } });
  return h ? h.contents.value : '';
};

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {} });
  conn.sendNotification('initialized', {});
  await indexed;
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri, languageId: 'selinux', version, text: GOOD } });
  await sleep(400);

  // 1. Clean module builds; hover shows what a call compiles to.
  let r = await conn.sendRequest('selinux/build', { uri });
  check(r.ok && r.errors === 0, `clean module builds (${r.ms} ms)`, r);
  let h = await hover('files_tmp_filetrans');
  check(/Compiles to/.test(h) && /type_transition myapp_t tmp_t:file myapp_tmp_t/.test(h), 'hover on files_tmp_filetrans shows the compiled type_transition', h);
  h = await hover('init_daemon_domain');
  check(/allow myapp_t myapp_exec_t:file entrypoint/.test(h), 'hover on init_daemon_domain includes nested expansion (entrypoint rule)', h.slice(-600));

  // 2. Errors only the compiler can see: unknown type, reported on the right line.
  await setText(GOOD + 'allow myapp_t nosuch_t:file read;\n');
  r = await save();
  check(!r.ok && r.errors >= 1, 'unknown type fails the build', r);
  const d1 = (diags[uri] || []).find(d => d.source === 'checkmodule');
  check(d1 && d1.range.start.line === 11 && /unknown type nosuch_t/.test(d1.message), "checkmodule error 'unknown type nosuch_t' on line 12", fmt());

  // 3. Editing makes build diagnostics stale: they disappear until the next build.
  await setText(GOOD + 'allow myapp_t nosuch_t:file read;\n\n');
  check(!(diags[uri] || []).some(d => d.source === 'checkmodule'), 'build diagnostics are dropped once the file changes', fmt());

  // 4. Deprecated interface: refpolicywarn surfaces as a warning, build still succeeds.
  await setText(GOOD + 'auth_file(myapp_tmp_t)\n');
  r = await save();
  check(r.ok, 'module with a deprecated interface still builds', r);
  const w = (diags[uri] || []).find(d => d.source === 'refpolicy');
  check(w && w.severity === 2 && w.range.start.line === 11 && /deprecated/.test(w.message), 'deprecation warning from refpolicywarn on line 12', fmt());

  // 5. Undefined interface: m4 leaves it unexpanded -> syntax error with a hint.
  //    The static check also flags it (with quick fixes), so the compiler's copy is suppressed.
  await setText(GOOD + 'files_read_etc_filez(myapp_t)\n');
  r = await save();
  check(!r.ok, 'undefined interface fails the build', r);
  const onLine = (diags[uri] || []).filter(d => d.range.start.line === 11);
  check(onLine.length === 1 && onLine[0].source === 'selinux', 'only the static diagnostic (with quick fixes) is shown for that line', fmt());

  // 6. Fixing it clears build errors.
  await setText(GOOD);
  r = await save();
  check(r.ok && !(diags[uri] || []).some(d => d.source !== 'selinux'), 'fixed module builds and clears build diagnostics', fmt());

  // 7. Interfaces from a sibling module in the same directory are callable.
  fs.writeFileSync(path.join(dir, 'other.te'), 'policy_module(other, 1.0.0)\ntype other_data_t;\nfiles_type(other_data_t)\n');
  fs.writeFileSync(path.join(dir, 'other.if'), "## <summary>other</summary>\ninterface(`other_read_data',`\n\tgen_require(`\n\t\ttype other_data_t;\n\t')\n\tallow $1 other_data_t:file read_file_perms;\n')\n");
  conn.sendNotification('workspace/didChangeWatchedFiles', { changes: ['other.te', 'other.if'].map(n => ({ uri: URI.file(path.join(dir, n)).toString(), type: 1 })) });
  await setText(GOOD + 'other_read_data(myapp_t)\n');
  r = await save();
  check(r.ok, 'call to a sibling module interface builds', r);
  h = await hover('other_read_data');
  check(/allow myapp_t other_data_t:file/.test(h), 'hover shows the sibling interface expansion', h.slice(-300));

  // 8. Saving the .if rebuilds the module (interface body changes reach the .te).
  const ifUri = URI.file(path.join(dir, 'myapp.if')).toString();
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: ifUri, languageId: 'selinux', version: 1, text: fs.readFileSync(path.join(dir, 'myapp.if'), 'utf8') } });
  const b = nextBuild();
  conn.sendNotification('textDocument/didSave', { textDocument: { uri: ifUri } });
  r = await b;
  check(r.module === 'myapp' && r.ok, 'saving myapp.if rebuilds myapp', r);

  // 9. Packaging (the Build command) writes <mod>.pp next to the .te; a failed build writes nothing.
  r = await conn.sendRequest('selinux/build', { uri, package: true });
  const pp = path.join(dir, 'myapp.pp');
  check(r.ok && r.package === pp && fs.statSync(pp).size > 1000, `package build writes myapp.pp (${fs.existsSync(pp) ? fs.statSync(pp).size : 0} bytes)`, r);
  fs.rmSync(pp, { force: true });
  await setText(GOOD + 'allow myapp_t nosuch_t:file read;\n');
  r = await conn.sendRequest('selinux/build', { uri, package: true });
  check(!r.ok && !r.package && !fs.existsSync(pp), 'failed package build writes no .pp', r);
  await setText(GOOD);

  // 10. Expanded policy view: rebuilds when stale, headers name source lines, boilerplate collapsed.
  const ex = await conn.sendRequest('selinux/expandedPolicy', { uri });
  check(ex.text && /# ──── myapp\.te:11: files_tmp_filetrans\(myapp_t, myapp_tmp_t, file\)\n[\s\S]*type_transition myapp_t tmp_t:file myapp_tmp_t/.test(ex.text),
    'expanded policy shows files_tmp_filetrans and its type_transition', ex.text && ex.text.slice(-800));
  check(ex.text && /category declarations omitted/.test(ex.text) && ex.text.split('\n').length < 800, `expanded policy collapses boilerplate (${ex.text ? ex.text.split('\n').length : 0} lines)`);

  // 11. A clean LSP shutdown removes the scratch build directory (and the server's whole scratch area).
  const scratch = (await conn.sendRequest('selinux/build', { uri })).workDir;
  const area = path.dirname(scratch);
  check(fs.existsSync(scratch) && path.basename(area) === String(proc.pid), `scratch build dir exists while the server runs, in its own area (${path.basename(area)})`);
  await conn.sendRequest('shutdown');
  const exited = new Promise(res => proc.on('exit', res));
  conn.sendNotification('exit');
  await Promise.race([exited, sleep(5000)]);
  check(!fs.existsSync(scratch) && !fs.existsSync(area), 'scratch build dir and area removed on server exit');

  console.log(failures ? `\n${failures} check(s) failed` : '\nall build checks passed');
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); process.exit(1); });
