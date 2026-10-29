// The practice module the tutorials walk through (media/practice): in a
// standalone workspace it shows the four mistakes the tutorial describes,
// each with a quick fix; with the fixes applied it builds cleanly, links with
// the installed policy and its property checks hold.
//   node test/tutorial-e2e.js
// Needs Linux with make, m4, checkpolicy, selinux-policy-devel; the checks part
// also policycoreutils, setools and an installed policy. Skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const { tempDir } = require('./tmpdirs');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain, installedKernelPolicy } = require('../server/build');

const tc = detectToolchain('/usr/share/selinux/devel/Makefile');
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }

const src = path.join(__dirname, '..', 'media', 'practice');
const ws = tempDir('selinux-practice-e2e-');
for (const f of fs.readdirSync(src)) fs.copyFileSync(path.join(src, f), path.join(ws, f));
const file = (f) => path.join(ws, f);

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
let doneIndex;
let indexed = new Promise(r => (doneIndex = r));
const diags = {};
let summary = null;
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/checks', s => { summary = s; });
conn.onNotification('selinux/build', () => {});
conn.onNotification('window/logMessage', () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};
const versions = {};
const open = (f) => {
  versions[f] = 1;
  const lang = f.endsWith('.fc') ? 'selinux-fc' : f.endsWith('.checks') ? 'selinux-checks' : 'selinux';
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(file(f)), languageId: lang, version: 1, text: fs.readFileSync(file(f), 'utf8') } });
};
const change = (f, text) => {
  fs.writeFileSync(file(f), text);
  conn.sendNotification('textDocument/didChange', { textDocument: { uri: uri(file(f)), version: ++versions[f] }, contentChanges: [{ text }] });
};
const waitDiags = async (f, pred, ms = 8000) => { for (let t = 0; t < ms && !pred(diags[uri(file(f))] || []); t += 100) await sleep(100); return diags[uri(file(f))] || []; };
const fixesFor = async (f, d) => (await conn.sendRequest('textDocument/codeAction', { textDocument: { uri: uri(file(f)) }, range: d.range, context: { diagnostics: [d] } })) || [];

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {} });
  conn.sendNotification('initialized', {});
  await indexed;
  for (const f of ['notesd.te', 'notesd.if', 'notesd.fc']) open(f);

  // The mistakes, in the order the tutorial fixes them.
  const lineOf = (f, s) => fs.readFileSync(file(f), 'utf8').split('\n').findIndex(l => l.includes(s));
  const at = (ds, f, s) => ds.find(d => d.range.start.line === lineOf(f, s));
  const fixesOf = async (f, d) => (d ? await fixesFor(f, d) : []);
  // Applies a quick fix's edit to the file, as VS Code does.
  const apply = (f, action) => {
    const edits = ((action && action.edit && action.edit.changes) || {})[uri(file(f))] || [];
    const lines = fs.readFileSync(file(f), 'utf8').split('\n');
    const off = (p) => lines.slice(0, p.line).reduce((n, l) => n + l.length + 1, 0) + p.character;
    let text = lines.join('\n');
    for (const e of edits.slice().sort((x, y) => off(y.range.start) - off(x.range.start))) text = text.slice(0, off(e.range.start)) + e.newText + text.slice(off(e.range.end));
    change(f, text);
    return edits.length;
  };
  let te = await waitDiags('notesd.te', ds => ds.length >= 2);
  const perm = at(te, 'notesd.te', 'lisen'), iface = at(te, 'notesd.te', 'syslog_mesg');
  check(perm && /lisen/.test(perm.message), `mistake 1, bad permission: ${perm && perm.message}`, te);
  check(iface && /logging_send_syslog_mesg/.test(iface.message), `mistake 2, misspelled interface: ${iface && iface.message}`, te);
  check(te.length === 2, `while an interface is unknown, nothing else is reported in notesd.te (${te.length})`, te.map(d => d.message));
  const ifd = await waitDiags('notesd.if', ds => ds.length >= 1);
  const gen = at(ifd, 'notesd.if', 'read_files_pattern');
  check(gen && /notesd_var_lib_t/.test(gen.message) && ifd.length === 1, `mistake 4, missing gen_require entry: ${gen && gen.message}`, ifd.map(d => d.message));
  check(!(diags[uri(file('notesd.fc'))] || []).length, 'notesd.fc is clean');

  // Quick fixes (Ctrl+.), applied one by one.
  const f2 = (await fixesOf('notesd.te', iface)).find(x => /logging_send_syslog_msg/.test(x.title));
  check(f2 && apply('notesd.te', f2), `quick fix for the interface: ${f2 && f2.title}`);
  te = await waitDiags('notesd.te', ds => ds.some(d => /urandom_device_t/.test(d.message)));
  const req = at(te, 'notesd.te', 'urandom_device_t:chr_file');
  check(req && /urandom_device_t/.test(req.message) && te.length === 2, `then mistake 3 shows: a type of another module without a require: ${req && req.message}`, te.map(d => d.message));
  const f3 = (await fixesOf('notesd.te', req)).find(x => /urandom_device_t/.test(x.title));
  check(!!f3, `quick fix for the require: ${f3 && f3.title}`);
  const perm2 = at(te, 'notesd.te', 'lisen');
  const f1 = (await fixesOf('notesd.te', perm2)).find(x => /listen/.test(x.title));
  check(f1 && apply('notesd.te', f1), `quick fix for the permission: ${f1 && f1.title}`);
  const f4 = (await fixesOf('notesd.if', gen)).find(x => /notesd_var_lib_t/.test(x.title));
  check(f4 && apply('notesd.if', f4), `quick fix for gen_require: ${f4 && f4.title}`);
  // Mistake 3 the way the tutorial recommends: the interface instead of the raw rule.
  change('notesd.te', fs.readFileSync(file('notesd.te'), 'utf8').replace('allow notesd_t urandom_device_t:chr_file read_chr_file_perms;', 'dev_read_urand(notesd_t)'));
  check(!(await waitDiags('notesd.te', ds => !ds.length)).length, 'fixed notesd.te has no problems', diags[uri(file('notesd.te'))]);
  check(!(await waitDiags('notesd.if', ds => !ds.length)).length, 'fixed notesd.if has no problems', diags[uri(file('notesd.if'))]);
  const b = await conn.sendRequest('selinux/build', { uri: uri(file('notesd.te')) });
  check(b.ok && !b.errors, `the fixed module builds (${b.ms} ms)`, b.log && b.log.slice(-1500));
  const hover = await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(file('notesd.te')) }, position: { line: lineOf('notesd.te', 'dev_read_urand'), character: 3 } });
  const hv = hover ? JSON.stringify(hover.contents) : '';
  check(/Compiles to/i.test(hv) && /urandom_device_t/.test(hv), 'hover on the new call shows what it compiles to', hv.slice(0, 400));

  // Property checks (the tutorial's last step).
  if (!installedKernelPolicy()) console.log('     (no installed policy: checks skipped)');
  else {
    open('selinux.checks');
    for (let t = 0; t < 120000 && !(summary && summary.failed !== undefined && !summary.note); t += 200) await sleep(200);
    await sleep(500);
    check(summary && summary.total === 4 && summary.failed === 0, `the practice checks hold: ${JSON.stringify(summary)}`, (diags[uri(file('selinux.checks'))] || []).map(d => `${d.range.start.line + 1}: ${d.message}`));

    // The tutorial's denials (sample-denials.log), against the module's build.
    const log = fs.readFileSync(file('sample-denials.log'), 'utf8');
    let r = await conn.sendRequest('selinux/analyzeDenials', { text: log, against: 'build' });
    const by = (s, t) => r.groups.find(g => g.source === s && g.target === t);
    const db = by('notesd_t', 'var_lib_t');
    check(db && db.v.verdict === 'label' && db.labels.some(l => l.expected === 'notesd_var_lib_t') && /restorecon -v \/var\/lib\/notesd\/notes\.db/.test((db.v.fixes[0] || {}).command || ''),
      `notes.db: wrong label (notesd.fc says notesd_var_lib_t): ${db && db.v.title}`, db && { v: db.v, labels: db.labels, fc: r.policy && r.policy.fileContexts });
    const http = by('notesd_t', 'http_port_t');
    const top = http && http.suggest && http.suggest.list && http.suggest.list[0];
    check(http && http.v.verdict === 'missing' && top && top.name === 'corenet_tcp_connect_http_port', `http_port_t: ${http && http.v.title}, ${top && top.name}`, http && http.suggest);
    const logw = by('notesd_t', 'notesd_log_t');
    check(logw && logw.suggest && logw.suggest.own && logw.suggest.rule === 'allow notesd_t notesd_log_t:file { write };', `own log: a plain rule in notesd`, logw && { v: logw.v, s: logw.suggest });
    const unc = by('unconfined_service_t', 'admin_home_t');
    check(unc && unc.v.verdict === 'transition' && /notesd_t/.test(unc.v.title + unc.v.detail), `unconfined_service_t: ${unc && unc.v.title}`, unc && unc.v);
    // Apply the http fix and the build allows it.
    const plan = await conn.sendRequest('selinux/denialFix', { domain: 'notesd_t', call: 'corenet_tcp_connect_http_port(notesd_t)' });
    check(plan.path === file('notesd.te') && plan.inserted.join() === 'corenet_tcp_connect_http_port(notesd_t)', `fix plan into notesd.te line ${plan.line + 1}`, plan);
    change('notesd.te', plan.text);
    await sleep(600);
    const b2 = await conn.sendRequest('selinux/build', { uri: uri(file('notesd.te')) });
    r = await conn.sendRequest('selinux/analyzeDenials', { text: log, against: 'build' });
    check(b2.ok && by('notesd_t', 'http_port_t').v.verdict === 'allowed', 'after the fix and a build: allowed');
  }

  await conn.sendRequest('shutdown');
  conn.sendNotification('exit');
  await sleep(300);
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  console.log(failures ? `\n${failures} check(s) failed` : '\nall tutorial checks passed');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
