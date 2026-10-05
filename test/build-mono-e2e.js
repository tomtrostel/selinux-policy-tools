// Monolithic (MONOLITHIC=y) tree builds: one policy.conf compiled with
// checkpolicy, no module packages. Drives the server over stdio LSP against a
// copy of upstream refpolicy (RHEL and CLIP trees don't build monolithic).
//   node test/build-mono-e2e.js [refpolicy-dir]
// Default: ~/sepol-test/refpolicy (git clone --depth 1 https://github.com/SELinuxProject/refpolicy).
// Needs Linux with make, m4, checkpolicy, policycoreutils and setools; skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain } = require('../server/build');

const tc = detectToolchain(null);
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }
const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/refpolicy');
if (!fs.existsSync(path.join(src, 'Rules.monolithic'))) { console.log(`SKIP: no refpolicy tree at ${src}`); process.exit(0); }

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-mono-e2e-'));
cp.execFileSync('cp', ['-a', src + '/.', ws]);
fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
const LOGGING = path.join(ws, 'policy/modules/system/logging.te');
const ORIG = fs.readFileSync(LOGGING, 'utf8');
const OUT = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-mono-out-')), 'build');
const isGit = fs.existsSync(path.join(ws, '.git'));
if (isGit) { try { cp.execFileSync('git', ['-C', ws, 'config', 'user.email', 'test@example.com']); cp.execFileSync('git', ['-C', ws, 'config', 'user.name', 'test']); } catch { /* ignore */ } }

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
const diags = {};
const waiters = [];
let doneIndex, stats;
const indexed = new Promise(r => (doneIndex = r));
let summary = null;
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') { stats = p.stats; doneIndex(); } });
conn.onNotification('selinux/build', p => { if (p.state === 'done') waiters.splice(0).forEach(w => w(p)); });
conn.onNotification('selinux/checks', s => { summary = s; });
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
let version = 1;
const edit = async (text) => { conn.sendNotification('textDocument/didChange', { textDocument: { uri: uri(LOGGING), version: ++version }, contentChanges: [{ text }] }); await sleep(400); };
const save = () => { const b = nextBuild(); conn.sendNotification('textDocument/didSave', { textDocument: { uri: uri(LOGGING) } }); return b; };
const lineOf = (text, needle) => text.split('\n').findIndex(l => l.includes(needle));
const fmt = () => (diags[uri(LOGGING)] || []).map(d => `${d.range.start.line + 1} [${d.source}] ${d.message}`);

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {},
    initializationOptions: { build: { tree: { makeArgs: ['MONOLITHIC=y'], outputDir: OUT } } } });
  conn.sendNotification('initialized', {});
  await indexed;
  check(stats.buildMode === 'tree', `refpolicy tree detected (${stats.modules} modules)`, stats);
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(LOGGING), languageId: 'selinux', version, text: ORIG } });
  await sleep(400);

  // 1. Monolithic build: the `policy` target, one kernel policy, no packages, no separate link step.
  let r = await conn.sendRequest('selinux/build', { uri: uri(LOGGING) });
  check(r.ok && r.tree && r.packages === 0 && /policy\.\d+$/.test(r.policyBin || '') && !r.validated,
    `monolithic build (${(r.ms / 1000).toFixed(1)} s): ${r.policyBin && path.basename(r.policyBin)}, ${r.packages} packages`, { ...r, log: r.log && r.log.slice(-1500) });

  // 2. A compile error lands on its line (checkpolicy on policy.conf, through #line markers).
  let t = ORIG + '\nallow syslogd_t nosuch_t:file read;\n';
  await edit(t);
  r = await save();
  let d = (diags[uri(LOGGING)] || []).find(x => x.source !== 'selinux');
  check(!r.ok && d && d.range.start.line === lineOf(t, 'nosuch_t') && /nosuch_t/.test(d.message), `checkpolicy error on logging.te:${d && d.range.start.line + 1}: ${d && d.message}`, fmt());
  await edit(ORIG);
  r = await save();
  check(r.ok && !(diags[uri(LOGGING)] || []).some(x => x.source !== 'selinux'), 'reverted: builds cleanly, build diagnostics cleared', fmt());

  // 3. What a line compiles to (hover, expanded view), read from policy.conf.
  const lines = ORIG.split('\n');
  const callLine = lines.findIndex(l => /^\s*init_daemon_domain\(syslogd_t/.test(l));
  const h = await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(LOGGING) }, position: { line: callLine, character: lines[callLine].indexOf('init_daemon_domain') + 2 } });
  check(h && /Compiles to/.test(h.contents.value) && /syslogd_t/.test(h.contents.value), `hover on init_daemon_domain(syslogd_t, …) shows what it compiles to`, h && h.contents.value.slice(0, 400));
  const ex = await conn.sendRequest('selinux/expandedPolicy', { uri: uri(LOGGING) });
  check(ex.text && /# ──── logging\.te:\d+: /.test(ex.text) && !/# ──── files\.te/.test(ex.text), 'expanded view shows logging.te\'s part of policy.conf', ex.unavailable || (ex.text && ex.text.slice(0, 300)));

  // 4. Compiled Policy view: model, rules, origins traced into policy.conf.
  const m = await conn.sendRequest('selinux/policyModel');
  check(!m.unavailable && m.types.length > 1000 && m.types.filter(t2 => t2.loc).length / m.types.length > 0.95,
    `policy model: ${m.types && m.types.length} types, ${m.types && m.types.filter(t2 => t2.loc).length} with source locations`, m.unavailable);
  const q = await conn.sendRequest('selinux/typeRules', { name: 'syslogd_t', dir: 'source', kinds: ['allow'] });
  const sample = q.rules && q.rules.find(x => x.s === 'syslogd_t' && !x.cond);
  const o = sample && await conn.sendRequest('selinux/ruleOrigins', { rule: sample });
  check(q.count > 50 && o && o.origins.length && /\.te$/.test(o.origins[0].path),
    `rules: syslogd_t can access ${q.count}; origin of "${sample && `${sample.t}:${sample.c}`}" → ${o && o.origins[0] && `${path.basename(o.origins[0].path)}:${o.origins[0].line + 1}`}`, { q: q.unavailable, o });

  // 5. Property checks on the monolithic policy.
  const CHECKS = path.join(ws, 'selinux.checks');
  const CT = 'never syslogd_t may write shadow_t\nrequire syslogd_t may { append } var_log_t:file\nnever shadow_t flows to user_t weight 10\n';
  fs.writeFileSync(CHECKS, CT);
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(CHECKS), languageId: 'selinux-checks', version: 1, text: CT } });
  for (let i = 0; i < 300 && !(summary && summary.failed !== undefined && !summary.note); i++) await sleep(200);
  const lenses = await conn.sendRequest('textDocument/codeLens', { textDocument: { uri: uri(CHECKS) } });
  check(summary && summary.total === 3 && lenses.length === 3 && lenses[0].command.title === '✓ holds' && lenses[1].command.title === '✓ holds' && /^(✓ holds|✗ data flows)/.test(lenses[2].command.title),
    `checks on the monolithic policy: ${lenses.map(l => l.command.title).join(' | ')}`, summary);

  // 6. Changes since HEAD (the clone is a git repo): an unsaved edit adding one permission.
  if (isGit) {
    const addLine = lines.findIndex(l => /^allow syslogd_t self:capability /.test(l));
    if (addLine >= 0) {
      t = ORIG + '\nallow syslogd_t self:capability sys_ptrace;\n';
      await edit(t);
      await save();
      const diff = await conn.sendRequest('selinux/policyDiff', { base: 'HEAD' });
      const ch = diff.rules && diff.rules.find(x => x.s === 'syslogd_t' && x.t === 'syslogd_t' && x.c === 'capability' && (x.add || []).includes('sys_ptrace'));
      const from = ch && ch.addFrom && ch.addFrom.origins && ch.addFrom.origins[0];
      // The line just added (logging.te mentions sys_ptrace elsewhere too).
      const added = t.split('\n').length - 2;
      check(!diff.unavailable && ch && from && path.basename(from.path) === 'logging.te' && from.line === added,
        `vs HEAD: +sys_ptrace on syslogd_t self:capability, traced to ${from && `${path.basename(from.path)}:${from.line + 1}`} (${diff.rules && diff.rules.length} rule changes)`, diff.unavailable || { expectedLine: added + 1, from, rule: ch });
      await edit(ORIG);
      await save();
    }
  }

  // 7. The explicit Build exports the kernel policy (no packages in a monolithic build).
  r = await conn.sendRequest('selinux/build', { uri: uri(LOGGING), package: true });
  const exported = fs.existsSync(OUT) ? fs.readdirSync(OUT) : [];
  check(r.ok && exported.some(n => /^policy\.\d+$/.test(n)) && exported.includes('build-info.json') && !exported.some(n => n.endsWith('.pp')),
    `explicit build exports ${exported.join(', ')}`, r.exportError || r);

  // 8. Features that need a modular build say so.
  const ci = await conn.sendRequest('selinux/compareInstalled', { name: 'targeted' });
  check(ci.unavailable && /modular|MONOLITHIC/i.test(ci.unavailable), `compare with installed policy: "${ci.unavailable}"`, ci);

  await conn.sendRequest('shutdown');
  const exited = new Promise(res => proc.on('exit', res));
  conn.sendNotification('exit');
  await Promise.race([exited, sleep(5000)]);
  console.log(failures ? `\n${failures} check(s) failed` : '\nall monolithic build checks passed');
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  fs.rmSync(path.dirname(OUT), { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); fs.rmSync(ws, { recursive: true, force: true }); process.exit(1); });
