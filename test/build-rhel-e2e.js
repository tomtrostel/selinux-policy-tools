// RHEL/Fedora selinux-policy tree build test: settings derived from the
// source RPM's spec (modules.conf, booleans.conf and users copied in from the
// spec's directory), built with the tree's Makefile. Usage:
//   node test/build-rhel-e2e.js [tree-dir] [selinux-policy.spec] [variant]
// Defaults are the RHEL 9 tree and unpacked source RPM on the test host.
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
const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/rhel9');
const spec = process.argv[3] || path.join(os.homedir(), 'sepol-test/srpm/selinux-policy.spec');
const variant = process.argv[4] || 'targeted';
if (!fs.existsSync(path.join(src, 'Rules.modular')) || !fs.existsSync(spec)) { console.log(`SKIP: need a tree at ${src} and a spec at ${spec}`); process.exit(0); }

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-rhel-e2e-'));
cp.execFileSync('cp', ['-a', src + '/.', ws]);
fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
const LOGGING = path.join(ws, 'policy/modules/system/logging.te');
const ORIG = fs.readFileSync(LOGGING, 'utf8');

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
const diags = {};
const waiters = [];
let stats, doneIndex;
let indexed = new Promise(r => (doneIndex = r));
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') { stats = p.stats; doneIndex(); } });
conn.onNotification('selinux/build', p => { if (p.state === 'done') waiters.splice(0).forEach(w => w(p)); });
conn.onNotification('window/logMessage', () => {});
let lastFlags = null;
conn.onNotification('selinux/inactiveChanged', p => { lastFlags = p.flags; });
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
const configure = async (tree) => {
  indexed = new Promise(r => (doneIndex = r));
  conn.sendNotification('workspace/didChangeConfiguration', { settings: { selinux: { build: { tree } } } });
  await indexed;
};

(async () => {
  // Start untrusted: builds must be refused.
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {}, initializationOptions: { trusted: false } });
  conn.sendNotification('initialized', {});
  await indexed;
  check(stats.buildMode === 'tree', `RHEL tree detected (${stats.modules} modules)`, stats);
  let r = await conn.sendRequest('selinux/build', { uri: uri(LOGGING) });
  check(r.unavailable && /Restricted Mode/.test(r.unavailable), 'untrusted workspace: builds refused', r);
  // Untrusted: the Makefile isn't asked for m4 flags, so no ifdef branch is decided.
  const PYZOR = path.join(ws, 'policy/modules/contrib/pyzor.te');
  let ranges = await conn.sendRequest('selinux/inactiveRanges', { uri: uri(PYZOR) });
  check(ranges.length === 0, 'untrusted: ifdef branches not decided (nothing dimmed)', ranges.length);
  conn.sendNotification('selinux/setTrusted', { trusted: true });

  // Settings from the spec.
  const sc = await conn.sendRequest('selinux/specBuildConfig', { specPath: spec });
  const cfg = sc.configs && sc.configs.find(c => c.variant === variant);
  check(cfg && cfg.missing.length === 0 && cfg.makeArgs.includes(`NAME=${variant}`) && cfg.files['policy/modules.conf'], `spec variants: ${sc.configs ? sc.configs.map(c => c.variant).join(', ') : sc.error}`, cfg);
  check(cfg && cfg.files['policy/modules.conf'].length === 2, 'modules.conf = base + contrib lists', cfg && cfg.files);

  // A missing config source is reported, not built.
  await configure({ makeArgs: cfg.makeArgs, files: { ...cfg.files, 'policy/users': [path.join(ws, 'no-such-users-file')] } });
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(LOGGING), languageId: 'selinux', version, text: ORIG } });
  r = await conn.sendRequest('selinux/build', { uri: uri(LOGGING) });
  check(!r.ok && /no-such-users-file not found/.test(r.log + JSON.stringify(diags[uri(LOGGING)] || [])), 'missing selinux.build.tree.files source is reported', { r: { ...r, log: undefined }, d: diags[uri(LOGGING)] });

  // Full build with the spec's settings (trusted now, so the m4 flags are asked from make).
  await configure({ makeArgs: cfg.makeArgs, files: cfg.files });
  for (let i = 0; i < 40 && !lastFlags; i++) await sleep(250);
  const flags = lastFlags;
  check(flags && /-D distro_redhat/.test(flags) && /-D enable_mcs/.test(flags), `m4 flags from the Makefile: ${flags}`);

  // ifdef(`distro_redhat', `typealias spamc_t alias pyzor_t ...', `type pyzor_t; ...') in pyzor.te
  const pz = fs.readFileSync(PYZOR, 'utf8').split('\n');
  const aliasLine = pz.findIndex(l => /typealias spamc_t alias pyzor_t/.test(l)), typeLine = pz.findIndex(l => /^\s*type pyzor_t;/.test(l));
  ranges = await conn.sendRequest('selinux/inactiveRanges', { uri: uri(PYZOR) });
  const dims = (l) => ranges.some(r => r.range.start.line <= l && l <= r.range.end.line);
  check(dims(typeLine) && !dims(aliasLine) && ranges.every(r => /distro_redhat/.test(r.reason) || /needs \w+/.test(r.reason)),
    `pyzor.te: the !distro_redhat branch (line ${typeLine + 1}) is dimmed, the RHEL one (line ${aliasLine + 1}) is not`, ranges.map(r => [r.range.start.line + 1, r.range.end.line + 1, r.reason]));
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(PYZOR), languageId: 'selinux', version: 1, text: pz.join('\n') } });
  await sleep(300);
  const defs = await conn.sendRequest('textDocument/definition', { textDocument: { uri: uri(PYZOR) }, position: { line: aliasLine, character: pz[aliasLine].indexOf('pyzor_t') + 1 } });
  // (spamassassin.te also aliases pyzor_t; the point is that the dead `type pyzor_t;` is gone)
  check(defs.some(d => d.uri === uri(PYZOR) && d.range.start.line === aliasLine) && !defs.some(d => d.uri === uri(PYZOR) && d.range.start.line === typeLine),
    `definition of pyzor_t skips the inactive declaration (${defs.map(d => `${path.basename(URI.parse(d.uri).fsPath)}:${d.range.start.line + 1}`).join(', ')})`);
  const hv = async (line, word) => (await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(PYZOR) }, position: { line, character: pz[line].indexOf(word) + 1 } })).contents.value;
  const redhatLine = pz.findIndex(l => l.includes('distro_redhat'));
  check(/build flag: \*\*defined\*\*/.test(await hv(redhatLine, 'distro_redhat')), 'hover on distro_redhat: defined in this build');
  const debFile = [...cp.execFileSync('grep', ['-rl', 'ifdef(`distro_debian', path.join(ws, 'policy/modules')]).toString().split('\n')].find(Boolean);
  const deb = fs.readFileSync(debFile, 'utf8').split('\n'), debLine = deb.findIndex(l => l.includes('distro_debian'));
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(debFile), languageId: 'selinux', version: 1, text: deb.join('\n') } });
  await sleep(300);
  const hd = await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(debFile) }, position: { line: debLine, character: deb[debLine].indexOf('distro_debian') + 1 } });
  check(hd && /build flag: \*\*not defined\*\*/.test(hd.contents.value), `hover on distro_debian (${path.basename(debFile)}): not defined`, hd && hd.contents.value);
  r = await conn.sendRequest('selinux/build', { uri: uri(LOGGING) });
  check(r.ok && r.validated, `full ${variant} build + validate (${(r.ms / 1000).toFixed(1)} s, ${r.packages} packages)`, { ...r, log: r.log && r.log.slice(-1500) });
  const work = r.outputDir;
  const specMods = cfg.files['policy/modules.conf'].map(f => fs.readFileSync(f, 'utf8')).join('\n');
  const enabled = new Set([...specMods.matchAll(/^(\w[\w-]*)\s*=\s*(module|base)\s*$/gm)].filter(m => m[2] === 'module').map(m => m[1]));
  const built = new Set(fs.readdirSync(work).filter(n => n.endsWith('.pp') && n !== 'base.pp').map(n => n.slice(0, -3)));
  const extra = [...built].filter(m => !enabled.has(m)), absent = [...enabled].filter(m => !built.has(m) && fs.existsSync(path.join(ws, 'policy/modules')));
  check(extra.length === 0, `no module packages beyond the spec's modules.conf (${built.size} built)`, extra.slice(0, 10));
  check(absent.length < 5, `spec modules that were built: ${enabled.size - absent.length}/${enabled.size}`, absent.slice(0, 10));
  check(fs.readFileSync(path.join(work, 'policy/booleans.conf'), 'utf8') === fs.readFileSync(cfg.files['policy/booleans.conf'][0], 'utf8'), 'scratch copy has the spec\'s booleans.conf');

  // Incremental: nothing changed -> nothing rewritten (overlays included).
  await edit(ORIG + '\n');
  await edit(ORIG);
  r = await save();
  check(r.ok, `unchanged rebuild ok (${(r.ms / 1000).toFixed(1)} s)`, r.ok);

  // Link error against a module the spec turns off (timidity = off).
  const t = ORIG + "gen_require(`\n\ttype timidity_t;\n')\nallow syslogd_t timidity_t:process signal;\n";
  await edit(t);
  r = await save();
  const d = (diags[uri(LOGGING)] || []).find(x => x.source === 'semodule_link');
  check(!r.ok && d && d.range.start.line === t.split('\n').findIndex(l => l.includes('type timidity_t')), 'link error on the require of timidity_t', (diags[uri(LOGGING)] || []).map(x => `${x.range.start.line + 1} [${x.source}] ${x.message}`));
  await edit(ORIG);
  r = await save();
  check(r.ok, 'reverted build ok');

  // Compiled policy: boolean defaults follow booleans.conf.
  const m = await conn.sendRequest('selinux/policyModel');
  check(!m.unavailable && m.types.length > 1000, `policy model (${m.types && m.types.length} types)`, m.unavailable);
  if (!m.unavailable) {
    const conf = new Map([...fs.readFileSync(cfg.files['policy/booleans.conf'][0], 'utf8').matchAll(/^\s*(\w+)\s*=\s*(\w+)/gm)].map(x => [x[1], /^(true|1|on)$/i.test(x[2])]));
    const mismatched = m.bools.filter(b => conf.has(b.name) && conf.get(b.name) !== b.state).map(b => b.name);
    check(conf.size > 0 && mismatched.length === 0, `boolean defaults follow booleans-${variant}.conf (${[...conf.keys()].filter(k => m.bools.some(b => b.name === k)).length} checked)`, mismatched.slice(0, 10));
    // Rule queries at RHEL scale: indexed once per build, then fast.
    let t0 = Date.now();
    const q1 = await conn.sendRequest('selinux/typeRules', { name: 'init_t', dir: 'source', kinds: ['allow'] });
    const first = Date.now() - t0; t0 = Date.now();
    const q2 = await conn.sendRequest('selinux/typeRules', { name: 'syslogd_t', dir: 'target', kinds: ['allow'] });
    const next = Date.now() - t0;
    const sample = q1.rules && q1.rules.find(r => r.s === 'init_t' && !r.cond);
    t0 = Date.now();
    const o = sample && await conn.sendRequest('selinux/ruleOrigins', { rule: sample });
    const tOrig = Date.now() - t0;
    check(q1.count > 500 && q2.count > 50 && first < 15000 && next < 1000 && o && o.origins.length,
      `rule queries: init_t can access ${q1.count} rules (first ${first} ms incl. indexing, next ${next} ms); origins of "${sample && `${sample.t}:${sample.c}`}" in ${tOrig} ms → ${o && o.origins[0] && `${path.basename(o.origins[0].path)}:${o.origins[0].line + 1}`}`, { q1: q1.unavailable, q2: q2.unavailable });
    const located = m.types.filter(x => x.loc).length;
    check(located / m.types.length > 0.95, `source location for ${located}/${m.types.length} types`, m.types.filter(x => !x.loc).slice(0, 15).map(x => x.name));
  }

  await conn.sendRequest('shutdown');
  const exited = new Promise(res => proc.on('exit', res));
  conn.sendNotification('exit');
  await Promise.race([exited, sleep(5000)]);
  check(!fs.existsSync(work), 'scratch tree removed on server exit');
  console.log(failures ? `\n${failures} check(s) failed` : '\nall RHEL tree build checks passed');
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); fs.rmSync(ws, { recursive: true, force: true }); process.exit(1); });
