// Denial assistant benchmark: how often the interface a real module uses is
// the one suggested for a denial it would fix. For top-level calls
// `iface(domain_t)` of other modules' interfaces in a directory of daemon .te
// files, one allow rule the call grants (on a plain type) becomes a fake AVC
// denial; the suggestions for it (against the installed policy, devel headers)
// should rank the original interface first, or an interface that grants no
// more. Prints the hit rates and a few misses.
//   node test/denials-bench.js [te-dir] [max-calls] [min-top1-%] [min-top3-%]
// Default te-dir: ~/sepol-test/rhel9/policy/modules/contrib (RHEL 9 sources,
// matching melody's installed policy). Needs Linux, selinux-policy-devel,
// python3-setools. Exits non-zero below the given rates.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const build = require('../server/build');
const denials = require('../server/denials');

const dir = process.argv[2] || path.join(os.homedir(), 'sepol-test/rhel9/policy/modules/contrib');
const MAX = +(process.argv[3] || 300);
const MIN1 = +(process.argv[4] || 0), MIN3 = +(process.argv[5] || 0);
const DEVEL = '/usr/share/selinux/devel/Makefile';
if (!fs.existsSync(dir) || !fs.existsSync(DEVEL) || !build.installedPolicies().some(p => p.active)) { console.log('SKIP: needs a .te directory, selinux-policy-devel and an installed policy'); process.exit(0); }

// 1. Calls: `iface(domain_t)` at the top level of a .te, interface from another module.
const calls = [];
for (const f of fs.readdirSync(dir).filter(n => n.endsWith('.te')).sort()) {
  const mod = f.slice(0, -3);
  const text = fs.readFileSync(path.join(dir, f), 'utf8');
  let depth = 0;
  for (const line of text.split('\n')) {
    const m = /^([a-z][a-z0-9_]*)\(([a-z][a-z0-9_]*_t)\)\s*$/.exec(line);
    if (m && depth === 0 && !m[1].startsWith(mod + '_') && !/^(optional_policy|tunable_policy|ifdef|ifndef|gen_require)$/.test(m[1])) calls.push({ iface: m[1], domain: m[2], mod });
    for (const ch of line.replace(/#.*$/, '')) { if (ch === '(') depth++; else if (ch === ')') depth = Math.max(0, depth - 1); }
  }
}
// An even sample across modules.
const step = Math.max(1, calls.length / MAX);
const sample = [];
for (let i = 0; i < calls.length && sample.length < MAX; i += step) sample.push(calls[Math.floor(i)]);
console.log(`${calls.length} calls in ${dir}; sampling ${sample.length}`);

(async () => {
  // 2. What each call grants (m4 with the devel headers), and one denial per call it would fix.
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-bench-probe-'));
  const ex = await build.expandCalls(sample.map(c => `${c.iface}(${c.domain})`), { work, develMakefile: DEVEL });
  if (!ex.ok) { console.log(`m4 failed: ${ex.log}`); process.exit(1); }
  const stmts = denials.probeStatements(ex.text);
  const READISH = new Set(['getattr', 'open', 'search', 'lock', 'ioctl', 'map']);
  const cases = [];
  for (const c of sample) {
    const list = stmts.get(`${c.iface}(${c.domain})`) || [];
    // The interface's own main rule (not one of the interfaces it calls): from the domain to one plain type
    // in one class, the most non-read permissions, the last on a tie (patterns search directories first).
    const rules = list.filter(s => s.rt === 'allow' && !s.cond && !s.nested && s.s.length === 1 && s.s[0] === c.domain && s.t.length === 1 && /_t$/.test(s.t[0]) && s.t[0] !== c.domain && s.c.length === 1 && s.perms.length && !s.perms.includes('*'));
    const strength = (x) => x.perms.filter(p => !READISH.has(p)).length;
    const r = rules.reduce((best, x) => (!best || strength(x) >= strength(best) ? x : best), null);
    if (!r) continue;
    const perm = r.perms.find(p => !READISH.has(p)) || r.perms[0];
    cases.push({ ...c, target: r.t[0], tclass: r.c[0], perm });
  }
  fs.rmSync(work, { recursive: true, force: true });
  // Several calls can give the same denial: any of their interfaces counts.
  const byKey = new Map();
  for (const k of cases) {
    const key = `${k.domain}|${k.target}|${k.tclass}|${k.perm}`;
    if (!byKey.has(key)) byKey.set(key, { ...k, ifaces: new Set() });
    byKey.get(key).ifaces.add(k.iface);
  }
  const uniq = [...byKey.values()];
  console.log(`${cases.length} calls give ${uniq.length} distinct denials`);

  // 3. Suggestions over LSP (standalone workspace = devel headers), against the installed policy.
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-bench-ws-'));
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let done;
  const indexed = new Promise(r => (done = r));
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') done(); });
  for (const n of ['textDocument/publishDiagnostics', 'selinux/checks', 'selinux/build', 'selinux/inactiveRanges', 'window/logMessage']) conn.onNotification(n, () => {});
  conn.listen();
  await conn.sendRequest('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: { trusted: true } });
  conn.sendNotification('initialized', {});
  await indexed;

  const t0 = Date.now();
  let exact = 0, top1 = 0, top3 = 0, top5 = 0, noGrant = 0, total = 0;
  const misses = [];
  const BATCH = 25;
  for (let i = 0; i < uniq.length; i += BATCH) {
    const batch = uniq.slice(i, i + BATCH);
    // Distinct (domain, target, class) per request, so each denial is its own group.
    const groups = new Map();
    for (const k of batch) { const g = `${k.domain}|${k.target}|${k.tclass}`; if (!groups.has(g)) groups.set(g, k); }
    const ks = [...groups.values()];
    const log = ks.map((k, j) => `type=AVC msg=audit(1728650000.${i + j}:${i + j + 1}): avc:  denied  { ${k.perm} } for  pid=1 comm="x" scontext=system_u:system_r:${k.domain}:s0 tcontext=system_u:object_r:${k.target}:s0 tclass=${k.tclass} permissive=0`).join('\n');
    const r = await conn.sendRequest('selinux/analyzeDenials', { text: log, suggest: { verdicts: ['allowed', 'missing'], max: BATCH, limit: 60 } });
    for (const k of ks) {
      const g = r.groups.find(x => x.source === k.domain && x.target === k.target && x.tclass === k.tclass);
      if (!g || !g.suggest || g.suggest.own) continue;
      total++;
      const names = (g.suggest.list || []).filter(x => x.covers).map(x => x.name);
      const at = names.findIndex(n => k.ifaces.has(n));
      // Ranked first, or the first one grants no more than the original (both shown with their extra rights).
      const orig = (g.suggest.list || []).find(x => k.ifaces.has(x.name));
      const asGood = names.length && orig && g.suggest.list[0].extra <= orig.extra;
      if (at === 0) exact++;
      if (at === 0 || asGood) top1++;
      if (at >= 0 && at < 3) top3++;
      if (at >= 0) top5++;
      if (!names.length) noGrant++;
      if (at !== 0 && !asGood && misses.length < 30) misses.push(`${k.domain} ${k.target}:${k.tclass} ${k.perm}: used ${[...k.ifaces].join('/')}${orig ? ` (extra ${orig.extra})` : ''}; suggested ${(g.suggest.list || []).slice(0, 3).map(x => `${x.name} (${x.extra})`).join(', ') || g.suggest.note}`);
    }
  }
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  const pct = (n) => (total ? Math.round(100 * n / total) : 0);
  console.log(`\n${total} denials in ${Math.round((Date.now() - t0) / 1000)} s: original or a narrower one first ${pct(top1)}% (exactly the original ${pct(exact)}%), in the top 3 ${pct(top3)}%, top 5 ${pct(top5)}%; no covering suggestion ${noGrant}`);
  console.log('\nnot first:\n  ' + misses.join('\n  '));
  const ok = pct(top1) >= MIN1 && pct(top3) >= MIN3;
  console.log(ok ? '\nbenchmark passed' : `\nbenchmark below ${MIN1}% / ${MIN3}%`);
  process.exit(ok ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
