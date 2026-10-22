// Login context check over real policies (Linux with python3-setools):
//   node test/loginctx-survey.js installed [NAME]          an installed policy (default: the running one)
//   node test/loginctx-survey.js tree <policy.bin> <appconfig dir>   a build and its tree's appconfig-<TYPE>
//   node test/loginctx-survey.js build <tree>                 builds a copy of a CLIP tree (its spec's make arguments) first
// Prints every problem; exits 0 (it reports, it doesn't judge).
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const L = require('../server/loginctx');

let [mode, a, b] = process.argv.slice(2);
const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } };
let bin, cfg;
if (mode === 'build') {
  const { clipArgs } = require('./clip-args');
  const args = clipArgs(a);
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'loginctx-survey-'));
  cp.execFileSync('cp', ['-a', a + '/.', work]);
  fs.rmSync(path.join(work, 'tmp'), { recursive: true, force: true });
  const t0 = Date.now();
  const r = cp.spawnSync('make', ['-C', work, ...args, 'base.pp', 'modules', 'validate'], { encoding: 'utf8', maxBuffer: 256 << 20 });
  if (r.status !== 0) { console.log(`build failed:\n${(r.stdout + r.stderr).slice(-3000)}`); process.exit(1); }
  console.log(`built ${a} in ${((Date.now() - t0) / 1000).toFixed(0)} s (${work})`);
  const type = (args.find(x => /^TYPE=/.test(x)) || 'TYPE=mcs').slice(5);
  mode = 'tree';
  a = path.join(work, 'tmp', 'policy.bin');
  b = path.join(work, 'config', `appconfig-${type}`);
}
if (mode === 'tree') {
  bin = a;
  cfg = { seusers: { path: path.join(b, 'seusers'), text: read(path.join(b, 'seusers')) }, defaults: { path: path.join(b, 'default_contexts'), text: read(path.join(b, 'default_contexts')) },
    userFile: (u) => ({ path: path.join(b, `${u}_default_contexts`), text: read(path.join(b, `${u}_default_contexts`)) }),
    failsafe: { path: path.join(b, 'failsafe_context'), text: read(path.join(b, 'failsafe_context')) } };
} else {
  const name = a || (/^SELINUXTYPE=(\S+)/m.exec(read('/etc/selinux/config') || '') || [])[1];
  const dir = `/etc/selinux/${name}`;
  bin = fs.readdirSync(path.join(dir, 'policy')).filter(n => /^policy\.\d+$/.test(n)).map(n => path.join(dir, 'policy', n)).sort().pop();
  const c = (n) => path.join(dir, 'contexts', n);
  cfg = { seusers: { path: path.join(dir, 'seusers'), text: read(path.join(dir, 'seusers')) }, defaults: { path: c('default_contexts'), text: read(c('default_contexts')) },
    userFile: (u) => ({ path: c(`users/${u}`), text: read(c(`users/${u}`)) }), failsafe: { path: c('failsafe_context'), text: read(c('failsafe_context')) } };
}
const proc = cp.spawn('python3', [path.join(__dirname, '../server/policy_query.py')], { stdio: ['pipe', 'pipe', 'inherit'] });
let buf = '';
const waiting = new Map();
let n = 0;
proc.stdout.on('data', (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf('\n')) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 1); const r = JSON.parse(line); waiting.get(r.id)(r); waiting.delete(r.id); }
});
const req = (o) => new Promise((res) => { const id = ++n; waiting.set(id, res); proc.stdin.write(JSON.stringify({ id, bin, ...o }) + '\n'); });
(async () => {
  const t0 = Date.now();
  let questions = 0;
  const r = await L.analyze(cfg, async (items) => { questions += items.length; const x = await req({ op: 'logincontexts', items }); if (x.error) throw new Error(x.error); return x.answers; });
  console.log(`${bin}: ${r.mappings.length} seusers lines, ${r.mappings.reduce((s, m) => s + m.ways.length, 0)} ways, ${questions} questions, ${Date.now() - t0} ms`);
  for (const m of r.mappings) console.log(`  ${m.group ? '%' : ''}${m.login} → ${m.user}${m.level ? ` ${m.level}` : ''}: ${m.ways.map(w => `${w.source}=${w.works3 ? w.v3.ctx.split(':').slice(1, 3).join(':') : '✗'}${w.works2 ? '' : '(✗ on 2.x)'}`).join(' ') || 'no ways'}`);
  for (const p of r.problems) console.log(`${p.severity.toUpperCase().padEnd(7)} ${path.basename(p.file)}:${p.l + 1} ${p.text}`);
  for (const x of r.notes) console.log(`note    ${x}`);
  proc.stdin.end();
})();
