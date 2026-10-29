// Context-file check over real policies (Linux with python3-setools):
//   node test/ctxfiles-survey.js installed [NAME]      an installed policy (default: the running one)
//   node test/ctxfiles-survey.js tree <built tree copy> [TYPE]   a tree copy built with `make base.pp modules validate`
//   node test/ctxfiles-survey.js build <tree>             builds a copy of a CLIP tree (its spec's make arguments) first
// Prints every problem; exits 0 (it reports, it doesn't judge).
const fs = require('fs');
const { tempDir } = require('./tmpdirs');
const path = require('path');
const cp = require('child_process');
const C = require('../server/ctxfiles');
const filelabel = require('../server/filelabel');

let [mode, a, typeArg] = process.argv.slice(2);
const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } };
let bin, cfg, type = typeArg || null;
if (mode === 'build') {
  const { clipArgs } = require('./clip-args');
  const args = clipArgs(a);
  const work = tempDir('ctxfiles-survey-');
  cp.execFileSync('cp', ['-a', a + '/.', work]);
  fs.rmSync(path.join(work, 'tmp'), { recursive: true, force: true });
  const t0 = Date.now();
  const r = cp.spawnSync('make', ['-C', work, ...args, 'base.pp', 'modules', 'validate'], { encoding: 'utf8', maxBuffer: 256 << 20 });
  if (r.status !== 0) { console.log(`build failed:\n${(r.stdout + r.stderr).slice(-3000)}`); process.exit(1); }
  console.log(`built ${a} in ${((Date.now() - t0) / 1000).toFixed(0)} s (${work})`);
  type = (args.find(x => /^TYPE=/.test(x)) || 'TYPE=mcs').slice(5);
  mode = 'tree';
  a = work;
}
if (mode === 'tree') {
  const work = a;
  bin = path.join(work, 'tmp', 'policy.bin');
  const conf = read(path.join(work, 'build.conf')) || '';
  if (!type) type = (/^\s*TYPE\s*=\s*(\S+)/m.exec(conf) || [])[1] || 'mcs';
  const dir = path.join(work, 'config', `appconfig-${type}`);
  const pps = fs.readdirSync(work).filter(n => n.endsWith('.pp') && n !== 'base.pp');
  const main = [path.join(work, 'base.fc'), ...pps.map(n => path.join(work, 'tmp', `${n.slice(0, -3)}.mod.fc`))].filter(p => fs.existsSync(p))
    .flatMap(p => filelabel.parseSpecs(read(p), p, path.basename(p).replace(/\.mod\.fc$|\.fc$/, '')));
  cfg = { files: C.FILES.map(def => ({ def, path: path.join(dir, def.name), text: read(path.join(dir, def.name)) })), seusers: { path: path.join(dir, 'seusers'), text: read(path.join(dir, 'seusers')) },
    usersExtra: read(path.join(work, 'tmp', 'users_extra')), fc: { main, templates: main.filter(s => C.templateKind(s)), build: true } };
} else {
  const name = a || (/^SELINUXTYPE=(\S+)/m.exec(read('/etc/selinux/config') || '') || [])[1];
  const dir = `/etc/selinux/${name}`;
  bin = fs.readdirSync(path.join(dir, 'policy')).filter(n => /^policy\.\d+$/.test(n)).map(n => path.join(dir, 'policy', n)).sort().pop();
  const f = (n) => path.join(dir, 'contexts', 'files', n);
  const specs = (n) => filelabel.parseSpecs(read(f(n)), f(n));
  cfg = { files: C.FILES.map(def => { const p = path.join(dir, 'contexts', def.where === 'files' ? 'files' : '', def.name); return { def, path: p, text: read(p) }; }),
    seusers: { path: path.join(dir, 'seusers'), text: read(path.join(dir, 'seusers')) }, usersExtra: null,
    fc: { main: specs('file_contexts'), homedirs: specs('file_contexts.homedirs'), local: specs('file_contexts.local') } };
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
  const r = await C.analyze(cfg, async (items) => { questions += items.length; const x = await req({ op: 'logincontexts', items }); if (x.error) throw new Error(x.error); return x.answers; });
  if (r.error) { console.log(`error: ${r.error}`); process.exit(1); }
  console.log(`${bin}: ${questions} questions, ${Date.now() - t0} ms`);
  console.log(`  files: ${r.files.map(f => `${f.name}${f.exists ? `(${f.entries}${f.problems ? `, ${f.problems} problem(s)` : ''}${f.unused ? ', unused' : ''})` : ' -'}`).join(' ')}`);
  console.log(`  file contexts: ${['main', 'local', 'homedirs'].map(k => `${k} ${r.fc[k].count}${r.fc[k].invalid ? ` (${r.fc[k].invalid} invalid)` : ''}`).join(', ')}; ${r.fc.templates} templates; ${r.fc.associateChecked} types checked for associate`);
  for (const h of r.homes) console.log(`  home lines for ${h.user} (prefix ${h.prefix}${h.role ? `, role ${h.role}` : ''}${h.level ? `, ${h.level}` : ''}; ${h.logins.join(' ')}): ${h.lines - h.dropped}/${h.lines} kept`);
  for (const p of r.problems) console.log(`${p.severity.toUpperCase().padEnd(7)} ${p.file ? `${path.basename(p.file)}:${p.l + 1}` : '-'} ${p.text}`);
  for (const x of r.notes) console.log(`note    ${x}`);
  proc.stdin.end();
})();
