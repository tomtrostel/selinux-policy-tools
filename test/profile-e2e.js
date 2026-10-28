// Install profiles (CLIP kickstarts) and optional_policy blocks the linker
// drops: a copy of the CLIP layout around the tree (kickstart/, conf/yum/
// comps.xml, CONFIG_BUILD, packages/selinux-policy/Makefile), driven over
// stdio LSP. Dimmed blocks without a profile (modules off in modules.conf),
// the hover's "Would compile to", then the clip-sftp-dropbox profile; finally
// the dimming is compared with the real linker: the build's packages linked
// with semodule (CIL) twice, all of them and only the profile's, and each
// block's expanded allow rules looked up in both policies.
//   node test/profile-e2e.js [tree]   (default: the CLIP RHEL 9 clone on melody)
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain, cilBuild } = require('../server/build');
const { parsePolicy } = require('../server/parser');
const { clipArgs } = require('./clip-args');

const tc = detectToolchain(null);
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }
const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');
const clip = path.resolve(src, '../../..');
if (!fs.existsSync(path.join(src, 'Rules.modular')) || !fs.existsSync(path.join(clip, 'kickstart'))) { console.log(`SKIP: no CLIP layout around ${src}`); process.exit(0); }
const makeArgs = clipArgs(src);
const PROFILE = 'clip-sftp-dropbox';

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-profile-e2e-'));
for (const p of ['kickstart', 'conf/yum/comps.xml', 'CONFIG_BUILD', 'packages/selinux-policy/Makefile']) {
  fs.mkdirSync(path.dirname(path.join(ws, p)), { recursive: true });
  cp.execFileSync('cp', ['-a', path.join(clip, p), path.join(ws, p)]);
}
for (const n of fs.readdirSync(path.dirname(src))) if (n.endsWith('.spec')) fs.copyFileSync(path.join(path.dirname(src), n), path.join(ws, 'packages/selinux-policy', n));
const tree = path.join(ws, 'packages/selinux-policy/selinux-policy');
fs.mkdirSync(tree, { recursive: true });
cp.execFileSync('cp', ['-a', src + '/.', tree]);
fs.rmSync(path.join(tree, 'tmp'), { recursive: true, force: true });
const T = (p) => path.join(tree, 'policy/modules', p);

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
let doneIndex;
const indexed = new Promise(r => (doneIndex = r));
const diags = {};
let inactiveChanged = 0;
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/inactiveChanged', () => { inactiveChanged++; });
for (const n of ['selinux/build', 'window/logMessage']) conn.onNotification(n, () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2000).replace(/\n/g, '\n     ')); }
};
const dropped = async (file) => (await conn.sendRequest('selinux/inactiveRanges', { uri: uri(file) })).filter(r => r.dropped);
const at = (list, line1) => list.find(r => r.range.start.line === line1 - 1);
/** The 1-based line of the n-th optional_policy block of a file whose body mentions `needle`. */
function blockLine(file, needle) {
  const f = parsePolicy(fs.readFileSync(file, 'utf8'), file);
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const b = f.calls.filter(c => c.name === 'optional_policy').find(c => lines.slice(c.l, c.endL + 1).join('\n').includes(needle));
  return b ? b.l + 1 : null;
}

/* policy_query.py for the comparison with the linked policies: one per policy (it indexes one at a time) */
const queriers = [];
function querier() {
  const pq = cp.spawn('python3', [path.join(__dirname, '../server/policy_query.py')]);
  const pending = new Map();
  let qid = 0;
  readline.createInterface({ input: pq.stdout }).on('line', (l) => { const r = JSON.parse(l); pending.get(r.id)(r); pending.delete(r.id); });
  queriers.push(pq);
  return (req) => new Promise((res) => { const id = ++qid; pending.set(id, res); pq.stdin.write(JSON.stringify({ ...req, id }) + '\n'); });
}

/**
 * Plain allow rules of statements: { s, t, c, perms } (single names; sets and
 * macros skipped). Statements in optional blocks nested deeper than the
 * block's own (interfaces' optional_policy blocks, dropped on their own) are
 * left out; `depth0` is the optional depth of the block itself.
 */
function allowRules(texts, depth0 = 1) {
  const out = [];
  const stack = [];
  for (const raw of texts) {
    const t = raw.trim();
    if (/^optional\s*\{/.test(t)) { stack.push('o'); continue; }
    if (/^(if\s*\(.*\)|else)\s*\{$/.test(t) || /^\}\s*else\s*\{$/.test(t)) { if (!/^\}/.test(t)) stack.push('i'); continue; }
    if (/^\}\s*$/.test(t)) { stack.pop(); continue; }
    if (stack.filter(x => x === 'o').length > depth0) continue;
    const m = /^allow\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*:\s*([A-Za-z_]\w*)\s+(\{[^}]*\}|[A-Za-z_]\w*)\s*;/.exec(t);
    if (!m) continue;
    const perms = m[4].replace(/[{}]/g, ' ').split(/\s+/).filter(p => /^[a-z_]\w*$/.test(p));
    if (perms.length) out.push({ s: m[1], t: m[2] === 'self' ? m[1] : m[2], c: m[3], perms });
  }
  return out;
}

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {}, initializationOptions: { build: { tree: { makeArgs } } } });
  conn.sendNotification('initialized', {});
  await indexed;

  // 1. Profiles found above the tree.
  let pr = await conn.sendRequest('selinux/installProfiles');
  check(pr.profiles.length >= 3 && pr.profiles.some(p => p.name === PROFILE) && !pr.active, `profiles: ${pr.profiles.map(p => p.name).join(', ')} (none active)`, pr);
  check(pr.separate.includes('postfix') && pr.separate.includes('ssh') && pr.type === 'mcs', `${pr.separate.length} separately packaged modules, type ${pr.type}`, pr);

  // 2. No profile: blocks needing a module off in modules.conf are dimmed (cron.te: nis_use_ypbind), blocks needing postfix (built) are not.
  const CRON = T('services/cron.te');
  const nisLine = blockLine(CRON, 'nis_use_ypbind');
  const pfLine = blockLine(CRON, 'postfix_read_config');
  let d = await dropped(CRON);
  const nis = at(d, nisLine);
  check(nis && /var_yp_t/.test(nis.reason) && /nis is off in modules.conf/.test(nis.reason), `cron.te:${nisLine} (nis_use_ypbind) dimmed: ${nis && nis.reason}`, d);
  check(!at(d, pfLine), `cron.te:${pfLine} (postfix_read_config) not dimmed without a profile`, d);

  // 3. Build, then the hover shows what the dimmed block would compile to.
  const b = await conn.sendRequest('selinux/build', { uri: uri(tree) });
  check(b.ok && b.validated, `tree build (${(b.ms / 1000).toFixed(1)} s)`, b);
  const cronText = fs.readFileSync(CRON, 'utf8');
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(CRON), languageId: 'selinux', version: 1, text: cronText } });
  await sleep(500);
  const col = cronText.split('\n')[nisLine - 1].indexOf('optional_policy');
  let h = await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(CRON) }, position: { line: nisLine - 1, character: col + 2 } });
  const hv = h && h.contents && h.contents.value || '';
  check(/Not in the linked policy/.test(hv) && /Would compile to\*\* \(the whole block/.test(hv) && /var_yp_t/.test(hv.split('Would compile to')[1] || ''),
    'hover on the dimmed optional_policy: why + the whole block\'s statements', hv.slice(0, 800));
  const callLine = cronText.split('\n').findIndex((l, i) => i >= nisLine - 1 && /nis_use_ypbind\(/.test(l));
  h = await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(CRON) }, position: { line: callLine, character: cronText.split('\n')[callLine].indexOf('nis_use_ypbind') + 3 } });
  const hc = h && h.contents && h.contents.value || '';
  if (process.env.DEBUG) for (let l = nisLine - 2; l <= nisLine + 2; l++) console.log('DEBUG line', l, JSON.stringify(await conn.sendRequest('selinux/expansion', { uri: uri(CRON), line: l })).slice(0, 300));
  check(/Not in the linked policy/.test(hc) && /\*\*Would compile to\*\* \(\d+ statement/.test(hc) && !/\*\*Compiles to\*\*/.test(hc), 'hover on a call inside it: "Would compile to" + the interface docs', hc.slice(0, 600));

  // 4. The sftp-dropbox profile: postfix isn't installed there.
  inactiveChanged = 0;
  const sel = await conn.sendRequest('selinux/selectInstallProfile', { profile: PROFILE });
  check(sel.ok && sel.profile === PROFILE && inactiveChanged > 0, `selected ${PROFILE} (editors told to re-dim)`, sel);
  pr = await conn.sendRequest('selinux/installProfiles');
  const M = (m) => pr.active.modules.find(x => x.module === m);
  check(M('ssh').state === 'installed' && M('aide').state === 'installed' && M('postfix').state === 'absent' && M('xserver').state === 'absent',
    `${PROFILE}: ssh, aide installed; postfix, xserver absent (${pr.active.modules.filter(m => m.state === 'installed').map(m => m.module).join(' ')})`, pr.active);
  d = await dropped(CRON);
  const pf = at(d, pfLine);
  check(pf && /selinux-policy-mcs-postfix/.test(pf.reason) && new RegExp(PROFILE).test(pf.reason), `cron.te:${pfLine} now dimmed: ${pf && pf.reason}`, d);
  const POSTFIX = T('services/postfix.te');
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(POSTFIX), languageId: 'selinux', version: 1, text: fs.readFileSync(POSTFIX, 'utf8') } });
  await sleep(800);
  const info = (diags[uri(POSTFIX)] || []).find(x => x.code === 'profile-not-installed');
  check(info && info.severity === 3 && /selinux-policy-mcs-postfix/.test(info.message), 'postfix.te: info that the profile leaves it out', diags[uri(POSTFIX)]);
  check((await dropped(POSTFIX)).length === 0, 'postfix.te itself: nothing dimmed (the whole module is out)');

  // 5. Against the real linker: CIL builds of every package and of the profile's.
  const absent = pr.active.modules.filter(m => m.state === 'absent' && m.built).map(m => m.module);
  const refused = [];
  let full;
  for (let i = 0; i < 4; i++) {
    full = await cilBuild({ workDir: b.workDir }, { name: 'mcs', root: 'cil-full', exclude: refused });
    const m = !full.ok && /modules\/\d+\/([^/]+)\/cil:/.exec(full.log || '');
    if (!m || refused.includes(m[1])) break;
    console.log(`     note: semodule (CIL) refuses ${m[1]}: ${full.log.split('\n')[0]}; left out of both links`);
    refused.push(m[1]);
  }
  const prof = await cilBuild({ workDir: b.workDir }, { name: 'mcs', root: 'cil-profile', exclude: [...absent, ...refused] });
  check(full.ok && prof.ok && prof.packages === full.packages - absent.filter(m => !refused.includes(m)).length, `semodule: all ${full.packages} packages, and ${prof.packages} without ${absent.length} left-out modules`, [full.log, prof.log]);

  // Dimmed blocks: a type/attribute they need is in the full policy but not in the profile's.
  // Kept blocks (in the same files): their own allow rules (not those of interfaces' inner
  // optional blocks) are all still in the profile's policy.
  const askFull = querier(), askProf = querier();
  const exists = async (ask, bin, names) => new Set((await ask({ op: 'users', bin, types: [], names })).exists || []);
  const files = [];
  for (const dir of ['admin', 'apps', 'kernel', 'roles', 'services', 'system']) {
    for (const n of fs.readdirSync(T(dir))) if (n.endsWith('.te') && (!process.env.ONLY_FILES || process.env.ONLY_FILES.split(',').includes(n))) files.push(T(path.join(dir, n)));
  }
  const stats = { dimmed: 0, byProfile: 0, confirmed: 0, wrong: [], kept: 0, keptChecked: 0, keptLost: [] };
  for (const file of files) {
    const dims = await dropped(file);
    if (!dims.length) continue;
    const f = parsePolicy(fs.readFileSync(file, 'utf8'), file);
    for (const blk of f.calls.filter(c => c.name === 'optional_policy' && !c.inDef)) {
      const dim = dims.find(x => x.range.start.line === blk.l);
      const where = `${path.relative(tree, file)}:${blk.l + 1}`;
      if (dim) {
        stats.dimmed++;
        const inFull = await exists(askFull, full.policy, dim.missing);
        const needed = dim.missing.filter(n => inFull.has(n));
        if (!needed.length) continue; // dropped by modules.conf (not built at all), or roles/booleans
        stats.byProfile++;
        const inProf = await exists(askProf, prof.policy, needed);
        if (needed.some(n => !inProf.has(n))) stats.confirmed++;
        else stats.wrong.push(`${where} needs ${needed.join(' ')}`);
        continue;
      }
      stats.kept++;
      const lines = [];
      for (let l = blk.l; l <= blk.endL; l++) {
        const r = await conn.sendRequest('selinux/expansion', { uri: uri(file), line: l });
        for (const e of r || []) lines.push(e.text);
      }
      const texts = lines; // not deduplicated: inner `optional {` / `}` lines repeat
      const rules = allowRules(texts, texts.length && /^optional\s*\{/.test(texts[0].trim()) ? 1 : 0);
      if (!rules.length) continue;
      const checks = rules.map((r, i) => ({ ...r, id: i }));
      const [rf, rp] = await Promise.all([askFull({ op: 'avc', bin: full.policy, checks }), askProf({ op: 'avc', bin: prof.policy, checks })]);
      const has = (res, i, p) => res[i] && res[i].perms && res[i].perms[p] && res[i].perms[p].status !== 'missing';
      const usable = rules.map((r, i) => ({ r, i })).filter(({ r, i }) => r.perms.every(p => has(rf.results, i, p)));
      if (!usable.length) continue;
      stats.keptChecked++;
      const lost = usable.filter(({ r, i }) => r.perms.some(p => !has(rp.results, i, p)));
      if (lost.length && process.env.DEBUG) console.log(`DEBUG ${where}\n` + texts.map(t => `  | ${t}`).join('\n'));
      if (lost.length) stats.keptLost.push(`${where} ${lost.slice(0, 2).map(({ r }) => `${r.s} ${r.t}:${r.c} ${r.perms.join(' ')}`).join(', ')}`);
    }
  }
  console.log(`     dimmed blocks: ${stats.dimmed} (${stats.byProfile} because of the profile, ${stats.confirmed} confirmed: a name they need isn't in its linked policy)`);
  console.log(`     kept blocks: ${stats.kept} (${stats.keptChecked} with rules to look up, ${stats.keptLost.length} lost rules in the profile's policy)`);
  check(stats.byProfile > 50 && stats.wrong.length === 0, 'every block dimmed for the profile needs a name the profile\'s linked policy lacks', stats.wrong);
  check(stats.keptChecked > 100 && stats.keptLost.length === 0, 'no kept block lost rules in the profile\'s linked policy', stats.keptLost);

  // 6. Back to every built module.
  await conn.sendRequest('selinux/selectInstallProfile', { profile: null });
  d = await dropped(CRON);
  check(!at(d, pfLine) && at(d, nisLine), 'no profile again: only the modules.conf drops');

  await conn.sendRequest('shutdown');
  conn.sendNotification('exit');
  for (const q of queriers) q.stdin.end();
  await sleep(300);
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  console.log(failures ? `\n${failures} check(s) failed` : '\nall install profile checks passed');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
