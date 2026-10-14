// File label lookup on a Linux host:
//  1. this module's lookup against matchpathcon for thousands of real paths
//     (and some that don't exist) with the running policy's file contexts;
//  2. selinux/fileLabel and selinux/fileTypeInfo over LSP on the running policy;
//  3. a tree build (default: the CLIP clone on melody): the build's file
//     contexts sorted as fc_sort.py sorts them, lookups traced to the .fc
//     source line, the file written for matchpathcon, rules and their sources.
//   node test/filelabel-e2e.js [tree-dir]
// Needs Linux running the targeted policy, matchpathcon and python3-setools;
// the tree part also the build toolchain. Skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { installedPolicies } = require('../server/build');
const F = require('../server/filelabel');
const { clipArgs } = require('./clip-args');

const installed = installedPolicies().find(p => p.active);
if (process.platform !== 'linux' || !installed || installed.name !== 'targeted') { console.log('SKIP: needs Linux running the targeted policy'); process.exit(0); }
const treeDir = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');
const CLIP_ARGS = clipArgs(treeDir);

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
const readIf = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } };

/** The path with its directories resolved, as restorecon (and the server) looks it up. matchpathcon doesn't resolve them. */
function resolved(p) {
  try { if (p !== '/') return path.posix.join(fs.realpathSync(path.posix.dirname(p)), path.posix.basename(p)); } catch { /* missing dir */ }
  return p;
}

/**
 * A file matchpathcon -f will read. Before libselinux 3 it refuses lines
 * whose types the running policy lacks (RHEL 8 with a CLIP build), so each
 * type of the file is renamed to a distinct type of the running policy, in a
 * copy (with its .subs_dist); back maps the answers' types to the real ones.
 */
function readableFc(fc) {
  // libselinux 3 (RHEL 9 on) doesn't check, and the answers there are the real test.
  const v = /libselinux-(\d+)/.exec(cp.spawnSync('rpm', ['-q', 'libselinux'], { encoding: 'utf8' }).stdout || '');
  if (!v || Number(v[1]) >= 3) return { fc, back: null };
  const host = cp.spawnSync('seinfo', ['-t'], { encoding: 'utf8', maxBuffer: 64 << 20 }).stdout.split('\n').map(l => l.trim()).filter(l => /^\w+$/.test(l));
  const hostSet = new Set(host);
  const specs = F.parseSpecs(readIf(fc));
  const used = new Set(specs.map(s => s.type).filter(Boolean));
  if ([...used].every(t => hostSet.has(t))) return { fc, back: null };
  const spare = host.filter(t => !used.has(t));
  const to = new Map(); const back = new Map();
  for (const t of used) {
    const h = hostSet.has(t) ? t : spare.shift();
    to.set(t, h); back.set(h, t);
  }
  const out = `${fc}.hosttypes`;
  fs.writeFileSync(out, F.renderSpecs(specs.map(s => (s.type ? { ...s, context: s.context.replace(/^([^:]*:[^:]*:)[^:]*/, `$1${to.get(s.type)}`) } : s))));
  for (const n of ['subs', 'subs_dist']) { const t = readIf(`${fc}.${n}`); if (t != null) fs.writeFileSync(`${out}.${n}`, t); }
  return { fc: out, back };
}

/** matchpathcon's answers for the resolved paths: path → context (null when it has none), per kind. */
function matchpathcon(items, fcGiven) {
  const { fc, back } = fcGiven ? readableFc(fcGiven) : { fc: null, back: null };
  const out = new Map();
  const byMode = new Map();
  for (const it of items) { if (!byMode.has(it.mode)) byMode.set(it.mode, []); byMode.get(it.mode).push(it.p); }
  for (const [mode, ps] of byMode) {
    for (let i = 0; i < ps.length; i += 400) {
      const chunk = ps.slice(i, i + 400);
      const real = new Map();
      for (const p of chunk) { const k = resolved(p); if (!real.has(k)) real.set(k, []); real.get(k).push(p); }
      // matchpathcon calls a fifo a pipe; it silently ignores names it doesn't know.
      const r = cp.spawnSync('matchpathcon', [...(fc ? ['-f', fc] : []), '-m', mode === 'fifo_file' ? 'pipe' : mode, ...real.keys()],{ encoding: 'utf8', maxBuffer: 64 << 20 });
      // (RHEL 8 says symlink_realpath … failed for missing links; that's fine.)
      const errs = r.stderr.split('\n').filter(l => l.trim() && !/symlink_realpath/.test(l));
      if (errs.length) console.log(`     matchpathcon -m ${mode}: ${errs.slice(0, 3).join(' | ')}`);
      for (const p of chunk) out.set(`${mode}\t${p}`, null);
      for (const line of r.stdout.split('\n')) {
        const m = /^(.*)\t(\S+)$/.exec(line);
        const c = m && back ? m[2].replace(/^([^:]*:[^:]*:)([^:]*)/, (x, a, t) => a + (back.get(t) || t)) : m && m[2];
        if (m) for (const p of real.get(m[1]) || []) out.set(`${mode}\t${p}`, c);
      }
    }
  }
  return out;
}

/** What this module answers for the same paths, as the server does (directories resolved, then subs). */
function ours(items, order, subs) {
  const out = new Map();
  for (const it of items) {
    const key = F.applySubs(resolved(it.p), subs.local, subs.dist);
    const m = F.matches(order, key, it.mode, 1);
    out.set(`${it.mode}\t${it.p}`, m.length ? m[0].context : null);
  }
  return out;
}

function compare(items, order, subs, fc, label) {
  const t0 = Date.now();
  const a = ours(items, order, subs);
  const t1 = Date.now();
  const b = matchpathcon(items, fc);
  const diff = [];
  for (const [k, v] of a) if (b.get(k) !== v) diff.push(`${k.replace('\t', ' ')}: ours ${v} / matchpathcon ${b.get(k)}`);
  check(diff.length === 0, `${label}: ${items.length} paths agree with matchpathcon (ours ${t1 - t0} ms)`, diff.slice(0, 20));
}

function samplePaths() {
  const r = cp.spawnSync('find', ['/usr/bin', '/usr/sbin', '/usr/libexec', '/usr/lib/systemd', '/usr/lib64', '/etc', '/var/lib', '/var/log', '/var/spool', '/var/cache', '/dev', '/run', '/opt', '/srv', '/tmp', os.homedir(),
    '-maxdepth', '3', '-not', '-name', '*[[:space:]]*'], { encoding: 'utf8', maxBuffer: 256 << 20 });
  const all = r.stdout.split('\n').filter(p => p.startsWith('/') && !/[\s\\]/.test(p));
  const step = Math.max(1, Math.floor(all.length / 6000));
  const items = [];
  for (let i = 0; i < all.length; i += step) {
    try { items.push({ p: all[i], mode: F.modeOf(fs.lstatSync(all[i])) }); } catch { /* gone */ }
  }
  // Paths that don't exist here, as each kind, and some through linked or equivalent directories.
  for (const p of ['/bin/rpm', '/sbin/restorecon', '/lib64/libc.so.6', '/usr/lib64/zz/new.so', '/usr/local/bin/tool', '/opt/app/bin/run', '/var/www/html/index.html',
    '/home/someone/.ssh/authorized_keys', '/root/.bashrc', '/etc/zz.conf', '/var/run/zz.pid', '/var/lib/mysql/x', '/srv/data']) {
    for (const mode of ['file', 'dir', 'lnk_file']) items.push({ p, mode });
  }
  return items;
}

function start(ws, initOptions = {}) {
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let doneIndex;
  const indexed = new Promise(r => (doneIndex = r));
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
  for (const n of ['textDocument/publishDiagnostics', 'selinux/checks', 'selinux/build', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged']) conn.onNotification(n, () => {});
  conn.listen();
  return { proc, conn, async init() {
    await conn.sendRequest('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: initOptions });
    conn.sendNotification('initialized', {});
    await indexed;
  } };
}

(async () => {
  // 1. The running policy: this module against matchpathcon.
  const dir = path.join('/etc/selinux', installed.name, 'contexts', 'files');
  const P = (n) => F.parseSpecs(readIf(path.join(dir, n)), path.join(dir, n));
  const order = F.lookupOrder(P('file_contexts'), P('file_contexts.homedirs'), P('file_contexts.local'));
  const subs = { local: F.parseSubs(readIf(path.join(dir, 'file_contexts.subs'))), dist: F.parseSubs(readIf(path.join(dir, 'file_contexts.subs_dist'))) };
  check(order.length > 5000, `running policy: ${order.length} file-context lines`);
  const items = samplePaths();
  compare(items, order, subs, null, 'running targeted policy');
  // Its file_contexts is already sorted the way fc_sort.py sorts, except that
  // libsemanage 2.9 (RHEL 8) puts equally specific lines with a file kind first.
  const main = P('file_contexts');
  const typedFirst = !!F.typedFirstIn(main);
  check(F.sortSpecs(main, typedFirst).every((s, i) => s === main[i]), `the installed file_contexts is in fc_sort order already (lines with a file kind ${typedFirst ? 'first, as libsemanage 2.9 sorts' : 'last'} among equals)`);

  // 2. Over LSP, running policy.
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-filelabel-e2e-'));
  fs.writeFileSync(path.join(ws, 'readme.txt'), 'empty workspace\n');
  const a = start(ws);
  await a.init();
  const L = (p, mode) => a.conn.sendRequest('selinux/fileLabel', { path: p, mode });
  const pol = (r, id) => (r.policies || []).find(x => x.id === id) || {};
  const run = `installed:${installed.name}`;
  let r = await L('/usr/bin/rpm');
  check(r.exists && r.mode === 'file' && r.executable && pol(r, run).type === 'rpm_exec_t' && /^rpm-/.test(r.pkg || '') && /rpm_exec_t/.test(r.current || ''),
    `/usr/bin/rpm: ${pol(r, run).context}, now ${r.current}, package ${r.pkg}`, r);
  check(pol(r, run).winner && pol(r, run).winner.file && /file_contexts$/.test(pol(r, run).winner.file.p) && pol(r, run).others.some(o => o.type === 'bin_t'),
    'set by a line of file_contexts; /usr/bin(/.*)? also matches and loses', pol(r, run));
  r = await L('/bin/rpm');
  check(r.lookedUp === '/usr/bin/rpm' && pol(r, run).type === 'rpm_exec_t', `/bin/rpm looked up as ${r.lookedUp}`, r);
  r = await L('/usr/bin/rpmbuild');
  check(!r.exists || pol(r, run).type === 'bin_t', `/usr/bin/rpmbuild: ${pol(r, run).type}`);
  r = await L('/usr/lib64/zz-not-here.so');
  check(!r.exists && r.mode === 'file' && pol(r, run).key === '/usr/lib/zz-not-here.so' && pol(r, run).type === 'lib_t', `a missing file in an equivalent directory: ${pol(r, run).key} → ${pol(r, run).type}`, pol(r, run));
  r = await L('/var/www/html', 'dir');
  check(r.mode === 'dir' && pol(r, run).type === 'httpd_sys_content_t', `kind given: /var/www/html as a directory → ${pol(r, run).type}`);
  r = await L('relative/path');
  check(/absolute path/.test(r.error || ''), 'a relative path is refused');

  let t0 = Date.now();
  let info = await a.conn.sendRequest('selinux/fileTypeInfo', { against: run, type: 'rpm_exec_t' });
  const rpmT = (info.entrypointOf || []).find(d => d.domain === 'rpm_t');
  check(rpmT && rpmT.from.some(f => f.source === 'unconfined_t'), `rpm_exec_t starts rpm_t, from ${rpmT && rpmT.from.slice(0, 6).map(f => f.source).join(', ')} (${Date.now() - t0} ms)`, info.error || info.entrypointOf);
  check(info.access.some(x => x.s === 'rpm_t' && (x.classes.file || []).includes('entrypoint')) && info.attrs.includes('exec_type') && info.traceable === false, 'access rows (rpm_t entrypoint), attributes, no sources for the installed policy');
  info = await a.conn.sendRequest('selinux/fileTypeInfo', { against: run, type: 'shadow_t' });
  check(info.access.some(x => x.s === 'passwd_t' && (x.classes.file || []).includes('write')) && info.entrypointOf.length === 0, `shadow_t: ${info.accessCount} rule groups, passwd_t writes it`);
  info = await a.conn.sendRequest('selinux/fileTypeInfo', { against: run, type: 'var_run_t' });
  check(info.inside.length > 10 && info.inside.some(x => x.name), `var_run_t: ${info.insideCount} type transitions for new objects inside (some named)`);
  info = await a.conn.sendRequest('selinux/fileTypeInfo', { against: run, type: 'httpd_var_run_t' });
  check(info.created.some(x => x.s === 'httpd_t' && x.t === 'var_run_t'), 'httpd_var_run_t: created by httpd_t in var_run_t', info.created.slice(0, 5));
  info = await a.conn.sendRequest('selinux/fileTypeInfo', { against: run, type: 'nope_t' });
  check(/not a type/.test(info.error || ''), 'an unknown type is reported');
  a.proc.kill();

  // 3. A tree build.
  if (!fs.existsSync(path.join(treeDir, 'Rules.modular'))) { console.log(`SKIP tree part: no tree at ${treeDir}`); }
  else {
    const b = start(treeDir, { build: { tree: { makeArgs: CLIP_ARGS } } });
    await b.init();
    t0 = Date.now();
    const res = await b.conn.sendRequest('selinux/build', { uri: URI.file(treeDir).toString() });
    check(res && res.ok, `tree build (${Date.now() - t0} ms)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
    const B = (p, mode) => b.conn.sendRequest('selinux/fileLabel', { path: p, mode });
    r = await B('/usr/bin/rpm');
    const w = pol(r, 'build').winner || {};
    const rpmLine = fs.readFileSync(path.join(treeDir, 'policy/modules/admin/rpm.fc'), 'utf8').split('\n').findIndex(l => /^\/usr\/bin\/rpm\s/.test(l));
    check(pol(r, 'build').type === 'rpm_exec_t' && w.src && /admin\/rpm\.fc$/.test(w.src.p) && w.src.l === rpmLine && w.module === 'rpm',
      `build: /usr/bin/rpm → ${pol(r, 'build').type} from ${w.src && path.basename(w.src.p)}:${w.src && w.src.l + 1} (module ${w.module})`, w);
    r = await B('/usr/bin/rpmbuild', 'file');
    check(pol(r, 'build').type === 'bin_t' && pol(r, 'build').others.some(o => o.type === 'usr_t'), `build: /usr/bin/rpmbuild → ${pol(r, 'build').type} (usr_t loses; the old unsorted lookup said usr_t)`, pol(r, 'build'));
    r = await B('/home/someone/.ssh', 'dir');
    check(pol(r, 'build').type === 'ssh_home_t' && pol(r, 'build').homeAssumed && pol(r, 'build').winner.template, `build: a home template line → ${pol(r, 'build').type}`, pol(r, 'build'));
    // The build's lines sorted as refpolicy's fc_sort.py sorts them.
    const work = res.workDir;
    const pps = fs.readdirSync(work).filter(n => n.endsWith('.pp') && n !== 'base.pp').map(n => n.slice(0, -3));
    const specs = [F.parseSpecs(readIf(path.join(work, 'base.fc'))), ...pps.map(m => F.parseSpecs(readIf(path.join(work, 'tmp', `${m}.mod.fc`))))].flat();
    const [, rest] = F.splitHomeTemplates(specs);
    const tmpIn = path.join(ws, 'fc.in');
    const tmpOut = path.join(ws, 'fc.out');
    fs.writeFileSync(tmpIn, rest.map(s => (s.flag ? `${s.spec} ${s.flag} ${s.context}` : `${s.spec} ${s.context}`)).join('\n') + '\n');
    const py = cp.spawnSync('python3', [path.join(treeDir, 'support', 'fc_sort.py'), tmpIn, tmpOut], { encoding: 'utf8' });
    const theirs = F.parseSpecs(readIf(tmpOut) || '').map(s => `${s.spec}|${s.flag}|${s.context}`);
    const mine = F.sortSpecs(rest).map(s => `${s.spec}|${s.flag}|${s.context}`);
    const firstDiff = mine.findIndex((x, i) => x !== theirs[i]);
    check(py.status === 0 && mine.length === theirs.length && firstDiff === -1, `sorted exactly as fc_sort.py (${mine.length} lines)`, { status: py.status, stderr: py.stderr, at: firstDiff, mine: mine[firstDiff], theirs: theirs[firstDiff] });
    // The file written for matchpathcon (denials, "can it …?") agrees with this module.
    const zz = path.join(work, 'tmp', 'zz_file_contexts');
    const tl = F.lookupOrder(F.sortSpecs(rest, typedFirst), F.sortSpecs(F.splitHomeTemplates(specs)[0], typedFirst));
    check(fs.existsSync(zz), 'sorted file contexts written for matchpathcon');
    compare(items.filter((x, i) => i % 3 === 0), tl, { local: [], dist: F.parseSubs(readIf(path.join(treeDir, 'config', 'file_contexts.subs_dist'))) }, zz, 'CLIP build');
    const can = await b.conn.sendRequest('selinux/loginCan', { against: 'build', user: 'staff_u', starts: [{ role: 'staff_r', type: 'staff_t' }], path: '/usr/bin/rpmbuild', tclass: 'file', perms: ['execute'] });
    check(can.target === 'bin_t', `"can it …?" resolves /usr/bin/rpmbuild to ${can.target} on the build`, can);
    t0 = Date.now();
    info = await b.conn.sendRequest('selinux/fileTypeInfo', { against: 'build', type: 'rpm_exec_t' });
    const d = (info.entrypointOf || []).find(x => x.domain === 'rpm_t');
    check(d && d.from.length > 0 && info.traceable && info.locs.rpm_exec_t && /rpm\.te$/.test(info.locs.rpm_exec_t.p),
      `build: rpm_exec_t starts rpm_t from ${d && d.from.map(f => f.source).join(', ')}; declared in ${info.locs.rpm_exec_t && path.basename(info.locs.rpm_exec_t.p)} (${Date.now() - t0} ms)`, info.error || info.entrypointOf);
    const row = info.access.find(x => x.s === 'rpm_t' && x.t === 'rpm_exec_t');
    const o = row && await b.conn.sendRequest('selinux/ruleOrigins', { rule: { rt: 'allow', s: row.s, t: row.t, c: 'file', perms: row.classes.file } });
    check(o && o.origins.length > 0 && o.origins.some(x => /rpm\.te$/.test(x.path)), `where from: ${o && o.origins.slice(0, 2).map(x => `${path.basename(x.path)}:${x.line + 1} ${x.via || ''}`).join(' | ')}`, o);
    b.proc.kill();
  }
  fs.rmSync(ws, { recursive: true, force: true });
  console.log(failures ? `\n${failures} check(s) failed` : '\nall file label e2e checks passed');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
