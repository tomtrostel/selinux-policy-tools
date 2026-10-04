'use strict';
/*
 * Real-toolchain builds (roadmap layer 2).
 *
 * A module is built with the actual selinux-policy-devel Makefile (m4 +
 * checkmodule) in a private scratch directory, so unsaved editor contents can
 * be compiled and the user's tree never gets a tmp/ directory. Nothing here
 * interprets policy: diagnostics come from the tools' own messages, and the
 * expansion map comes from the m4 output, using the `#line` sync markers that
 * the Makefile's `m4 -s` emits plus refpolicy's `##### begin/end` call markers.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

const MOD_EXT = ['.te', '.if', '.fc'];

function which(cmd) {
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    const p = path.join(dir, cmd);
    try { fs.accessSync(p, fs.constants.X_OK); return p; } catch { /* next */ }
  }
  return null;
}

/**
 * What the build needs, or the reason it can't run (shown to the user).
 * With a Makefile path: standalone-module builds against the devel headers.
 * With `null`: full source-tree builds (the tree brings its own Makefile).
 */
function detectToolchain(develMakefile) {
  if (process.platform === 'win32') return { ok: false, reason: 'Building needs Linux with the SELinux toolchain (use VS Code Remote-SSH to a RHEL/Fedora host).' };
  const tools = develMakefile ? ['make', 'm4', 'checkmodule'] : ['make', 'm4', 'checkmodule', 'semodule_package', 'semodule_link', 'semodule_expand'];
  const missing = tools.filter(c => !which(c));
  if (missing.length) return { ok: false, reason: `Missing build tools: ${missing.join(', ')} (install make, m4, checkpolicy, policycoreutils-devel).` };
  if (develMakefile && !fs.existsSync(develMakefile)) return { ok: false, reason: `${develMakefile} not found (install selinux-policy-devel).` };
  return { ok: true, develMakefile };
}

/*
 * Scratch area: <tmp>/selinux-policy-tools-<uid>/<server pid>/. Per user
 * (tmp is shared; the directory is private), per language server so two
 * VS Code windows on the same tree never share build directories, and
 * removed as a whole when the server exits (see cleanupScratch). Areas left
 * by servers that died without cleaning up are swept at startup.
 */
const SCRATCH_BASE = path.join(os.tmpdir(), `selinux-policy-tools-${typeof process.getuid === 'function' ? process.getuid() : 'user'}`);
const SCRATCH = path.join(SCRATCH_BASE, String(process.pid));

const scratchDir = (kind, key) => path.join(SCRATCH,
  (kind ? kind + '-' : '') + crypto.createHash('sha1').update(key).digest('hex').slice(0, 12));

/** Remove scratch areas of servers that are no longer running. */
function sweepStaleScratch() {
  let names = [];
  try { fs.mkdirSync(SCRATCH_BASE, { recursive: true, mode: 0o700 }); names = fs.readdirSync(SCRATCH_BASE); } catch { return 0; }
  let removed = 0;
  for (const n of names) {
    if (!/^\d+$/.test(n) || +n === process.pid) continue;
    let alive = true;
    try { process.kill(+n, 0); } catch (e) { alive = e.code === 'EPERM'; }
    if (!alive) { fs.rmSync(path.join(SCRATCH_BASE, n), { recursive: true, force: true }); removed++; }
  }
  // The shared directory of versions before per-server areas: remove it once
  // it's empty (rmdir refuses otherwise, so an older running server is safe).
  try { fs.rmdirSync(path.join(os.tmpdir(), 'selinux-policy-tools')); } catch { /* in use, absent, or not ours */ }
  return removed;
}

/** Remove this server's whole scratch area (on exit). */
function cleanupScratch() { try { fs.rmSync(SCRATCH, { recursive: true, force: true }); } catch { /* best effort */ } }

const run = (args, cwd, timeoutMs) => new Promise((resolve) => {
  execFile('make', args, { cwd, timeout: timeoutMs, maxBuffer: 64 << 20 },
    (err, stdout, stderr) => resolve({ code: err ? (err.code || 1) : 0, killed: !!(err && err.killed), out: stdout + stderr }));
});

/**
 * Build the module whose .te is `tePath`.
 * `readText(p)` returns the current contents of a source file (editor buffer
 * or disk), or null if it doesn't exist. With `pkg`, the module package is
 * built too and <mod>.pp is copied next to the .te (what `make <mod>.pp` does).
 */
async function buildModule(tePath, readText, { develMakefile, pkg = false, timeoutMs = 60000 } = {}) {
  const t0 = Date.now();
  const modDir = path.dirname(tePath);
  const mod = path.basename(tePath, '.te');
  const work = scratchDir('', modDir);
  fs.rmSync(work, { recursive: true, force: true });
  fs.mkdirSync(work, { recursive: true });

  // The Makefile puts every *.if next to a *.te into all_interfaces.conf, so
  // sibling modules' interfaces are callable. Copy the whole module directory.
  const fileMap = new Map(); // scratch-relative name -> real path
  let names = [];
  try { names = fs.readdirSync(modDir); } catch { /* new dir */ }
  for (const n of new Set([...names, ...MOD_EXT.map(e => mod + e)])) {
    if (!MOD_EXT.includes(path.extname(n))) continue;
    const real = path.join(modDir, n);
    const text = readText(real);
    if (text == null) continue;
    fs.writeFileSync(path.join(work, n), text);
    fileMap.set(n, real);
  }

  // The Makefile creates a missing .fc/.if itself; a .pp always needs both.
  const targets = pkg ? [`${mod}.pp`] : [`tmp/${mod}.mod`, ...(fileMap.has(mod + '.fc') ? [`tmp/${mod}.mod.fc`] : [])];
  const result = await run(['-f', develMakefile, 'QUIET=n', ...targets], work, timeoutMs);

  const resolveFile = (f) => {
    if (fileMap.has(f)) return fileMap.get(f);
    if (path.isAbsolute(f)) return f;
    return null; // tmp/all_interfaces.conf etc.: no editable source
  };
  const diagnostics = parseBuildOutput(result.out).map(d => ({ ...d, path: resolveFile(d.file) })).filter(d => d.path || d.severity === 'error');

  const expandedPath = path.join(work, 'tmp', mod + '.tmp');
  let expansion = null;
  try { expansion = parseExpansion(fs.readFileSync(expandedPath, 'utf8'), resolveFile); } catch { /* m4 failed */ }

  let pkgPath = null;
  if (pkg && result.code === 0) {
    pkgPath = path.join(modDir, mod + '.pp');
    fs.copyFileSync(path.join(work, mod + '.pp'), pkgPath);
  }

  return {
    ok: result.code === 0, timedOut: result.killed, module: mod, tePath, workDir: work,
    ms: Date.now() - t0, log: result.out, diagnostics, expansion, expandedPath, resolveFile, pkgPath,
  };
}

/* ---------- m4 build flags (for deciding ifdef/ifndef branches) ---------- */

/**
 * The -D flags the build passes to m4, asked from the Makefile itself
 * (`make --eval` prints the expanded M4PARAM; no recipe runs).
 * Returns { defined: Set, universe: Set, patterns: [RegExp], flags: string }:
 * `universe` are the symbols the Makefile can pass at all (so their absence
 * means "not defined"); flags it only passes for some steps (Rules.* add
 * self_contained_policy, users_extra) are left out, so they stay undecided.
 */
function m4Defines({ cwd, makefile, makeArgs = [], timeoutMs = 20000 }) {
  return new Promise((resolve) => {
    const args = ['-s', '--no-print-directory', ...(makefile ? ['-f', makefile] : []), ...makeArgs,
      '--eval', 'selinux-print-m4param: ; @echo $(M4PARAM)', 'selinux-print-m4param'];
    execFile('make', args, { cwd, timeout: timeoutMs }, (err, stdout) => {
      if (err) { resolve(null); return; }
      const flags = stdout.trim().split('\n').pop();
      const defined = new Set([...flags.matchAll(/-D\s*(\w+)/g)].map(m => m[1]));
      const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } };
      const mk = makefile ? read(makefile) + read(path.join(path.dirname(makefile), 'include', 'Makefile')) : read(path.join(cwd, 'Makefile'));
      const stepOnly = new Set([...(read(path.join(cwd, 'Rules.modular')) + read(path.join(cwd, 'Rules.monolithic'))).matchAll(/-D\s*(\w+)/g)].map(m => m[1]));
      const universe = new Set([...mk.matchAll(/-D\s*(\w+)/g)].map(m => m[1]).filter(s => !stepOnly.has(s)));
      for (const s of defined) if (!stepOnly.has(s)) universe.add(s);
      // `-D distro_$(DISTRO)`: any distro_* symbol is a build flag.
      const patterns = /-D\s*distro_\$\(DISTRO\)/.test(mk) ? [/^distro_\w+$/] : [];
      resolve({ defined, universe, patterns, flags });
    });
  });
}

/* ---------- git: the tree as of HEAD (baseline for "what did this change") ---------- */

const git = (cwd, args) => new Promise((resolve) => {
  execFile('git', args, { cwd, maxBuffer: 16 << 20 }, (err, stdout) => resolve(err ? null : stdout.trim()));
});

/** { top, prefix, sha, subject } for the git repository containing `root`, or null. */
async function gitInfo(root, ref = 'HEAD') {
  const top = await git(root, ['rev-parse', '--show-toplevel']);
  if (!top) return null;
  const sha = await git(root, ['rev-parse', '--verify', '--quiet', `${ref}^{commit}`]);
  if (!sha) return null; // no commits yet, or not a commit
  const [prefix, head] = await Promise.all([git(root, ['rev-parse', '--show-prefix']), git(root, ['log', '-1', '--format=%s%x00%cr', sha])]);
  const [subject, when] = (head || '').split('\0');
  return { top, prefix: (prefix || '').replace(/\/$/, ''), sha, subject, when, ref };
}

/**
 * Tree files that differ between commit `from` and `to` (a commit, or null
 * for the working tree, untracked files included). Absolute paths.
 */
async function gitChangedFiles(root, info, from = info.sha, to = null) {
  const scope = ['--', info.prefix || '.'];
  const diff = await git(info.top, ['diff', '--name-only', from, ...(to ? [to] : []), ...scope]);
  const out = (diff || '').split('\n').filter(Boolean);
  if (!to) {
    const untracked = await git(info.top, ['ls-files', '--others', '--exclude-standard', ...scope]);
    out.push(...(untracked || '').split('\n').filter(Boolean));
  }
  return out.map(f => path.join(info.top, f));
}

/** Branches, tags (newest first) and recent commits, for picking a comparison base. */
async function gitRefs(root, max = 20) {
  const fmt = '--format=%(refname:short)%00%(objectname:short)%00%(creatordate:relative)%00%(subject)';
  const [heads, tags, log] = await Promise.all([
    git(root, ['for-each-ref', '--sort=-committerdate', fmt, 'refs/heads', 'refs/remotes']),
    git(root, ['for-each-ref', '--sort=-creatordate', fmt, 'refs/tags']),
    git(root, ['log', `-${max}`, '--format=%h%x00%h%x00%cr%x00%s']),
  ]);
  const parse = (s) => (s || '').split('\n').filter(Boolean).map(l => { const [name, short, when, subject] = l.split('\0'); return { name, short, when, subject }; });
  return { branches: parse(heads).filter(b => !/\/HEAD$/.test(b.name)).slice(0, max), tags: parse(tags).slice(0, max), commits: parse(log) };
}

/** Export the tree at HEAD into `dest` (git archive | tar); returns the tree root inside it. */
function exportHead(info, dest) {
  return new Promise((resolve, reject) => {
    fs.rmSync(dest, { recursive: true, force: true });
    fs.mkdirSync(dest, { recursive: true });
    const archive = require('child_process').spawn('git', ['archive', info.sha, ...(info.prefix ? ['--', info.prefix] : [])], { cwd: info.top });
    const tar = require('child_process').spawn('tar', ['-x', '-C', dest]);
    archive.stdout.pipe(tar.stdin);
    let err = '';
    archive.stderr.on('data', d => { err += d; });
    tar.on('close', (code) => (code === 0 ? resolve(path.join(dest, info.prefix)) : reject(new Error(`git archive failed: ${err.trim() || code}`))));
  });
}

/**
 * Build the kernel policy the way an installed system does: load every module
 * package of a (modular) tree build into a scratch policy store with semodule
 * (CIL), like the RPM's `make load SEMODULE="semodule -p <buildroot> -X 100"`
 * but with all packages the build produced (APPS_MODS ones included). Works
 * unprivileged. Uses the host's semanage.conf so store options (e.g.
 * optimize-policy) match the installed policy.
 */
async function cilBuild(res, { name, timeoutMs = 900000 } = {}) {
  const t0 = Date.now();
  const work = res.workDir;
  let pkgs = [];
  try { pkgs = fs.readdirSync(work).filter(n => n.endsWith('.pp')); } catch { /* none */ }
  if (!pkgs.includes('base.pp')) return { ok: false, log: 'No base.pp: a modular build is needed (MONOLITHIC=n).', ms: Date.now() - t0 };
  const root = path.join(work, 'cil-root');
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(path.join(root, 'var', 'lib', 'selinux'), { recursive: true });
  fs.mkdirSync(path.join(root, 'etc', 'selinux'), { recursive: true });
  try { fs.copyFileSync('/etc/selinux/semanage.conf', path.join(root, 'etc', 'selinux', 'semanage.conf')); } catch { /* defaults */ }
  const args = ['-p', root, '-X', '100', '-s', name, '-i', 'base.pp', ...pkgs.filter(n => n !== 'base.pp').sort().flatMap(n => ['-i', n])];
  const r = await new Promise((resolve) => {
    execFile('semodule', args, { cwd: work, timeout: timeoutMs, maxBuffer: 16 << 20 },
      (err, stdout, stderr) => resolve({ code: err ? (err.code || 1) : 0, out: `${stdout}${stderr}` }));
  });
  if (r.code === 'ENOENT') return { ok: false, log: 'semodule not found: install policycoreutils.', ms: Date.now() - t0 };
  // Ownership warnings are expected when not running as root.
  const log = r.out.split('\n').filter(l => l && !/Could not set ownership/.test(l)).join('\n');
  const polDir = path.join(root, 'etc', 'selinux', name, 'policy');
  let policy = null;
  try { const f = fs.readdirSync(polDir).filter(n => /^policy\.\d+$/.test(n)).sort().pop(); if (f) policy = path.join(polDir, f); } catch { /* failed */ }
  return { ok: r.code === 0 && !!policy, policy, root, log, packages: pkgs.length, ms: Date.now() - t0 };
}

/** Installed policies on this host: [{ name, policy }] from /etc/selinux/<name>/policy/policy.NN. */
function installedPolicies() {
  const out = [];
  let names = [];
  try { names = fs.readdirSync('/etc/selinux'); } catch { return out; }
  for (const n of names) {
    const dir = path.join('/etc/selinux', n, 'policy');
    try {
      const f = fs.readdirSync(dir).filter(x => /^policy\.\d+$/.test(x)).sort().pop();
      if (f) out.push({ name: n, policy: path.join(dir, f) });
    } catch { /* not a policy dir */ }
  }
  let active = null;
  try { const m = /^\s*SELINUXTYPE\s*=\s*(\S+)/m.exec(fs.readFileSync('/etc/selinux/config', 'utf8')); if (m) active = m[1]; } catch { /* none */ }
  return out.map(x => ({ ...x, active: x.name === active }));
}

/* ---------- standalone modules linked with the installed policy ---------- */

/*
 * A standalone module isn't linked into a policy, so there is nothing to run
 * property checks against. The installed kernel policy is world-readable
 * (the module store under /var/lib/selinux is not): decompile it to CIL
 * (checkpolicy -b -C), convert the module to CIL (hll/pp) and compile both
 * into a throwaway store with `semodule -p`, unprivileged. The result is
 * "this host's policy plus the module as it is now".
 *
 * Kernel policies drop what only the module linker needs: the
 * cil_gen_require attributes and small attributes expanded into their member
 * types. A shim declares those so the module's requirements resolve (an
 * expanded attribute loses its old members; rules written for it already
 * name the types). If the module is installed already, the kernel policy has
 * its old declarations: the module's own are dropped and its old rules stay.
 */

const execP = (cmd, args, opts = {}) => new Promise((resolve) => {
  execFile(cmd, args, { maxBuffer: 64 << 20, timeout: 600000, ...opts }, (err, stdout, stderr) => resolve({ code: err ? (err.code || 1) : 0, out: `${stdout}${stderr}` }));
});

/** The active installed kernel policy: { name, path } of /etc/selinux/<SELINUXTYPE>/policy/policy.N, or null. */
function installedKernelPolicy() {
  const all = installedPolicies();
  const p = all.find(x => x.active) || all[0];
  return p ? { name: p.name, path: p.policy } : null;
}

const CIL_DECL_RE = /^\((type|typeattribute|typealias|role|roleattribute|boolean) ([^\s()]+)/gm;
let installedBase = null; // { key, cil, names: Set }

async function installedBaseCil(kernelPolicy) {
  const st = fs.statSync(kernelPolicy);
  const key = `${kernelPolicy}:${st.mtimeMs}`;
  if (installedBase && installedBase.key === key && fs.existsSync(installedBase.cil)) return installedBase;
  const dir = scratchDir('installed', kernelPolicy);
  fs.mkdirSync(dir, { recursive: true });
  const cil = path.join(dir, 'base.cil');
  const r = await execP('checkpolicy', ['-b', '-C', '-M', kernelPolicy, '-o', cil]);
  if (r.code !== 0) throw new Error(`checkpolicy could not decompile ${kernelPolicy}: ${r.out.trim().split('\n').pop()}`);
  const names = new Set();
  for (const m of fs.readFileSync(cil, 'utf8').matchAll(CIL_DECL_RE)) names.add(m[2]);
  installedBase = { key, cil, names };
  return installedBase;
}

/**
 * Link a module build (tmp/<mod>.mod) with the installed policy.
 * isAttribute(name) tells, from the sources, whether a required name is an
 * attribute (may have been expanded away) or a type (must exist).
 * Returns { ok, policy, kernelPolicy, installed, missing, log, ms }.
 */
async function linkWithInstalled(res, { isAttribute = () => false, kernelPolicy = null } = {}) {
  const t0 = Date.now();
  const done = (x) => ({ ms: Date.now() - t0, missing: [], installed: false, ...x });
  const kp = kernelPolicy ? { path: kernelPolicy } : installedKernelPolicy();
  if (!kp) return done({ ok: false, log: 'No installed policy found under /etc/selinux.' });
  const work = path.join(res.workDir, 'linked');
  fs.rmSync(work, { recursive: true, force: true });
  fs.mkdirSync(work, { recursive: true });
  const modFile = path.join(res.workDir, 'tmp', `${res.module}.mod`);
  if (!fs.existsSync(modFile)) return done({ ok: false, log: `${modFile} is missing: build the module first.` });
  let base;
  try { base = await installedBaseCil(kp.path); } catch (e) { return done({ ok: false, log: e.message }); }
  const pp = path.join(work, `${res.module}.pp`);
  let r = await execP('semodule_package', ['-o', pp, '-m', modFile]);
  if (r.code !== 0) return done({ ok: false, log: `semodule_package failed: ${r.out.trim()}` });
  r = await execP('/usr/libexec/selinux/hll/pp', [pp, path.join(work, `${res.module}.cil`)]);
  if (r.code !== 0) return done({ ok: false, log: `Converting the module to CIL failed (/usr/libexec/selinux/hll/pp): ${r.out.trim()}` });

  // Drop declarations the installed policy already has (an installed copy of this module).
  const modCilPath = path.join(work, `${res.module}.cil`);
  const lines = fs.readFileSync(modCilPath, 'utf8').split('\n');
  let installed = false;
  const kept = lines.filter((l) => {
    const m = /^\((type|typeattribute|typealias|role|roleattribute|boolean) ([^\s()]+)/.exec(l);
    if (m && base.names.has(m[2])) { installed = true; return false; }
    return true;
  });
  fs.writeFileSync(modCilPath, kept.join('\n'));
  const own = new Set(kept.map(l => (/^\((?:type|typeattribute|typealias|role|roleattribute|boolean) ([^\s()]+)/.exec(l) || [])[1]).filter(Boolean));

  // Requirements the kernel policy no longer has.
  const shim = ['(typeattribute cil_gen_require)', '(roleattribute cil_gen_require)'];
  const missing = [];
  for (const l of kept) {
    const m = /^\((type|role)attributeset cil_gen_require ([^\s()]+)\)/.exec(l);
    if (!m || base.names.has(m[2]) || own.has(m[2])) continue;
    if (m[1] === 'role' || isAttribute(m[2])) shim.push(`(${m[1]}attribute ${m[2]})`);
    else missing.push(m[2]);
  }
  if (missing.length) {
    return done({ ok: false, missing, installed, log: `The installed policy has no ${missing.length > 1 ? 'types' : 'type'} ${missing.join(', ')}, which the module requires (is the module that declares ${missing.length > 1 ? 'them' : 'it'} installed?).` });
  }
  const shimName = `${res.module}_shim_`;
  fs.writeFileSync(path.join(work, `${shimName}.cil`), [...new Set(shim)].join('\n') + '\n');

  const root = path.join(work, 'root');
  fs.mkdirSync(path.join(root, 'var', 'lib', 'selinux'), { recursive: true });
  fs.mkdirSync(path.join(root, 'etc', 'selinux'), { recursive: true });
  try { fs.copyFileSync('/etc/selinux/semanage.conf', path.join(root, 'etc', 'selinux', 'semanage.conf')); } catch { /* defaults */ }
  // The base goes in from the cache (semodule copies it into the store).
  r = await execP('semodule', ['-p', root, '-X', '100', '-s', 'linked', '-i', base.cil, '-i', `${shimName}.cil`, '-i', `${res.module}.cil`], { cwd: work });
  if (r.code === 'ENOENT') return done({ ok: false, installed, log: 'semodule not found: install policycoreutils.' });
  const log = r.out.split('\n').filter(l => l && !/Could not set ownership/.test(l)).join('\n');
  const polDir = path.join(root, 'etc', 'selinux', 'linked', 'policy');
  let policy = null;
  try { const f = fs.readdirSync(polDir).filter(n => /^policy\.\d+$/.test(n)).sort().pop(); if (f) policy = path.join(polDir, f); } catch { /* failed */ }
  // The store's copies are no longer needed; the policy file is.
  try { fs.rmSync(path.join(root, 'var'), { recursive: true, force: true }); } catch { /* best effort */ }
  return done({ ok: r.code === 0 && !!policy, policy, kernelPolicy: kp.path, installed, log });
}

/** The m4 output files of a tree build (for explaining its rules). */
function treeOutputs(res) {
  const tmp = path.join(res.workDir, 'tmp');
  let mods = [];
  try { mods = fs.readdirSync(tmp).filter(n => n.endsWith('.tmp')).map(n => path.join(tmp, n)); } catch { /* none */ }
  return [...mods, path.join(res.workDir, res.monolithic ? 'policy.conf' : 'base.conf')];
}

/* ---------- full source trees (refpolicy Makefile) ---------- */

/** The refpolicy tree root for an indexed support file path, or null. */
function treeRootOf(p) {
  const m = /^(.*)[\\/]policy[\\/]support[\\/]obj_perm_sets\.spt$/.exec(p);
  if (!m) return null;
  const root = m[1];
  return ['Makefile', 'Rules.modular', 'build.conf'].every(f => fs.existsSync(path.join(root, f))) ? root : null;
}

// Not copied to the scratch tree: VCS/editor dirs, build outputs (the same
// list refpolicy's .gitignore has), and directories the build never reads.
const TREE_SKIP_DIRS = new Set(['tmp', 'man', 'testing', 'doc/html', 'doc/tmp']);
const TREE_GENERATED = [/^[^/]+\.pp$/, /^base\.(conf|fc)$/, /^policy\.conf$/, /^policy\.\d+$/, /^file_contexts$/,
  /^doc\/(policy|global_booleans|global_tunables)\.xml$/, /\.py[co]$/];

/** Root-relative paths of the tree's source files. */
function treeSources(root) {
  const out = [];
  const walk = (rel) => {
    let ents;
    try { ents = fs.readdirSync(path.join(root, rel), { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (e.name.startsWith('.')) continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { if (!TREE_SKIP_DIRS.has(r)) walk(r); continue; }
      if (!e.isFile() || TREE_GENERATED.some(re => re.test(r))) continue;
      // corenetwork.te/.if are generated from their .in files by the build.
      if (/corenetwork\.(te|if)$/.test(r) && fs.existsSync(path.join(root, r + '.in'))) continue;
      out.push(r);
    }
  };
  walk('');
  return out;
}

/**
 * Make the scratch copy match the tree (editor buffers win over disk).
 * Only files whose content differs are rewritten, so make's incremental
 * rebuild sees exactly what changed.
 */
function syncTree(root, work, readText, overlays = new Map()) {
  const want = new Set();
  let written = 0;
  for (const rel of new Set([...treeSources(root), ...overlays.keys()])) {
    want.add(rel);
    const src = path.join(root, rel), dst = path.join(work, rel);
    const t = overlays.has(rel) ? overlays.get(rel) : readText(src, true);
    if (t == null) continue;
    const buf = Buffer.isBuffer(t) ? t : Buffer.from(t);
    let cur = null;
    try { cur = fs.readFileSync(dst); } catch { /* new */ }
    if (cur && cur.equals(buf)) continue;
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.writeFileSync(dst, buf);
    written++;
  }
  // Drop files deleted from the tree (build outputs are left alone).
  for (const rel of treeSources(work)) if (!want.has(rel)) { fs.rmSync(path.join(work, rel), { force: true }); written++; }
  return written;
}

/**
 * refpolicy's Makefile doesn't notice when the set of enabled modules changes
 * (modules.conf, APPS_MODS, NAME/TYPE): tmp/all_mods.fc keeps contexts of
 * modules no longer built (validate then fails on "type X is not defined"),
 * and packages of dropped modules stay behind. When the set changes, remove
 * the outputs that depend on it; per-module compiles (tmp/<mod>.mod) stay.
 */
function forgetStaleModuleSet(work, makeArgs) {
  let conf = '';
  try { conf = fs.readFileSync(path.join(work, 'policy', 'modules.conf'), 'utf8'); } catch { /* none */ }
  const key = crypto.createHash('sha1').update(conf).update(JSON.stringify(makeArgs.filter(a => /^(APPS_MODS|NAME|TYPE|MONOLITHIC)=/.test(a)))).digest('hex');
  const stamp = path.join(work, 'tmp', '.module-set');
  let prev = null;
  try { prev = fs.readFileSync(stamp, 'utf8'); } catch { /* first build */ }
  if (prev === key) return;
  if (prev !== null) {
    for (const n of fs.readdirSync(work)) if (/\.pp$/.test(n) || /^base\.(conf|fc)$/.test(n) || /^policy\.(conf|\d+)$/.test(n)) fs.rmSync(path.join(work, n), { force: true });
    for (const n of ['all_mods.fc', 'test.lnk', 'policy.bin', 'base.mod', 'base.mod.fc']) fs.rmSync(path.join(work, 'tmp', n), { force: true });
  }
  fs.mkdirSync(path.join(work, 'tmp'), { recursive: true });
  fs.writeFileSync(stamp, key);
}

function treeOption(root, makeArgs, name) {
  for (const a of makeArgs) { const m = new RegExp(`^${name}=(.*)$`).exec(a); if (m) return m[1].trim(); }
  try {
    const m = new RegExp(`^\\s*${name}\\s*=\\s*(\\S*)`, 'm').exec(fs.readFileSync(path.join(root, 'build.conf'), 'utf8'));
    return m ? m[1] : null;
  } catch { return null; }
}

/**
 * Build a whole refpolicy source tree with its own Makefile in a persistent
 * scratch copy. `makeArgs` are extra make variables (e.g. the NAME/TYPE/
 * APPS_MODS an RPM spec passes); `targets` default to a modular build plus
 * link validation, or `policy` for MONOLITHIC=y trees.
 */
async function buildTree(root, readText, { makeArgs = [], targets, files = {}, jobs = os.cpus().length, timeoutMs = 600000, sync = true, variant = '' } = {}) {
  const t0 = Date.now();
  // `variant` builds the same tree in a separate scratch copy (e.g. a module preview).
  const work = scratchDir('tree', variant ? `${root}#${variant}` : root);
  fs.mkdirSync(work, { recursive: true });
  // selinux.build.tree.files: tree-relative path -> source file(s), concatenated,
  // replacing (or adding) that file in the scratch copy only.
  const overlays = new Map(), missing = [];
  for (const [rel, srcs] of Object.entries(files || {})) {
    const parts = [];
    for (const s of [].concat(srcs)) { try { parts.push(fs.readFileSync(s)); } catch { missing.push(s); } }
    overlays.set(rel.replace(/\\/g, '/').replace(/^\/+/, ''), Buffer.concat(parts));
  }
  if (missing.length) {
    // Sync anyway (make doesn't run), so the error is attached to current file contents.
    if (sync) syncTree(root, work, readText, overlays);
    const msgs = missing.map(m => `selinux.build.tree.files: ${m} not found`);
    return { ok: false, tree: true, module: path.basename(root), root, workDir: work, ms: Date.now() - t0, synced: 0, log: msgs.join('\n'),
      diagnostics: msgs.map(msg => ({ file: null, l: 0, severity: 'error', tool: 'settings', msg })),
      resolveFile: () => null, monolithic: false, policyBin: null, packages: 0 };
  }
  const synced = sync ? syncTree(root, work, readText, overlays) : 0;
  if (sync) forgetStaleModuleSet(work, makeArgs);
  const monolithic = (treeOption(root, makeArgs, 'MONOLITHIC') || 'n').toLowerCase() === 'y';
  if (!targets || !targets.length) targets = monolithic ? ['policy'] : ['base.pp', 'modules', 'validate'];
  const result = await run([`-j${jobs}`, ...makeArgs, ...targets], work, timeoutMs);

  const resolveFile = (f) => {
    if (path.isAbsolute(f)) f = path.relative(work, f);
    if (f.startsWith('..') || /^tmp[\\/]/.test(f)) return null;
    // Generated files (corenetwork.te from .te.in) have no editable source with matching lines.
    const real = path.join(root, f);
    return fs.existsSync(real) ? real : null;
  };
  const diagnostics = parseBuildOutput(result.out).map(d => ({ ...d, path: d.file ? resolveFile(d.file) : null }));
  const policyBin = [path.join(work, 'tmp', 'policy.bin'), ...fs.readdirSync(work).filter(n => /^policy\.\d+$/.test(n)).map(n => path.join(work, n))]
    .find(p => fs.existsSync(p)) || null;
  return {
    ok: result.code === 0, timedOut: result.killed, tree: true, module: path.basename(root), root, workDir: work,
    ms: Date.now() - t0, synced, log: result.out, diagnostics, resolveFile, monolithic, policyBin,
    packages: monolithic ? 0 : fs.readdirSync(work).filter(n => n.endsWith('.pp')).length,
  };
}

/**
 * Copy a successful tree build's installable outputs (module packages, the
 * kernel policy, file contexts) to `outDir`, with a build-info.json record.
 * Files from the previous export that this build didn't produce (e.g. a
 * module since turned off) are removed, so the directory is one build.
 */
function exportTreeOutputs(res, outDir, makeArgs) {
  const work = res.workDir;
  const pick = [];
  for (const n of fs.readdirSync(work)) if (/\.pp$/.test(n) || /^policy\.\d+$/.test(n) || n === 'file_contexts') pick.push([path.join(work, n), n]);
  if (fs.existsSync(path.join(work, 'tmp', 'policy.bin'))) pick.push([path.join(work, 'tmp', 'policy.bin'), 'policy.bin']);
  fs.mkdirSync(outDir, { recursive: true });
  const infoPath = path.join(outDir, 'build-info.json');
  let previous = [];
  try { previous = JSON.parse(fs.readFileSync(infoPath, 'utf8')).files || []; } catch { /* first export */ }
  const files = pick.map(([, n]) => n).sort();
  for (const n of previous) if (!files.includes(n) && path.basename(n) === n) fs.rmSync(path.join(outDir, n), { force: true });
  for (const [from, n] of pick) fs.copyFileSync(from, path.join(outDir, n));
  fs.writeFileSync(infoPath, JSON.stringify({ builtAt: new Date().toISOString(), tree: res.root, makeArgs, validated: !!res.validated, files }, null, 2) + '\n');
  return { dir: outDir, files };
}

/** What the last tree build compiled for a source file (its scratch copy), or null. */
function treeBuiltText(res, realPath) {
  const rel = path.relative(res.root, realPath);
  if (rel.startsWith('..')) return null;
  try { return fs.readFileSync(path.join(res.workDir, rel), 'utf8'); } catch { return null; }
}

/** The m4 output (with #line markers) that covers a tree source file. */
function treeOutputFor(res, realPath) {
  const mod = path.basename(realPath).replace(/\.te(\.in)?$/, '');
  const candidates = [path.join(res.workDir, 'tmp', mod + '.tmp'), path.join(res.workDir, res.monolithic ? 'policy.conf' : 'base.conf')];
  return candidates.find(p => fs.existsSync(p)) || null;
}

const expansionCache = new Map(); // output path -> { mtimeMs, expansion }
/** Expansion map for one tree source file, parsed lazily from the build output. */
function treeExpansion(res, realPath) {
  const out = treeOutputFor(res, realPath);
  if (!out) return null;
  const mtimeMs = fs.statSync(out).mtimeMs;
  let c = expansionCache.get(out);
  if (!c || c.mtimeMs !== mtimeMs) {
    c = { mtimeMs, expansion: parseExpansion(fs.readFileSync(out, 'utf8'), res.resolveFile) };
    expansionCache.set(out, c);
  }
  return c.expansion;
}

/**
 * Readable view of the module's m4 output: only the part produced by the
 * module's own sources, each group headed by the source line it came from.
 */
function renderExpanded(text, resolveFile, readText, onlyPath) {
  const out = [];
  const srcLines = new Map();
  const srcLine = (p, l) => {
    if (!srcLines.has(p)) srcLines.set(p, (readText(p) || '').split('\n'));
    return (srcLines.get(p)[l - 1] || '').trim();
  };
  let file = null, real = null, next = 0;
  let group = null; // { key, real, line, lines }
  const flush = () => {
    if (!group) return;
    const src = srcLine(group.real, group.line);
    // A plain statement passes through m4 unchanged; only expansions get a header.
    if (group.lines.length === 1 && group.lines[0].trim() === src) { out.push(group.lines[0]); group = null; return; }
    // policy_module() requires every class, sensitivity and MCS category; collapse long runs.
    const lines = [];
    const kw = (s) => { const m = /^\s*(class|category|sensitivity)\b/.exec(s); return m && m[1]; };
    for (let i = 0; i < group.lines.length;) {
      const k = kw(group.lines[i]);
      let j = i;
      while (k && j < group.lines.length && kw(group.lines[j]) === k) j++;
      if (j - i > 10) { lines.push(`  # … ${j - i} ${k} declarations omitted`); i = j; }
      else lines.push(group.lines[i++]);
    }
    out.push('', `# ──── ${path.basename(group.real)}:${group.line}: ${src}`, ...lines, '');
    group = null;
  };
  for (const raw of text.split('\n')) {
    const d = /^#line (\d+)(?: "(.*)")?$/.exec(raw);
    if (d) {
      if (d[2] !== undefined) { file = d[2]; real = resolveFile(file); }
      next = +d[1];
      continue;
    }
    const line = next++;
    if (!real || !raw.trim() || (onlyPath && real !== onlyPath)) continue;
    const key = `${file}:${line}`;
    if (!group || group.key !== key) { flush(); group = { key, real, line, lines: [] }; }
    group.lines.push(raw.replace(/^\t+/, m => '  '.repeat(m.length)));
  }
  flush();
  return out.join('\n').replace(/\n{3,}/g, '\n\n').trim() + '\n';
}

/* ---------- tool output ---------- */

const CHECKMODULE_RE = /^(.+?):(\d+):(ERROR|WARNING) '(.*)' at token '(.*)' on line \d+:/;
const M4_RE = /^m4:(.+?):(\d+): (?:(ERROR|Warning): )?(.*)$/;
const REFPOLICY_RE = /^(.+?):(\d+): (Warning|Error): (.*)$/;

// semodule_link: a module requires something no enabled module provides.
const LINK_RE = /^libsepol\.print_missing_requirements: (\S+)'s global requirements were not met: (\S+) (\S+)/;

function parseBuildOutput(out) {
  const res = [];
  for (const line of out.split('\n')) {
    let m;
    if ((m = LINK_RE.exec(line))) {
      // No line number: the server places it where the module names the requirement.
      res.push({ file: null, l: 0, severity: 'error', tool: 'semodule_link', linkModule: m[1], token: m[3],
        msg: `Link failed: ${m[1]} requires ${m[2]} ${m[3]}, which no enabled module provides (is its module turned off in modules.conf?)` });
    } else if ((m = CHECKMODULE_RE.exec(line))) {
      let msg = m[4];
      const token = m[5];
      // An interface name m4 didn't know is left unexpanded and reaches checkmodule as a syntax error.
      if (msg === 'syntax error' && /^[A-Za-z_]\w*$/.test(token)) msg = `syntax error at '${token}' (if this is an interface call, it is not defined in the headers or this directory)`;
      res.push({ file: m[1], l: +m[2] - 1, severity: m[3] === 'ERROR' ? 'error' : 'warning', msg, token, tool: 'checkmodule' });
    } else if ((m = M4_RE.exec(line))) {
      res.push({ file: m[1], l: +m[2] - 1, severity: m[3] === 'Warning' ? 'warning' : 'error', msg: m[4], tool: 'm4' });
    } else if ((m = REFPOLICY_RE.exec(line)) && !line.startsWith('make')) {
      res.push({ file: m[1], l: +m[2] - 1, severity: m[3] === 'Warning' ? 'warning' : 'error', msg: m[4], tool: 'refpolicy' });
    }
  }
  return res;
}

/**
 * Map m4 output back to source lines. `m4 -s` emits `#line N "file"` (file only
 * when it changes); undirected output lines continue from the last marker.
 * Returns Map<realPath, Map<line0, [{text, depth, via}]>> for editable sources.
 */
function parseExpansion(text, resolveFile) {
  const out = new Map();
  let file = null, real = null, next = 0;
  const stack = []; // open "##### begin name(args)" markers
  for (const raw of text.split('\n')) {
    const d = /^#line (\d+)(?: "(.*)")?$/.exec(raw);
    if (d) {
      if (d[2] !== undefined) { file = d[2]; real = resolveFile(file); }
      next = +d[1];
      continue;
    }
    const line = next++;
    if (raw.startsWith('##### begin ')) { stack.push(raw.slice(12, raw.lastIndexOf(' depth:'))); continue; }
    if (/^##### end /.test(raw)) { stack.pop(); continue; }
    if (!real) continue;
    const t = raw.trim();
    if (!t || t.startsWith('#')) continue;
    let byLine = out.get(real);
    if (!byLine) out.set(real, byLine = new Map());
    let a = byLine.get(line - 1);
    if (!a) byLine.set(line - 1, a = []);
    a.push({ text: t, depth: stack.length, via: stack[stack.length - 1] || null });
  }
  return out;
}

/** Policy statements from one source line, without require blocks. */
function rulesAt(expansion, realPath, line0) {
  const a = expansion && expansion.get(realPath) && expansion.get(realPath).get(line0);
  if (!a) return [];
  const rules = [];
  let inReq = 0;
  for (const e of a) {
    if (/^(require|gen_require)\s*\{/.test(e.text) || e.text === 'require {') { inReq++; continue; }
    if (inReq) { if (/^\}/.test(e.text)) inReq--; continue; }
    if (/^(module|class) /.test(e.text) && !e.via) continue;
    rules.push(e);
  }
  return rules;
}

module.exports = { detectToolchain, linkWithInstalled, installedKernelPolicy, scratchDir, sweepStaleScratch, cleanupScratch, SCRATCH, m4Defines, gitInfo, gitChangedFiles, gitRefs, exportHead, treeOutputs, cilBuild, installedPolicies, buildModule, buildTree, exportTreeOutputs, treeRootOf, treeBuiltText, treeOutputFor, treeExpansion, parseBuildOutput, parseExpansion, renderExpanded, rulesAt };
