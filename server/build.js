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

const scratchDir = (kind, key) => path.join(os.tmpdir(), 'selinux-policy-tools',
  (kind ? kind + '-' : '') + crypto.createHash('sha1').update(key).digest('hex').slice(0, 12));

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
async function buildTree(root, readText, { makeArgs = [], targets, files = {}, jobs = os.cpus().length, timeoutMs = 600000, sync = true } = {}) {
  const t0 = Date.now();
  const work = scratchDir('tree', root);
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

module.exports = { detectToolchain, m4Defines, buildModule, buildTree, exportTreeOutputs, treeRootOf, treeBuiltText, treeOutputFor, treeExpansion, parseBuildOutput, parseExpansion, renderExpanded, rulesAt };
