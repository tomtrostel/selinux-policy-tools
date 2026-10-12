'use strict';
const fs = require('fs');
const path = require('path');
const {
  createConnection, ProposedFeatures, TextDocuments, TextDocumentSyncKind,
  CompletionItemKind, SymbolKind, InsertTextFormat, MarkupKind, CodeActionKind,
  DiagnosticSeverity, FileChangeType,
} = require('vscode-languageserver/node');
const { TextDocument } = require('vscode-languageserver-textdocument');
const { URI } = require('vscode-uri');
const { PolicyIndex } = require('./indexer');
const { diagnose, globalRequirements, callRequires } = require('./diagnostics');
const build = require('./build');

const connection = createConnection(ProposedFeatures.all);
const documents = new TextDocuments(TextDocument);
const log = (m) => connection.console.log(`[selinux] ${m}`);
const idx = new PolicyIndex(log);

let roots = [];
let settings = {
  extraIncludePaths: [],
  useDevelHeaders: 'auto',
  develHeadersPath: '/usr/share/selinux/devel/include',
  diagnostics: { unknownMacros: true, classPerms: true, genRequire: true },
  ifdef: { evaluate: true },
  checks: { file: 'selinux.checks' },
  // RPM specs of standalone service modules.
  packaging: { license: 'MIT', customLicenses: [] },
  build: { enabled: true, onSave: true, develMakefile: '/usr/share/selinux/devel/Makefile',
    tree: { makeArgs: [], targets: [], validate: true, outputDir: '', files: {} },
    // Per-tree overrides of `tree`, keyed by tree path (absolute or relative to a workspace folder).
    trees: {} },
  // The policy tree to work on when the workspace has several (sent by the client).
  activeTree: null,
  // Set by the client from vscode.workspace.isTrusted. Building runs the tree's
  // Makefile and the build settings can carry commands, so untrusted
  // workspaces never build. Defaults to trusted for non-VS Code clients.
  trusted: true,
};
let usingDevel = false; // index came from the devel headers (standalone modules)
let indexing = Promise.resolve();

const toPath = (uri) => URI.parse(uri).fsPath;
const toUri = (p) => URI.file(p).toString();
const range = (l, c, len) => ({ start: { line: l, character: c }, end: { line: l, character: c + len } });
const rel = (p) => {
  for (const r of roots) if (p.startsWith(r + path.sep)) return path.relative(r, p);
  return p;
};
const STRUCTURAL = new Set(['interface', 'template', 'define', 'gen_require', 'optional_policy', 'tunable_policy',
  'ifdef', 'ifndef', 'ifelse', 'policy_module', 'gen_tunable', 'gen_bool', 'require']);

/* ---------------- lifecycle ---------------- */

connection.onInitialize((params) => {
  const folders = params.workspaceFolders || (params.rootUri ? [{ uri: params.rootUri }] : []);
  roots = folders.map(f => toPath(f.uri));
  if (params.initializationOptions) mergeSettings(params.initializationOptions);
  return {
    capabilities: {
      textDocumentSync: { openClose: true, change: TextDocumentSyncKind.Incremental, save: { includeText: false } },
      hoverProvider: true,
      definitionProvider: true,
      referencesProvider: true,
      documentHighlightProvider: true,
      documentSymbolProvider: true,
      workspaceSymbolProvider: true,
      completionProvider: { triggerCharacters: ['(', ':', '{', ' ', ','] },
      signatureHelpProvider: { triggerCharacters: ['(', ','], retriggerCharacters: [','] },
      codeActionProvider: { codeActionKinds: [CodeActionKind.QuickFix] },
      codeLensProvider: { resolveProvider: false },
    },
  };
});

connection.onInitialized(() => { reindex(); });

connection.onDidChangeConfiguration((change) => {
  const s = change.settings && change.settings.selinux;
  if (s) { mergeSettings(s); reindex(); }
});

function mergeSettings(s) {
  settings = { ...settings, ...s, diagnostics: { ...settings.diagnostics, ...(s.diagnostics || {}) },
    ifdef: { ...settings.ifdef, ...(s.ifdef || {}) },
    checks: { ...settings.checks, ...(s.checks || {}) },
    packaging: { ...settings.packaging, ...(s.packaging || {}) },
    build: { ...settings.build, ...(s.build || {}), tree: { ...settings.build.tree, ...((s.build && s.build.tree) || {}) } } };
  toolchain = null;
}

function reindex() {
  indexing = indexing.then(() => new Promise((resolve) => {
    connection.sendNotification('selinux/indexing', { state: 'start' });
    setImmediate(() => {
      const t0 = Date.now();
      idx.files.clear();
      const scanRoots = [...roots, ...(settings.extraIncludePaths || [])].filter(p => fs.existsSync(p));
      // Several refpolicy trees in the workspace: work on one at a time (their
      // names would collide in one index); the others stay out of it.
      trees = build.findTrees(scanRoots);
      if (!activeTree || !trees.includes(activeTree)) activeTree = pickTree();
      excludedTrees = trees.length > 1 ? trees.filter(t => t !== activeTree) : [];
      let n = idx.scanRoots(scanRoots, excludedTrees);
      const devel = settings.develHeadersPath;
      const wantDevel = settings.useDevelHeaders === 'always' ||
        (settings.useDevelHeaders === 'auto' && !idx.defs.has('gen_require'));
      usingDevel = !!(wantDevel && devel && fs.existsSync(devel));
      if (usingDevel) {
        log(`support macros not found in workspace; indexing devel headers from ${devel}`);
        n += idx.scanRoots([devel]);
      }
      for (const d of documents.all()) if (!inExcludedTree(toPath(d.uri))) idx.setFile(toPath(d.uri), d.getText(), true);
      idx.rebuild();
      findTreeRoot();
      updateModuleKinds();
      toolchain = null; // the mode (and so the tools needed) may have changed
      if (treeRoot) log(`refpolicy source tree: ${treeRoot}`);
      const stats = { ...idx.stats(), ms: Date.now() - t0, buildMode: usingDevel ? 'module' : treeRoot ? 'tree' : null,
        tree: treeRoot, trees: trees.map(t => ({ root: t, name: treeName(t), key: treeKey(t), active: t === activeTree })) };
      connection.sendNotification('selinux/indexing', { state: 'done', stats });
      publishAll();
      resolve();
      updateM4Defines().catch(e => log(`m4 flags: ${e.message}`));
    });
  }));
  return indexing;
}

/* ---------------- ifdef/ifndef on build flags ---------------- */

let m4Key = null;

/**
 * Ask the build's Makefile which -D flags it passes to m4 and let the index
 * decide ifdef/ifndef branches on them. Needs make (Linux) and a trusted
 * workspace, since parsing a Makefile can run $(shell ...).
 */
async function updateM4Defines() {
  let job = null;
  if (settings.ifdef.evaluate !== false && settings.trusted !== false && process.platform !== 'win32') {
    if (treeRoot) job = { cwd: treeRoot, makeArgs: treeCfg().makeArgs || [] };
    else if (usingDevel && roots[0] && fs.existsSync(settings.build.develMakefile || '')) job = { cwd: roots[0], makefile: settings.build.develMakefile };
  }
  const key = JSON.stringify(job);
  if (key === m4Key) return;
  m4Key = key;
  const m4 = job ? await build.m4Defines(job) : null;
  if (key !== m4Key) return; // superseded while make ran
  idx.setM4Defines(m4);
  idx.rebuild();
  if (m4) {
    let off = 0;
    for (const f of idx.files.values()) off += idx.inactiveBranches(f).length;
    log(`m4 build flags: ${m4.flags} (${off} ifdef/ifndef branches inactive)`);
  }
  publishAll();
  connection.sendNotification('selinux/inactiveChanged', { flags: m4 ? m4.flags : null });
}

/* ---------------- document sync ---------------- */

let rebuildTimer = null;
function scheduleRebuild() {
  clearTimeout(rebuildTimer);
  rebuildTimer = setTimeout(() => { idx.rebuild(); updateModuleKinds(); publishAll(); }, 300);
}

/**
 * Which modules are built as loadable modules, for the .te require check:
 * standalone modules always; in a tree, `module` in the effective
 * modules.conf, plus APPS_MODS (built as modules whatever modules.conf says).
 * Without a modules.conf, what `make conf` would write; in a monolithic
 * build nothing is loadable.
 */
function updateModuleKinds() {
  idx.allLoadable = usingDevel;
  idx.moduleKinds = null;
  if (usingDevel || !treeRoot) return;
  let { conf, states, apps } = moduleStates(treeRoot);
  if (!conf) states = idx.defaultModuleKinds(treeRoot);
  for (const m of apps) states.set(m, 'module');
  if (isMonolithic(treeRoot)) for (const [m, k] of states) if (k === 'module') states.set(m, 'base');
  if (!conf && moduleKindsNote !== treeRoot) {
    moduleKindsNote = treeRoot;
    const n = [...states.values()].filter(k => k === 'module').length;
    log(`no ${MODULES_CONF}: module kinds as make conf would write them (${states.size - n} base, ${n} loadable)`);
  }
  idx.moduleKinds = states;
}
let moduleKindsNote = null;

/** MONOLITHIC=y in the build's make arguments, else in build.conf. */
function isMonolithic(root) {
  const arg = (treeCfg().makeArgs || []).map(a => /^MONOLITHIC=(\S*)/.exec(a)).filter(Boolean).pop();
  if (arg) return arg[1] === 'y';
  const m = /^\s*MONOLITHIC\s*\??=\s*(\S+)/m.exec(readSource(path.join(root, 'build.conf')) || '');
  return !!(m && m[1] === 'y');
}

documents.onDidChangeContent((e) => {
  const p = toPath(e.document.uri);
  if (isChecksFile(p)) { clearTimeout(checksTimer); checksTimer = setTimeout(() => runChecks().catch(err => log(`checks failed: ${err.message}`)), 500); return; }
  if (inExcludedTree(p)) { publish(e.document); return; }
  idx.setFile(p, e.document.getText(), true);
  scheduleRebuild();
});
let checksTimer = null;

documents.onDidClose((e) => {
  const p = toPath(e.document.uri);
  if (inExcludedTree(p)) { connection.sendDiagnostics({ uri: e.document.uri, diagnostics: [] }); return; }
  try { idx.setFile(p, fs.readFileSync(p, 'utf8'), true); } catch { idx.files.delete(p); }
  connection.sendDiagnostics({ uri: e.document.uri, diagnostics: [] });
  scheduleRebuild();
});

connection.onDidChangeWatchedFiles((ev) => {
  for (const ch of ev.changes) {
    if (documents.get(ch.uri)) continue; // open editors are authoritative
    const p = toPath(ch.uri);
    if (isChecksFile(p)) { runChecks().catch(err => log(`checks failed: ${err.message}`)); continue; }
    // modules.conf (or a spec module list): which modules are built changed; re-read on the rebuild below.
    if (/(^|[\\/])modules[^\\/]*\.conf$|\.lst$/.test(p)) continue;
    if (inExcludedTree(p)) continue;
    if (ch.type === FileChangeType.Deleted) idx.files.delete(p);
    else { try { idx.setFile(p, fs.readFileSync(p, 'utf8'), true); } catch { /* ignore */ } }
  }
  scheduleRebuild();
});

function publishAll() {
  for (const d of documents.all()) publish(d);
}

function publish(doc) {
  const p = toPath(doc.uri);
  if (isChecksFile(p)) { connection.sendDiagnostics({ uri: doc.uri, diagnostics: checksDiagnostics() }); return; }
  if (inExcludedTree(p)) {
    const t = excludedTrees.find(x => p.startsWith(x + path.sep));
    connection.sendDiagnostics({ uri: doc.uri, diagnostics: [{ range: range(0, 0, 0), severity: DiagnosticSeverity.Information, source: 'selinux', code: 'inactive-tree',
      message: `This file is in the policy tree ${treeName(t)}, but ${treeName(activeTree)} is the one being worked on, so it isn't analyzed. Switch with "SELinux: Select Policy Tree…".` }] });
    return;
  }
  const f = idx.files.get(p);
  const diags = diagnose(idx, f, settings.diagnostics).map(d => ({
    range: range(d.l, d.c, d.len),
    severity: d.severity,
    code: d.code,
    source: 'selinux',
    message: d.msg,
    data: d.data,
  }));
  connection.sendDiagnostics({ uri: doc.uri, diagnostics: diags.concat(buildDiagnosticsFor(p, doc.getText(), diags)) });
}

/* ---------------- real builds (m4 + checkmodule) ---------------- */

/*
 * Two build modes:
 *  - module: a standalone module dir compiled against selinux-policy-devel
 *    (workspace has no support macros). Keyed by the module's .te path.
 *  - tree:   a full refpolicy source tree built with its own Makefile.
 *    Keyed by the tree root. Phase 1 compiles (base.pp modules) and reports
 *    at once; phase 2 runs `validate` (link + expand + file contexts).
 */
let toolchain = null;             // cached detectToolchain() result
let trees = [];                   // refpolicy trees found in the workspace
let activeTree = null;            // the one indexed and built
let excludedTrees = [];           // the others (kept out of the index)

const inExcludedTree = (p) => excludedTrees.some(t => p === t || p.startsWith(t + path.sep));
/** A tree's display name: its path relative to the workspace folder (or its basename). */
function treeName(t) {
  if (!t) return '';
  for (const r of roots) if (t === r) return path.basename(t);
  for (const r of roots) if (t.startsWith(r + path.sep)) return path.relative(r, t).split(path.sep).join('/');
  return path.basename(t);
}
/** The key for its selinux.build.trees entry: relative to the workspace folder it is under, else absolute. */
function treeKey(t) {
  for (const r of roots) if (t.startsWith(r + path.sep)) return path.relative(r, t).split(path.sep).join('/');
  return t;
}
/** Without a choice: the tree of the first open policy file, else the first tree. */
function pickTree() {
  if (settings.activeTree) {
    const want = path.resolve(settings.activeTree);
    const hit = trees.find(t => path.resolve(t) === want || path.resolve(t).toLowerCase() === want.toLowerCase());
    if (hit) return hit;
  }
  for (const d of documents.all()) {
    const p = toPath(d.uri);
    const t = trees.find(x => p.startsWith(x + path.sep));
    if (t) return t;
  }
  return trees[0] || null;
}
/** The build settings for the current tree: selinux.build.tree, overridden by its selinux.build.trees entry. */
function treeCfg() {
  const base = settings.build.tree || {};
  if (!treeRoot) return base;
  for (const [k, v] of Object.entries(settings.build.trees || {})) {
    const cands = path.isAbsolute(k) ? [k] : roots.map(r => path.resolve(r, k));
    if (cands.some(c => path.resolve(c) === treeRoot || path.resolve(c).toLowerCase() === treeRoot.toLowerCase())) return { ...base, ...(v || {}) };
  }
  return base;
}
let treeRoot = null;              // refpolicy tree in the workspace, if any
const lastBuild = new Map();      // build key -> build result
const builtText = new Map();      // source path -> text the last module build compiled
const buildState = new Map();     // build key -> { running, again, pkg }
const buildDiagUris = new Set();  // closed files we published build diagnostics for
const workDirs = new Set();       // scratch build dirs, removed when the server exits

process.on('exit', () => {
  for (const d of workDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
  build.cleanupScratch(); // this server's whole scratch area
});
// Scratch areas are per server; sweep those of servers that died without cleaning up.
if (process.platform !== 'win32') {
  const swept = build.sweepStaleScratch();
  if (swept) setImmediate(() => log(`removed ${swept} stale scratch area${swept > 1 ? 's' : ''}`));
}
process.on('SIGTERM', () => process.exit(0));

function findTreeRoot() {
  treeRoot = null;
  if (usingDevel) return;
  if (activeTree) { treeRoot = activeTree; return; }
  for (const p of idx.files.keys()) {
    const r = build.treeRootOf(p);
    if (r && roots.concat(settings.extraIncludePaths || []).some(w => r === w || r.startsWith(w + path.sep) || w.startsWith(r + path.sep))) { treeRoot = r; return; }
  }
}

function getToolchain() {
  if (!toolchain) toolchain = build.detectToolchain(usingDevel ? settings.build.develMakefile : null);
  return toolchain;
}

const isTreeKey = (k) => !!treeRoot && k === treeRoot;

/**
 * A module file next to the active tree but outside its policy/ directory: a
 * standalone module (packaged on its own, e.g. as an RPM), built and checked
 * with the devel headers instead of the tree.
 */
function isStandaloneModule(p) {
  return !!treeRoot && !usingDevel && /\.(te|if|fc)$/.test(p) && !p.startsWith(path.join(treeRoot, 'policy') + path.sep)
    && !inExcludedTree(p) && roots.some(r => p.startsWith(r + path.sep));
}

/** What building `p` means: its module .te (module mode, standalone modules) or the tree root. */
function buildTarget(p) {
  if (isStandaloneModule(p)) {
    const te = p.replace(/\.(if|fc)$/, '.te');
    return (documents.get(toUri(te)) || fs.existsSync(te)) ? te : null;
  }
  if (treeRoot && !usingDevel) {
    return p === treeRoot || (p.startsWith(treeRoot + path.sep) && !p.startsWith(path.join(treeRoot, 'tmp') + path.sep)) ? treeRoot : null;
  }
  if (!/\.(te|if|fc)$/.test(p)) return null;
  const te = p.replace(/\.(if|fc)$/, '.te');
  return (documents.get(toUri(te)) || fs.existsSync(te)) ? te : null;
}

function buildUnavailable() {
  if (settings.trusted === false) return 'Builds are off in Restricted Mode: building runs the policy tree\'s Makefile. Trust this workspace (Manage Workspace Trust) to enable them.';
  if (!settings.build.enabled) return 'Builds are disabled (selinux.build.enabled).';
  if (!usingDevel && !treeRoot) return 'No buildable policy found: open a standalone module directory, or a refpolicy source tree (with Makefile, Rules.modular, build.conf and policy/).';
  const t = getToolchain();
  return t.ok ? null : t.reason;
}

function readSource(p) {
  const d = documents.get(toUri(p));
  if (d) return d.getText();
  try { return fs.readFileSync(p, 'utf8'); } catch { return null; }
}

/** The text the last build compiled for `p`, to tell whether its results still apply. */
function builtTextOf(p, res) {
  return res.tree ? build.treeBuiltText(res, p) : builtText.get(p);
}

/**
 * Build. Requests arriving during a build are coalesced into one more run
 * (packaging if any of them asked for it); all callers get its result.
 */
function runBuild(key, pkg = false, trigger = null) {
  let st = buildState.get(key);
  if (!st) buildState.set(key, st = { running: null, again: false, pkg: false });
  st.pkg = st.pkg || pkg;
  if (trigger) st.trigger = trigger;
  if (st.running) { st.again = true; return st.running; }
  st.running = (async () => {
    let res;
    try {
      do {
        st.again = false;
        const wantPkg = st.pkg;
        st.pkg = false;
        res = isTreeKey(key) ? await treeBuild(key, st) : await moduleBuild(key, wantPkg);
        // Explicit builds of a tree keep their outputs (builds on save are checks only).
        if (res.tree && wantPkg && res.ok && treeCfg().outputDir) {
          try { res.exported = build.exportTreeOutputs(res, resolvePath(key, treeCfg().outputDir), treeCfg().makeArgs || []); } catch (e) { res.exportError = e.message; }
        }
        res.trigger = st.trigger;
        lastBuild.set(key, res);
      } while (st.again);
    } finally {
      st.running = null;
    }
    publishBuild(res);
    const summary = buildSummary(res);
    // If rules have been browsed this session, re-index the new policy in the
    // background so the next expand doesn't wait for it (RHEL: ~5 s).
    if (res.tree && res.ok && res.policyBin && policyQuery.proc) policyQuery.request({ op: 'rules', bin: res.policyBin, name: '', dir: 'source', kinds: ['allow'] });
    if (!res.tree && res.ok) lastModule = key;
    if (res.ok && (res.tree || (usingDevel && checksPath() && fs.existsSync(checksPath())))) runChecks().catch(err => log(`checks failed: ${err.message}`));
    connection.sendNotification('selinux/build', { state: 'done', ...summary });
    return summary;
  })();
  return st.running;
}

async function moduleBuild(te, pkg) {
  const mod = path.basename(te, '.te');
  if (!fs.existsSync(settings.build.develMakefile || '')) {
    const log = `${mod} is a standalone module: it builds with ${settings.build.develMakefile}, which isn't there (dnf install selinux-policy-devel).`;
    return { ok: false, module: mod, tePath: te, ms: 0, log, diagnostics: [{ severity: 'error', message: log, path: te, line: 0, col: 0 }], resolveFile: () => null };
  }
  connection.sendNotification('selinux/build', { state: 'start', module: mod });
  const snapshot = new Map();
  const res = await build.buildModule(te, (p) => { const t = readSource(p); if (t != null) snapshot.set(p, t); return t; },
    { develMakefile: settings.build.develMakefile, pkg });
  workDirs.add(res.workDir);
  for (const [p, t] of snapshot) builtText.set(p, t);
  return res;
}

/** A selinux.build.tree.files source with its paths resolved: a path, or { from, disable: [lists] }. */
function resolveOverlay(root, src) {
  if (typeof src === 'string') return resolvePath(root, src);
  if (src && typeof src.from === 'string') return { from: resolvePath(root, src.from), disable: [].concat(src.disable || []).map(l => resolvePath(root, l)) };
  return src;
}

/** A configured path: `~/x` → home, relative → under the tree root, absolute as is. */
function resolvePath(root, dir) {
  if (dir === '~' || dir.startsWith('~/')) return path.join(require('os').homedir(), dir.slice(1));
  return path.resolve(root, dir);
}

async function treeBuild(root, st) {
  const name = path.basename(root);
  const files = {};
  for (const [rel, srcs] of Object.entries(treeCfg().files || {})) files[rel] = [].concat(srcs).map(s => resolveOverlay(root, s));
  const opts = { makeArgs: treeCfg().makeArgs || [], files };
  const readText = (p) => { const d = documents.get(toUri(p)); if (d) return d.getText(); try { return fs.readFileSync(p); } catch { return null; } };
  connection.sendNotification('selinux/build', { state: 'start', module: name });
  const custom = (treeCfg().targets || []).length > 0;
  const res = await build.buildTree(root, readText, { ...opts, targets: custom ? treeCfg().targets : phase1Targets(root, opts.makeArgs) });
  workDirs.add(res.workDir);
  mapLinkDiagnostics(res);
  if (custom || res.monolithic || !res.ok || st.again || !treeCfg().validate) return res;
  // Phase 2: report compile results now, then link-validate in the background.
  lastBuild.set(root, res);
  publishBuild(res);
  connection.sendNotification('selinux/build', { state: 'validating', module: name, ms: res.ms });
  const v = await build.buildTree(root, null, { ...opts, targets: ['validate'], sync: false });
  mapLinkDiagnostics(v);
  return { ...v, diagnostics: res.diagnostics.concat(v.diagnostics), log: `${res.log}\n${v.log}`, ms: res.ms + v.ms, synced: res.synced, packages: res.packages, validated: true };
}

/** Phase-1 targets: compile everything; MONOLITHIC=y trees build `policy` in one go. */
function phase1Targets(root, makeArgs) {
  const mono = makeArgs.some(a => /^MONOLITHIC=y/i.test(a)) ||
    (!makeArgs.some(a => /^MONOLITHIC=/.test(a)) && /^\s*MONOLITHIC\s*=\s*y/mi.test((() => { try { return fs.readFileSync(path.join(root, 'build.conf'), 'utf8'); } catch { return ''; } })()));
  return mono ? ['policy'] : ['base.pp', 'modules'];
}

/** semodule_link names only the module and the missing name: point at where the module uses it. */
function mapLinkDiagnostics(res) {
  for (const d of res.diagnostics) {
    if (!d.linkModule) continue;
    const f = [...idx.files.values()].find(x => x.module === d.linkModule && /\.te(\.in)?$/.test(x.path) && x.path.startsWith(res.root + path.sep));
    if (!f) continue;
    d.path = f.path;
    // Where the module requires it outside optional_policy (only there can a
    // missing requirement fail the link): a require entry, or the interface
    // call that brings it in.
    const sites = globalRequirements(idx, f).names.get(d.token);
    if (sites && sites.length) {
      const s = sites[0];
      d.l = s.l;
      if (s.via) { d.msg += ` (required through ${s.via}())`; d.token = s.via; }
      continue;
    }
    const hit = f.refs && f.refs.get(d.token);
    if (hit) { d.l = hit[0][0]; continue; }
    // Otherwise the first call whose interface (or one it calls) requires it.
    const call = (f.calls || []).find(c => interfaceRequires(c.name, d.token, 3) && idx.isActive(f, c.l, c.c));
    if (call) { d.l = call.l; d.token = call.name; d.msg += ` (required through ${call.name}())`; } else d.l = 0;
  }
}

/** Does interface `name` (or an interface it calls, up to `depth` levels) gen_require `token`? */
function interfaceRequires(name, token, depth, seen = new Set()) {
  if (depth < 0 || seen.has(name)) return false;
  seen.add(name);
  for (const d of idx.defs.get(name) || []) {
    if (d.requires.some(r => r.name === token)) return true;
    if (d.bodyCalls.some(bc => interfaceRequires(bc.name, token, depth - 1, seen))) return true;
  }
  return false;
}

function buildSummary(res) {
  const errors = res.diagnostics.filter(d => d.severity === 'error').length;
  return { ok: res.ok, module: res.module, ms: res.ms, errors, warnings: res.diagnostics.length - errors, workDir: res.workDir,
    timedOut: res.timedOut, log: res.log, package: res.pkgPath || null,
    tree: !!res.tree, outputDir: res.tree ? res.workDir : null, policyBin: res.policyBin || null,
    exportDir: res.exported ? res.exported.dir : null, exportedFiles: res.exported ? res.exported.files.length : 0, exportError: res.exportError || null,
    packages: res.packages || 0, validated: !!res.validated };
}

function publishBuild(res) {
  const paths = new Set([res.tePath, res.trigger, ...res.diagnostics.map(d => d.path)].filter(Boolean));
  for (const u of buildDiagUris) paths.add(toPath(u));
  buildDiagUris.clear();
  for (const p of paths) {
    const doc = documents.get(toUri(p));
    if (doc) { publish(doc); continue; }
    const diags = buildDiagnosticsFor(p, readSource(p) || '', []);
    if (diags.length) buildDiagUris.add(toUri(p));
    connection.sendDiagnostics({ uri: toUri(p), diagnostics: diags });
  }
}

/** Diagnostics from the last build for one file, if they still match its text. */
function buildDiagnosticsFor(p, text, staticDiags) {
  const key = buildTarget(p);
  const res = key && lastBuild.get(key);
  if (!res || builtTextOf(p, res) !== text) return [];
  const lines = text.split('\n');
  // Errors with no source location go on the module's .te (module mode) or
  // the file whose save started the build (tree mode).
  const home = res.tree ? res.trigger : res.tePath;
  // Static checks carry quick fixes; when one already flags a line, the
  // compiler's report of the same problem is redundant.
  const staticLines = new Set(staticDiags.filter(d => /^unknown-|^missing-te-require$|^link-missing$|^net-port/.test(d.code)).map(d => d.range.start.line));
  const out = [];
  for (const d of res.diagnostics) {
    const own = d.path === p;
    if (!own && !(d.path == null && p === home)) continue;
    const l = own ? Math.min(d.l, lines.length - 1) : 0;
    if (own && staticLines.has(l)) continue;
    const lt = lines[l] || '';
    let c = Math.max(lt.search(/\S/), 0), len = lt.trimEnd().length - c;
    if (d.token && /^\w+$/.test(d.token) && lt.includes(d.token)) { c = lt.indexOf(d.token); len = d.token.length; }
    out.push({
      range: range(l, c, Math.max(len, 1)),
      severity: d.severity === 'error' ? DiagnosticSeverity.Error : DiagnosticSeverity.Warning,
      source: d.tool, code: 'build',
      message: own || !d.file ? d.msg : `${d.file}:${d.l + 1}: ${d.msg}`,
    });
  }
  return out;
}

documents.onDidSave((e) => {
  const p = toPath(e.document.uri);
  // Saving the checks file re-checks the last build; it doesn't rebuild.
  if (isChecksFile(p)) { runChecks().catch(err => log(`checks failed: ${err.message}`)); return; }
  if (!settings.build.onSave) return;
  const key = buildTarget(p);
  if (key && !buildUnavailable()) runBuild(key, false, p).catch(err => log(`build failed: ${err.message}`));
});

/** Compiled statements behind a source line, from the last build of an unchanged file. */
function expansionAt(p, line) {
  const key = buildTarget(p);
  const res = key && lastBuild.get(key);
  if (!res || builtTextOf(p, res) !== readSource(p)) return null;
  const expansion = res.tree ? build.treeExpansion(res, p) : res.expansion;
  return expansion ? build.rulesAt(expansion, p, line) : null;
}

/* ---------------- helpers ---------------- */

function wordAt(doc, pos) {
  const line = doc.getText({ start: { line: pos.line, character: 0 }, end: { line: pos.line + 1, character: 0 } });
  const isW = (ch) => /[A-Za-z0-9_$]/.test(ch);
  let s = pos.character, e = pos.character;
  while (s > 0 && isW(line[s - 1])) s--;
  while (e < line.length && isW(line[e])) e++;
  if (s === e) return null;
  return { word: line.slice(s, e), start: s, end: e };
}

function signatureOf(d) {
  const params = paramNames(d);
  return `${d.name}(${params.join(', ')})`;
}

function paramNames(d) {
  if (d.doc && d.doc.params && d.doc.params.length) return d.doc.params.map(p => (p.optional ? `[${p.name}]` : p.name));
  const n = d.maxArg || 0;
  return Array.from({ length: n }, (_, i) => `$${i + 1}`);
}

function defMarkdown(d, count) {
  const parts = [];
  parts.push('```selinux\n' + `${d.kind} ${signatureOf(d)}` + '\n```');
  if (d.doc) {
    const { summary, desc } = d.doc;
    // refpolicy descriptions usually repeat the summary as their first sentence
    if (desc && summary && desc.startsWith(summary)) parts.push(desc);
    else { if (summary) parts.push(summary); if (desc) parts.push(desc); }
  }
  if (d.doc && d.doc.params && d.doc.params.length) {
    parts.push(d.doc.params.map(p => `- \`${p.name}\`${p.optional ? ' (optional)' : ''}${p.unused ? ' (unused)' : ''}: ${p.summary}`).join('\n'));
  }
  if (d.requires && d.requires.length) {
    const req = [...new Set(d.requires.map(r => r.name))];
    parts.push(`**Requires:** ${req.slice(0, 12).map(r => '`' + r + '`').join(', ')}${req.length > 12 ? ` … (+${req.length - 12})` : ''}`);
  }
  if (d.generated) parts.push(`*Generated by \`${d.via}\` at ${rel(d.path)}:${d.l + 1}*`);
  else parts.push(`*Defined in ${rel(d.path)}:${d.l + 1}*${count > 1 ? ` (${count} definitions)` : ''}`);
  return parts.join('\n\n');
}

function declMarkdown(name, list) {
  const d = list[0];
  const parts = [];
  let kind = d.kind;
  if (kind === 'bool') kind = d.tunable ? 'tunable' : 'boolean';
  parts.push('```selinux\n' + `${kind} ${name}${d.default ? ' = ' + d.default : ''}` + '\n```');
  if (d.doc && (d.doc.desc || d.doc.summary)) parts.push(d.doc.desc || d.doc.summary);
  const attrs = idx.attributesOf(name);
  if (attrs.length) parts.push(`**Attributes:** ${attrs.map(a => '`' + a + '`').join(', ')}`);
  const fcs = idx.fcByType.get(name) || [];
  if (fcs.length) {
    parts.push(`**File contexts (${fcs.length}):**\n` + fcs.slice(0, 6).map(e => `- \`${e.spec}\` (${rel(e.path)})`).join('\n') + (fcs.length > 6 ? `\n- … and ${fcs.length - 6} more` : ''));
  }
  for (const x of list.slice(0, 3)) {
    parts.push(x.generated ? `*Generated by \`${x.via}(…)\` at ${rel(x.path)}:${x.l + 1}*` : `*Declared in ${rel(x.path)}:${x.l + 1}*`);
  }
  return parts.join('\n\n');
}

/* ---------------- hover ---------------- */

/**
 * Hover on the name tested by ifdef/ifndef: which branch this build
 * configuration compiles, and why. Null when the word isn't such a name or
 * nothing is decided (no build flags).
 */
function ifdefConditionHover(doc, position, name) {
  const f = idx.files.get(toPath(doc.uri));
  if (!f || !f.branches || !idx.m4) return null;
  const off = doc.offsetAt(position);
  const call = (f.calls || []).find(c => (c.name === 'ifdef' || c.name === 'ifndef') && c.args[0] === name &&
    c.argRanges[0] && c.argRanges[0].s <= off && off <= c.argRanges[0].e);
  if (!call) return null;
  const after = f.branches.filter(b => b.sym === name && (b.s.l > call.l || (b.s.l === call.l && b.s.c > call.c)));
  const b = after.sort((x, y) => x.s.l - y.s.l || x.s.c - y.s.c)[0];
  if (!b) return null;
  const st = idx.branchState(f, b);
  if (st.v === null) return `\`${name}\`: can't be decided statically, so both branches count as compiled.`;
  const reason = idx.branchReason(f, b).replace(/^needs `[^`]*` (not )?defined; /, '');
  return (st.kind === 'flag' ? `\`${name}\` is an m4 build flag: **${st.v ? 'defined' : 'not defined'}** in this build configuration.\n\n`
    : `\`${name}\` is **${st.v ? 'defined' : 'not defined'}** here: ${reason}\n\n`) +
    `This build configuration compiles the ${st.v === (call.name === 'ifdef') ? 'first' : 'second (else)'} branch.` +
    (st.kind === 'flag' ? `\n\nFlags from the Makefile: \`${idx.m4.flags}\`` : '');
}

connection.onHover(({ textDocument, position }) => {
  const doc = documents.get(textDocument.uri);
  if (!doc) return null;
  const w = wordAt(doc, position);
  if (!w) return null;
  const name = w.word;
  const r = { start: { line: position.line, character: w.start }, end: { line: position.line, character: w.end } };
  const defs = idx.defs.get(name);
  const cond = ifdefConditionHover(doc, position, name);
  if (cond) {
    return { range: r, contents: { kind: MarkupKind.Markdown, value: cond + (defs && defs.length ? '\n\n---\n\n' + defMarkdown(defs[0], defs.length) : '') } };
  }
  if (defs && defs.length) {
    let value = defMarkdown(defs[0], defs.length);
    const p = toPath(textDocument.uri);
    const f = idx.files.get(p);
    const isCall = f && (f.calls || []).some(c => c.name === name && c.l === position.line && c.c === w.start);
    const rules = isCall && expansionAt(p, position.line);
    if (rules && rules.length) {
      const MAX = 40;
      value += `\n\n---\n\n**Compiles to** (${rules.length} statement${rules.length > 1 ? 's' : ''}, last build):\n\n` +
        '```selinux\n' + rules.slice(0, MAX).map(e => e.text).join('\n') +
        (rules.length > MAX ? `\n# … ${rules.length - MAX} more` : '') + '\n```';
    }
    return { range: r, contents: { kind: MarkupKind.Markdown, value } };
  }
  const decls = idx.decls.get(name);
  if (decls && decls.length) return { range: r, contents: { kind: MarkupKind.Markdown, value: declMarkdown(name, decls) + compiledRoleNote(name) } };
  const u = policyModelCache.model && policyModelCache.model.users.find(x => x.name === name);
  if (u) {
    const logins = (u.logins || []).map(x => `\`${x.login}\`${x.range ? ` (${x.range})` : ''}`).join(', ');
    return { range: r, contents: { kind: MarkupKind.Markdown, value:
      '```selinux\nuser ' + name + '\n```\n\n' + `**Roles:** ${u.roles.map(x => '`' + x + '`').join(', ')}` +
      (u.range ? `\n\n**Range:** \`${u.range}\`, default level \`${u.level}\`` : '') +
      (logins ? `\n\n**Linux logins** (seusers): ${logins}` : '') + '\n\n*From the last build.*' } };
  }
  const cls = idx.classes.get(name);
  if (cls) {
    const perms = [...cls.allPerms].sort();
    return { range: r, contents: { kind: MarkupKind.Markdown, value:
      '```selinux\nclass ' + name + (cls.inherits ? ` inherits ${cls.inherits}` : '') + '\n```\n\n' +
      (perms.length ? `**Permissions (${perms.length}):** ${perms.join(' ')}` : '*No permissions defined*') } };
  }
  if (idx.decides(name)) {
    const on = idx.m4.defined.has(name);
    return { range: r, contents: { kind: MarkupKind.Markdown, value:
      `\`${name}\` is an m4 build flag: **${on ? 'defined' : 'not defined'}** in this build configuration.\n\n` +
      `Flags from the Makefile: \`${idx.m4.flags}\`` } };
  }
  const inactive = idx.inactiveDefs && idx.inactiveDefs.get(name);
  if (inactive) {
    const b = inactive[0].inactive;
    return { range: r, contents: { kind: MarkupKind.Markdown, value:
      defMarkdown(inactive[0], inactive.length) + `\n\n*Not part of this build configuration: its ifdef branch ${idx.branchReason(idx.files.get(inactive[0].path), b)}*` } };
  }
  return null;
});

/* ---------------- navigation ---------------- */

connection.onDefinition(({ textDocument, position }) => {
  const doc = documents.get(textDocument.uri);
  const w = doc && wordAt(doc, position);
  if (!w) return null;
  return idx.definitionsOf(w.word).map(d => ({ uri: toUri(d.path), range: range(d.l, d.c, d.len) }));
});

connection.onReferences(({ textDocument, position }) => {
  const doc = documents.get(textDocument.uri);
  const w = doc && wordAt(doc, position);
  if (!w) return null;
  return idx.referencesOf(w.word).map(r => ({ uri: toUri(r.path), range: range(r.l, r.c, r.len) }));
});

connection.onDocumentHighlight(({ textDocument, position }) => {
  const doc = documents.get(textDocument.uri);
  const w = doc && wordAt(doc, position);
  if (!w) return null;
  const f = idx.files.get(toPath(textDocument.uri));
  const a = f && f.refs && f.refs.get(w.word);
  return (a || []).map(([l, c]) => ({ range: range(l, c, w.word.length) }));
});

connection.onDocumentSymbol(({ textDocument }) => {
  const f = idx.files.get(toPath(textDocument.uri));
  if (!f) return [];
  const sym = (name, kind, l, c, len, detail) => ({ name, kind, detail, range: range(l, c, len), selectionRange: range(l, c, len) });
  const out = [];
  if (f.kind === 'fc') {
    for (const e of f.entries) out.push(sym(e.spec, SymbolKind.File, e.l, e.c, e.type.length, e.type));
    return out;
  }
  for (const d of f.defs || []) {
    const r = d.bodyEnd ? { start: { line: d.l, character: 0 }, end: { line: d.bodyEnd.l, character: d.bodyEnd.c + 1 } } : range(d.l, d.c, d.len);
    out.push({ name: d.name, kind: d.kind === 'define' ? SymbolKind.Constant : SymbolKind.Function, detail: d.doc && d.doc.summary,
      range: r, selectionRange: range(d.l, d.c, d.len) });
  }
  for (const d of f.decls || []) {
    if (d.inDef) continue;
    const kind = d.kind === 'type' ? SymbolKind.Class : d.kind === 'attribute' ? SymbolKind.Interface : d.kind === 'bool' ? SymbolKind.Boolean : SymbolKind.Variable;
    out.push(sym(d.name, kind, d.l, d.c, d.len, d.kind));
  }
  return out;
});

connection.onWorkspaceSymbol(({ query }) => {
  const q = (query || '').toLowerCase();
  if (q.length < 2) return [];
  const out = [];
  const add = (name, kind, x, container) => {
    out.push({ name, kind, containerName: container, location: { uri: toUri(x.path), range: range(x.l, x.c, x.len) } });
  };
  for (const [name, list] of idx.defs) {
    if (out.length >= 300) break;
    if (!name.toLowerCase().includes(q)) continue;
    add(name, list[0].kind === 'define' ? SymbolKind.Constant : SymbolKind.Function, list[0], rel(list[0].path));
  }
  for (const [name, list] of idx.decls) {
    if (out.length >= 300) break;
    if (!name.toLowerCase().includes(q)) continue;
    add(name, list[0].kind === 'type' ? SymbolKind.Class : SymbolKind.Variable, list[0], rel(list[0].path));
  }
  return out;
});

/* ---------------- completion ---------------- */

const KEYWORDS = ['allow', 'dontaudit', 'auditallow', 'neverallow', 'allowxperm', 'type_transition', 'type_change',
  'type_member', 'range_transition', 'role_transition', 'type', 'attribute', 'attribute_role', 'typealias',
  'typeattribute', 'roleattribute', 'role', 'types', 'alias', 'bool', 'if', 'else', 'require', 'self'];
const AV_RE = /\b(allow|dontaudit|auditallow|neverallow)\b([^;]*)$/;

connection.onCompletion(({ textDocument, position }) => {
  const doc = documents.get(textDocument.uri);
  if (!doc) return null;
  const lineText = doc.getText({ start: { line: position.line, character: 0 }, end: position });
  if (isChecksFile(toPath(textDocument.uri))) return checksCompletion(lineText);
  const gu = genUserArg(doc, position);
  if (gu !== null) return genUserCompletion(gu, /[A-Za-z0-9_]*$/.exec(lineText)[0]);
  const pm = /[A-Za-z0-9_$]*$/.exec(lineText);
  const prefix = pm[0];
  const before = lineText.slice(0, lineText.length - prefix.length);
  const items = [];

  // .fc: type position inside gen_context(user:role:TYPE
  if (/gen_context\(\s*\w+:\w+:$/.test(before)) {
    return { isIncomplete: true, items: matchDecls(prefix, ['type'], 300) };
  }

  const av = AV_RE.exec(before);
  if (av) {
    const rest = av[2];
    const colon = rest.indexOf(':');
    if (colon >= 0) {
      const afterColon = rest.slice(colon + 1);
      // still in the class part?
      const clsDone = /^\s*(\{[^}]*\}|[A-Za-z0-9_$]+)\s+/.exec(afterColon);
      if (!clsDone) {
        for (const c of idx.classes.keys()) if (c.startsWith(prefix)) items.push({ label: c, kind: CompletionItemKind.Struct, detail: 'class' });
        for (const name of idx.defs.keys()) if (name.endsWith('_class_set') && name.startsWith(prefix)) items.push({ label: name, kind: CompletionItemKind.Constant, detail: 'class set' });
        return { isIncomplete: false, items };
      }
      const clsText = clsDone[1].replace(/[{}]/g, ' ').trim();
      const perms = new Set();
      for (const c of clsText.split(/\s+/)) for (const p of idx.permsOf(c) || []) perms.add(p);
      for (const p of perms) if (p.startsWith(prefix)) items.push({ label: p, kind: CompletionItemKind.EnumMember, detail: `permission (${clsText})` });
      for (const name of idx.defs.keys()) {
        if (name.endsWith('_perms') && name.startsWith(prefix)) {
          const d = idx.defs.get(name)[0];
          items.push({ label: name, kind: CompletionItemKind.Constant, detail: 'permission set', documentation: d.doc && d.doc.summary, sortText: 'z' + name });
        }
      }
      return { isIncomplete: false, items };
    }
    // source / target position: types and attributes
    return { isIncomplete: true, items: matchDecls(prefix, ['type', 'attribute'], 300).concat(prefix.length ? [] : [{ label: 'self', kind: CompletionItemKind.Keyword }]) };
  }

  if (prefix.length < 2) return { isIncomplete: true, items: [] };

  for (const k of KEYWORDS) if (k.startsWith(prefix)) items.push({ label: k, kind: CompletionItemKind.Keyword });
  let n = 0;
  for (const [name, list] of idx.defs) {
    if (n >= 300) break;
    if (!name.startsWith(prefix)) continue;
    n++;
    const d = list[0];
    const params = paramNames(d);
    const snippet = params.length
      ? `${name}(${params.map((p, i) => '${' + (i + 1) + ':' + p.replace(/[[\]$}]/g, '') + '}').join(', ')})`
      : `${name}($1)`;
    items.push({
      label: name,
      kind: d.kind === 'define' ? CompletionItemKind.Snippet : CompletionItemKind.Function,
      detail: signatureOf(d),
      documentation: d.doc && d.doc.summary ? { kind: MarkupKind.Markdown, value: d.doc.summary } : undefined,
      insertText: snippet,
      insertTextFormat: InsertTextFormat.Snippet,
    });
  }
  items.push(...matchDecls(prefix, ['type', 'attribute', 'bool', 'role', 'attribute_role'], 200));
  return { isIncomplete: true, items };
});

function matchDecls(prefix, kinds, cap) {
  const out = [];
  for (const [name, list] of idx.decls) {
    if (out.length >= cap) break;
    if (!name.startsWith(prefix)) continue;
    const d = list.find(x => kinds.includes(x.kind));
    if (!d) continue;
    const kind = d.kind === 'type' ? CompletionItemKind.Class : d.kind === 'attribute' ? CompletionItemKind.Interface : CompletionItemKind.Variable;
    out.push({ label: name, kind, detail: `${d.kind} — ${rel(d.path)}` });
  }
  return out;
}

/* ---------------- signature help ---------------- */

connection.onSignatureHelp(({ textDocument, position }) => {
  const doc = documents.get(textDocument.uri);
  if (!doc) return null;
  const offset = doc.offsetAt(position);
  const text = doc.getText().slice(Math.max(0, offset - 4000), offset);
  let depth = 0, commas = 0;
  for (let i = text.length - 1; i >= 0; i--) {
    const ch = text[i];
    if (ch === ')') depth++;
    else if (ch === '(') {
      if (depth === 0) {
        const m = /([A-Za-z0-9_$]+)$/.exec(text.slice(0, i));
        if (!m || STRUCTURAL.has(m[1])) return null;
        const defs = idx.defs.get(m[1]);
        if (!defs) return null;
        const d = defs[0];
        const names = paramNames(d);
        const docs = (d.doc && d.doc.params) || [];
        return {
          signatures: [{
            label: signatureOf(d),
            documentation: d.doc && d.doc.summary,
            parameters: names.map((p, k) => ({ label: p, documentation: docs[k] ? docs[k].summary : undefined })),
          }],
          activeSignature: 0,
          activeParameter: Math.min(commas, Math.max(0, names.length - 1)),
        };
      }
      depth--;
    } else if (ch === ',' && depth === 0) commas++;
  }
  return null;
});

/* ---------------- code actions ---------------- */

function lev(a, b) {
  if (Math.abs(a.length - b.length) > 3) return 99;
  const dp = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0]; dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j];
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length];
}

function closest(word, candidates, max = 3) {
  return candidates.map(c => [c, lev(word, c)]).filter(([, d]) => d <= 3).sort((a, b) => a[1] - b[1]).slice(0, max).map(x => x[0]);
}

connection.onCodeAction(({ textDocument, context }) => {
  const doc = documents.get(textDocument.uri);
  const f = idx.files.get(toPath(textDocument.uri));
  if (!doc || !f) return [];
  const actions = [];
  for (const diag of context.diagnostics) {
    if (diag.source !== 'selinux') continue;
    const word = doc.getText(diag.range);
    const replace = (title, newText) => actions.push({
      title, kind: CodeActionKind.QuickFix, diagnostics: [diag],
      edit: { changes: { [textDocument.uri]: [{ range: diag.range, newText }] } },
    });

    if (diag.code === 'missing-require' && diag.data) {
      const edit = requireEdit(doc, f, diag.data);
      if (edit) actions.push({ title: `Add '${diag.data.kind} ${diag.data.name};' to gen_require`, kind: CodeActionKind.QuickFix,
        diagnostics: [diag], isPreferred: true, edit: { changes: { [textDocument.uri]: [edit] } } });
    } else if (diag.code === 'missing-te-require' && diag.data) {
      const edit = teRequireEdit(doc, f, diag.data);
      if (edit) actions.push({ title: `Add '${diag.data.kind} ${diag.data.name};' to ${diag.data.scope ? "the optional block's" : "the module's"} require block`, kind: CodeActionKind.QuickFix,
        diagnostics: [diag], isPreferred: true, edit: { changes: { [textDocument.uri]: [edit] } } });
    } else if (diag.code === 'unknown-perm') {
      const perms = new Set();
      for (const c of (diag.data && diag.data.classes) || []) for (const p of idx.permsOf(c) || []) perms.add(p);
      for (const s of closest(word, [...perms])) replace(`Change to '${s}'`, s);
    } else if (diag.code === 'unknown-class') {
      for (const s of closest(word, [...idx.classes.keys()])) replace(`Change to '${s}'`, s);
    } else if (diag.code === 'unknown-macro' || diag.code === 'unknown-macro-optional') {
      const cands = [];
      const head = word.slice(0, 3);
      for (const name of idx.defs.keys()) if (name.startsWith(head)) cands.push(name);
      for (const s of closest(word, cands)) replace(`Change to '${s}'`, s);
    }
  }
  return actions;
});

/** Build a TextEdit that adds `kind name;` to a definition's gen_require block (or creates one). */
function requireEdit(doc, f, data) {
  const d = (f.defs || []).find(x => x.name === data.def);
  if (!d) return null;
  const line = `${data.kind} ${data.name};`;
  if (d.reqBlocks.length) {
    const b = d.reqBlocks[0];
    const closeLine = doc.getText({ start: { line: b.endL, character: 0 }, end: { line: b.endL, character: b.endC } });
    if (/^\s*'$/.test(closeLine)) {
      // Standard layout: closing `')` on its own line. Match the indentation of an existing entry.
      const prevLine = doc.getText({ start: { line: b.endL - 1, character: 0 }, end: { line: b.endL, character: 0 } });
      const indent = (/^(\s*)\S/.exec(prevLine) || [, '\t\t'])[1];
      return { range: range(b.endL, 0, 0), newText: `${indent}${line}\n` };
    }
    // One-line form: gen_require(`type a;') -> insert before the closing quote
    return { range: range(b.endL, Math.max(0, b.endC - 1), 0), newText: ` ${line}` };
  }
  // No gen_require: create one at the top of the body.
  return { range: range(d.callLine + 1, 0, 0), newText: `\tgen_require(\`\n\t\t${line}\n\t')\n\n` };
}

/**
 * TextEdit adding `kind name;` to a .te require block in the scope of the
 * use: after an existing entry of a require/gen_require block directly in
 * that scope, or a new gen_require block (after policy_module, or at the
 * start of the optional_policy block).
 */
function teRequireEdit(doc, f, data) {
  const line = `${data.kind} ${data.name};`;
  const blocks = (f.calls || []).filter(c => c.name === 'optional_policy');
  const within = (b, l, c) => (l > b.l || (l === b.l && c > b.c)) && (l < b.endL || (l === b.endL && c < b.endC));
  const scopeOf = (l, c) => {
    let best = null;
    for (const b of blocks) if (within(b, l, c) && (!best || within(best, b.l, b.c))) best = b;
    return best;
  };
  const scope = data.scope ? blocks.find(b => b.l === data.scope.l && b.c === data.scope.c) : null;
  if (data.scope && !scope) return null;
  const lineText = (l) => doc.getText({ start: { line: l, character: 0 }, end: { line: l + 1, character: 0 } }).replace(/\r?\n$/, '');
  // An existing entry on a line of its own (`	type foo_t;`), directly in this scope.
  for (const r of f.requires || []) {
    if (r.l === undefined || scopeOf(r.l, r.c) !== scope) continue;
    const t = lineText(r.l);
    if (!/^\s*(type|attribute|class|role|bool|attribute_role)\s+[^{}`']*;\s*$/.test(t)) continue;
    const indent = /^(\s*)/.exec(t)[1];
    return { range: range(r.l + 1, 0, 0), newText: `${indent}${line}\n` };
  }
  if (scope) {
    // optional_policy(` on its own line: the block's body starts on the next line.
    const indent = (/^(\s*)/.exec(lineText(scope.l))[1]) + '\t';
    return { range: range(scope.l + 1, 0, 0), newText: `${indent}gen_require(\`\n${indent}\t${line}\n${indent}')\n\n` };
  }
  const pm = (f.calls || []).find(c => c.name === 'policy_module');
  const at = pm ? pm.endL + 1 : 0;
  return { range: range(at, 0, 0), newText: `\ngen_require(\`\n\t${line}\n')\n` };
}

/* ---------------- custom requests for the explorer view ---------------- */

connection.onRequest('selinux/modules', async () => { await indexing; return idx.modules(); });
connection.onRequest('selinux/moduleContents', async ({ path: p }) => { await indexing; return idx.moduleContents(p); });
connection.onRequest('selinux/stats', async () => { await indexing; return idx.stats(); });
// The policy trees in the workspace, and switching between them.
connection.onRequest('selinux/trees', async () => {
  await indexing;
  return { trees: trees.map(t => ({ root: t, name: treeName(t), key: treeKey(t), active: t === activeTree })), active: activeTree };
});
connection.onRequest('selinux/selectTree', async ({ root }) => {
  await indexing;
  const t = trees.find(x => path.resolve(x) === path.resolve(root || ''));
  if (!t) return { error: `${root} is not a policy tree in this workspace.` };
  if (t === activeTree) return { ok: true, tree: t, name: treeName(t), unchanged: true };
  settings.activeTree = t;
  activeTree = t;
  m4Key = null; // the flags come from this tree's Makefile
  await reindex();
  return { ok: true, tree: t, name: treeName(t) };
});
connection.onRequest('selinux/reindex', async () => { await reindex(); return idx.stats(); });
function buildRequestTarget(uri) {
  const why = buildUnavailable();
  if (why) return { unavailable: why };
  const p = toPath(uri);
  let key = buildTarget(p);
  // Not a file of the tree or of a module (the workspace folder around the tree, a README, a panel
  // with no editor): building means building the active tree. A file of another tree is refused.
  if (!key && treeRoot && !usingDevel && !inExcludedTree(p)) key = treeRoot;
  if (!key) return { unavailable: treeRoot ? `This file is outside the policy tree (${treeRoot}); it belongs to another tree of the workspace. Switch to that tree (status bar) to build it.` : 'This file is not part of a module (no .te file next to it).' };
  return { key };
}
connection.onRequest('selinux/build', async ({ uri, package: pkg }) => {
  await indexing;
  const { key, unavailable } = buildRequestTarget(uri);
  return key ? runBuild(key, !!pkg, toPath(uri)) : { ok: false, unavailable };
});
// A module's m4 output as readable text; builds first if the last build is missing or stale.
connection.onRequest('selinux/expandedPolicy', async ({ uri }) => {
  await indexing;
  const p = toPath(uri);
  const { key, unavailable } = buildRequestTarget(uri);
  if (!key) return { unavailable };
  const name = path.basename(p).replace(/\.(te|if|fc)(\.in)?$/, '');
  const prev = lastBuild.get(key);
  const stale = !prev || (prev.tree ? builtTextOf(p, prev) !== readSource(p)
    : [...builtText].some(([q, t]) => buildTarget(q) === key && readSource(q) !== t));
  if (stale) await runBuild(key, false, p);
  const r = lastBuild.get(key);
  const failed = { module: name, unavailable: 'm4 failed, so there is no expanded policy; see the SELinux Build output.' };
  if (!r.tree) {
    try { return { module: r.module, text: build.renderExpanded(fs.readFileSync(r.expandedPath, 'utf8'), r.resolveFile, readSource) }; } catch { return failed; }
  }
  if (!/\.te(\.in)?$/.test(p)) return { module: name, unavailable: 'Only .te files have an expansion of their own: interface bodies are expanded where a .te calls them.' };
  const out = build.treeOutputFor(r, p);
  if (!out) return failed;
  const text = build.renderExpanded(fs.readFileSync(out, 'utf8'), r.resolveFile, readSource, p);
  return text.trim() ? { module: name, text } : { module: name, unavailable: `${name} produced no policy in the last build: its module is probably off in modules.conf.` };
});
connection.onRequest('selinux/expansion', async ({ uri, line }) => expansionAt(toPath(uri), line));

// Workspace trust can be granted while the server runs.
connection.onNotification('selinux/setTrusted', ({ trusted }) => {
  settings.trusted = !!trusted;
  updateM4Defines().catch(e => log(`m4 flags: ${e.message}`));
});

// ifdef/ifndef branches the build flags turn off, for dimming in the editor.
connection.onRequest('selinux/inactiveRanges', async ({ uri }) => {
  await indexing;
  const f = idx.files.get(toPath(uri));
  return idx.inactiveBranches(f).map(b => ({ range: { start: { line: b.s.l, character: b.s.c }, end: { line: b.e.l, character: b.e.c } },
    reason: `Not compiled in this build configuration: ${idx.branchReason(f, b)}` }));
});

// Build settings derived from a Fedora/RHEL selinux-policy.spec, one entry per policy variant.
connection.onRequest('selinux/specBuildConfig', async ({ specPath }) => {
  try { return { configs: require('./specconfig').specBuildConfigs(specPath, treeRoot) }; } catch (e) { return { error: e.message }; }
});

/* ---------------- what changed since HEAD ---------------- */

/*
 * Baseline: the tree exported at HEAD (git archive) and built with the same
 * settings in its own scratch tree, cached per commit + settings. The current
 * side is the last build of the working tree. The compiled policies are
 * diffed with setools (policy_diff.py) and each change is traced to source
 * statements in the matching side's m4 output (explain.js).
 */
const explain = require('./explain');
// Builds of committed trees (git archive + build), keyed by commit + settings; at most REF_BUILDS kept.
const refBuilds = new Map(); // key -> { res, info, srcRoot, dest, pending, used }
const REF_BUILDS = 3;
let explainIdle = null;

function treeBuildOptions(root) {
  const files = {};
  for (const [rel, srcs] of Object.entries(treeCfg().files || {})) files[rel] = [].concat(srcs).map(s => resolveOverlay(root, s));
  const makeArgs = treeCfg().makeArgs || [];
  const custom = (treeCfg().targets || []).length > 0;
  const p1 = custom ? treeCfg().targets : phase1Targets(root, makeArgs);
  return { makeArgs, files, targets: custom || p1.includes('policy') ? p1 : [...p1, 'validate'] };
}

/** The tree at commit `info.sha`, exported and built with the current settings (cached). */
async function ensureRefBuild(root, info) {
  const opts = treeBuildOptions(root);
  const key = JSON.stringify({ root, sha: info.sha, opts });
  let e = refBuilds.get(key);
  if (e && e.res) { e.used = Date.now(); return e; }
  if (e && e.pending) { await e.pending; return refBuilds.get(key); }
  e = { info, used: Date.now() };
  refBuilds.set(key, e);
  e.pending = (async () => {
    connection.sendNotification('selinux/build', { state: 'baseline', module: path.basename(root), short: info.sha.slice(0, 7), ref: info.ref });
    e.dest = build.scratchDir('head', `${root}@${info.sha}`);
    workDirs.add(e.dest);
    e.srcRoot = await build.exportHead(info, e.dest);
    e.res = await build.buildTree(e.srcRoot, (p) => { try { return fs.readFileSync(p); } catch { return null; } }, opts);
    workDirs.add(e.res.workDir);
  })();
  try { await e.pending; } catch (err) { refBuilds.delete(key); throw err; } finally { e.pending = null; }
  // Keep the most recently used few; drop the rest (exported copy + its build).
  const done = [...refBuilds.entries()].filter(([, x]) => x.res).sort((a, b) => b[1].used - a[1].used);
  for (const [k, x] of done.slice(REF_BUILDS)) {
    refBuilds.delete(k);
    for (const d of [x.dest, x.res.workDir]) { workDirs.delete(d); fs.rmSync(d, { recursive: true, force: true }); }
  }
  return e;
}

/** Origins in an exported commit point into the copy; also give the working-tree path and the ref's name. */
const fromRef = (label, srcRoot) => {
  const f = (o) => ({ ...o, head: true, ref: label, real: path.join(treeRoot, path.relative(srcRoot, o.path)), because: o.because && o.because.map(f) });
  return f;
};

connection.onRequest('selinux/gitRefs', async () => {
  if (!treeRoot) return { unavailable: 'Needs a full policy source tree.' };
  const info = await build.gitInfo(treeRoot);
  if (!info) return { unavailable: `${treeRoot} is not in a git repository with commits.` };
  return build.gitRefs(treeRoot);
});

/*
 * Compare two versions of the compiled policy:
 *   base:   a git ref (default HEAD), or `saved`: a directory with an
 *           exported build (policy.bin; selinux.build.tree.outputDir)
 *   target: a git ref, or null for the working tree (its last build)
 * Each side that has sources is traced; a saved build has none.
 */
connection.onRequest('selinux/policyDiff', async (params = {}) => {
  await indexing;
  const { base: baseRef = 'HEAD', target: targetRef = null, saved = null } = params || {};
  if (!treeRoot) return { unavailable: 'Comparing builds needs a full policy source tree.' };
  const why = buildUnavailable();
  if (why) return { unavailable: why };
  const t0 = Date.now();
  const describe = (info) => ({ sha: info.sha, short: info.sha.slice(0, 7), subject: info.subject, when: info.when, label: info.ref === info.sha || /^[0-9a-f]{7,40}$/.test(info.ref) ? info.sha.slice(0, 7) : info.ref });

  // Base side.
  let A, baseInfo = null, baseDesc;
  if (saved) {
    const bin = path.join(saved, 'policy.bin');
    if (!fs.existsSync(bin)) return { unavailable: `${saved} has no policy.bin (export a build there with selinux.build.tree.outputDir and SELinux: Build).` };
    let meta = {};
    try { meta = JSON.parse(fs.readFileSync(path.join(saved, 'build-info.json'), 'utf8')); } catch { /* optional */ }
    A = { policyBin: bin, side: null };
    baseDesc = { saved, label: `saved build ${path.basename(saved)}`, builtAt: meta.builtAt || null, subject: meta.builtAt ? `exported ${new Date(meta.builtAt).toLocaleString()}` : 'saved build' };
  } else {
    baseInfo = await build.gitInfo(treeRoot, baseRef);
    if (!baseInfo) return { unavailable: baseRef === 'HEAD' ? `${treeRoot} is not in a git repository with commits, so there is no HEAD to compare with.` : `'${baseRef}' is not a commit, branch or tag of this repository.` };
    const e = await ensureRefBuild(treeRoot, baseInfo);
    if (!e.res.ok || !e.res.policyBin) return { unavailable: `${baseRef} (${baseInfo.sha.slice(0, 7)}) does not build with the current settings, so there is nothing to compare with.`, log: e.res.log };
    baseDesc = describe(baseInfo);
    A = { policyBin: e.res.policyBin, side: { res: e.res, map: fromRef(baseDesc.label, e.srcRoot), srcRoot: e.srcRoot } };
  }

  // Target side: the working tree, or another ref.
  let B, targetDesc, targetInfo = null;
  if (!targetRef) {
    let cur = lastBuild.get(treeRoot);
    if (!cur || !cur.ok || !cur.policyBin) { await runBuild(treeRoot, false, null); cur = lastBuild.get(treeRoot); }
    if (!cur || !cur.ok || !cur.policyBin) return { unavailable: 'The working tree does not build; fix its errors (see Problems) and compare again.' };
    B = { policyBin: cur.policyBin, side: { res: cur } };
    targetDesc = { working: true, label: 'working tree' };
  } else {
    targetInfo = await build.gitInfo(treeRoot, targetRef);
    if (!targetInfo) return { unavailable: `'${targetRef}' is not a commit, branch or tag of this repository.` };
    const e = await ensureRefBuild(treeRoot, targetInfo);
    if (!e.res.ok || !e.res.policyBin) return { unavailable: `${targetRef} (${targetInfo.sha.slice(0, 7)}) does not build with the current settings.`, log: e.res.log };
    targetDesc = describe(targetInfo);
    B = { policyBin: e.res.policyBin, side: { res: e.res, map: fromRef(targetDesc.label, e.srcRoot), srcRoot: e.srcRoot } };
  }

  let diff;
  try { diff = await runPython('policy_diff.py', [A.policyBin, B.policyBin]); } catch (e) { return { unavailable: `Comparing the policies failed: ${e.message}` }; }
  const tDiff = Date.now();

  // Files that changed between the two sides rank first when several statements explain a change.
  let changed = new Set();
  const info = baseInfo || targetInfo || await build.gitInfo(treeRoot);
  if (info && baseInfo) {
    changed = new Set(await build.gitChangedFiles(treeRoot, info, baseInfo.sha, targetInfo ? targetInfo.sha : null));
    if (!targetInfo) for (const d of documents.all()) {
      const p = toPath(d.uri);
      if (p.startsWith(treeRoot + path.sep)) { let disk = null; try { disk = fs.readFileSync(p, 'utf8'); } catch { /* new */ } if (disk !== d.getText()) changed.add(p); }
    }
  }
  const inCopy = (s) => (s && s.srcRoot ? new Set([...changed].map(p => path.join(s.srcRoot, path.relative(treeRoot, p)))) : changed);
  explainDiff(diff,
    A.side && { ...A.side, changed: inCopy(A.side) },
    B.side && { ...B.side, changed: inCopy(B.side) });
  return {
    ...diff,
    base: baseDesc, target: targetDesc,
    head: baseInfo ? { sha: baseInfo.sha, short: baseDesc.short, subject: baseInfo.subject } : null, // (older clients)
    builtAt: fs.statSync(B.policyBin).mtimeMs,
    ms: { total: Date.now() - t0, diff: tDiff - t0 },
  };
});

/**
 * Trace a policy_diff.py result to source: added permissions through side
 * B's build output, removed ones through side A's. `map` post-processes
 * origins of a side (e.g. HEAD copies). Mutates `diff` (addFrom/delFrom,
 * typeLocations) and drops the bulky attribute maps.
 */
function explainDiff(diff, a, b) {
  // A side without sources (an installed policy) is passed as null: its changes aren't traced.
  const side = (s, attrs, gained) => (s ? { index: explain.byName(explain.indexBuild(build.treeOutputs(s.res), s.res.resolveFile)), attrs, gained, changedFiles: s.changed || null } : null);
  const sideA = side(a, diff.attrsA, new Map(diff.membership.map(m => [m.type, new Set(m.removed)])));
  const sideB = side(b, diff.attrsB, new Map(diff.membership.map(m => [m.type, new Set(m.added)])));
  const mapA = (a && a.map) || ((o) => o), mapB = (b && b.map) || ((o) => o);
  const mapped = (x, f) => ({ origins: x.origins.map(f), more: x.more });
  const noSource = { origins: [], more: 0, noSource: true };
  for (const r of diff.rules) {
    if (r.add.length) r.addFrom = sideB ? mapped(explain.explainRule(r, r.add, sideB), mapB) : noSource;
    if (r.del.length) r.delFrom = sideA ? mapped(explain.explainRule(r, r.del, sideA), mapA) : noSource;
  }
  for (const m of diff.membership) {
    m.addFrom = m.added.map(x => ({ attr: x, origins: sideB ? explain.membershipOrigins(m.type, x, sideB).map(mapB) : [], noSource: !sideB }));
    m.delFrom = m.removed.map(x => ({ attr: x, origins: sideA ? explain.membershipOrigins(m.type, x, sideA).map(mapA) : [], noSource: !sideA }));
  }
  explain.releaseTexts();
  // The statement index is ~100 MB per side on a RHEL tree: keep it while
  // comparisons are being refreshed, drop it when they go idle.
  clearTimeout(explainIdle);
  explainIdle = setTimeout(() => { explain.dropCache(); ruleIndex = { key: null, side: null }; }, 120000);
  diff.typeLocations = Object.fromEntries(diff.types.added.map(t => [t, sourceLocation(t, ['type'])]));
  delete diff.attrsA; delete diff.attrsB; delete diff.aliasesA; delete diff.aliasesB;
  return diff;
}

/* ---------------- compare with an installed policy (CIL build) ---------------- */

/*
 * Installed policies are built by semodule (CIL), which represents attributes
 * differently from the Makefile's semodule_link/semodule_expand, so the
 * working tree is rebuilt the same way (build.cilBuild) and diffed against
 * /etc/selinux/<name>/policy/policy.NN. "+" = only in the build (installing
 * it adds this), "−" = only on the host (separately packaged modules, local
 * customizations, or things the build removes).
 */
let cilCache = { key: null, res: null };

function buildName(root) {
  for (const a of treeCfg().makeArgs || []) { const m = /^NAME=(\S+)/.exec(a); if (m) return m[1]; }
  try { const m = /^\s*NAME\s*=\s*(\S+)/m.exec(fs.readFileSync(path.join(root, 'build.conf'), 'utf8')); if (m) return m[1]; } catch { /* none */ }
  return 'refpolicy';
}

connection.onRequest('selinux/installedPolicies', async () => ({ policies: build.installedPolicies(), buildName: treeRoot ? buildName(treeRoot) : null }));

connection.onRequest('selinux/compareInstalled', async ({ name }) => {
  await indexing;
  if (!treeRoot) return { unavailable: 'Comparing with an installed policy needs a full policy source tree.' };
  const why = buildUnavailable();
  if (why) return { unavailable: why };
  const installed = build.installedPolicies();
  const target = installed.find(p => p.name === name) || installed.find(p => p.name === buildName(treeRoot)) || installed.find(p => p.active);
  if (!target) return { unavailable: 'No installed policy found under /etc/selinux/*/policy on this host.' };
  const t0 = Date.now();
  let cur = lastBuild.get(treeRoot);
  if (!cur || !cur.ok) { await runBuild(treeRoot, false, null); cur = lastBuild.get(treeRoot); }
  if (!cur || !cur.ok) return { unavailable: 'The working tree does not build; fix its errors (see Problems) and compare again.' };
  // Rebuild the CIL policy only when the build's packages changed.
  const pkgs = fs.readdirSync(cur.workDir).filter(n => n.endsWith('.pp'));
  const key = `${cur.workDir}:${pkgs.length}:${Math.max(...pkgs.map(n => fs.statSync(path.join(cur.workDir, n)).mtimeMs))}`;
  if (cilCache.key !== key || !cilCache.res || !cilCache.res.ok) {
    connection.sendNotification('selinux/build', { state: 'cil', module: path.basename(treeRoot) });
    cilCache = { key, res: await build.cilBuild(cur, { name: buildName(treeRoot) }) };
  }
  const cil = cilCache.res;
  if (!cil.ok) return { unavailable: `Building the policy with semodule failed: ${(cil.log || '').split('\n').slice(-6).join(' ')}` };
  let diff;
  try { diff = await runPython('policy_diff.py', [target.policy, cil.policy]); } catch (e) { return { unavailable: `Comparing the policies failed: ${e.message}` }; }
  explainDiff(diff, null, { res: cur });
  return {
    ...diff,
    installed: { name: target.name, policy: target.policy, active: target.active, others: installed.map(p => p.name) },
    cil: { policy: cil.policy, packages: cil.packages, ms: cil.ms },
    builtAt: fs.statSync(cil.policy).mtimeMs,
    ms: { total: Date.now() - t0 },
  };
});

/* ---------------- module on/off preview ---------------- */

/*
 * "What happens if this module is turned off (or on)?" The tree is built in
 * a separate scratch copy with the module's line in modules.conf flipped
 * (and, if APPS_MODS forces it on, dropped from APPS_MODS), then compared
 * with the current build like Changes since HEAD. optional_policy blocks
 * that depend on the module are found statically: m4 drops a whole block
 * when any of its requirements is missing, unrelated rules included.
 */
const MODULES_CONF = 'policy/modules.conf';

/** The modules.conf the build uses: the spec overlay if configured, else the tree's (editor contents win). */
function effectiveModulesConf(root) {
  const overlay = treeCfg().files && treeCfg().files[MODULES_CONF];
  if (overlay) {
    // A filtered source ({ from, disable }) is edited in its `from` file: the filter keeps line numbers.
    const srcs = [].concat(overlay).map(s => resolveOverlay(root, s));
    const parts = [];
    for (const src of srcs) {
      const r = build.overlaySource(src, readSource);
      if (r.missing) return null;
      parts.push({ path: typeof src === 'string' ? src : src.from, text: String(r.text) });
    }
    return { text: parts.map(x => x.text).join(''), parts };
  }
  const p = path.join(root, MODULES_CONF);
  const t = readSource(p);
  return t == null ? null : { text: t, parts: [{ path: p, text: t }] };
}

const confLineRe = (mod) => new RegExp(`^(\\s*${mod.replace(/[-.]/g, '\\$&')}\\s*=\\s*)(\\w+)\\s*$`, 'm');

/** module -> 'base' | 'module' | 'off' (modules.conf), plus APPS_MODS (always built as modules). */
function moduleStates(root) {
  const conf = effectiveModulesConf(root);
  const states = new Map();
  if (conf) for (const m of conf.text.matchAll(/^\s*([\w-]+)\s*=\s*(\w+)\s*$/gm)) states.set(m[1], m[2]);
  const apps = (treeCfg().makeArgs || []).map(a => /^APPS_MODS=(.*)$/.exec(a)).filter(Boolean).flatMap(m => m[1].split(/\s+/).filter(Boolean));
  return { conf, states, apps: new Set(apps) };
}

/**
 * optional_policy blocks in enabled modules (other than `mod`) that depend on
 * `mod`: they call one of its interfaces, or name one of its types/attributes.
 * The innermost block around each use is the one m4 drops.
 */
function dependentOptionalBlocks(mod, enabled) {
  const modFiles = [...idx.files.values()].filter(f => f.module === mod && f.path.startsWith(treeRoot + path.sep));
  const ifaces = new Set(), names = new Set();
  for (const f of modFiles) {
    for (const d of f.defs || []) if (/\.if$/.test(f.path)) ifaces.add(d.name);
    for (const d of f.decls || []) if (/\.te(\.in)?$/.test(f.path) && (d.kind === 'type' || d.kind === 'attribute')) names.add(d.name);
  }
  // Interfaces generated by the module's templates count too.
  for (const [n, list] of idx.defs) if (list.some(d => d.generated && modFiles.some(f => f.path === d.path))) ifaces.add(n);
  const within = (b, l, c) => (l > b.l || (l === b.l && c > b.c)) && (l < b.endL || (l === b.endL && c < b.endC));
  const out = [];
  for (const f of idx.files.values()) {
    if (!/\.te(\.in)?$/.test(f.path) || f.module === mod || !enabled.has(f.module) || !f.path.startsWith(treeRoot + path.sep)) continue;
    const blocks = (f.calls || []).filter(c => c.name === 'optional_policy' && idx.isActive(f, c.l, c.c));
    if (!blocks.length) continue;
    const innermost = (l, c) => blocks.filter(b => within(b, l, c)).sort((x, y) => (y.l - x.l) || (y.c - x.c))[0];
    const hits = new Map(); // block -> Set(reasons)
    const hit = (b, why) => { if (!b) return; if (!hits.has(b)) hits.set(b, new Set()); hits.get(b).add(why); };
    for (const c of f.calls || []) if (ifaces.has(c.name) && idx.isActive(f, c.l, c.c)) hit(innermost(c.l, c.c), `${c.name}()`);
    for (const n of names) for (const [l, c] of (f.refs && f.refs.get(n)) || []) if (idx.isActive(f, l, c)) hit(innermost(l, c), n);
    for (const [b, why] of hits) {
      const inside = (f.calls || []).filter(c => c !== b && within(b, c.l, c.c) && c.name !== 'gen_require').length;
      out.push({ path: f.path, module: f.module, l: b.l, c: b.c, endL: b.endL, uses: [...why], calls: inside });
    }
  }
  return out.sort((x, y) => x.module.localeCompare(y.module) || x.l - y.l);
}

connection.onRequest('selinux/moduleStates', async () => {
  await indexing;
  if (!treeRoot) return { unavailable: 'Module previews need a full policy source tree.' };
  const { conf, states, apps } = moduleStates(treeRoot);
  if (!conf) return { unavailable: `No ${MODULES_CONF} (and no selinux.build.tree.files entry for it), so module states are unknown.` };
  const mods = [...idx.files.values()].filter(f => /\.te(\.in)?$/.test(f.path) && f.path.startsWith(treeRoot + path.sep)).map(f => f.module);
  return { modules: [...new Set(mods)].sort().map(m => ({ module: m, state: apps.has(m) ? 'module' : (states.get(m) || 'unlisted'), apps: apps.has(m), conf: states.get(m) || null })) };
});

connection.onRequest('selinux/modulePreview', async ({ module: mod, to }) => {
  await indexing;
  if (!treeRoot) return { unavailable: 'Module previews need a full policy source tree.' };
  const why = buildUnavailable();
  if (why) return { unavailable: why };
  const t0 = Date.now();
  const { conf, states, apps } = moduleStates(treeRoot);
  if (!conf) return { unavailable: `No ${MODULES_CONF} (and no selinux.build.tree.files entry for it), so module states are unknown.` };
  const inConf = states.get(mod) || null;
  const from = apps.has(mod) ? 'module' : (inConf || 'off');
  if (!to) to = from === 'off' ? 'module' : 'off';
  if (to === from) return { unavailable: `${mod} is already ${from}.` };

  // Current side: the last good build (build now if needed).
  let cur = lastBuild.get(treeRoot);
  if (!cur || !cur.ok || !cur.policyBin) { await runBuild(treeRoot, false, null); cur = lastBuild.get(treeRoot); }
  if (!cur || !cur.ok || !cur.policyBin) return { unavailable: 'The working tree does not build; fix its errors (see Problems) and preview again.' };

  // modules.conf with the module's line flipped (added if missing), in the preview's own scratch area.
  const re = confLineRe(mod);
  const newConf = re.test(conf.text) ? conf.text.replace(re, `$1${to}`) : `${conf.text.replace(/\n?$/, '\n')}${mod} = ${to}\n`;
  const dir = build.scratchDir('preview', treeRoot);
  fs.mkdirSync(dir, { recursive: true });
  workDirs.add(dir);
  const confFile = path.join(dir, 'modules.conf');
  fs.writeFileSync(confFile, newConf);
  const opts = treeBuildOptions(treeRoot);
  opts.files[MODULES_CONF] = [confFile];
  let appsChanged = false;
  if (apps.has(mod) && to === 'off') {
    opts.makeArgs = opts.makeArgs.map(a => (/^APPS_MODS=/.test(a) ? `APPS_MODS=${[...apps].filter(m => m !== mod).join(' ')}` : a));
    appsChanged = true;
  }
  connection.sendNotification('selinux/build', { state: 'preview', module: mod, to });
  const res = await build.buildTree(treeRoot, (p) => { const t = readSource(p); return t == null ? null : t; }, { ...opts, variant: 'preview' });
  workDirs.add(res.workDir);
  mapLinkDiagnostics(res);

  // Where the user would make the change.
  const lineRe = new RegExp(re.source); // same pattern, one line at a time
  let apply = { path: conf.parts[conf.parts.length - 1].path, line: null, to };
  for (const p of conf.parts) {
    const i = p.text.split('\n').findIndex(l => lineRe.test(l));
    if (i >= 0) { apply = { path: p.path, line: i, to }; break; }
  }

  // Blocks that depend on the module: they drop out (off) or come alive (on).
  const enabledNow = new Set([...states].filter(([, s]) => s === 'base' || s === 'module').map(([m]) => m).concat([...apps]));
  const blocks = dependentOptionalBlocks(mod, enabledNow);

  const result = { module: mod, from, to, conf: inConf, appsMods: apps.has(mod), appsChanged, apply, optionalBlocks: blocks, ok: res.ok };
  if (!res.ok) {
    result.errors = res.diagnostics.filter(d => d.severity === 'error').map(d => ({ path: d.path, l: d.l, msg: d.msg, tool: d.tool, file: d.file }));
    result.log = res.log.split('\n').slice(-40).join('\n');
    result.ms = { total: Date.now() - t0 };
    return result;
  }
  let diff;
  try { diff = await runPython('policy_diff.py', [cur.policyBin, res.policyBin]); } catch (e) { return { ...result, unavailable: `Comparing the policies failed: ${e.message}` }; }
  explainDiff(diff, { res: cur }, { res });
  return { ...result, diff, ms: { total: Date.now() - t0 } };
});

/* ---------------- property checks (selinux.checks) ---------------- */

/*
 * Service editor (server/service.js): create a service module from a simple
 * model, or edit an existing one (a module with init_daemon_domain), changing
 * only the lines of settings the user changed. The client shows the model in
 * a webview and applies the planned texts as workspace edits.
 */
const service = require('./service');
const packaging = require('./packaging');

/** "Name <email>" from git's configuration (for the spec's %changelog), or a placeholder. */
function gitPackager(dir) {
  const get = (k) => { try { return require('child_process').execFileSync('git', ['config', '--get', k], { cwd: fs.existsSync(dir) ? dir : (roots[0] || '.'), encoding: 'utf8', timeout: 3000 }).trim(); } catch { return ''; } };
  const n = get('user.name'), e = get('user.email');
  return n && e ? `${n} <${e}>` : 'Your Name <you@example.com>';
}

// Statements checkmodule refuses inside a conditional (if / tunable_policy): declarations,
// attributes, roles, optional and nested conditional blocks. type_transition is fine.
const COND_BAD_RE = /^\s*(typeattribute|attribute|attribute_role|typealias|type|role|roleattribute|role_transition|range_transition|neverallow|if)\b|^\s*allow\s+[^:;]+;|\b(optional_policy|tunable_policy|gen_tunable|gen_bool)\s*\(/m;
const COND_SKIP = new Set(['gen_require', 'require', 'ifdef', 'ifndef', 'ifelse', 'refpolicywarn', 'refpolicyerr']);

/** name -> whether a call to it may go under a boolean (its body and everything it calls). */
function makeCondSafe() {
  const memo = new Map();
  const texts = new Map();
  const linesOf = (p) => { if (!texts.has(p)) texts.set(p, (readSource(p) || '').split('\n')); return texts.get(p); };
  const safe = (name, depth = 0) => {
    if (memo.has(name)) return memo.get(name);
    if (name === 'optional_policy' || name === 'tunable_policy') return false;
    const d = (idx.defs.get(name) || [])[0];
    if (!d || d.generated || !d.bodyStart || !d.bodyEnd || depth > 8) return true;
    memo.set(name, true); // cycles
    const body = linesOf(d.path).slice(d.bodyStart.l, d.bodyEnd.l + 1);
    for (const r of d.reqBlocks || []) for (let l = r.l; l <= r.endL; l++) body[l - d.bodyStart.l] = '';
    let ok = !COND_BAD_RE.test(body.join('\n').replace(/#.*$/gm, ''));
    for (const bc of d.bodyCalls || []) if (ok && !COND_SKIP.has(bc.name) && !safe(bc.name, depth + 1)) ok = false;
    memo.set(name, ok);
    return ok;
  };
  return (name) => safe(name);
}

/** corenetwork.te.in of the tree (new port types go there), or null for standalone modules. */
function corenetPath() {
  if (!treeRoot || usingDevel) return null;
  const p = path.join(treeRoot, 'policy', 'modules', 'kernel', 'corenetwork.te.in');
  return idx.files.has(p) || fs.existsSync(p) ? p : null;
}

/** network_port() lines of corenetwork.te.in: [{ name, nums: [{ proto, port, level }], l, single }]. */
function networkPorts() {
  const p = corenetPath();
  const f = p && idx.files.get(p);
  if (!f) return [];
  const out = [];
  for (const c of f.calls || []) {
    if (c.inDef || c.name !== 'network_port' || !c.args[0] || !idx.isActive(f, c.l, c.c)) continue;
    const nums = [];
    for (let i = 1; i + 2 < c.args.length + 1; i += 3) {
      const proto = (c.args[i] || '').trim(), port = (c.args[i + 1] || '').trim();
      if (/^(tcp|udp|sctp|dccp)$/.test(proto) && port) nums.push({ proto, port, level: (c.args[i + 2] || 's0').trim() });
    }
    out.push({ name: c.args[0].trim(), nums, l: c.l, single: c.c === 0 && c.l === c.endL });
  }
  return out;
}

/** The port types in corenetwork.te.in that belong to a module: named after it, on one line of their own. */
function ownedPorts(mod) {
  if (!mod) return [];
  return networkPorts().filter(p => p.single && (p.name === mod || p.name.startsWith(mod + '_'))).map(p => ({ name: p.name, nums: p.nums }));
}

/** What the service model needs to know about this tree. */
let develIfCache = { key: null, value: null };
/** Interfaces and templates of the devel headers (incl. distributed/): { names: name → layer, modules }, or null. */
function develInterfaces() {
  const inc = path.join(path.dirname(settings.build.develMakefile || '/nonexistent/Makefile'), 'include');
  let key;
  try { key = `${inc}:${fs.statSync(inc).mtimeMs}:${fs.statSync(path.join(inc, 'distributed')).mtimeMs}`; } catch { try { key = `${inc}:${fs.statSync(inc).mtimeMs}`; } catch { return null; } }
  if (develIfCache.key === key) return develIfCache.value;
  const names = new Map(), modules = new Set();
  for (const layer of fs.readdirSync(inc, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name)) {
    for (const n of fs.readdirSync(path.join(inc, layer)).filter(x => x.endsWith('.if'))) {
      modules.add(n.slice(0, -3));
      let text = '';
      try { text = fs.readFileSync(path.join(inc, layer, n), 'utf8'); } catch { continue; }
      for (const m of text.matchAll(/^\s*(?:interface|template)\(\s*`(\w+)'/gm)) names.set(m[1], layer);
    }
  }
  develIfCache = { key, value: { names, modules } };
  return develIfCache.value;
}

/**
 * The service editor's context. standalone: a module packaged on its own
 * and built against the devel headers of the build host, so only their
 * interfaces exist (also deciding the helper variants, e.g. files_pid_file
 * vs files_runtime_file), calls outside the kernel/system layers are
 * optional, and port types are declared in the module.
 */
function serviceCtx(standalone = false) {
  const base = treeServiceCtx();
  if (!standalone || usingDevel) return base;
  const dev = develInterfaces();
  if (!dev) return base;
  return {
    ...base, standalone: true, corenet: false, moduleArgs: 2,
    has: (n) => dev.names.has(n),
    optional: (n) => { const l = dev.names.get(n); return !!l && !['kernel', 'system'].includes(l); },
    moduleExists: (n) => base.moduleExists(n) || dev.modules.has(n),
    portRef: ['http', 'ssh', 'ntp'].find(n => dev.names.has(`corenet_tcp_bind_${n}_port`)) || null,
  };
}

function treeServiceCtx() {
  const fileOf = (p) => idx.files.get(p);
  let moduleArgs = 2;
  let one = 0, two = 0;
  for (const f of idx.files.values()) {
    if (!/\.te$/.test(f.path) || !f.calls) continue;
    const pm = f.calls.find(c => c.name === 'policy_module');
    if (pm) { if (pm.args.length === 1) one++; else two++; }
  }
  if (one > two) moduleArgs = 1;
  const mods = new Set(idx.modules().map(m => m.module));
  return {
    has: (n) => idx.defs.has(n),
    // Name patterns a template declares ($1_t, …), to read back domains declared by one.
    declares: (n) => (((idx.defs.get(n) || [])[0] || {}).declPatterns || []).map(p => p.pattern),
    // Start calls inside templates (rpc_domain_template(nfsd) starts nfsd_t).
    startsVia: (n) => startingTemplates().startsVia(n),
    // Calls into modules that may be turned off belong in optional_policy.
    optional: (n) => {
      const d = (idx.defs.get(n) || [])[0];
      const f = d && fileOf(d.path);
      if (!f) return false;
      if (idx.moduleKinds && idx.moduleKinds.has(f.module)) return idx.moduleKinds.get(f.module) !== 'base';
      return !['kernel', 'system'].includes(f.layer);
    },
    // The module defining it is off in this tree (modules.conf): calling it outside optional_policy fails to link.
    off: (n) => {
      const d = (idx.defs.get(n) || [])[0];
      const f = d && fileOf(d.path);
      return !!(f && idx.moduleKinds && idx.moduleKinds.get(f.module) === 'off') && f.module;
    },
    moduleArgs,
    moduleExists: (n) => mods.has(n),
    typeExists: (t) => idx.decls.has(t),
    boolExists: (n) => (idx.decls.get(n) || []).some(d => d.kind === 'bool'),
    condSafe: makeCondSafe(),
    // New port types go into corenetwork.te.in (trees); its numbers for conflict checks.
    corenet: !!corenetPath(),
    portNums: networkPorts().flatMap(p => p.nums.map(x => {
      const m = /^(\d+)(?:-(\d+))?$/.exec(x.port);
      return m ? { name: p.name, proto: x.proto, lo: +m[1], hi: m[2] ? +m[2] : +m[1] } : null;
    }).filter(Boolean)),
    portRef: ['http', 'ssh', 'ntp'].find(n => idx.defs.has(`corenet_tcp_bind_${n}_port`)) || null,
  };
}

/** Booleans and tunables declared in the tree (outside module `except`), for "use an existing boolean". */
function serviceBools(except) {
  const out = [];
  for (const [n, list] of idx.decls) {
    const d = list.find(x => x.kind === 'bool');
    if (!d || d.generated) continue;
    const f = idx.files.get(d.path);
    if (f && except && f.module === except) continue;
    out.push({ n, s: ((d.doc && (d.doc.desc || d.doc.summary)) || '').replace(/\s+/g, ' ').trim(), m: f ? f.module : '', def: d.default || '' });
  }
  return out.sort((a, b) => a.n.localeCompare(b.n));
}

/** The workspace's modules that the editor can open: a .te with a call that starts a service (init_daemon_domain, dbus_system_domain, …). */
function serviceModules() {
  const out = [];
  for (const m of idx.modules()) {
    if (!m.files.te || (treeRoot && !m.files.te.startsWith(treeRoot + path.sep) && !isStandaloneModule(m.files.te))) continue;
    const text = readSource(m.files.te);
    const st = startingTemplates();
    if (!text || !(service.ENTRY_RE.test(text) || st.re.test(text))) continue;
    const domains = service.daemonDomains(text, { startsVia: st.startsVia, web: st.web });
    if (!domains.length) continue;
    out.push({ module: m.module, layer: m.layer, files: m.files, domains });
  }
  return out;
}

/**
 * Templates and interfaces whose body (through nested calls) starts a service domain, e.g.
 * rpc_domain_template: startsVia(name) → [{ d: '$1_t', e: '$1_exec_t', via }], and a regex
 * matching calls to any of them. Cached per index generation.
 */
let startingCache = null;
function startingTemplates() {
  if (startingCache && startingCache.defs === idx.defs) return startingCache;
  const startsVia = service.makeStartsVia((n) => (idx.defs.get(n) || [])[0]);
  const names = [...idx.defs.keys()].filter(n => /^\w+$/.test(n) && !service.ENTRY_CALLS.includes(n) && startsVia(n).length);
  // Web applications: apache_content_template declares the domain Apache runs the scripts in.
  const web = service.webPatterns({ has: (n) => idx.defs.has(n), declares: (n) => (((idx.defs.get(n) || [])[0] || {}).declPatterns || []).map(p => p.pattern) });
  if (web) names.push(web.template);
  const re = names.length ? new RegExp(`\\b(${names.join('|')})\\s*\\(`) : /$^/;
  startingCache = { defs: idx.defs, startsVia, names, re, web };
  return startingCache;
}

/** Where a new module's files go: a layer of the tree, or a folder (standalone modules). */
function newServicePaths(name, where, standalone = false) {
  let dir;
  if (standalone && treeRoot && !usingDevel) dir = where && path.isAbsolute(where) ? where : path.join(roots[0] || treeRoot, `${name}-selinux`);
  else if (treeRoot && !usingDevel) dir = path.join(treeRoot, 'policy', 'modules', where && /^[\w-]+$/.test(where) ? where : 'services');
  else dir = where && path.isAbsolute(where) ? where : path.join(roots[0] || '.', name);
  return { te: path.join(dir, `${name}.te`), if: path.join(dir, `${name}.if`), fc: path.join(dir, `${name}.fc`) };
}

/** Port types from corenetwork's network_port() calls: name -> 'tcp 80,443; udp 80'. */
function servicePorts() {
  const ports = new Map();
  for (const f of idx.files.values()) {
    for (const c of f.calls || []) {
      if (c.inDef || !/^network_port$/.test(c.name) || !c.args[0] || !idx.isActive(f, c.l, c.c)) continue;
      const by = {};
      for (let i = 1; i + 1 < c.args.length; i += 3) { const p = c.args[i]; if (/^(tcp|udp|sctp|dccp)$/.test(p)) (by[p] = by[p] || []).push(c.args[i + 1]); }
      ports.set(c.args[0], Object.entries(by).map(([p, n]) => `${p} ${n.join(',')}`).join('; '));
    }
  }
  // Port types without numbers (network_port(name) or generic ones) still have interfaces.
  for (const n of idx.defs.keys()) { const m = /^corenet_tcp_bind_(\w+)_port$/.exec(n); if (m && !ports.has(m[1])) ports.set(m[1], ''); }
  return [...ports.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([name, nums]) => ({ name, nums }));
}

/** Interfaces taking just a domain, for the "other interfaces" picker. */
function serviceInterfaces(condSafe) {
  const out = [];
  // How many modules call each interface (a hint of what services usually need).
  const uses = new Map();
  for (const file of idx.files.values()) {
    if (!/\.te$/.test(file.path)) continue;
    for (const n of new Set((file.calls || []).map(c => c.name))) uses.set(n, (uses.get(n) || 0) + 1);
  }
  for (const [n, list] of idx.defs) {
    const d = list[0];
    if (d.generated || d.kind !== 'interface' || !/\.if(\.in)?$/.test(d.path)) continue;
    const ps = d.doc && d.doc.params;
    if (!(ps ? ps.length === 1 : d.maxArg === 1)) continue;
    // Its one argument is a domain (not a type, role or name prefix: files_pid_file, term_login_pty, …).
    if (ps && ps[0] && ps[0].name && (!/domain|^user/i.test(ps[0].name) || /prefix/i.test(ps[0].name))) continue;
    const f = idx.files.get(d.path);
    const it = { n, s: (d.doc && d.doc.summary || '').replace(/\s+/g, ' ').trim(), m: f ? f.module : '' };
    // The types it requires itself (not through other interfaces): the keyword search matches them too.
    const ts = [...new Set((d.requires || []).filter(r => r.kind === 'type' && /^\w+$/.test(r.name)).map(r => r.name))].slice(0, 8);
    if (ts.length) it.t = ts;
    if (uses.get(n)) it.c = uses.get(n);
    if (condSafe && !condSafe(n)) it.u = 1; // not allowed under a boolean
    out.push(it);
  }
  return out.sort((a, b) => a.n.localeCompare(b.n));
}

function serviceTexts(files) {
  return { te: readSource(files.te) || '', if: (files.if && readSource(files.if)) || '', fc: (files.fc && readSource(files.fc)) || '' };
}

connection.onRequest('selinux/serviceList', async () => {
  await indexing;
  return { modules: serviceModules().map(m => ({ module: m.module, layer: m.layer, domains: m.domains })) };
});

connection.onRequest('selinux/serviceInfo', async ({ module: mod, domain, standalone, prefill } = {}) => {
  await indexing;
  if (!treeRoot && !usingDevel) return { unavailable: 'Open a policy source tree or a standalone module folder first.' };
  const existing = mod ? serviceModules().find(x => x.module === mod) : null;
  const canStandalone = !!treeRoot && !usingDevel && !!develInterfaces();
  // Standalone: a module packaged on its own (devel headers); in a tree workspace a choice for new modules.
  const sa = usingDevel || (canStandalone && (existing ? isStandaloneModule(existing.files.te) : !!standalone));
  const ctx = serviceCtx(sa);
  const inTree = !!treeRoot && !usingDevel && !sa;
  const dev = sa && !usingDevel ? develInterfaces() : null;
  const info = {
    catalog: service.catalog(ctx),
    ports: dev ? servicePorts().filter(p => dev.names.has(`corenet_tcp_bind_${p.name}_port`) || dev.names.has(`corenet_udp_bind_${p.name}_port`)) : servicePorts(),
    interfaces: dev ? serviceInterfaces(ctx.condSafe).filter(x => dev.names.has(x.n)) : serviceInterfaces(ctx.condSafe),
    mode: inTree ? 'tree' : 'module',
    layers: inTree ? fs.readdirSync(path.join(treeRoot, 'policy', 'modules'), { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name).sort() : null,
    folder: roots[0] || null,
    folderSuffix: sa && !usingDevel ? '-selinux' : '',
    // License for the RPM spec of a standalone module: common ones, the user's saved ones, their default.
    licenses: sa ? { common: packaging.LICENSES, custom: [...new Set((settings.packaging.customLicenses || []).map(x => String(x).trim()).filter(Boolean))], default: (settings.packaging.license || '').trim() || 'MIT' } : null,
    standalone: sa, canStandalone: canStandalone && !mod,
    develMakefile: settings.build.develMakefile,
  };
  if (info.layers) info.defaultLayer = ['contrib', 'services'].find(l => info.layers.includes(l)) || info.layers[0];
  info.bools = serviceBools(mod);
  if (!mod) {
    const model = service.newModel();
    // From the denial assistant: a program that has no policy yet.
    if (prefill && typeof prefill.exec === 'string' && prefill.exec.startsWith('/')) {
      model.exec = [prefill.exec];
      const base = path.basename(prefill.exec).toLowerCase().replace(/\.(sh|py|pl|bin)$/, '').replace(/[^a-z0-9_]+/g, '_').replace(/^[^a-z]+/, '').replace(/_+$/, '');
      if (base && !serviceCtx(sa).moduleExists(base)) model.name = base;
    }
    return { ...info, isNew: true, model };
  }
  const m = existing;
  if (!m) return { unavailable: `${mod} has no init_daemon_domain() in its .te (nor another call that starts a service, such as dbus_system_domain() or inetd_service_domain()), so it isn't a service module the editor understands.` };
  const rec = service.recognize(serviceTexts(m.files), ctx, { domain, module: mod, ports: ownedPorts(mod) });
  if (rec.error) return { unavailable: rec.error };
  const prov = new Set(rec.provided);
  rec.model.provides = service.PROVIDES.map(p => p[0]).filter(id => prov.has(service.PROVIDES.find(p => p[0] === id)[1].replace(/%/g, mod)));
  // An existing standalone module gets a spec only if it has none yet: only then does the license matter.
  if (info.licenses && fs.existsSync(path.join(path.dirname(m.files.te), `${mod}-selinux.spec`))) info.licenses = null;
  return { ...info, isNew: false, module: mod, layer: m.layer, files: m.files, model: rec.model, kept: rec.kept, provided: rec.provided, domains: rec.domains };
});

connection.onRequest('selinux/servicePlan', async ({ model, module: mod, where, standalone, license }) => {
  await indexing;
  const isNew = !mod;
  const existingMod = mod ? serviceModules().find(x => x.module === mod) : null;
  const sa = usingDevel || (!!treeRoot && !!develInterfaces() && (existingMod ? isStandaloneModule(existingMod.files.te) : !!standalone));
  const ctx = serviceCtx(sa);
  let paths, before, rec = null;
  if (!isNew) {
    const m = serviceModules().find(x => x.module === mod);
    if (!m) return { problems: [`${mod} is no longer a service module.`], files: [] };
    paths = { te: m.files.te, if: m.files.if || m.files.te.replace(/\.te$/, '.if'), fc: m.files.fc || m.files.te.replace(/\.te$/, '.fc') };
    before = serviceTexts(m.files);
    rec = service.recognize(before, ctx, { domain: model.domain, ports: ownedPorts(mod) });
  }
  // Checks on what the user adds (an existing module isn't blamed for what it already has).
  const problems = service.validate(model, ctx, { isNew, baseline: rec && !rec.error ? rec.model : null });
  if (isNew && problems.some(p => /name must|already exists/.test(p))) return { problems, files: [] };
  if (isNew) {
    paths = newServicePaths(model.name, where, sa);
    before = { te: null, if: null, fc: null };
  } else {
    // Removing a file type that the .if or other modules still use would break the build.
    if (!rec.error) {
      const keep = new Set((model.files || []).map(r => service.fileType(model, r, ctx)));
      for (const r of rec.model.files) {
        if (keep.has(r.type)) continue;
        const uses = idx.referencesOf(r.type).filter(u => u.path !== paths.te && u.path !== paths.fc);
        if (uses.length) problems.push(`${r.type} is still used in ${rel(uses[0].path)}:${uses[0].l + 1}${uses.length > 1 ? ` and ${uses.length - 1} more place${uses.length > 2 ? 's' : ''}` : ''}; remove those uses first, or keep the type.`);
      }
      // Likewise a boolean declared here that other modules or the rules kept as they are still test.
      const keepB = new Set((model.booleans || []).filter(b => !b.external).map(b => b.name));
      for (const b of rec.model.booleans.filter(x => !x.external && !keepB.has(x.name))) {
        const uses = idx.referencesOf(b.name).filter(u => u.path !== paths.te);
        const keptUse = rec.kept.find(k => new RegExp(`\\b${b.name}\\b`).test(k.text));
        if (uses.length) problems.push(`Boolean ${b.name} is still used in ${rel(uses[0].path)}:${uses[0].l + 1}; remove that use first, or keep the boolean.`);
        else if (keptUse) problems.push(`Boolean ${b.name} is still used on line ${keptUse.l + 1} of ${path.basename(paths.te)} (kept as is); remove that use first, or keep the boolean.`);
      }
      // And a helper domain whose types are used outside what the editor models.
      const keepH = new Set((model.helpers || []).map(h => service.helperNames(model, h).H));
      for (const h of rec.model.helpers.filter(x => !keepH.has(service.helperNames(rec.model, x).H))) {
        const { H, HE } = service.helperNames(rec.model, h);
        for (const t of [H, HE]) {
          const uses = idx.referencesOf(t).filter(u => u.path !== paths.te && u.path !== paths.fc);
          const keptUse = rec.kept.find(k => new RegExp(`\\b${t}\\b`).test(k.text));
          if (uses.length) problems.push(`${t} is still used in ${rel(uses[0].path)}:${uses[0].l + 1}${uses.length > 1 ? ` and ${uses.length - 1} more place${uses.length > 2 ? 's' : ''}` : ''}; remove those uses first, or keep the helper.`);
          else if (keptUse) problems.push(`${t} is still used on line ${keptUse.l + 1} of ${path.basename(paths.te)} (kept as is); remove that use first, or keep the helper.`);
          if (uses.length || keptUse) break;
        }
      }
    }
  }
  const cp = sa ? null : corenetPath();
  const corenet = cp ? { text: readSource(cp) || '', ports: isNew ? [] : ownedPorts(mod) } : null;
  const out = service.plan(model, ctx, isNew ? null : before, corenet);
  if (out.error) return { problems: [out.error], files: [] };
  const files = [];
  for (const k of ['te', 'if', 'fc']) {
    const old = before[k] || '';
    files.push({ path: paths[k], kind: k, exists: !isNew && fs.existsSync(paths[k]), text: out[k], changed: out[k] !== old, diff: service.lineDiff(old, out[k]) });
  }
  // New or changed port types: corenetwork.te.in.
  if (corenet && out.net != null && out.net !== corenet.text) files.push({ path: cp, kind: 'net', exists: true, text: out.net, changed: true, diff: service.lineDiff(corenet.text, out.net) });
  // A standalone module gets RPM packaging (written once; edit it freely afterwards).
  if (sa && model.name) {
    const dir = path.dirname(paths.te);
    const version = (/policy_module\(\s*\w+\s*,\s*([^)\s]+)\s*\)/.exec(out.te) || [])[1] || '1.0.0';
    const ports = [];
    for (const p of model.ports || []) {
      const type = `${p.name || model.name}_port_t`;
      for (const x of p.nums || []) if (x.port) ports.push({ type, proto: x.proto, port: x.port });
    }
    const spec = path.join(dir, `${model.name}-selinux.spec`), mk = path.join(dir, 'Makefile');
    if (readSource(spec) == null) {
      const lic = license != null ? String(license).trim() : ((settings.packaging.license || '').trim() || 'MIT');
      const why = packaging.licenseProblem(lic);
      if (why) problems.push(why);
      const text = packaging.specText({ name: model.name, version, summary: model.summary, ports, packager: gitPackager(dir), license: lic });
      files.push({ path: spec, kind: 'spec', exists: false, text, changed: true, diff: service.lineDiff('', text) });
    }
    if (readSource(mk) == null) {
      const text = packaging.makefileText(model.name);
      files.push({ path: mk, kind: 'make', exists: false, text, changed: true, diff: service.lineDiff('', text) });
    }
  }
  // A new module in a tree is built only when modules.conf lists it.
  if (isNew && treeRoot && !usingDevel && !sa) {
    const { conf, states } = moduleStates(treeRoot);
    if (conf && !states.has(model.name)) {
      const part = conf.parts[conf.parts.length - 1];
      const text = part.text.replace(/\s*$/, '\n') + `\n# ${model.summary || model.name}\n${model.name} = module\n`;
      files.push({ path: part.path, kind: 'conf', exists: true, text, changed: true, diff: service.lineDiff(part.text, text) });
    }
  }
  return { problems, files };
});

/* ---------------- user editor ---------------- */

const userfiles = require('./userfiles');
const USERS_FILE = 'policy/users';

/** The users file the build uses: the spec overlay (RHEL users-targeted) if configured, else policy/users. */
function effectiveUsersFile(root) {
  const overlay = treeCfg().files && treeCfg().files[USERS_FILE];
  if (overlay) {
    const src = [].concat(overlay).map(s => resolveOverlay(root, s)).pop();
    const p = typeof src === 'string' ? src : src && src.from;
    if (p) return { path: p, text: readSource(p) };
  }
  const p = path.join(root, USERS_FILE);
  return { path: p, text: readSource(p) };
}

/** The service context plus the role catalog (userfiles.userTreeCtx), cached per index generation. */
let userCtxCache = null;
function userCtx() {
  const base = serviceCtx(false);
  if (!userCtxCache || userCtxCache.defs !== idx.defs) {
    const u = userfiles.userTreeCtx(idx, {});
    userCtxCache = { defs: idx.defs, extra: { params: u.params, roleIfaces: u.roleIfaces, roleExists: u.roleExists, roleCalls: u.roleCalls } };
  }
  return { ...base, ...userCtxCache.extra };
}

/** The tree's login configuration files for a user: seusers and <user>_default_contexts in config/appconfig-<TYPE>. */
function userConfigPaths(name) {
  const dir = appconfigDir(treeRoot);
  return { seusers: path.join(dir, 'seusers'), contexts: path.join(dir, `${name}_u_default_contexts`) };
}

/** The tree's user role modules: a .te with a userdomain template call on a name (staff, sysadm, webadm, …). */
function userModules() {
  const out = [];
  const re = new RegExp(`\\b(${service.USER_TEMPLATES.join('|')})\\s*\\(`);
  for (const m of idx.modules()) {
    if (!m.files.te || !treeRoot || !m.files.te.startsWith(treeRoot + path.sep)) continue;
    const text = readSource(m.files.te);
    if (!text || !re.test(text)) continue;
    const u = service.userDomainOf(text);
    if (u) out.push({ module: m.module, layer: m.layer, files: m.files, stem: u.stem, user: `${u.stem}_u`, kind: u.kind });
  }
  return out.sort((a, b) => a.module.localeCompare(b.module));
}

/** An existing user's files: the module's, the users file, seusers, its contexts file and default_contexts. */
function userTexts(m) {
  const cp = userConfigPaths(m.stem);
  const uf = effectiveUsersFile(treeRoot);
  return {
    paths: { te: m.files.te, if: m.files.if || m.files.te.replace(/\.te$/, '.if'), fc: m.files.fc || m.files.te.replace(/\.te$/, '.fc'), users: uf.path, seusers: cp.seusers, contexts: cp.contexts, defaults: path.join(path.dirname(cp.seusers), 'default_contexts') },
    te: readSource(m.files.te) || '', if: (m.files.if && readSource(m.files.if)) || '', fc: (m.files.fc && readSource(m.files.fc)) || '',
    users: uf.text, seusers: readSource(cp.seusers), contexts: readSource(cp.contexts), defaults: readSource(path.join(path.dirname(cp.seusers), 'default_contexts')),
  };
}

/** An existing user's model as read back from its module and the login files ({ error } when not a user module). */
function readExistingUser(m, ctx) {
  const t = userTexts(m);
  const rec = service.recognize({ te: t.te, if: t.if, fc: t.fc }, ctx, { user: true, module: m.module });
  if (rec.error) return { error: rec.error };
  userfiles.readUser(rec.model, t);
  const prov = new Set(rec.provided);
  rec.model.provides = ['role_change', 'role_change_to'].filter(id => prov.has(`${m.module}_${id}`));
  return { rec, texts: t };
}

connection.onRequest('selinux/userList', async () => {
  await indexing;
  return { modules: userModules().map(({ module, layer, stem, user, kind }) => ({ module, layer, stem, user, kind })) };
});

connection.onRequest('selinux/userInfo', async ({ module: mod } = {}) => {
  await indexing;
  if (!treeRoot || usingDevel) return { unavailable: 'The user editor works on a policy source tree (open one as the workspace).' };
  const ctx = userCtx();
  if (mod) {
    const m = userModules().find(x => x.module === mod);
    if (!m) return { unavailable: `${mod} isn't a user role module (no userdomain template call on a name in its .te).` };
    const r = readExistingUser(m, ctx);
    if (r.error) return { unavailable: r.error };
    const uf = effectiveUsersFile(treeRoot);
    return {
      isNew: false, module: mod, model: r.rec.model, kept: r.rec.kept, files: r.texts.paths,
      catalog: service.userCatalog(ctx, userfiles.WAYS.filter(([, , sources]) => sources.some(s => ctx.typeExists(s)))),
      interfaces: serviceInterfaces(ctx.condSafe),
      users: [...new Set(userfiles.parseGenUsers(uf.text || '').map(u => u.name))].filter(n => n !== 'system_u' && n !== `${m.stem}_u`).sort(),
      usersFile: uf.path, configDir: path.dirname(r.texts.paths.seusers), prefixDefault: r.rec.model.prefix || m.stem,
      seusers: userfiles.parseSeusers(r.texts.seusers || ''),
    };
  }
  const uf = effectiveUsersFile(treeRoot);
  const genUsers = userfiles.parseGenUsers(uf.text || '');
  // The home directory prefix most users of this tree have (Fedora/RHEL: user; upstream: the role's name).
  // A prefix shared by most users (Fedora/RHEL: user) is the default; when most users have their own (upstream), none.
  const counts = new Map();
  let own = 0;
  for (const u of genUsers) {
    if (u.name === 'system_u' || !/^\w+$/.test(u.prefix)) continue;
    if (u.prefix === u.name.replace(/_u$/, '')) own++;
    else counts.set(u.prefix, (counts.get(u.prefix) || 0) + 1);
  }
  const prefix = [...counts].sort((a, b) => b[1] - a[1])[0];
  const model = service.newUserModel();
  if (prefix && prefix[1] > 1 && prefix[1] > own) model.prefix = prefix[0];
  const cp = userConfigPaths('x');
  return {
    isNew: true, model,
    catalog: service.userCatalog(ctx, userfiles.WAYS.filter(([, , sources]) => sources.some(s => ctx.typeExists(s)))),
    interfaces: serviceInterfaces(ctx.condSafe),
    users: [...new Set(genUsers.map(u => u.name))].filter(n => n !== 'system_u').sort(),
    usersFile: uf.path, configDir: path.dirname(cp.seusers), prefixDefault: model.prefix || '(the user’s name)',
    seusers: userfiles.parseSeusers(readSource(cp.seusers) || ''),
  };
});

/**
 * Minimal edits for an existing user: its module through the service editor's unit diff, the
 * gen_user line (fields that changed; role switches added or removed; other users' lines for
 * grantUsers), seusers lines of its user, its contexts file (ways and sudo/su lines toggled).
 */
function existingUserPlan(model, m, ctx) {
  const r = readExistingUser(m, ctx);
  if (r.error) return { problems: [r.error], files: [] };
  const prev = r.rec.model, t = r.texts, P = t.paths;
  const U = `${m.stem}_u`;
  const taken = new Map(userfiles.parseSeusers(t.seusers || '').filter(x => x.user !== U).map(x => [x.login, x.user]));
  const problems = service.validate(model, ctx, { isNew: false, baseline: prev, loginTaken: (n) => taken.get(n) || null })
    .filter(p => !/^Note: no (way to log in is ticked|role may switch)/.test(p) || JSON.stringify(model.ways) !== JSON.stringify(prev.ways) || JSON.stringify(model.enteredFrom) !== JSON.stringify(prev.enteredFrom));
  const out = service.plan(model, ctx, { te: t.te, if: t.if, fc: t.fc }, null);
  if (out.error) return { problems: [out.error], files: [] };
  const files = [];
  const push = (p, kind, old, text) => { if (text != null && text !== (old || '')) files.push({ path: p, kind, exists: old != null, text, changed: true, diff: service.lineDiff(old || '', text) }); };
  for (const k of ['te', 'if', 'fc']) push(P[k], k, t[k], out[k]);
  const switched = JSON.stringify([...(model.switchTo || [])].sort()) !== JSON.stringify([...(prev.switchTo || [])].sort());
  const fields = ['prefix', 'level', 'range', 'cats'].some(k => (model[k] || '') !== (prev[k] || ''));
  if (!prev.genUser.exists && (fields || (model.logins || []).some(l => (l.login || '').trim()))) problems.push(`${U} has no gen_user line in ${rel(P.users)}, so it has no levels or logins of its own; users get ${m.stem}_r through their own lines (below).`);
  if (prev.genUser.exists && !prev.genUser.simple && (switched || fields)) problems.push(`${U}'s gen_user line in ${rel(P.users)} is written with ifdef() or more than once, so the editor doesn't rewrite it; change its roles or levels there by hand.`);
  if (t.users != null) push(P.users, 'users', t.users, userfiles.editUsers(t.users, model, { prev, prevGrant: prev.grantUsers, prefix: prev.prefix }));
  if (t.seusers != null && prev.genUser.exists) push(P.seusers, 'seusers', t.seusers, userfiles.editSeusers(t.seusers, model));
  const level = (/^s\d+/.exec(model.level || 's0') || ['s0'])[0];
  const ctxNew = userfiles.editContexts(t.contexts, model, prev, { typeExists: ctx.typeExists, level });
  if (ctxNew != null && ctxNew !== (t.contexts || '')) push(P.contexts, 'contexts', t.contexts, ctxNew);
  // A way turned off also comes off default_contexts, which libselinux falls back to (shared by all users: only this role's context goes).
  const defNew = userfiles.editDefaults(t.defaults, model, prev);
  if (defNew !== t.defaults) push(P.defaults, 'defaults', t.defaults, defNew);
  return { problems, files };
}

connection.onRequest('selinux/userPlan', async ({ model, module: mod }) => {
  await indexing;
  if (!treeRoot || usingDevel) return { problems: ['The user editor works on a policy source tree.'], files: [] };
  const ctx = userCtx();
  if (mod) {
    const m = userModules().find(x => x.module === mod);
    if (!m) return { problems: [`${mod} is no longer a user role module.`], files: [] };
    return existingUserPlan(model, m, ctx);
  }
  const U = `${model.name}_u`;
  const cp = userConfigPaths(model.name);
  const seText = readSource(cp.seusers);
  const taken = new Map(userfiles.parseSeusers(seText || '').filter(x => x.user !== U).map(x => [x.login, x.user]));
  const problems = service.validate(model, ctx, { isNew: true, loginTaken: (n) => taken.get(n) || null });
  if (model.user && (model.ways || []).includes('cron') && ctx.has('cron_role') && !(model.roleCalls || []).includes('cron_role')) problems.push('Note: cron jobs run in the user’s domain only with the cron role call (cron_role); add it under Programs.');
  if (problems.some(p => /name must|already exists|already declared/.test(p))) return { problems, files: [] };
  const paths = newServicePaths(model.name, 'roles');
  for (const k of ['te', 'if', 'fc']) if (fs.existsSync(paths[k])) { problems.push(`${rel(paths[k])} already exists.`); return { problems, files: [] }; }
  const out = service.plan(model, ctx, null, null);
  const files = [];
  const push = (p, kind, old, text) => { if (text !== (old || '')) files.push({ path: p, kind, exists: old != null, text, changed: true, diff: service.lineDiff(old || '', text) }); };
  for (const k of ['te', 'if', 'fc']) files.push({ path: paths[k], kind: k, exists: false, text: out[k], changed: true, diff: service.lineDiff('', out[k]) });
  const uf = effectiveUsersFile(treeRoot);
  if (uf.text == null) problems.push(`No users file at ${rel(uf.path)}: add the gen_user line yourself.`);
  else push(uf.path, 'users', uf.text, userfiles.editUsers(uf.text, model, { comment: model.summary }));
  // The users file is part of the base module: base must declare the role too (kernel.te, as for staff_r).
  const kmod = idx.modules().find(x => x.module === 'kernel' && x.files.te && x.files.te.startsWith(treeRoot + path.sep));
  const kText = kmod ? readSource(kmod.files.te) : null;
  const kNew = kText != null ? userfiles.editKernelRoles(kText, `${model.name}_r`) : null;
  if (kNew == null) problems.push('No role declarations found in kernel.te: declare the role in a base module yourself, or the gen_user line won’t compile.');
  else push(kmod.files.te, 'kernel', kText, kNew);
  if (seText == null) { if ((model.logins || []).some(l => (l.login || '').trim())) problems.push(`No seusers file at ${rel(cp.seusers)}: map the logins with semanage login after installing.`); }
  else push(cp.seusers, 'seusers', seText, userfiles.editSeusers(seText, model));
  const level = (/^s\d+/.exec(model.level || 's0') || ['s0'])[0];
  const ctxText = userfiles.contextsText(model, { typeExists: ctx.typeExists, level });
  const oldCtx = readSource(cp.contexts);
  if (ctxText || oldCtx != null) push(cp.contexts, 'contexts', oldCtx, ctxText);
  const { conf, states } = moduleStates(treeRoot);
  if (conf && !states.has(model.name)) {
    const part = conf.parts[conf.parts.length - 1];
    const text = part.text.replace(/\s*$/, '\n') + `\n# ${model.summary || `The ${model.name} user role`}\n${model.name} = module\n`;
    files.push({ path: part.path, kind: 'conf', exists: true, text, changed: true, diff: service.lineDiff(part.text, text) });
  }
  return { problems, files };
});

/*
 * Assertions about the compiled policy, kept in a file in the tree and
 * evaluated by policy_query.py after every successful build and whenever the
 * file is saved or edited. Failures become diagnostics on the checks file,
 * with related information pointing at the source statements that grant the
 * violating rules; code lenses show ✓/✗ per check.
 */
const checksLib = require('./checks');
let checksState = { path: null, parsed: null, results: null, note: null };

// In a tree: at its root. Standalone modules: at the workspace folder, checked against the installed policy.
const checksRoot = () => treeRoot || (usingDevel ? roots[0] : null);
const checksPath = () => (checksRoot() ? path.join(checksRoot(), settings.checks.file || 'selinux.checks') : null);
const isChecksFile = (p) => !!checksRoot() && p === checksPath();

async function runChecks() {
  const file = checksPath();
  if (!file) return;
  const text = readSource(file);
  if (text == null) {
    if (checksState.path) { connection.sendDiagnostics({ uri: toUri(checksState.path), diagnostics: [] }); checksState = { path: null, parsed: null, results: null, note: null }; }
    return;
  }
  const parsed = checksLib.parseChecks(text);
  checksState = { path: file, parsed, results: null, note: null };
  const model = await getPolicyModel();
  if (model.unavailable) {
    checksState.note = model.needsBuild ? (usingDevel ? 'not checked yet: build the module' : 'not checked yet: build the policy') : model.unavailable;
  } else if (parsed.checks.length) {
    const r = await policyQuery.request({ op: 'check', bin: model.bin, checks: parsed.checks.map(c => ({ id: c.id, kind: c.kind, sources: c.sources, targets: c.targets, classes: c.classes, perms: c.perms, except: c.except, weight: c.weight })) });
    if (r.error) checksState.note = `checks failed: ${r.error}`;
    else {
      checksState.results = new Map(r.results.map(x => [x.id, x]));
      // Trace the violating rules (a few per check) and each step of an information-flow path to source.
      const failing = r.results.filter(x => (x.violations && x.violations.length) || x.flow);
      if (failing.length) {
        const side = await currentSide();
        if (side) {
          for (const x of failing) {
            for (const v of (x.violations || []).slice(0, 8)) v.origins = explain.explainRule(v.rule, v.perms, side, 3).origins;
            for (const st of x.flow || []) st.origins = explain.explainRule(st.rule, st.perms, side, 1).origins;
          }
          explain.releaseTexts();
        }
      }
      checksState.builtAt = model.builtAt;
    }
  }
  if (readSource(file) !== text) return; // edited meanwhile; a newer run follows
  connection.sendDiagnostics({ uri: toUri(file), diagnostics: checksDiagnostics() });
  connection.sendNotification('selinux/checks', checksSummary());
}

function checksSummary() {
  const s = checksState;
  if (!s.parsed) return { total: 0 };
  const res = s.results ? [...s.results.values()] : [];
  return { total: s.parsed.checks.length, failed: res.filter(x => !x.ok).length, errors: s.parsed.errors.length, note: s.note };
}

const lineRange = (l, text) => ({ start: { line: l, character: 0 }, end: { line: l, character: (text || '').length } });

function checksDiagnostics() {
  const s = checksState;
  if (!s.parsed) return [];
  const lines = (readSource(s.path) || '').split('\n');
  const out = s.parsed.errors.map(e => ({ range: range(e.l, e.c, e.len), severity: DiagnosticSeverity.Error, source: 'selinux-checks', message: e.msg }));
  if (!s.results) return out;
  for (const c of s.parsed.checks) {
    const x = s.results.get(c.id);
    if (!x || x.ok) continue;
    const d = { range: lineRange(c.line, lines[c.line].replace(/\s*#.*$/, '')), severity: DiagnosticSeverity.Error, source: 'selinux-checks', message: checkMessage(c, x) };
    const rel = [];
    for (const v of x.violations || []) {
      const o = v.origins && v.origins[0];
      if (o) rel.push({ location: { uri: toUri(o.path), range: range(o.line, 0, 1) }, message: `allow ${v.rule.s} ${v.rule.t}:${v.rule.c} { ${v.perms.join(' ')} }${v.rule.cond ? ` [${v.rule.cond}]` : ''} → ${v.sources.length} domain${v.sources.length > 1 ? 's' : ''}${o.via ? ` (via ${o.via})` : ''}` });
    }
    if (x.rbac) {
      const users = c.kind.endsWith('-use') ? userLocations() : null;
      for (const v of x.rbac) {
        const loc = users ? users.get(v.holder) : sourceLocation(v.holder, ['role']);
        if (loc) rel.push({ location: { uri: toUri(loc.p), range: range(loc.l, loc.c, loc.len) }, message: `${v.holder} ${users ? 'has roles' : 'may run'} ${v.items.join(', ')}` });
      }
    }
    for (const st of x.flow || []) {
      const o = st.origins && st.origins[0];
      const loc = o ? { p: o.path, l: o.line, c: 0, len: 1 } : sourceLocation(st.to, ['type']);
      if (loc) rel.push({ location: { uri: toUri(loc.p), range: range(loc.l, loc.c, loc.len) }, message: `${st.from} → ${st.to}: ${flowStep(st)}${o && o.via ? ` (via ${o.via})` : ''}` });
    }
    for (const step of x.path || []) {
      const loc = sourceLocation(step.to, ['type']);
      if (loc) rel.push({ location: { uri: toUri(loc.p), range: range(loc.l, loc.c, loc.len) }, message: `${step.from} → ${step.to} via ${step.entrypoints.join(', ')}${step.auto ? ' (automatic)' : ''}${step.conditional.length ? ` [${step.conditional.join(', ')}]` : ''}` });
    }
    if (rel.length) d.relatedInformation = rel.slice(0, 12);
    out.push(d);
  }
  return out;
}

/** One information-flow step as the rule behind it: "staff_t reads (allow staff_t etc_t:file { read })". */
function flowStep(st) {
  const r = st.rule;
  return `${st.dir === 'read' ? `${st.to} reads` : `${st.from} writes`} (allow ${r.s} ${r.t}:${r.c} { ${st.perms.join(' ')} }${r.cond ? ` [${r.cond}]` : ''})`;
}

function checkMessage(c, x) {
  if (x.error) return x.error;
  const names = (a) => a.join(', ');
  const domains = (v) => [...new Set(v.flatMap(y => y.sources))];
  if (c.kind === 'only' || c.kind === 'never') {
    const ds = domains(x.violations || []);
    const who = c.kind === 'only' ? `${ds.length} other domain${ds.length > 1 ? 's' : ''} (${ds.slice(0, 6).join(', ')}${ds.length > 6 ? ', …' : ''})` : names(ds);
    const verb = c.perms === '*' ? 'access' : c.permsLabel;
    return `${who} may ${verb} ${names(c.targets)}: ${x.count} rule${x.count > 1 ? 's' : ''}; the related information shows where they come from.`;
  }
  if (c.kind === 'flows') return `Data in ${x.flow[0].from} can reach ${x.flow[x.flow.length - 1].to}: ${[x.flow[0].from, ...x.flow.map(st => st.to)].join(' → ')}. Fix the policy, or list domains trusted to pass it on after 'except'.`;
  if (c.kind === 'reaches') return `${x.path[0].from} can reach ${x.path[x.path.length - 1].to}: ${[x.path[0].from, ...x.path.map(s => s.to)].join(' → ')}`;
  if (c.kind === 'require') return `Not allowed: ${x.missing.slice(0, 4).map(m => `${m.source} ${m.target}:${m.class} { ${m.missing.join(' ')} }`).join('; ')}${x.count > 4 ? ` (+${x.count - 4} more)` : ''}`;
  if (x.rbac) {
    const run = c.kind.endsWith('-run');
    const list = x.rbac.slice(0, 6).map(v => `${v.holder} (${v.items.slice(0, 3).join(', ')}${v.items.length > 3 ? ', …' : ''})`).join('; ');
    return run ? `${c.kind.startsWith('only') ? 'Other roles' : 'These roles'} may run ${names(c.targets)}: ${list}${x.count > 6 ? ` (+${x.count - 6} more)` : ''}`
      : `${c.kind.startsWith('only') ? 'Other users' : 'These users'} may use ${names(c.targets)}: ${list}${x.count > 6 ? ` (+${x.count - 6} more)` : ''}`;
  }
  return 'violated';
}

connection.onRequest('selinux/checksFile', async () => {
  await indexing;
  const p = checksPath();
  return p ? { path: p, exists: fs.existsSync(p), summary: checksSummary() } : { unavailable: 'Property checks need a policy source tree or a standalone module directory.' };
});

/** For a role, what the last build says about it (domains, users), appended to its hover. */
function compiledRoleNote(name) {
  const m = policyModelCache.model;
  const r = m && m.roles.find(x => x.name === name);
  if (!r) return '';
  const users = m.users.filter(u => u.roles.includes(name)).map(u => '`' + u.name + '`');
  return `\n\n**In the last build:** ${r.types.length} domain${r.types.length === 1 ? '' : 's'}; users ${users.join(', ') || 'none'}`;
}

/** If the cursor is inside gen_user(...), the 0-based argument index; else null. */
function genUserArg(doc, pos) {
  const text = doc.getText({ start: { line: Math.max(0, pos.line - 3), character: 0 }, end: pos });
  const at = text.lastIndexOf('gen_user(');
  if (at < 0) return null;
  let depth = 0, arg = 0;
  for (const ch of text.slice(at + 9)) {
    if (ch === '(') depth++;
    else if (ch === ')') { if (depth === 0) return null; depth--; }
    else if (ch === ',' && depth === 0) arg++;
  }
  return arg;
}

function genUserCompletion(arg, prefix) {
  const items = [];
  if (arg === 2) for (const r of [...idx.knownRoles()].sort()) if (r.startsWith(prefix) && r !== 'object_r') items.push({ label: r, kind: CompletionItemKind.EnumMember, detail: 'role' });
  if (arg >= 3) {
    for (const [n, list] of idx.defs) if (/^(mls|mcs)_/.test(n) && n.startsWith(prefix) && list.some(d => d.kind === 'define')) items.push({ label: n, kind: CompletionItemKind.Constant, detail: (list[0].doc && list[0].doc.summary) || 'MLS/MCS macro' });
    if ('s0'.startsWith(prefix)) items.push({ label: 's0', kind: CompletionItemKind.Value, detail: 'lowest sensitivity' });
  }
  return { isIncomplete: false, items };
}

/** Completion in the checks file: keywords, permission groups, and types/attributes (compiled policy if built). */
function checksCompletion(lineText) {
  const prefix = /[A-Za-z0-9_]*$/.exec(lineText)[0];
  const items = [];
  const words = lineText.trim().split(/\s+/);
  if (words.length <= 1) for (const k of ['only', 'never', 'require']) if (k.startsWith(prefix)) items.push({ label: k, kind: CompletionItemKind.Keyword });
  if (/\bmay\s+[A-Za-z]*$/.test(lineText)) for (const k of ['read', 'write', 'execute', 'any', 'run', 'use']) if (k.startsWith(prefix)) items.push({ label: k, kind: CompletionItemKind.Keyword, detail: k === 'any' ? 'any permission' : k === 'run' ? 'roles: may run <domains>' : k === 'use' ? 'users: may use <roles>' : (checksLib.PERM_GROUPS[k] || []).join(' ') });
  if (/^\s*(only|never|require)\b[^#]*[A-Za-z0-9_,]\s+[A-Za-z]*$/.test(lineText) && !/\b(may|reaches|flows)\b/.test(lineText)) for (const k of ['may', 'reaches', 'flows']) if (k.startsWith(prefix)) items.push({ label: k, kind: CompletionItemKind.Keyword });
  if (/\bflows\s+[A-Za-z]*$/.test(lineText) && 'to'.startsWith(prefix)) items.push({ label: 'to', kind: CompletionItemKind.Keyword });
  if (/\bflows\s+to\b[^#]*[A-Za-z0-9_,]\s+[A-Za-z]*$/.test(lineText)) {
    for (const k of ['except', 'weight']) {
      if (k.startsWith(prefix) && !new RegExp(`\\b${k}\\b`).test(lineText.slice(0, -prefix.length || undefined))) items.push({ label: k, kind: CompletionItemKind.Keyword, detail: k === 'except' ? 'types trusted to pass the data on' : 'weakest permission counted: 1 (all) to 10 (data reads/writes, default)' });
    }
  }
  if (prefix.length >= 2) {
    const m = policyModelCache.model;
    const types = m ? m.types.map(t => t.name) : [...idx.decls].filter(([, l]) => l.some(d => d.kind === 'type')).map(([n]) => n);
    const attrs = m ? m.attributes.map(a => a.name) : [...idx.decls].filter(([, l]) => l.some(d => d.kind === 'attribute')).map(([n]) => n);
    for (const n of types) if (n.startsWith(prefix) && items.length < 300) items.push({ label: n, kind: CompletionItemKind.Class });
    for (const n of attrs) if (n.startsWith(prefix) && items.length < 300) items.push({ label: n, kind: CompletionItemKind.Interface, detail: 'attribute' });
  }
  return { isIncomplete: true, items };
}

connection.onCodeLens(({ textDocument }) => {
  const p = toPath(textDocument.uri);
  const s = checksState;
  if (!isChecksFile(p) || !s.parsed || s.path !== p) return [];
  return s.parsed.checks.map((c) => {
    const x = s.results && s.results.get(c.id);
    let title;
    if (!x) title = s.note ? `… ${s.note}` : '…';
    else if (x.error) title = `⚠ ${x.error}`;
    else if (x.ok) title = '✓ holds';
    else if (c.kind === 'flows') title = `✗ data flows in ${x.flow.length} step${x.flow.length > 1 ? 's' : ''}`;
    else if (c.kind === 'reaches') title = `✗ reachable in ${x.path.length} step${x.path.length > 1 ? 's' : ''}`;
    else if (c.kind === 'require') title = `✗ ${x.count} missing`;
    else if (x.rbac) title = `✗ ${x.count} ${c.kind.endsWith('-run') ? 'role' : 'user'}${x.count > 1 ? 's violate' : ' violates'} it`;
    else title = `✗ violated by ${x.domains} domain${x.domains > 1 ? 's' : ''} (${x.count} rule${x.count > 1 ? 's' : ''})`;
    return { range: lineRange(c.line, ''), command: { title, command: '' } };
  });
});

/* ---------------- compiled policy model (setools export of the last build) ---------------- */

const policyModelCache = { bin: null, mtimeMs: 0, model: null };

/** Run one of the setools scripts next to this file; resolves with its JSON output. */
function runPython(script, args) {
  return new Promise((resolve, reject) => {
    require('child_process').execFile('python3', [path.join(__dirname, script), ...args], { maxBuffer: 64 << 20 }, (err, stdout, stderr) => {
      if (err) reject(new Error(/No module named 'setools'/.test(stderr) ? 'python3-setools is not installed (dnf install setools-console).' : (stderr || err.message).trim()));
      else resolve(JSON.parse(stdout));
    });
  });
}
const exportPolicy = (bin) => runPython('policy_model.py', [bin]);

/** Where a compiled element is declared: { p, l, c, len, m (module) }, preferring the tree being built. */
function sourceLocation(name, kinds) {
  const inTree = (x) => treeRoot && x.path.startsWith(treeRoot + path.sep);
  const list = (idx.decls.get(name) || []).filter(d => kinds.includes(d.kind));
  const d = list.find(inTree) || list[0];
  if (!d) return null;
  const f = idx.files.get(d.path);
  return { p: d.path, l: d.l, c: d.c, len: d.len, m: f ? f.module : null, via: d.generated ? d.via : undefined };
}

/**
 * Linux login → SELinux user mappings the build installs: the tree's
 * config/appconfig-<TYPE>/seusers (TYPE from the build arguments or
 * build.conf). Lines: login:seuser[:range]; '#' comments.
 */
function seusersMappings(root) {
  const file = path.join(appconfigDir(root), 'seusers');
  const text = readSource(file);
  if (text == null) return { file: null, list: [] };
  const list = [];
  text.split('\n').forEach((line, l) => {
    const t = line.replace(/#.*$/, '').trim();
    const m = /^([^:\s]+):([^:\s]+)(?::(.+))?$/.exec(t);
    if (m) list.push({ login: m[1], user: m[2], range: m[3] || null, loc: { p: file, l, c: 0 } });
  });
  return { file, list };
}

/** The tree's config/appconfig-<TYPE> (TYPE from the build arguments or build.conf; mcs by default). */
function appconfigDir(root) {
  let type = null;
  for (const a of treeCfg().makeArgs || []) { const m = /^TYPE=(\S+)/.exec(a); if (m) type = m[1]; }
  if (!type) { try { const m = /^\s*TYPE\s*=\s*(\S+)/m.exec(fs.readFileSync(path.join(root, 'build.conf'), 'utf8')); if (m) type = m[1]; } catch { /* none */ } }
  return path.join(root, 'config', `appconfig-${type || 'mcs'}`);
}

/** Users come from gen_user(name, ...) calls (refpolicy's policy/users file). */
function userLocations() {
  const out = new Map();
  for (const f of idx.files.values()) {
    for (const c of f.calls || []) {
      if (c.name === 'gen_user' && c.args[0] && !out.has(c.args[0])) out.set(c.args[0], { p: f.path, l: c.l, c: c.c, len: c.len, m: f.module });
    }
  }
  return out;
}

connection.onRequest('selinux/policyModel', async () => { await indexing; return getPolicyModel(); });

/** The compiled policy of the last tree build with source locations, or { unavailable }. */
async function getPolicyModel() {
  let bin, linked = null;
  if (usingDevel) {
    const l = await linkedPolicy();
    if (l.unavailable) return l;
    bin = l.policy;
    linked = { module: l.module, kernelPolicy: l.kernelPolicy, installed: l.installed };
  } else {
    if (!treeRoot) return { unavailable: 'Open a refpolicy source tree to see its compiled policy.' };
    const res = lastBuild.get(treeRoot);
    if (!res || !res.policyBin || !fs.existsSync(res.policyBin)) {
      return { unavailable: res && !res.ok ? 'The last build failed; fix its errors and build again.' : 'Build the policy (SELinux: Build) to see what it contains.', needsBuild: true };
    }
    bin = res.policyBin;
  }
  const mtimeMs = fs.statSync(bin).mtimeMs;
  if (policyModelCache.bin !== bin || policyModelCache.mtimeMs !== mtimeMs) {
    let model;
    try { model = await exportPolicy(bin); } catch (e) { return { unavailable: `Could not read ${bin}: ${e.message}` }; }
    const users = userLocations();
    for (const t of model.types) t.loc = sourceLocation(t.name, ['type']);
    for (const a of model.attributes) a.loc = sourceLocation(a.name, ['attribute']);
    for (const r of model.roles) r.loc = sourceLocation(r.name, ['role']);
    for (const b of model.bools) b.loc = sourceLocation(b.name, ['bool']);
    for (const u of model.users) u.loc = users.get(u.name) || null;
    for (const c of model.classes) { const k = idx.classes.get(c.name); c.loc = k ? { p: k.path, l: k.l, c: k.c, len: c.name.length } : null; }
    model.bin = bin;
    model.builtAt = mtimeMs;
    model.tree = treeRoot;
    model.linked = linked;
    const se = treeRoot ? seusersMappings(treeRoot) : { file: null, list: [] };
    model.seusersFile = se.file;
    for (const u of model.users) u.logins = se.list.filter(x => x.user === u.name);
    model.unmappedLogins = se.list.filter(x => !model.users.some(u => u.name === x.user));
    model.roleAllows = model.roleAllows || [];
    model.roleTransitions = model.roleTransitions || [];
    Object.assign(policyModelCache, { bin, mtimeMs, model });
  }
  return policyModelCache.model;
}

/*
 * Standalone modules: the last built module linked with this host's
 * installed policy (build.linkWithInstalled), redone after each build of it.
 */
let lastModule = null;               // .te of the last successful module build
let linkState = { key: null, promise: null };

function linkedPolicy() {
  const res = lastModule && lastBuild.get(lastModule);
  if (!res || !res.ok) {
    return Promise.resolve({ unavailable: res ? 'The last build failed; fix its errors and build again.' : 'Build the module (SELinux: Build): it is then linked with this host\'s installed policy to check it.', needsBuild: true });
  }
  if (process.platform === 'win32') return Promise.resolve({ unavailable: 'Linking with the installed policy needs a Linux host with SELinux (use Remote-SSH).' });
  const key = res; // each build result is linked once
  if (linkState.key !== key) {
    linkState = { key, promise: (async () => {
      connection.sendNotification('selinux/build', { state: 'linking', module: res.module });
      const required = requiredAttributes();
      const l = await build.linkWithInstalled(res, { isAttribute: (n) => required.has(n) });
      log(`linked ${res.module} with ${l.kernelPolicy || 'the installed policy'}: ${l.ok ? 'ok' : 'failed'} (${l.ms} ms)${l.ok ? '' : `\n${l.log}`}`);
      connection.sendNotification('selinux/build', { state: 'linked', module: res.module, ok: l.ok, ms: l.ms });
      if (!l.ok) return { unavailable: `Linking ${res.module} with the installed policy failed: ${l.log.split('\n').slice(-3).join(' ')}` };
      return { policy: l.policy, module: res.module, kernelPolicy: l.kernelPolicy, installed: l.installed };
    })() };
  }
  return linkState.promise;
}

/** Names declared or required as attributes anywhere in the sources (the devel headers only require them). */
function requiredAttributes() {
  const out = new Set();
  for (const [n, list] of idx.decls) if (list.some(d => d.kind === 'attribute')) out.add(n);
  for (const list of idx.defs.values()) for (const d of list) for (const r of d.requires || []) if (r.kind === 'attribute') out.add(r.name);
  for (const f of idx.files.values()) for (const r of (f.requires || [])) if (r.kind === 'attribute') out.add(r.name);
  return out;
}

/* ---------------- rules of a type (Compiled Policy view) ---------------- */

/** policy_query.py, kept running so the policy is indexed once per build. */
const policyQuery = {
  proc: null, next: 1, waiting: new Map(), buf: '',
  request(msg) {
    if (!this.proc) {
      this.proc = require('child_process').spawn('python3', [path.join(__dirname, 'policy_query.py')], { stdio: ['pipe', 'pipe', 'pipe'] });
      this.proc.stdout.on('data', (d) => {
        this.buf += d;
        let nl;
        while ((nl = this.buf.indexOf('\n')) >= 0) {
          const line = this.buf.slice(0, nl); this.buf = this.buf.slice(nl + 1);
          let r; try { r = JSON.parse(line); } catch { continue; }
          const w = this.waiting.get(r.id); this.waiting.delete(r.id);
          if (w) w(r);
        }
      });
      this.proc.on('exit', () => { for (const w of this.waiting.values()) w({ error: 'policy query helper exited' }); this.waiting.clear(); this.proc = null; this.buf = ''; });
      this.proc.stderr.on('data', (d) => { if (/No module named 'setools'/.test(d)) log('policy_query.py: python3-setools is not installed'); });
    }
    const id = this.next++;
    return new Promise((resolve) => { this.waiting.set(id, resolve); this.proc.stdin.write(JSON.stringify({ id, ...msg }) + '\n'); });
  },
};
process.on('exit', () => { if (policyQuery.proc) policyQuery.proc.kill(); });

// Rules with `name` as source or target (directly or through its attributes), from the last build.
connection.onRequest('selinux/typeRules', async ({ name, dir, kinds }) => {
  await indexing;
  const model = await getPolicyModel();
  if (model.unavailable) return model;
  const r = await policyQuery.request({ op: 'rules', bin: model.bin, name, dir, kinds });
  return r.error ? { unavailable: `Rule query failed: ${r.error}` } : r;
});

// Domain transitions out of (or into) a domain, with source locations of every domain involved.
connection.onRequest('selinux/transitions', async ({ name, dir }) => {
  await indexing;
  const model = await getPolicyModel();
  if (model.unavailable) return model;
  const r = await policyQuery.request({ op: 'transitions', bin: model.bin, name, dir: dir === 'in' ? 'in' : 'out' });
  if (r.error) return { unavailable: `Transition query failed: ${r.error}` };
  const locs = {};
  const typeByName = new Map(model.types.map(t => [t.name, t]));
  for (const n of new Set([name, ...r.transitions.flatMap(x => [x.source, x.target])])) { const t = typeByName.get(n); if (t && t.loc) locs[n] = t.loc; }
  return { name, dir, transitions: r.transitions, locs };
});

// Domains of the last build (for the transition graph's root picker).
connection.onRequest('selinux/domains', async () => {
  await indexing;
  const model = await getPolicyModel();
  if (model.unavailable) return model;
  return { domains: model.types.filter(t => t.attrs.includes('domain')).map(t => t.name).sort(), builtAt: model.builtAt };
});

/* ---------------- denial assistant ---------------- */

/**
 * The file contexts of a tree build, for matchpathcon: file_contexts or
 * tmp/all_mods.fc when the build wrote one (upstream refpolicy's validate),
 * else base.fc plus every module's tmp/<mod>.mod.fc combined (RHEL's
 * Makefile writes no combined file). null without a build.
 */
function treeFileContexts(res) {
  if (!res || !res.workDir) return null;
  const direct = [path.join(res.workDir, 'file_contexts'), path.join(res.workDir, 'tmp', 'all_mods.fc')].find(p => fs.existsSync(p));
  if (direct) return direct;
  let parts = [];
  try { parts = fs.readdirSync(path.join(res.workDir, 'tmp')).filter(n => n.endsWith('.mod.fc')).map(n => path.join(res.workDir, 'tmp', n)); } catch { return null; }
  const base = path.join(res.workDir, 'base.fc');
  if (fs.existsSync(base)) parts.unshift(base);
  if (!parts.length) return null;
  const out = path.join(res.workDir, 'tmp', 'zz_file_contexts');
  const newest = Math.max(...parts.map(p => fs.statSync(p).mtimeMs));
  try { if (fs.statSync(out).mtimeMs >= newest) return out; } catch { /* write it */ }
  fs.writeFileSync(out, parts.map(p => fs.readFileSync(p, 'utf8')).join('\n'));
  return out;
}

const denials = require('./denials');

/** Policies denials can be checked against: this host's installed policies and the workspace's last build. */
function denialPolicies() {
  const list = build.installedPolicies().map(p => ({
    id: `installed:${p.name}`, label: `Installed ${p.name} policy${p.active ? ' (running here)' : ''}`, bin: p.policy, name: p.name, active: p.active,
    // The running policy: matchpathcon's defaults include file_contexts.local and home directories.
    fc: p.active ? null : path.join('/etc/selinux', p.name, 'contexts', 'files', 'file_contexts'),
  }));
  if (usingDevel) {
    const res = lastModule && lastBuild.get(lastModule);
    if (res && res.ok) list.push({ id: 'build', label: `This host's policy + ${res.module} (last build)`, build: true, fc: null });
  } else if (treeRoot) {
    const res = lastBuild.get(treeRoot);
    if (res && res.policyBin && fs.existsSync(res.policyBin)) {
      const fc = treeFileContexts(res);
      list.push({ id: 'build', label: `Last build of ${path.basename(treeRoot)}`, bin: res.policyBin, build: true, fc });
    }
  }
  return list;
}

const execFileP = (cmd, args) => new Promise((resolve) => {
  require('child_process').execFile(cmd, args, { maxBuffer: 16 << 20 }, (err, stdout, stderr) => resolve({ err, stdout: String(stdout || ''), stderr: String(stderr || '') }));
});

/** Current boolean values of the running policy (/sys/fs/selinux/booleans), {} when not available. */
function runningBooleans() {
  const dir = '/sys/fs/selinux/booleans';
  const out = {};
  let names = [];
  try { names = fs.readdirSync(dir); } catch { return out; }
  for (const n of names) {
    try { out[n] = fs.readFileSync(path.join(dir, n), 'utf8').trim().split(/\s+/)[0] === '1'; } catch { /* unreadable */ }
  }
  return out;
}

/**
 * Expected (file contexts) and current labels of the groups' paths:
 * Map path → { expected, current } (types). matchpathcon per file kind, with
 * the policy's file_contexts unless it is the running one; stat for the
 * current label (missing files have none).
 */
async function denialLabels(groups, fc) {
  const out = new Map();
  if (process.platform === 'win32') return out;
  const byMode = new Map();
  for (const g of groups) {
    const mode = denials.FILE_MODES[g.tclass];
    if (!mode || g.kind !== 'deny') continue;
    for (const p of g.paths) { if (!byMode.has(mode)) byMode.set(mode, new Set()); byMode.get(mode).add(p); }
  }
  const all = new Set();
  for (const [mode, set] of byMode) {
    const paths = [...set];
    paths.forEach(p => all.add(p));
    const r = await execFileP('matchpathcon', [...(fc ? ['-f', fc] : []), '-m', mode, ...paths]);
    for (const line of r.stdout.split('\n')) {
      const m = /^(.*)\t(\S+)$/.exec(line);
      if (!m) continue;
      const ctx = denials.parseContext(m[2]);
      out.set(m[1], { expected: ctx ? ctx.type : null, current: null });
    }
  }
  if (all.size) {
    const r = await execFileP('stat', ['-c', '%n\t%C', '--', ...all]);
    for (const line of r.stdout.split('\n')) {
      const m = /^(.*)\t(\S+)$/.exec(line);
      if (!m) continue;
      const ctx = denials.parseContext(m[2]);
      const e = out.get(m[1]) || { expected: null, current: null };
      e.current = ctx ? ctx.type : null;
      out.set(m[1], e);
    }
  }
  return out;
}

/*
 * Interface suggestions for denials with a missing rule. Candidates are found
 * by name (interfaces of one argument whose requirements, followed through the
 * interfaces they call, include the target type or one of its attributes);
 * what each one really grants comes from m4: one probe module calls them all
 * with the denied domain (build.expandCalls), and denials.rankInterfaces
 * keeps those that cover the denied permissions, fewest other rights first.
 */
const PROBE_ARG = 'zzprobe_domain_t';
let ifaceReqCache = { defs: null, byName: null };

/** name → [interface defs] whose requirements include it (cached per index). */
function interfacesRequiring() {
  if (ifaceReqCache.defs === idx.defs) return ifaceReqCache.byName;
  const byName = new Map();
  for (const [name, list] of idx.defs) {
    const d = list[0];
    if (!d || d.kind !== 'interface' || /\.spt$/.test(d.path || '')) continue;
    if (!d.generated && d.maxArg !== 1) continue;
    for (const n of callRequires(idx, name, [PROBE_ARG]).names) {
      if (n === PROBE_ARG) continue;
      if (!byName.has(n)) byName.set(n, []);
      byName.get(n).push(d);
    }
  }
  ifaceReqCache = { defs: idx.defs, byName };
  return byName;
}

/** Where to run the probe: the tree build's scratch copy, or a module build dir with the devel Makefile. */
function probeConfig() {
  if (usingDevel) {
    if (!fs.existsSync(settings.build.develMakefile || '')) return { unavailable: `Interface suggestions need ${settings.build.develMakefile} (selinux-policy-devel).` };
    const res = lastModule && lastBuild.get(lastModule);
    const work = res && res.workDir && fs.existsSync(res.workDir) ? res.workDir : build.scratchDir('probe', roots[0] || 'devel');
    workDirs.add(work);
    return { work, develMakefile: settings.build.develMakefile };
  }
  if (!treeRoot) return { unavailable: 'Interface suggestions need a policy tree or module in the workspace.' };
  const res = lastBuild.get(treeRoot);
  if (!res || !res.workDir || !fs.existsSync(path.join(res.workDir, 'tmp', 'all_interfaces.conf'))) return { unavailable: 'Build the tree (SELinux: Build) to get interface suggestions: they are worked out with its m4 output.', needsBuild: true };
  return { work: res.workDir, makeArgs: treeCfg().makeArgs || [] };
}

/** Adds `suggest` to groups with a missing rule: { own } (a rule in the domain's own module) or { list, note }. */
async function suggestInterfaces(groups, bin, notes, verdicts = ['missing'], max = 25, limit = 5) {
  const want = groups.filter(g => g.kind === 'deny' && verdicts.includes(g.v.verdict)).slice(0, max);
  if (!want.length) return;
  const loc = new Map();
  const locOf = (n) => { if (!loc.has(n)) loc.set(n, sourceLocation(n, ['type', 'attribute'])); return loc.get(n); };
  const needProbe = [];
  for (const g of want) {
    const s = locOf(g.source), t = locOf(g.target);
    if (g.source === g.target || (s && t && s.m && s.m === t.m)) {
      g.suggest = { own: true, module: s ? s.m : null, rule: g.v.needed };
      continue;
    }
    needProbe.push(g);
  }
  if (!needProbe.length || !bin) return;
  const cfg = probeConfig();
  if (cfg.unavailable) { notes.push(cfg.unavailable); return; }
  const t0 = Date.now();
  // The targets' attributes (from the policy) widen the search to interfaces written for them.
  let ti = await policyQuery.request({ op: 'typeinfo', bin, names: [...new Set(needProbe.map(g => g.target))], sourceRules: [] });
  if (ti.error) { notes.push(`Policy query failed: ${ti.error}`); return; }
  const info = ti.info || {};
  const byName = interfacesRequiring();
  const attrSize = new Map();
  const attrQuery = [...new Set(needProbe.flatMap(g => (info[g.target] && info[g.target].attrs) || []))];
  if (attrQuery.length) {
    const r = await policyQuery.request({ op: 'typeinfo', bin, names: attrQuery, sourceRules: [] });
    for (const [n, x] of Object.entries(r.info || {})) attrSize.set(n, x.size);
  }
  const offModules = idx.moduleKinds ? new Set([...idx.moduleKinds].filter(([, k]) => k === 'off').map(([m]) => m)) : new Set();
  const perGroup = new Map();
  const calls = new Set();
  for (const g of needProbe) {
    // Interfaces that require the type themselves (not through a call) first, the type's own module's first among them.
    const ownReq = (d) => (d.requires || []).some(r => r.name === g.target) || (d.generated && [...(idx.generatedAt(d.path, d.l, d.c) || [])].includes(g.target));
    // The module that owns the type: where it is declared, else (devel headers: no declarations) the module
    // whose interfaces most often require it themselves.
    let tMod = (locOf(g.target) || {}).m || null;
    if (!tMod) {
      const votes = new Map();
      for (const d of byName.get(g.target) || []) if (ownReq(d)) { const m = (idx.files.get(d.path) || {}).module; if (m) votes.set(m, (votes.get(m) || 0) + 1); }
      tMod = [...votes].sort((a, b) => b[1] - a[1])[0]?.[0] || null;
    }
    const direct = (byName.get(g.target) || []).map(d => ({ d, k: (ownReq(d) ? 0 : 2) + ((idx.files.get(d.path) || {}).module === tMod ? 0 : 1) })).sort((a, b) => a.k - b.k).map(x => x.d);
    // Attribute interfaces (e.g. files_read_all_files) only for smaller attributes: they are rarely the right answer.
    const viaAttr = ((info[g.target] && info[g.target].attrs) || []).filter(a => (attrSize.get(a) || 0) <= 300)
      .sort((a, b) => (attrSize.get(a) || 0) - (attrSize.get(b) || 0)).flatMap(a => byName.get(a) || []).slice(0, 80);
    const seen = new Set();
    const cands = [];
    for (const d of [...direct.slice(0, 600), ...viaAttr]) {
      if (seen.has(d.name)) continue;
      seen.add(d.name);
      const f = idx.files.get(d.path);
      const m = f ? f.module : null;
      const call = `${d.name}(${g.source})`;
      calls.add(call);
      cands.push({ name: d.name, call, module: m, owner: !!(m && m === tMod), off: !!(m && offModules.has(m)),
        summary: (d.doc && d.doc.summary) || '', loc: { p: d.path, l: d.l, c: d.c } });
    }
    perGroup.set(g, cands);
  }
  if (!calls.size) { for (const g of needProbe) { g.suggest = { list: [], note: `No interface mentions ${g.target}.` }; proposeInterface(g); } return; }
  const ex = await build.expandCalls([...calls].sort(), cfg);
  if (!ex.ok) { notes.push(`Interface suggestions: m4 failed (${ex.log.trim().split('\n').slice(-2).join(' ')}).`); return; }
  const stmts = denials.probeStatements(ex.text);
  // Sizes of every type/attribute the candidates grant on, and the rules on attributes they add.
  const names = new Set(), added = new Set();
  for (const list of stmts.values()) for (const s of list) {
    if (s.rt === 'typeattribute') s.attrs.forEach(a => added.add(a));
    else if (s.t) s.t.forEach(n => names.add(n));
  }
  ti = await policyQuery.request({ op: 'typeinfo', bin, names: [...names, ...needProbe.map(g => g.target)], sourceRules: [...added] });
  if (ti.error) { notes.push(`Policy query failed: ${ti.error}`); return; }
  const types = ti.info || {};
  const more = new Set();
  for (const rules of Object.values(ti.rules || {})) for (const r of rules) if (!(r.t in types)) more.add(r.t);
  if (more.size) { const r2 = await policyQuery.request({ op: 'typeinfo', bin, names: [...more], sourceRules: [] }); Object.assign(types, r2.info || {}); }
  for (const g of needProbe) {
    const ranked = denials.rankInterfaces({ domain: g.source, target: g.target, tclass: g.tclass, perms: g.perms }, perGroup.get(g) || [], stmts, types, ti.rules || {});
    const full = ranked.filter(x => x.covers);
    const list = (full.length ? full : ranked).slice(0, full.length ? limit : 3);
    const combos = full.length ? [] : (ranked.combos || []);
    g.suggest = { list, partial: !full.length && list.length > 0, combos,
      note: !ranked.length ? `None of the ${(perGroup.get(g) || []).length} interfaces that mention ${g.target} grants this.` : null };
    if (!full.length && !combos.length) proposeInterface(g);
  }
  log(`denial suggestions: ${calls.size} interface calls probed in ${ex.ms} ms, ${Date.now() - t0} ms total`);
}

/* ---------- finding interfaces (service editor) ---------- */

/** A compiled policy to size attributes against: the workspace build, else the running policy. */
async function policyForRanking() {
  if (usingDevel) {
    const res = lastModule && lastBuild.get(lastModule);
    if (res && res.ok) { const l = await linkedPolicy(); if (!l.unavailable) return l.policy; }
  } else if (treeRoot) {
    const res = lastBuild.get(treeRoot);
    if (res && res.policyBin && fs.existsSync(res.policyBin)) return res.policyBin;
  }
  const active = build.installedPolicies().find(p => p.active);
  return active ? active.policy : null;
}

/**
 * Interfaces that give `domain` an access, narrowest first, the same way the
 * denial assistant ranks them: { target, tclass, perms } or { path, tclass,
 * perms } (the path's type from the file contexts).
 */
connection.onRequest('selinux/findInterfaces', async ({ domain, target, path: p, tclass, perms } = {}) => {
  await indexing;
  if (!/^[A-Za-z_]\w*$/.test(domain || '')) return { error: 'Give the service a name first.' };
  if (!/^\w+$/.test(tclass || '') || !(perms || []).length || !perms.every(x => /^\w+$/.test(x))) return { error: 'Choose what kind of object and which permissions.' };
  let resolved = null;
  if (!target && p) {
    if (!p.startsWith('/')) return { error: 'A path must be absolute.' };
    if (process.platform === 'win32') return { error: 'Looking up a path needs a Linux host (use Remote-SSH); give the type instead.' };
    const fc = !usingDevel && treeRoot ? treeFileContexts(lastBuild.get(treeRoot)) : null;
    const r = await execFileP('matchpathcon', [...(fc ? ['-f', fc] : []), '-m', denials.FILE_MODES[tclass] || 'file', p]);
    const m = /\t(\S+)\s*$/.exec(r.stdout);
    const ctx = m && denials.parseContext(m[1]);
    if (!ctx) return { error: `No file context gives ${p} a label${(r.stderr || '').trim() ? ` (${r.stderr.trim().split('\n')[0]})` : ''}.` };
    target = ctx.type;
    resolved = { path: p, type: target, from: fc ? 'the tree\'s file contexts' : 'this host\'s file contexts' };
  }
  if (!/^[A-Za-z_]\w*$/.test(target || '')) return { error: 'Give a type (e.g. etc_t) or an absolute path.' };
  const bin = await policyForRanking();
  const notes = [];
  const g = { kind: 'deny', source: domain, target, tclass, perms, v: { verdict: 'missing', needed: `allow ${domain} ${target}:${tclass} { ${perms.join(' ')} };` } };
  await suggestInterfaces([g], bin, notes, ['missing'], 1, 12);
  return { target, resolved, suggest: g.suggest || null, notes, readOnly: perms.every(x => denials.permWeight(x) === 1) };
});

/**
 * What policy statements written in a module compile to (m4 with the policy's own Makefile):
 * items = statement texts (calls like mmap_manage_files_pattern(D, T, T), allow rules with
 * permission macros) → [{ rules: [text], attrs }]. Marker comments between the items (m4
 * copies comments unexpanded) split the output.
 */
connection.onRequest('selinux/expandStatements', async ({ items } = {}) => {
  await indexing;
  const list = (items || []).filter(x => typeof x === 'string' && x.length < 2000 && !/^\s*#/.test(x)).slice(0, 200);
  if (!list.length) return { results: [] };
  const cfg = probeConfig();
  if (cfg.unavailable) return { error: cfg.unavailable };
  const lines = list.flatMap((x, i) => [`# zzitem ${i}`, x.replace(/\n/g, ' ')]);
  lines.push(`# zzitem ${list.length}`);
  const ex = await build.expandCalls(lines, cfg);
  if (!ex.ok) return { error: `m4 failed: ${ex.log.trim().split('\n').slice(-2).join(' ')}` };
  const parts = ex.text.split(/^# zzitem (\d+)\s*$/m);
  const chunks = new Map();
  for (let i = 1; i + 1 < parts.length; i += 2) chunks.set(+parts[i], parts[i + 1]);
  const fmt = (x) => (x.length === 1 ? x[0] : `{ ${x.join(' ')} }`);
  return { results: list.map((_, i) => {
    const text = (chunks.get(i) || '').split('\n').filter(l => !l.startsWith('#')).join('\n');
    const st = denials.parseStatements(text);
    const seen = new Set(), rules = [], attrs = [];
    for (const s of st) {
      if (s.rt === 'typeattribute') { attrs.push(`${s.s[0]}: ${s.attrs.join(', ')}`); continue; }
      if (!['allow', 'dontaudit', 'auditallow'].includes(s.rt)) continue;
      const t = `${s.rt} ${fmt(s.s)} ${fmt(s.t)}:${fmt(s.c)} ${fmt(s.perms)};`;
      if (!seen.has(t)) { seen.add(t); rules.push({ text: t, rt: s.rt, s: s.s, t: s.t, c: s.c, perms: s.perms, cond: !!s.cond }); }
    }
    // type_transition lines (file type transitions) are worth showing too.
    for (const m of text.matchAll(/^\s*type_transition\s+([^;]+);/gm)) rules.push({ text: `type_transition ${m[1].replace(/\s+/g, ' ').trim()};`, rt: 'type_transition' });
    return { rules, attrs };
  }) };
});

let grantsCache = { key: null, map: new Map() };
/** What interface calls really compile to for a domain (m4 with the policy's own Makefile): name → { rules, attrs, cond }. */
connection.onRequest('selinux/interfaceGrants', async ({ domain, names } = {}) => {
  await indexing;
  if (!/^[A-Za-z_]\w*$/.test(domain || '')) return { error: 'Give the service a name first.' };
  const list = [...new Set((names || []).filter(n => /^\w+$/.test(n)))].slice(0, 400);
  const cfg = probeConfig();
  if (cfg.unavailable) return { error: cfg.unavailable };
  const res = usingDevel ? lastBuild.get(lastModule) : lastBuild.get(treeRoot);
  const key = `${cfg.work}:${res ? res.ms + ':' + (res.workDir || '') : ''}:${idx.defs.size}`;
  if (grantsCache.key !== key) grantsCache = { key, map: new Map() };
  const todo = list.filter(n => !grantsCache.map.has(`${domain}|${n}`));
  if (todo.length) {
    const ex = await build.expandCalls(todo.map(n => `${n}(${domain})`), cfg);
    if (!ex.ok) return { error: `m4 failed: ${ex.log.trim().split('\n').slice(-2).join(' ')}` };
    const stmts = denials.probeStatements(ex.text);
    const fmt = (x) => (x.length === 1 ? x[0] : `{ ${x.join(' ')} }`);
    for (const n of todo) {
      const st = stmts.get(`${n}(${domain})`) || [];
      const rules = [], attrs = [];
      let cond = 0;
      const seen = new Set();
      for (const s of st) {
        if (s.rt === 'typeattribute') { if (s.s[0] === domain) attrs.push(...s.attrs); continue; }
        if (s.rt !== 'allow' && s.rt !== 'dontaudit') continue;
        const text = `${s.rt} ${fmt(s.s)} ${fmt(s.t)}:${fmt(s.c)} ${fmt(s.perms)};`;
        if (seen.has(text)) continue;
        seen.add(text);
        if (s.cond) cond++;
        rules.push({ text, cond: !!s.cond, nested: !!s.nested });
      }
      grantsCache.map.set(`${domain}|${n}`, { rules, attrs: [...new Set(attrs)], cond });
    }
  }
  return { grants: Object.fromEntries(list.map(n => [n, grantsCache.map.get(`${domain}|${n}`)])) };
});

/** Whether calls into a module belong in optional_policy (it can be off): not base, or outside kernel/system. */
function moduleOptional(mod, file) {
  if (idx.moduleKinds && idx.moduleKinds.has(mod)) return idx.moduleKinds.get(mod) !== 'base';
  const f = idx.files.get(file);
  return !(f && ['kernel', 'system'].includes(f.layer));
}

/**
 * No interface grants the access: if the module that owns the target type is
 * in the workspace, propose a new interface for it (sets g.suggest.newIface).
 */
function proposeInterface(g) {
  const ownerTe = domainModuleFile(g.target);
  if (!ownerTe) return;
  const ownerMod = (idx.files.get(ownerTe) || {}).module || path.basename(ownerTe, '.te');
  const domTe = domainModuleFile(g.source);
  if (domTe && ((idx.files.get(domTe) || {}).module || path.basename(domTe, '.te')) === ownerMod) return; // own types: a plain rule
  const gen = denials.newInterfaceText({ module: ownerMod, target: g.target, tclass: g.tclass, perms: g.perms }, (n) => idx.defs.has(n));
  g.suggest.newIface = { module: ownerMod, name: gen.name, summary: gen.summary, call: `${gen.name}(${g.source})`, ifPath: ownerTe.replace(/\.te$/, '.if'),
    rule: `allow ${g.source} ${g.target}:${g.tclass} { ${g.perms.join(' ')} };` };
}

/** The workspace .te that declares a domain (the active tree's, or a standalone module's), or null. */
function domainModuleFile(domain) {
  const inWs = (p) => roots.some(r => p.startsWith(r + path.sep)) && !inExcludedTree(p) && (!treeRoot || p.startsWith(treeRoot + path.sep) || isStandaloneModule(p));
  const d = (idx.decls.get(domain) || []).find(x => x.kind === 'type' && /\.te$/.test(x.path) && inWs(x.path));
  return d ? d.path : null;
}

/**
 * Plan the fix for a denial: an interface call (or a plain rule for the
 * domain's own types) inserted into the domain's module, wrapped in
 * optional_policy when the interface's module can be off; for a domain only
 * in the installed policy (standalone workspace), a new local module.
 * → { path, exists, text, line, inserted, diff, optional } | { already } | { unavailable }.
 */
connection.onRequest('selinux/denialFix', async ({ domain, call, calls, rule, newInterface }) => {
  await indexing;
  let list = (calls && calls.length ? calls : call ? [call] : []).filter(c => /^\w+\(\w+\)$/.test(c));
  if (!/^[A-Za-z_]\w*$/.test(domain || '') || (!list.length && !rule && !newInterface)) return { unavailable: 'Nothing to add.' };
  // A new interface in the module that owns the target type, then a call to it.
  const also = [];
  let newMod = null;
  if (newInterface) {
    const { target, tclass, perms } = newInterface;
    const ownerTe = domainModuleFile(target);
    if (!ownerTe) return { unavailable: `${target} isn't declared in this workspace, so there is no module to add an interface to.` };
    newMod = { mod: (idx.files.get(ownerTe) || {}).module || path.basename(ownerTe, '.te'), te: ownerTe };
    const ifPath = ownerTe.replace(/\.te$/, '.if');
    const oldIf = readSource(ifPath);
    const gen = denials.newInterfaceText({ module: newMod.mod, target, tclass, perms }, (n) => idx.defs.has(n));
    const base = oldIf != null ? oldIf.replace(/\s*$/, '\n') : `## <summary>${newMod.mod}</summary>\n`;
    const ifText = base + gen.text;
    also.push({ path: ifPath, exists: oldIf != null, text: ifText, line: base.split('\n').length, inserted: gen.text.trim().split('\n'), diff: service.lineDiff(oldIf || '', ifText), what: `new interface ${gen.name}` });
    list = [`${gen.name}(${domain})`];
  }
  const ifaceModule = (c) => {
    const n = c.slice(0, c.indexOf('('));
    if (newMod && list.length === 1) return { mod: newMod.mod, optional: moduleOptional(newMod.mod, newMod.te) };
    const d = (idx.defs.get(n) || [])[0];
    return { mod: d ? (idx.files.get(d.path) || {}).module || null : null, n };
  };
  const te = domainModuleFile(domain);
  if (te) {
    const old = readSource(te);
    if (old == null) return { unavailable: `Can't read ${rel(te)}.` };
    const domMod = (idx.files.get(te) || {}).module || path.basename(te, '.te');
    let text = old, first = null, optional = false;
    const inserted = [];
    if (rule && !list.length) {
      const r = denials.insertFix(text, { domain, rule });
      if (r.already) return { already: true, path: te, message: `${rel(te)} already has ${rule}; the denial should go away once the module is rebuilt and loaded.` };
      return { path: te, exists: true, module: domMod, text: r.text, line: r.line, inserted: r.inserted, optional: false, diff: service.lineDiff(old, r.text), also };
    }
    for (const c of list) {
      const m = ifaceModule(c);
      const opt = m.mod !== domMod && (m.optional !== undefined ? m.optional : serviceCtx(isStandaloneModule(te)).optional(m.n));
      const r = denials.insertFix(text, { domain, call: c, optional: opt, module: m.mod });
      if (r.already) continue;
      text = r.text;
      if (first == null || r.line < first) first = r.line;
      inserted.push(...r.inserted);
      optional = optional || opt;
    }
    if (!inserted.length) return { already: true, path: te, message: `${rel(te)} already has ${list.join(' and ')}; the denial should go away once the module is rebuilt and loaded.` };
    return { path: te, exists: true, module: domMod, text, line: first, inserted, optional, diff: service.lineDiff(old, text), also };
  }
  const call0 = list[0];
  call = call0;
  if (!usingDevel) return { unavailable: `${domain} isn't declared in ${treeRoot ? path.basename(treeRoot) : 'this workspace'}, so there is no module to add the fix to.` };
  if (!call) return { unavailable: `${domain} isn't declared in this workspace; a plain rule on another module's type isn't offered (use an interface).` };
  // A local module for a domain of the installed policy: local_<name>/local_<name>.te in the workspace.
  if (!roots[0]) return { unavailable: 'Open a folder to put the local module in.' };
  const base = `local_${domain.replace(/_t$/, '')}`;
  const p = path.join(roots[0], base, `${base}.te`);
  const old = readSource(p);
  if (old != null) {
    let text = old;
    const inserted = [];
    for (const c of list) { const r = denials.insertFix(text, { domain, call: c, optional: false }); if (!r.already) { text = r.text; inserted.push(...r.inserted); } }
    if (!inserted.length) return { already: true, path: p, message: `${rel(p)} already has ${list.join(' and ')}.` };
    return { path: p, exists: true, module: base, text, line: Math.max(0, text.split('\n').indexOf(inserted[0])), inserted, optional: false, diff: service.lineDiff(old, text), also };
  }
  let text = denials.localModuleText(base, domain, call);
  for (const c of list.slice(1)) text = denials.insertFix(text, { domain, call: c, optional: false }).text || text;
  return { path: p, exists: false, module: base, text, line: text.split('\n').indexOf(call), inserted: list, optional: false, diff: service.lineDiff('', text), also,
    note: `${domain} belongs to the installed policy, so this creates a small module of its own (${base}) that adds the call. Install it with SELinux: Install Module.` };
});

/**
 * Denials from domains a program lands in when it didn't get a domain of its
 * own (unconfined_service_t, init_t, unconfined_t, …): what the program's
 * file is labeled (now, and by the file contexts) and which domains that
 * label is the entry point of. Map group key → { exe, expected, current, domains, generic }.
 */
const UNCONFINED_SOURCES = new Set(['unconfined_service_t', 'init_t', 'initrc_t', 'unconfined_t', 'kernel_t']);
const GENERIC_ENTRY = new Set(['unconfined_service_t', 'initrc_t', 'unconfined_t']);
async function denialTransitions(groups, fc, bin) {
  const out = new Map();
  const want = groups.filter(g => g.kind === 'deny' && UNCONFINED_SOURCES.has(g.source) && (g.exes || []).some(e => e.startsWith('/')));
  if (!want.length || process.platform === 'win32') return out;
  const exes = [...new Set(want.map(g => g.exes.find(e => e.startsWith('/'))))];
  const labels = new Map();
  const r = await execFileP('matchpathcon', [...(fc ? ['-f', fc] : []), '-m', 'file', ...exes]);
  for (const line of r.stdout.split('\n')) { const m = /^(.*)\t(\S+)$/.exec(line); if (m) labels.set(m[1], { expected: (denials.parseContext(m[2]) || {}).type || null, current: null }); }
  const st = await execFileP('stat', ['-c', '%n\t%C', '--', ...exes]);
  for (const line of st.stdout.split('\n')) { const m = /^(.*)\t(\S+)$/.exec(line); if (m) { const e = labels.get(m[1]) || { expected: null }; e.current = (denials.parseContext(m[2]) || {}).type || null; labels.set(m[1], e); } }
  const types = [...new Set([...labels.values()].flatMap(e => [e.expected, e.current]).filter(Boolean))];
  const ep = types.length ? await policyQuery.request({ op: 'entrypoints', bin, types }) : { domains: {} };
  for (const g of want) {
    const exe = g.exes.find(e => e.startsWith('/'));
    const l = labels.get(exe) || {};
    const of = (t) => ((ep.domains || {})[t] || []);
    const typeFor = l.expected || l.current;
    const all = of(typeFor);
    // A program label that unconfined domains enter (bin_t, usr_t) has no domain of its own.
    const generic = !all.length || all.some(d => GENERIC_ENTRY.has(d));
    const stem = (typeFor || '').replace(/_exec_t$/, '');
    const domains = generic ? [] : all.filter(d => !UNCONFINED_SOURCES.has(d)).sort((a, b) => ((b === `${stem}_t`) - (a === `${stem}_t`)) || (b.startsWith(stem) - a.startsWith(stem)) || a.localeCompare(b));
    out.set(g.key, { exe, expected: l.expected || null, current: l.current || null, domains, generic });
  }
  return out;
}

/** For a standalone module build: the running policy's file contexts plus the module's own (they win), in one file for matchpathcon. */
function moduleFileContexts() {
  const res = lastModule && lastBuild.get(lastModule);
  if (!res || !res.workDir) return null;
  const own = path.join(res.workDir, 'tmp', `${res.module}.mod.fc`);
  const active = build.installedPolicies().find(p => p.active);
  if (!active || !fs.existsSync(own)) return null;
  const dir = path.join('/etc/selinux', active.name, 'contexts', 'files');
  const parts = ['file_contexts', 'file_contexts.homedirs', 'file_contexts.local'].map(n => path.join(dir, n)).filter(p => fs.existsSync(p)).map(p => fs.readFileSync(p, 'utf8'));
  const out = path.join(res.workDir, 'denial_file_contexts');
  // m4's leftovers (blank lines, #line markers) are harmless comments to matchpathcon.
  fs.writeFileSync(out, [...parts, fs.readFileSync(own, 'utf8')].join('\n'));
  return out;
}

connection.onRequest('selinux/denialPolicies', async () => {
  await indexing;
  const list = denialPolicies();
  return { policies: list.map(({ id, label, active, build: b }) => ({ id, label, active, build: !!b })) };
});

/**
 * Parse audit text, group the denials and give each group a verdict against
 * `against` (a denialPolicies id; default: the running installed policy, else
 * the workspace build).
 */
connection.onRequest('selinux/analyzeDenials', async ({ text, against, suggest } = {}) => {
  await indexing;
  const parsed = denials.parseDenials(text || '');
  const groups = denials.groupDenials(parsed);
  const policies = denialPolicies();
  const pol = policies.find(p => p.id === against) || policies.find(p => p.active) || policies.find(p => p.build) || policies[0] || null;
  const notes = [];
  const unparsed = (text || '').split('\n').filter(l => /avc:\s+denied/.test(l)).length - parsed.filter(d => d.kind !== 'error').length;
  if (unparsed > 0) notes.push(`${unparsed} line${unparsed > 1 ? 's' : ''} mentioning "avc: denied" could not be read (no scontext/tcontext?).`);
  let te = new Map(), labels = new Map(), transitions = new Map(), policyName = pol ? pol.label : 'the policy', usedBin = null, fcFile = pol ? pol.fc : null;
  if (!pol) notes.push(process.platform === 'win32' ? 'Checking denials against a policy needs a Linux host (use Remote-SSH).' : 'No policy to check against: no installed policy under /etc/selinux, and no workspace build.');
  else if (groups.length) {
    let bin = pol.bin;
    if (pol.build && usingDevel) {
      const l = await linkedPolicy();
      if (l.unavailable) notes.push(l.unavailable); else bin = l.policy;
    }
    if (bin) {
      usedBin = bin;
      // A standalone module's own file contexts count too (they label the files it is about).
      if (pol.build && usingDevel) fcFile = moduleFileContexts();
      const bools = pol.active ? runningBooleans() : {};
      if (pol.active && Object.keys(bools).length) policyName = `the running ${pol.name} policy`;
      const checks = groups.filter(g => g.kind === 'deny').map(g => ({ id: g.key, s: g.source, t: g.target, c: g.tclass, perms: g.perms }));
      if (checks.length) {
        const r = await policyQuery.request({ op: 'avc', bin, checks, bools });
        if (r.error) notes.push(`Policy query failed: ${r.error}`);
        else for (const x of r.results) te.set(x.id, x);
      }
      labels = await denialLabels(groups, fcFile);
      // Accesses type enforcement allows: a constraint (MCS/MLS, UBAC) may be what denied them.
      for (const g of groups) {
        const x = te.get(g.key);
        if (!x || !x.perms || !g.perms.every(p => x.perms[p] && x.perms[p].status === 'allowed')) continue;
        const r = await policyQuery.request({ op: 'constraints', bin, s: g.scontext, t: g.tcontext, c: g.tclass, perms: g.perms });
        if (!r.error && r.failing && r.failing.length) x.constraints = r.failing;
      }
      transitions = await denialTransitions(groups, fcFile, bin);
    }
  }
  const out = groups.map(g => {
    const lab = g.paths.filter(p => labels.has(p)).map(p => ({ path: p, ...labels.get(p) }));
    const x = te.get(g.key);
    if (x && transitions.has(g.key)) x.transition = transitions.get(g.key);
    return { ...g, labels: lab, v: denials.verdict(g, x || null, lab, policyName),
      srcLoc: sourceLocation(g.source, ['type']), tgtLoc: sourceLocation(g.target, ['type']) };
  });
  // suggest: false = none; { verdicts, max } widens it (the benchmark asks for allowed accesses too).
  if (suggest !== false) await suggestInterfaces(out, usedBin, notes, (suggest && suggest.verdicts) || ['missing'], (suggest && suggest.max) || 25, (suggest && suggest.limit) || 5);
  return { groups: out, count: parsed.length, policy: pol ? { id: pol.id, label: pol.label, fileContexts: fcFile || pol.fc || "the running policy's file contexts" } : null, policies: policies.map(({ id, label, active, build: b }) => ({ id, label, active, build: !!b })), notes };
});

/* ---------------- logins: who logs in as what, and what they can reach ---------------- */

const logins = require('./logins');
const ADMIN_ROLES = ['sysadm_r', 'secadm_r', 'auditadm_r', 'unconfined_r'];
let reachCache = { key: null, map: new Map() };

/**
 * The login configuration that goes with a policy (a denialPolicies entry):
 * an installed policy's /etc/selinux/<name> files; a tree build's
 * config/appconfig-<TYPE> files (editor contents win); a standalone module
 * build uses this host's running configuration. host = this host's accounts
 * apply (installed running policy, or a module linked with it).
 */
function loginConfig(pol) {
  const read = (p) => { const t = readSource(p); return t == null ? null : t; };
  if (pol.build && !usingDevel && treeRoot) {
    const dir = appconfigDir(treeRoot);
    return { dir, host: false, seusers: path.join(dir, 'seusers'), defaults: path.join(dir, 'default_contexts'), userFile: (u) => path.join(dir, `${u}_default_contexts`), read };
  }
  const name = pol.name || (build.installedPolicies().find(p => p.active) || {}).name;
  if (!name) return null;
  const dir = path.join('/etc/selinux', name);
  return { dir, host: !!(pol.active || pol.build), seusers: path.join(dir, 'seusers'), defaults: path.join(dir, 'contexts', 'default_contexts'),
    userFile: (u) => path.join(dir, 'contexts', 'users', u), read };
}

/** The policy file for a login report: the entry's own, or the module linked with this host's policy. */
async function loginPolicy(against) {
  const policies = denialPolicies();
  const pol = policies.find(p => p.id === against) || policies.find(p => p.active) || policies.find(p => p.build) || policies[0] || null;
  if (!pol) return { policies, error: process.platform === 'win32' ? 'Login reports need a Linux host (use Remote-SSH).' : 'No policy to report on: no installed policy under /etc/selinux, and no workspace build.' };
  let bin = pol.bin;
  if (pol.build && usingDevel) {
    const l = await linkedPolicy();
    if (l.unavailable) return { policies, pol, error: l.unavailable };
    bin = l.policy;
  }
  return { policies, pol, bin };
}

/** Reach of one user from its login start contexts, cached per policy file + mtime. */
async function userReach(bin, user, starts) {
  const key = `${bin}:${fs.statSync(bin).mtimeMs}`;
  if (reachCache.key !== key) reachCache = { key, map: new Map() };
  const k = `${user}|${starts.map(s => `${s.role}:${s.type}`).sort().join(',')}`;
  if (!reachCache.map.has(k)) {
    reachCache.map.set(k, policyQuery.request({ op: 'reach', bin, user, starts,
      access: logins.ABILITIES.map(a => ({ id: a.id, attr: a.attr, t: a.t, classes: a.classes, perms: a.perms })) }));
  }
  return reachCache.map.get(k);
}

const pathOut = (r, d) => { const k = r.reached[d]; return k ? logins.pathTo(r.steps, k).map(s => ({ ...s, text: logins.stepText(s) })) : []; };

/**
 * Logins report: every SELinux user with its roles, the Linux logins mapped
 * to it, where each way of logging in lands, how many domains its sessions
 * can reach and which risky abilities among them (with the path there).
 * On this host's running policy also the accounts in /etc/passwd: people's
 * logins with the seusers line that applies, and service accounts.
 */
connection.onRequest('selinux/logins', async ({ against } = {}) => {
  await indexing;
  const lp = await loginPolicy(against);
  const policies = lp.policies.map(({ id, label, active, build: b }) => ({ id, label, active, build: !!b }));
  if (lp.error) return { error: lp.error, policies, policy: lp.pol ? { id: lp.pol.id, label: lp.pol.label } : null };
  const { pol, bin } = lp;
  const cfg = loginConfig(pol);
  if (!cfg) return { error: 'No login configuration found for this policy.', policies };
  const notes = [];
  const seText = cfg.read(cfg.seusers);
  if (seText == null) notes.push(`No seusers file at ${cfg.seusers}: every login falls back to the policy's defaults.`);
  const seusers = logins.parseSeusers(seText);
  const defText = cfg.read(cfg.defaults);
  if (defText == null) notes.push(`No default_contexts at ${cfg.defaults}.`);
  const defaults = { path: cfg.defaults, list: logins.parseContexts(defText) };
  const r = await policyQuery.request({ op: 'users', bin, types: [], names: [] });
  if (r.error) return { error: `Policy query failed: ${r.error}`, policies };
  const userFiles = {};
  const types = new Set(defaults.list.flatMap(x => x.to.map(c => c.type)));
  for (const u of Object.keys(r.users)) {
    if (!/^\w+$/.test(u)) continue;
    const p = cfg.userFile(u);
    const t = cfg.read(p);
    if (t != null) { userFiles[u] = { path: p, list: logins.parseContexts(t) }; userFiles[u].list.forEach(x => x.to.forEach(c => types.add(c.type))); }
  }
  const info = await policyQuery.request({ op: 'users', bin, types: [...types],
    names: logins.ABILITIES.map(a => a.attr || a.t) });
  const roleTypes = (role) => new Set((info.roleTypes || {})[role] || []);
  const locs = userLocations();
  const users = [];
  for (const [name, u] of Object.entries(info.users || {}).sort((a, b) => a[0].localeCompare(b[0]))) {
    const ent = logins.entries(u.roles, roleTypes, userFiles[name] || null, defaults);
    const starts = [];
    for (const e of ent) for (const c of e.contexts) if (!starts.some(s => s.role === c.role && s.type === c.type)) starts.push(c);
    const mapped = seusers.filter(x => x.user === name);
    const out = { name, roles: u.roles, range: u.range, loc: pol.build && !usingDevel ? locs.get(name) || null : null, logins: mapped.map(x => ({ ...x, file: cfg.seusers })),
      entries: ent, contextsFile: userFiles[name] ? userFiles[name].path : null, reached: 0, abilities: [] };
    if (starts.length && name !== 'system_u') {
      const rr = await userReach(bin, name, starts);
      if (rr.error) { out.error = rr.error; } else {
        out.reached = Object.keys(rr.reached).length;
        out.roleSet = rr.roles;
        for (const a of logins.ABILITIES) {
          const hit = rr.access && rr.access[a.id];
          if (!hit) continue;
          const n = logins.nearest(rr, Object.keys(hit));
          if (!n) continue;
          out.abilities.push({ id: a.id, label: a.label, severity: a.severity, domain: n.d, count: Object.keys(hit).length,
            rule: hit[n.d].rule || null, path: pathOut(rr, n.d) });
        }
      }
    }
    users.push(out);
  }
  const userByName = new Map(users.map(u => [u.name, u]));
  const adminRoles = ADMIN_ROLES.filter(x => (info.roleTypes || {})[x]);
  const mappings = seusers.map(m => ({ ...m, file: cfg.seusers, notes: logins.mappingNotes(m, userByName.get(m.user), adminRoles) }));
  let accounts = null;
  if (cfg.host && process.platform !== 'win32') {
    const pw = logins.parsePasswd(readSource('/etc/passwd'));
    const groupsOf = logins.parseGroups(readSource('/etc/group'), pw);
    let uidMin = 1000;
    try { const m = /^\s*UID_MIN\s+(\d+)/m.exec(fs.readFileSync('/etc/login.defs', 'utf8')); if (m) uidMin = +m[1]; } catch { /* default */ }
    const people = pw.filter(p => p.uid === 0 || (p.uid >= uidMin && p.uid !== 65534)).map(p => {
      const m = logins.mappingFor(p.name, seusers, groupsOf);
      return { name: p.name, uid: p.uid, shell: p.shell, canLogin: !logins.NO_LOGIN.test(p.shell || ''), mapping: m ? { user: m.user, range: m.range, how: m.how, login: m.login, l: m.l } : null };
    });
    accounts = { people, services: logins.serviceAccounts(pw, seusers, groupsOf, uidMin), uidMin };
  } else if (!cfg.host) {
    notes.push('A tree build: its seusers and contexts are shown; the accounts of the system it will run on are not known here.');
  }
  return { policy: { id: pol.id, label: pol.label, configDir: cfg.dir, host: cfg.host }, policies, users, mappings, seusersFile: seText == null ? null : cfg.seusers, accounts, notes };
});

/** Every domain a user's sessions can reach, nearest first, with the path to each. */
connection.onRequest('selinux/loginReach', async ({ against, user, starts } = {}) => {
  await indexing;
  const lp = await loginPolicy(against);
  if (lp.error) return { error: lp.error };
  const rr = await userReach(lp.bin, user, starts || []);
  if (rr.error) return { error: rr.error };
  const list = Object.keys(rr.reached).map(d => ({ d, depth: rr.steps[rr.reached[d]].depth, role: rr.steps[rr.reached[d]].role }))
    .sort((a, b) => a.depth - b.depth || a.d.localeCompare(b.d));
  return { roles: rr.roles, domains: list.map(x => ({ name: x.d, depth: x.depth, role: x.role, path: x.depth ? pathOut(rr, x.d) : [] })) };
});

/**
 * Can a user's sessions get an access: { against, user, starts, target | path,
 * tclass, perms } → the nearest reached domain allowed it, the path there and
 * the rule; or no.
 */
connection.onRequest('selinux/loginCan', async ({ against, user, starts, target, path: p, tclass, perms } = {}) => {
  await indexing;
  const lp = await loginPolicy(against);
  if (lp.error) return { error: lp.error };
  let resolved = null;
  if (!target && p) {
    if (!p.startsWith('/')) return { error: 'A path must be absolute.' };
    const fc = lp.pol.build ? (usingDevel ? moduleFileContexts() : treeFileContexts(lastBuild.get(treeRoot))) : lp.pol.fc;
    const r = await execFileP('matchpathcon', [...(fc ? ['-f', fc] : []), '-m', denials.FILE_MODES[tclass] || 'file', p]);
    const m = /\t(\S+)\s*$/.exec(r.stdout);
    const ctx = m && denials.parseContext(m[1]);
    if (!ctx) return { error: `No file context gives ${p} a label${(r.stderr || '').trim() ? ` (${r.stderr.trim().split('\n')[0]})` : ''}.` };
    target = ctx.type;
    resolved = { path: p, type: target };
  }
  if (!/^[A-Za-z_]\w*$/.test(target || '')) return { error: 'Give a type (e.g. shadow_t) or an absolute path.' };
  if (!/^\w+$/.test(tclass || '')) return { error: 'Choose the kind of object.' };
  const rr = await userReach(lp.bin, user, starts || []);
  if (rr.error) return { error: rr.error };
  const r = await policyQuery.request({ op: 'access', bin: lp.bin, domains: Object.keys(rr.reached), t: target, classes: [tclass], perms: perms && perms.length ? perms : '*' });
  if (r.error) return { error: /KeyError/.test(r.error) ? `${target} is not a type in this policy.` : `Policy query failed: ${r.error}` };
  const n = logins.nearest(rr, Object.keys(r.access));
  if (!n) return { target, resolved, can: false, reached: Object.keys(rr.reached).length };
  return { target, resolved, can: true, domain: n.d, count: Object.keys(r.access).length, rule: r.access[n.d].rule, perms: r.access[n.d].perms, path: pathOut(rr, n.d) };
});

/** Statement index of the last tree build (shared with Changes since HEAD's idle drop). */
let ruleIndex = { key: null, side: null };
async function currentSide() {
  const res = lastBuild.get(usingDevel ? lastModule : treeRoot);
  const model = await getPolicyModel();
  if (!res || model.unavailable) return null;
  const key = `${res.workDir}:${model.builtAt}`;
  if (ruleIndex.key !== key || !ruleIndex.side) {
    const attrs = Object.fromEntries(model.types.map(t => [t.name, t.attrs]));
    const outputs = res.tree ? build.treeOutputs(res) : [res.expandedPath];
    ruleIndex = { key, side: { index: explain.byName(explain.indexBuild(outputs, res.resolveFile)), attrs, gained: null, changedFiles: null } };
  }
  clearTimeout(explainIdle);
  explainIdle = setTimeout(() => { explain.dropCache(); ruleIndex = { key: null, side: null }; }, 120000);
  return ruleIndex.side;
}

// The source statements that produce one compiled rule (expanded on demand in the view).
connection.onRequest('selinux/ruleOrigins', async ({ rule }) => {
  await indexing;
  const side = await currentSide();
  if (!side) return { origins: [], more: 0 };
  const x = explain.explainRule(rule, rule.perms, side, 8);
  explain.releaseTexts();
  return x;
});

documents.listen(connection);
connection.listen();
