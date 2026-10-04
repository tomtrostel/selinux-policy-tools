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
const { diagnose } = require('./diagnostics');
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
  build: { enabled: true, onSave: true, develMakefile: '/usr/share/selinux/devel/Makefile',
    tree: { makeArgs: [], targets: [], validate: true, outputDir: '', files: {} } },
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
      let n = idx.scanRoots(scanRoots);
      const devel = settings.develHeadersPath;
      const wantDevel = settings.useDevelHeaders === 'always' ||
        (settings.useDevelHeaders === 'auto' && !idx.defs.has('gen_require'));
      usingDevel = !!(wantDevel && devel && fs.existsSync(devel));
      if (usingDevel) {
        log(`support macros not found in workspace; indexing devel headers from ${devel}`);
        n += idx.scanRoots([devel]);
      }
      for (const d of documents.all()) idx.setFile(toPath(d.uri), d.getText(), true);
      idx.rebuild();
      findTreeRoot();
      toolchain = null; // the mode (and so the tools needed) may have changed
      if (treeRoot) log(`refpolicy source tree: ${treeRoot}`);
      const stats = { ...idx.stats(), ms: Date.now() - t0, buildMode: usingDevel ? 'module' : treeRoot ? 'tree' : null };
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
    if (treeRoot) job = { cwd: treeRoot, makeArgs: settings.build.tree.makeArgs || [] };
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
  rebuildTimer = setTimeout(() => { idx.rebuild(); publishAll(); }, 300);
}

documents.onDidChangeContent((e) => {
  const p = toPath(e.document.uri);
  if (isChecksFile(p)) { clearTimeout(checksTimer); checksTimer = setTimeout(() => runChecks().catch(err => log(`checks failed: ${err.message}`)), 500); return; }
  idx.setFile(p, e.document.getText(), true);
  scheduleRebuild();
});
let checksTimer = null;

documents.onDidClose((e) => {
  const p = toPath(e.document.uri);
  try { idx.setFile(p, fs.readFileSync(p, 'utf8'), true); } catch { idx.files.delete(p); }
  connection.sendDiagnostics({ uri: e.document.uri, diagnostics: [] });
  scheduleRebuild();
});

connection.onDidChangeWatchedFiles((ev) => {
  for (const ch of ev.changes) {
    if (documents.get(ch.uri)) continue; // open editors are authoritative
    const p = toPath(ch.uri);
    if (isChecksFile(p)) { runChecks().catch(err => log(`checks failed: ${err.message}`)); continue; }
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

/** What building `p` means: its module .te (module mode) or the tree root. */
function buildTarget(p) {
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
        if (res.tree && wantPkg && res.ok && settings.build.tree.outputDir) {
          try { res.exported = build.exportTreeOutputs(res, resolvePath(key, settings.build.tree.outputDir), settings.build.tree.makeArgs || []); } catch (e) { res.exportError = e.message; }
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
  connection.sendNotification('selinux/build', { state: 'start', module: path.basename(te, '.te') });
  const snapshot = new Map();
  const res = await build.buildModule(te, (p) => { const t = readSource(p); if (t != null) snapshot.set(p, t); return t; },
    { develMakefile: settings.build.develMakefile, pkg });
  workDirs.add(res.workDir);
  for (const [p, t] of snapshot) builtText.set(p, t);
  return res;
}

/** A configured path: `~/x` → home, relative → under the tree root, absolute as is. */
function resolvePath(root, dir) {
  if (dir === '~' || dir.startsWith('~/')) return path.join(require('os').homedir(), dir.slice(1));
  return path.resolve(root, dir);
}

async function treeBuild(root, st) {
  const name = path.basename(root);
  const files = {};
  for (const [rel, srcs] of Object.entries(settings.build.tree.files || {})) files[rel] = [].concat(srcs).map(s => resolvePath(root, s));
  const opts = { makeArgs: settings.build.tree.makeArgs || [], files };
  const readText = (p) => { const d = documents.get(toUri(p)); if (d) return d.getText(); try { return fs.readFileSync(p); } catch { return null; } };
  connection.sendNotification('selinux/build', { state: 'start', module: name });
  const custom = (settings.build.tree.targets || []).length > 0;
  const res = await build.buildTree(root, readText, { ...opts, targets: custom ? settings.build.tree.targets : phase1Targets(root, opts.makeArgs) });
  workDirs.add(res.workDir);
  mapLinkDiagnostics(res);
  if (custom || res.monolithic || !res.ok || st.again || !settings.build.tree.validate) return res;
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
    const hit = f.refs && f.refs.get(d.token);
    if (hit) { d.l = hit[0][0]; continue; }
    // Usually the requirement comes from an interface the module calls:
    // point at the first call whose interface (or one it calls) requires it.
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
  const staticLines = new Set(staticDiags.filter(d => /^unknown-/.test(d.code)).map(d => d.range.start.line));
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

connection.onHover(({ textDocument, position }) => {
  const doc = documents.get(textDocument.uri);
  if (!doc) return null;
  const w = wordAt(doc, position);
  if (!w) return null;
  const name = w.word;
  const r = { start: { line: position.line, character: w.start }, end: { line: position.line, character: w.end } };
  const defs = idx.defs.get(name);
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
      defMarkdown(inactive[0], inactive.length) + `\n\n*Not part of this build configuration: defined only when \`${b.sym}\` is ${b.want ? '' : 'not '}defined.*` } };
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

/* ---------------- custom requests for the explorer view ---------------- */

connection.onRequest('selinux/modules', async () => { await indexing; return idx.modules(); });
connection.onRequest('selinux/moduleContents', async ({ path: p }) => { await indexing; return idx.moduleContents(p); });
connection.onRequest('selinux/stats', async () => { await indexing; return idx.stats(); });
connection.onRequest('selinux/reindex', async () => { await reindex(); return idx.stats(); });
function buildRequestTarget(uri) {
  const why = buildUnavailable();
  if (why) return { unavailable: why };
  const key = buildTarget(toPath(uri));
  if (!key) return { unavailable: treeRoot ? `This file is outside the policy tree (${treeRoot}).` : 'This file is not part of a module (no .te file next to it).' };
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
    reason: `Not compiled in this build configuration: needs ${b.sym} ${b.want ? 'defined' : 'not defined'}.` }));
});

// Build settings derived from a Fedora/RHEL selinux-policy.spec, one entry per policy variant.
connection.onRequest('selinux/specBuildConfig', async ({ specPath }) => {
  try { return { configs: require('./specconfig').specBuildConfigs(specPath) }; } catch (e) { return { error: e.message }; }
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
  for (const [rel, srcs] of Object.entries(settings.build.tree.files || {})) files[rel] = [].concat(srcs).map(s => resolvePath(root, s));
  const makeArgs = settings.build.tree.makeArgs || [];
  const custom = (settings.build.tree.targets || []).length > 0;
  const p1 = custom ? settings.build.tree.targets : phase1Targets(root, makeArgs);
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
  for (const a of settings.build.tree.makeArgs || []) { const m = /^NAME=(\S+)/.exec(a); if (m) return m[1]; }
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
  const overlay = settings.build.tree.files && settings.build.tree.files[MODULES_CONF];
  if (overlay) {
    const parts = [].concat(overlay).map(s => resolvePath(root, s));
    const texts = parts.map(p => readSource(p));
    if (texts.some(t => t == null)) return null;
    return { text: texts.join(''), parts: parts.map((p, i) => ({ path: p, text: texts[i] })) };
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
  const apps = (settings.build.tree.makeArgs || []).map(a => /^APPS_MODS=(.*)$/.exec(a)).filter(Boolean).flatMap(m => m[1].split(/\s+/).filter(Boolean));
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
  let type = null;
  for (const a of settings.build.tree.makeArgs || []) { const m = /^TYPE=(\S+)/.exec(a); if (m) type = m[1]; }
  if (!type) { try { const m = /^\s*TYPE\s*=\s*(\S+)/m.exec(fs.readFileSync(path.join(root, 'build.conf'), 'utf8')); if (m) type = m[1]; } catch { /* none */ } }
  const file = path.join(root, 'config', `appconfig-${type || 'mcs'}`, 'seusers');
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
