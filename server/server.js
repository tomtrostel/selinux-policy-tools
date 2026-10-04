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
  idx.setFile(toPath(e.document.uri), e.document.getText(), true);
  scheduleRebuild();
});

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

process.on('exit', () => { for (const d of workDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } } });
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
    d.l = hit ? hit[0][0] : 0;
  }
}

function buildSummary(res) {
  const errors = res.diagnostics.filter(d => d.severity === 'error').length;
  return { ok: res.ok, module: res.module, ms: res.ms, errors, warnings: res.diagnostics.length - errors,
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
  if (!settings.build.onSave) return;
  const p = toPath(e.document.uri);
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
  if (decls && decls.length) return { range: r, contents: { kind: MarkupKind.Markdown, value: declMarkdown(name, decls) } };
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
const baseline = { key: null, res: null, info: null, srcRoot: null, pending: null, pendingKey: null };
let explainIdle = null;

function treeBuildOptions(root) {
  const files = {};
  for (const [rel, srcs] of Object.entries(settings.build.tree.files || {})) files[rel] = [].concat(srcs).map(s => resolvePath(root, s));
  const makeArgs = settings.build.tree.makeArgs || [];
  const custom = (settings.build.tree.targets || []).length > 0;
  const p1 = custom ? settings.build.tree.targets : phase1Targets(root, makeArgs);
  return { makeArgs, files, targets: custom || p1.includes('policy') ? p1 : [...p1, 'validate'] };
}

async function ensureBaseline(root, info) {
  const opts = treeBuildOptions(root);
  const key = JSON.stringify({ root, sha: info.sha, opts });
  if (baseline.key === key && baseline.res) return baseline;
  if (baseline.pending && baseline.pendingKey === key) { await baseline.pending; return baseline; }
  baseline.pendingKey = key;
  baseline.pending = (async () => {
    connection.sendNotification('selinux/build', { state: 'baseline', module: path.basename(root), short: info.sha.slice(0, 7) });
    const dest = build.scratchDir('head', root);
    workDirs.add(dest);
    const srcRoot = await build.exportHead(info, dest);
    const res = await build.buildTree(srcRoot, (p) => { try { return fs.readFileSync(p); } catch { return null; } }, opts);
    workDirs.add(res.workDir);
    Object.assign(baseline, { key, res, info, srcRoot });
  })();
  try { await baseline.pending; } finally { baseline.pending = null; }
  return baseline;
}

connection.onRequest('selinux/policyDiff', async () => {
  await indexing;
  if (!treeRoot) return { unavailable: 'Comparing with HEAD needs a full policy source tree.' };
  const why = buildUnavailable();
  if (why) return { unavailable: why };
  const info = await build.gitInfo(treeRoot);
  if (!info) return { unavailable: `${treeRoot} is not in a git repository with commits, so there is no HEAD to compare with.` };
  const t0 = Date.now();

  // Current side: the last build of the working tree (build now if there is none or it failed).
  let cur = lastBuild.get(treeRoot);
  if (!cur || !cur.ok || !cur.policyBin) { await runBuild(treeRoot, false, null); cur = lastBuild.get(treeRoot); }
  if (!cur || !cur.ok || !cur.policyBin) return { unavailable: 'The working tree does not build; fix its errors (see Problems) and compare again.' };

  const base = await ensureBaseline(treeRoot, info);
  const short = info.sha.slice(0, 7);
  if (!base.res.ok || !base.res.policyBin) return { unavailable: `HEAD (${short}) does not build with the current settings, so there is nothing to compare with.`, log: base.res.log };

  let diff;
  try { diff = await runPython('policy_diff.py', [base.res.policyBin, cur.policyBin]); } catch (e) { return { unavailable: `Comparing the policies failed: ${e.message}` }; }
  const tDiff = Date.now();

  // Files that differ from HEAD rank first when several statements explain a change.
  const changedB = new Set(await build.gitChangedFiles(treeRoot, info));
  for (const d of documents.all()) {
    const p = toPath(d.uri);
    if (p.startsWith(treeRoot + path.sep)) { let disk = null; try { disk = fs.readFileSync(p, 'utf8'); } catch { /* new */ } if (disk !== d.getText()) changedB.add(p); }
  }
  const toHead = (p) => path.join(base.srcRoot, path.relative(treeRoot, p));
  const changedA = new Set([...changedB].map(toHead));
  const side = (res, attrs, gained, changedFiles) => ({ index: explain.byName(explain.indexBuild(build.treeOutputs(res), res.resolveFile)), attrs, gained, changedFiles });
  const sideB = side(cur, diff.attrsB, new Map(diff.membership.map(m => [m.type, new Set(m.added)])), changedB);
  const sideA = side(base.res, diff.attrsA, new Map(diff.membership.map(m => [m.type, new Set(m.removed)])), changedA);
  // HEAD-side origins point into the exported copy; also give the working-tree path.
  const fromHead = (o) => ({ ...o, head: true, real: path.join(treeRoot, path.relative(base.srcRoot, o.path)), because: o.because && o.because.map(fromHead) });
  const headSide = (x) => ({ origins: x.origins.map(fromHead), more: x.more });
  for (const r of diff.rules) {
    if (r.add.length) r.addFrom = explain.explainRule(r, r.add, sideB);
    if (r.del.length) r.delFrom = headSide(explain.explainRule(r, r.del, sideA));
  }
  for (const m of diff.membership) {
    m.addFrom = m.added.map(a => ({ attr: a, origins: explain.membershipOrigins(m.type, a, sideB) }));
    m.delFrom = m.removed.map(a => ({ attr: a, origins: explain.membershipOrigins(m.type, a, sideA).map(fromHead) }));
  }
  explain.releaseTexts();
  // The statement index is ~100 MB per side on a RHEL tree: keep it while
  // comparisons are being refreshed, drop it when they go idle.
  clearTimeout(explainIdle);
  explainIdle = setTimeout(() => explain.dropCache(), 120000);
  diff.typeLocations = Object.fromEntries(diff.types.added.map(t => [t, sourceLocation(t, ['type'])]));
  delete diff.attrsA; delete diff.attrsB; delete diff.aliasesA; delete diff.aliasesB;
  return {
    ...diff,
    head: { sha: info.sha, short, subject: info.subject },
    builtAt: fs.statSync(cur.policyBin).mtimeMs,
    ms: { total: Date.now() - t0, diff: tDiff - t0 },
  };
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

connection.onRequest('selinux/policyModel', async () => {
  await indexing;
  if (usingDevel) return { unavailable: 'The compiled policy view needs a full policy source tree: standalone modules are not linked into a kernel policy.' };
  if (!treeRoot) return { unavailable: 'Open a refpolicy source tree to see its compiled policy.' };
  const res = lastBuild.get(treeRoot);
  if (!res || !res.policyBin || !fs.existsSync(res.policyBin)) {
    return { unavailable: res && !res.ok ? 'The last build failed; fix its errors and build again.' : 'Build the policy (SELinux: Build) to see what it contains.', needsBuild: true };
  }
  const mtimeMs = fs.statSync(res.policyBin).mtimeMs;
  if (policyModelCache.bin !== res.policyBin || policyModelCache.mtimeMs !== mtimeMs) {
    let model;
    try { model = await exportPolicy(res.policyBin); } catch (e) { return { unavailable: `Could not read ${res.policyBin}: ${e.message}` }; }
    const users = userLocations();
    for (const t of model.types) t.loc = sourceLocation(t.name, ['type']);
    for (const a of model.attributes) a.loc = sourceLocation(a.name, ['attribute']);
    for (const r of model.roles) r.loc = sourceLocation(r.name, ['role']);
    for (const b of model.bools) b.loc = sourceLocation(b.name, ['bool']);
    for (const u of model.users) u.loc = users.get(u.name) || null;
    for (const c of model.classes) { const k = idx.classes.get(c.name); c.loc = k ? { p: k.path, l: k.l, c: k.c, len: c.name.length } : null; }
    model.bin = res.policyBin;
    model.builtAt = mtimeMs;
    model.tree = treeRoot;
    Object.assign(policyModelCache, { bin: res.policyBin, mtimeMs, model });
  }
  return policyModelCache.model;
});

documents.listen(connection);
connection.listen();
