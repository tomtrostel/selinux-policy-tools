#!/usr/bin/env node
'use strict';
/*
 * selinux-policy-check: the extension's checks without VS Code, for CI.
 *
 *   selinux-policy-check [options] <policy tree | folder of standalone modules>
 *
 * Runs the language server over stdio (the same code the editor uses) on
 * that workspace and reports, in this order: static diagnostics of every
 * source file, the real build (compile + link), the property checks
 * (selinux.checks), login contexts and session starts, context files, and
 * the optional_policy blocks the linker drops. Exit status 0 when nothing
 * fails, 1 when something does, 2 when it couldn't check (no toolchain, no
 * tree, a timeout).
 *
 * Options:
 *   --spec <file>        build settings from a selinux-policy.spec (RHEL/Fedora/CLIP), as
 *                        "Configure Build from Spec File…" (a CLIP tree finds its spec itself)
 *   --variant <name>     the spec's policy variant (targeted, mls, …; CLIP has one)
 *   --make "<args>"      make arguments instead of a spec (build.conf otherwise)
 *   --profile <name>     install profile (CLIP kickstart) for the dropped-block report
 *   --strict             warnings fail too (static warnings, login/context warnings)
 *   --no-build           static diagnostics only (no toolchain needed)
 *   --skip <list>        parts to leave out: checks,logins,contexts,dropped
 *   --json <file>        write every result as JSON
 *   --report <file>      write the evidence report of the build (.md, or .html by the extension)
 *   --timeout <s>        for the build (default 1800)
 *   --verbose            show info-level findings and the server's log
 */
const cp = require('child_process');
const fs = require('fs');
const path = require('path');

const USAGE = 'usage: selinux-policy-check [--spec FILE [--variant NAME] | --make "ARGS"] [--profile NAME] [--strict] [--no-build] [--skip a,b] [--json FILE] [--report FILE.md|.html] [--timeout S] [--verbose] <tree-or-folder>';

function parseArgs(argv) {
  const o = { build: true, strict: false, skip: new Set(), verbose: false, timeout: 1800, target: null };
  const a = argv.slice();
  while (a.length) {
    const x = a.shift();
    const val = () => { if (!a.length) throw new Error(`${x} needs a value`); return a.shift(); };
    if (x === '--spec') o.spec = val();
    else if (x === '--variant') o.variant = val();
    else if (x === '--make') o.make = val().split(/\s+/).filter(Boolean);
    else if (x === '--profile') o.profile = val();
    else if (x === '--strict') o.strict = true;
    else if (x === '--no-build') o.build = false;
    else if (x === '--skip') for (const s of val().split(',')) o.skip.add(s.trim());
    else if (x === '--json') o.json = val();
    else if (x === '--report') o.report = val();
    else if (x === '--timeout') o.timeout = +val() || 1800;
    else if (x === '--verbose' || x === '-v') o.verbose = true;
    else if (x === '--help' || x === '-h') o.help = true;
    else if (x.startsWith('-')) throw new Error(`unknown option ${x}`);
    else if (o.target) throw new Error('one workspace at a time');
    else o.target = x;
  }
  if (!o.help && !o.target) throw new Error(USAGE);
  return o;
}

/** The build settings for the tree: from --make, --spec, or a CLIP spec next to the tree. */
function buildSettings(o, target) {
  if (o.make) return { makeArgs: o.make, files: {}, source: `make arguments: ${o.make.join(' ')}` };
  let spec = o.spec ? path.resolve(o.spec) : null;
  if (!spec) {
    // CLIP: packages/selinux-policy/selinux-policy.spec (RHEL 9) or -cil.spec (RHEL 8) next to the tree.
    const dir = path.dirname(target);
    let names = [];
    try { names = fs.readdirSync(dir).filter(n => n.endsWith('.spec')); } catch { /* none */ }
    names.sort((x, y) => (y.includes('-cil') - x.includes('-cil')) || x.localeCompare(y));
    if (names.length) spec = path.join(dir, names[0]);
  }
  if (!spec) return { makeArgs: [], files: {}, source: "the tree's build.conf" };
  if (!fs.existsSync(spec)) throw new Error(`no such spec: ${spec}`);
  const { specBuildConfigs } = require('../server/specconfig');
  const configs = specBuildConfigs(spec);
  if (!configs.length) throw new Error(`${spec}: no build configuration found in it`);
  let c = configs[0];
  if (o.variant) {
    c = configs.find(x => x.variant === o.variant);
    if (!c) throw new Error(`${spec} has no variant ${o.variant} (${configs.map(x => x.variant).join(', ')})`);
  } else if (configs.length > 1) throw new Error(`${spec} has several variants (${configs.map(x => x.variant).join(', ')}): choose one with --variant`);
  if (c.missing && c.missing.length) throw new Error(`${spec}: missing ${c.missing.join(', ')}`);
  return { makeArgs: c.makeArgs, files: c.files || {}, source: `${path.basename(spec)}${c.variant ? ` (${c.variant})` : ''}`, notes: c.notes || [] };
}

const SEV = { error: 0, warning: 1, info: 2, hint: 3 };

/** Starts the server on the workspace; resolves to { conn, proc, diags, stats, events }. */
function startServer(ws, initOptions, verbose) {
  const rpc = require('vscode-jsonrpc/node');
  const proc = cp.spawn(process.execPath, [path.join(__dirname, '..', 'server', 'server.js'), '--stdio'], { stdio: ['pipe', 'pipe', 'pipe'] });
  proc.stderr.on('data', (d) => { if (verbose) process.stderr.write(d); });
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  const s = { conn, proc, diags: {}, stats: null, checks: [], builds: [] };
  let doneIndex;
  s.indexed = new Promise(r => (doneIndex = r));
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') { s.stats = p.stats; doneIndex(); } });
  conn.onNotification('textDocument/publishDiagnostics', p => { s.diags[p.uri] = p.diagnostics; });
  conn.onNotification('selinux/checks', p => { s.checks.push(p); if (s.onChecks) s.onChecks(p); });
  conn.onNotification('selinux/build', p => { s.builds.push(p); });
  conn.onNotification('window/logMessage', p => { if (verbose) process.stderr.write(`[server] ${p.message}\n`); });
  for (const n of ['selinux/inactiveChanged', 'selinux/linking', 'selinux/linked', 'selinux/loginsChanged']) conn.onNotification(n, () => {});
  conn.listen();
  s.init = async () => {
    const { URI } = require('vscode-uri');
    await conn.sendRequest('initialize', { processId: process.pid, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: initOptions });
    conn.sendNotification('initialized', {});
    await s.indexed;
  };
  return s;
}

const withTimeout = (p, ms, what) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`${what} took longer than ${ms / 1000} s`)), ms).unref())]);

/** Runs every part; returns the results (pure data, formatted by format()). */
async function run(o) {
  const { URI } = require('vscode-uri');
  const target = path.resolve(o.target);
  if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) throw new Error(`${target} is not a directory`);
  const res = { target, parts: {}, problems: [], failed: false, unable: null };
  let settings = { makeArgs: [], files: {}, source: null };
  try { settings = buildSettings(o, target); } catch (e) { if (o.build) throw e; }
  res.settings = settings.source;
  const s = startServer(target, { trusted: true, build: { onSave: false, tree: { makeArgs: settings.makeArgs, files: settings.files } } }, o.verbose);
  try {
    await withTimeout(s.init(), 600000, 'indexing');
    const st = s.stats || {};
    res.mode = st.buildMode || null;
    res.tree = st.tree || null;
    res.stats = { files: st.files, modules: st.modules, interfaces: st.interfaces, types: st.types };
    // A folder of sources that is neither (a bare policy/ directory): static analysis is still possible.
    if (!res.mode && o.build) { res.unable = `${target} holds neither a policy tree (Makefile, Rules.modular, build.conf, policy/support/obj_perm_sets.spt) nor standalone modules (.te files); with --no-build its sources are still analyzed.`; return res; }
    if (!res.mode) res.mode = 'sources';
    if (o.profile) {
      const r = await s.conn.sendRequest('selinux/selectInstallProfile', { profile: o.profile });
      if (r.error) { res.unable = r.error; return res; }
      res.profile = r.profile;
    }
    // 1. Static diagnostics of every file.
    const all = await s.conn.sendRequest('selinux/diagnoseAll', { minSeverity: 'info', dropped: !o.skip.has('dropped') });
    res.m4Flags = all.m4Flags;
    res.parts.static = { files: all.files, items: all.diagnostics };
    for (const d of all.diagnostics) addProblem(res, 'static', d.severity, d.path, d.l, `[${d.code}] ${d.msg}`, o);
    res.parts.dropped = o.skip.has('dropped') ? null : { items: all.dropped, profile: all.profile };
    if (!o.build) { if (o.report) res.parts.report = { error: 'needs a build (--no-build given), not written' }; return res; }
    // 2. The build: trees as a whole, standalone modules one by one.
    const uriOf = (p) => URI.file(p).toString();
    const checksDone = new Promise(r => { s.onChecks = r; });
    const t0 = Date.now();
    const targets = res.mode === 'tree' ? [res.tree] : moduleFiles(target);
    const builds = [];
    for (const t of targets) {
      const b = await withTimeout(s.conn.sendRequest('selinux/build', { uri: uriOf(t) }), o.timeout * 1000, `building ${path.basename(t)}`);
      builds.push({ target: t, ok: !!b.ok, unavailable: b.unavailable || null, ms: b.ms, packages: b.packages, diagnostics: (b.diagnostics || []).map(d => ({ path: d.file, l: d.l, severity: d.severity, msg: d.msg, tool: d.tool })) });
      if (b.unavailable) { res.unable = b.unavailable; return res; }
      for (const d of b.diagnostics || []) addProblem(res, 'build', d.severity || 'error', d.file, d.l, d.msg, o);
      if (!b.ok && !(b.diagnostics || []).some(d => d.severity === 'error')) addProblem(res, 'build', 'error', t, 0, `build failed (see the log: ${(b.log || '').trim().split('\n').slice(-3).join(' | ')})`, o);
    }
    res.parts.build = { builds, ms: Date.now() - t0, ok: builds.every(b => b.ok) };
    if (!res.parts.build.ok) return res;
    // 3. Property checks (run by the server after a good build; the results land on the checks file).
    if (!o.skip.has('checks')) {
      const cf = await s.conn.sendRequest('selinux/checksFile');
      if (cf && cf.path && cf.exists) {
        const summary = s.checks.length ? s.checks[s.checks.length - 1] : await withTimeout(checksDone, 300000, 'property checks').catch(e => ({ error: e.message }));
        const items = (s.diags[uriOf(cf.path)] || []).map(d => ({ path: cf.path, l: d.range.start.line, severity: 'error', msg: d.message,
          related: (d.relatedInformation || []).map(r => ({ path: URI.parse(r.location.uri).fsPath, l: r.location.range.start.line, msg: r.message })) }));
        res.parts.checks = { path: cf.path, total: summary.total, failed: summary.failed, errors: summary.errors, note: summary.note || summary.error || null, items };
        for (const d of items) addProblem(res, 'checks', 'error', d.path, d.l, d.msg, o, d.related);
        if (summary.note && /failed|unavailable/.test(summary.note)) addProblem(res, 'checks', 'error', cf.path, 0, summary.note, o);
      } else res.parts.checks = { path: cf && cf.path, total: 0, missing: true };
    }
    // 4. Login contexts and session starts; 5. context files.
    for (const [part, req, skipKey] of [['logins', 'selinux/loginContexts', 'logins'], ['contexts', 'selinux/contextFiles', 'contexts']]) {
      if (o.skip.has(skipKey)) continue;
      const r = await withTimeout(s.conn.sendRequest(req, { against: 'build' }), 600000, part);
      if (r.error) { res.parts[part] = { error: r.error }; addProblem(res, part, 'error', res.tree || target, 0, r.error, o); continue; }
      const problems = (r.problems || []).map(p => ({ severity: p.severity, kind: p.kind, path: p.file || null, l: p.l || 0, msg: p.text, login: p.login || null, way: p.way || null, hypothetical: !!p.hypothetical,
        related: (p.related || []).slice(0, 6).map(x => ({ path: x.file, l: x.l, msg: x.text })) }));
      res.parts[part] = { policy: r.policy && r.policy.label, problems, mappings: (r.mappings || []).length, sessions: (r.sessions || []).length, files: (r.files || []).length, notes: r.notes || [] };
      for (const p of problems) addProblem(res, part, p.severity, p.path, p.l, `${p.kind}: ${p.msg}`, o, p.related);
    }
    // 6. The evidence report (Markdown or HTML by the file's extension), from the same build.
    if (o.report) {
      const format = /\.html?$/i.test(o.report) ? 'html' : 'markdown';
      const r = await withTimeout(s.conn.sendRequest('selinux/evidenceReport', { against: 'build', format }), 600000, 'the evidence report');
      if (r.error) { res.parts.report = { error: r.error }; addProblem(res, 'report', 'error', res.tree || target, 0, r.error, o); } else {
        fs.writeFileSync(o.report, r.text);
        res.parts.report = { path: path.resolve(o.report), format, sections: r.sections, bytes: r.text.length };
      }
    }
    return res;
  } finally {
    try { s.conn.sendNotification('exit'); } catch { /* gone */ }
    setTimeout(() => { try { s.proc.kill(); } catch { /* gone */ } }, 1500).unref();
  }
}

/** Standalone modules in a folder: each .te at the top or one level down (a folder per module). */
function moduleFiles(dir) {
  const out = [];
  const add = (d) => { for (const n of fs.readdirSync(d)) if (n.endsWith('.te')) out.push(path.join(d, n)); };
  add(dir);
  for (const n of fs.readdirSync(dir)) { const d = path.join(dir, n); try { if (fs.statSync(d).isDirectory() && n !== 'node_modules' && !n.startsWith('.')) add(d); } catch { /* skip */ } }
  return out;
}

function addProblem(res, part, severity, file, l, msg, o, related = []) {
  const sev = severity in SEV ? severity : 'error';
  const fails = sev === 'error' || (o.strict && sev === 'warning');
  if (fails) res.failed = true;
  res.problems.push({ part, severity: sev, path: file || null, l: l || 0, msg, related, fails });
}

const PART_TITLES = { static: 'Static analysis', build: 'Build', checks: 'Property checks', logins: 'Login contexts and session starts', contexts: 'Context files', dropped: 'Dropped optional blocks' };

/** The report as text. */
function format(res, o = {}) {
  const out = [];
  // Paths relative to the tree (or the folder checked); Windows paths come back with a lowercase drive letter.
  const base = res.tree || res.target;
  const under = (p) => base && (process.platform === 'win32' ? p.toLowerCase().startsWith(base.toLowerCase()) : p.startsWith(base));
  const rel = (p) => (p ? (under(p) ? path.relative(base, p) : p).split(path.sep).join('/') : '-');
  const where = (p, l) => (p ? `${rel(p)}:${(l || 0) + 1}` : '');
  const count = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
  out.push(`selinux-policy-check: ${res.target}${res.mode === 'tree' ? ` (policy tree${res.tree && res.tree !== res.target ? ` ${rel(res.tree)}` : ''}${res.settings ? `, built with ${res.settings}` : ''}${res.profile ? `, install profile ${res.profile}` : ''})` : res.mode === 'module' ? ' (standalone modules)' : ''}`);
  if (res.unable) { out.push(`unable to check: ${res.unable}`); return out.join('\n'); }
  const show = (p) => p.severity !== 'info' || o.verbose;
  const lines = (part) => res.problems.filter(p => p.part === part && show(p)).map(p => `  ${p.severity.padEnd(7)} ${where(p.path, p.l)} ${p.msg}`.replace(/\s+$/, '')
    + (o.verbose ? p.related.map(r => `\n          ↳ ${where(r.path, r.l)} ${r.msg}`).join('') : ''));
  const sums = (part) => { const ps = res.problems.filter(p => p.part === part); return ['error', 'warning', 'info'].map(sv => [sv, ps.filter(p => p.severity === sv).length]).filter(([, n]) => n).map(([sv, n]) => count(n, sv)).join(', ') || 'nothing found'; };
  const st = res.parts.static;
  if (st) { out.push(`${PART_TITLES.static}: ${count(st.files, 'file')}, ${sums('static')}${!o.verbose && res.problems.some(p => p.part === 'static' && p.severity === 'info') ? ' (info with --verbose)' : ''}`); out.push(...lines('static')); }
  const b = res.parts.build;
  if (b) {
    for (const x of b.builds) { const r = rel(x.target); out.push(`${PART_TITLES.build}: ${x.ok ? 'ok' : 'FAILED'}${r && r !== '-' ? ` ${r}` : ''}${x.packages ? `, ${count(x.packages, 'package')}` : ''} (${((x.ms || 0) / 1000).toFixed(0)} s)`); }
    out.push(...lines('build'));
  } else if (st && !res.unable) out.push('Build: skipped (--no-build)');
  const c = res.parts.checks;
  if (c) {
    if (c.missing) out.push(`${PART_TITLES.checks}: no ${c.path ? path.basename(c.path) : 'selinux.checks'} file`);
    else { out.push(`${PART_TITLES.checks}: ${count(c.total || 0, 'check')}, ${c.failed ? `${c.failed} failing` : 'all hold'}${c.errors ? `, ${count(c.errors, 'syntax error')}` : ''}${c.note ? ` (${c.note})` : ''}`); out.push(...lines('checks')); }
  }
  for (const part of ['logins', 'contexts']) {
    const p = res.parts[part];
    if (!p) continue;
    if (p.error) { out.push(`${PART_TITLES[part]}: ${p.error}`); continue; }
    out.push(`${PART_TITLES[part]}: ${part === 'logins' ? `${count(p.mappings, 'seusers line')}, ${count(p.sessions, 'session start')}` : count(p.files, 'file')} checked, ${sums(part)}`);
    out.push(...lines(part));
  }
  const rp = res.parts.report;
  if (rp) out.push(rp.error ? `Evidence report: ${rp.error}` : `Evidence report: ${rp.path} (${rp.format}, ${rp.sections} sections)`);
  const d = res.parts.dropped;
  if (d && res.mode === 'tree') {
    out.push(`${PART_TITLES.dropped}: ${count(d.items.length, 'block')}${d.profile ? ` with install profile ${d.profile}` : ''}${d.items.length && !o.verbose ? ' (listed with --verbose)' : ''}`);
    if (o.verbose) for (const x of d.items) out.push(`  ${where(x.path, x.l)} needs ${x.missing.map(m => m.name).join(', ')}`);
  }
  const fails = res.problems.filter(p => p.fails);
  out.push(fails.length ? `Result: FAIL (${count(fails.length, 'problem')}${o.strict ? ', --strict' : ''})` : 'Result: OK');
  return out.join('\n');
}

async function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); console.error(USAGE); process.exit(2); }
  if (o.help) { console.log(fs.readFileSync(__filename, 'utf8').split('\n').slice(2).filter(l => l.startsWith(' *')).map(l => l.replace(/^ \*\/?\s?/, '')).join('\n').trim()); process.exit(0); }
  let res;
  try {
    res = await run(o);
  } catch (e) {
    console.error(`selinux-policy-check: ${e.message}`);
    process.exit(2);
  }
  console.log(format(res, o));
  if (o.json) fs.writeFileSync(o.json, JSON.stringify(res, null, 1));
  process.exit(res.unable ? 2 : res.failed ? 1 : 0);
}

if (require.main === module) main();

module.exports = { parseArgs, buildSettings, format, run, moduleFiles, USAGE };
