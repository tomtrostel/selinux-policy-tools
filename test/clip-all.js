'use strict';
// Every tree-based end-to-end test on each CLIP branch, then a diagnostics
// survey of each tree compared with the known findings in
// test/survey-baseline.json (keyed by the tree's refpolicy VERSION).
//   node test/clip-all.js [tree ...] [--only build-tree,checks] [--update-baseline]
// Default trees: CLIP for RHEL 8 and RHEL 9 on the test host
// (~/sepol-test/clip8, ~/sepol-test/clip). Linux with the SELinux toolchain
// only; skips elsewhere. Logs of each run go to a temporary directory.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { detectToolchain } = require('../server/build');
const { clipArgs } = require('./clip-args');

const TESTS = ['build-tree', 'checks', 'diff', 'preview', 'filelabel', 'logins', 'loginctx', 'sessions', 'restricted', 'ctxfiles', 'denials', 'service', 'user', 'wrapper', 'package', 'levels', 'hostmods', 'profile', 'multi-tree'];
const BASELINE = path.join(__dirname, 'survey-baseline.json');

const args = process.argv.slice(2);
const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args.splice(i, 2)[1] : null; };
const only = flag('--only');
const update = args.includes('--update-baseline');
const trees = args.filter(a => !a.startsWith('--'));
const DEFAULT_TREES = [path.join(os.homedir(), 'sepol-test/clip8/packages/selinux-policy/selinux-policy'), path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy')];

const tc = detectToolchain(null);
if (process.platform !== 'linux' || !tc.ok) { console.log(`SKIP: ${tc.reason || 'needs Linux'}`); process.exit(0); }
const todo = (trees.length ? trees : DEFAULT_TREES).filter(t => fs.existsSync(path.join(t, 'Rules.modular')));
if (!todo.length) { console.log('SKIP: no CLIP tree found'); process.exit(0); }
const tests = only ? TESTS.filter(t => only.split(',').includes(t)) : TESTS;
const logs = fs.mkdtempSync(path.join(os.tmpdir(), 'clip-all-'));
const version = (tree) => { try { return fs.readFileSync(path.join(tree, 'VERSION'), 'utf8').trim(); } catch { return 'unknown'; } };
const label = (tree) => `CLIP refpolicy ${version(tree)}`;

const run = (cmd, argv, logFile, timeoutMs) => new Promise((resolve) => {
  const t0 = Date.now();
  const p = cp.spawn(cmd, argv, { cwd: path.join(__dirname, '..') });
  let out = '';
  p.stdout.on('data', d => { out += d; });
  p.stderr.on('data', d => { out += d; });
  const timer = setTimeout(() => { out += `\n(timed out after ${timeoutMs / 1000} s)\n`; p.kill('SIGKILL'); }, timeoutMs);
  p.on('close', (code) => { clearTimeout(timer); fs.writeFileSync(logFile, out); resolve({ code, out, ms: Date.now() - t0 }); });
});

/** The survey's findings as "code | file | message" (no line numbers, so edits elsewhere don't matter). */
async function survey(tree, logFile) {
  const json = logFile.replace(/\.log$/, '.json');
  const make = clipArgs(tree).filter(a => !a.startsWith('APPS_MODS=')).join(' ');
  const r = await run('node', [path.join(__dirname, 'diag-survey.js'), path.join(tree, 'policy'), '--make', make, '--modules', path.join(tree, 'policy/modules.conf'), '--json', json], logFile, 600000);
  if (r.code !== 0 || !fs.existsSync(json)) return { error: `survey failed (exit ${r.code}); see ${logFile}` };
  return { findings: [...new Set(JSON.parse(fs.readFileSync(json, 'utf8')).map(f => `${f.code} | ${f.file} | ${f.msg}`))].sort() };
}

(async () => {
  const results = [];
  const baseline = fs.existsSync(BASELINE) ? JSON.parse(fs.readFileSync(BASELINE, 'utf8')) : {};
  console.log(`logs in ${logs}`);
  for (const tree of todo) {
    console.log(`\n=== ${label(tree)}: ${tree}`);
    for (const t of tests) {
      const logFile = path.join(logs, `${path.basename(path.dirname(path.dirname(path.dirname(tree))))}-${t}.log`);
      const r = await run('node', [path.join(__dirname, `${t}-e2e.js`), tree], logFile, 1800000);
      const fails = r.out.split('\n').filter(l => /^FAIL\b/.test(l));
      const skipped = /^SKIP/m.test(r.out);
      const ok = r.code === 0 && !fails.length;
      console.log(`${ok ? (skipped ? 'skip' : 'ok  ') : 'FAIL'} ${t.padEnd(11)} ${(r.ms / 1000).toFixed(0).padStart(4)} s${skipped ? `  ${(r.out.match(/^SKIP.*$/m) || [''])[0]}` : ''}`);
      for (const f of fails.slice(0, 8)) console.log(`       ${f.slice(0, 220)}`);
      if (!ok && !fails.length) console.log(`       exit ${r.code}; see ${logFile}`);
      results.push({ tree, test: t, ok });
    }
    // Diagnostics survey vs the known findings for this refpolicy version.
    const s = await survey(tree, path.join(logs, `${version(tree)}-survey.log`));
    const key = version(tree);
    if (s.error) { console.log(`FAIL survey      ${s.error}`); results.push({ tree, test: 'survey', ok: false }); continue; }
    if (update) {
      baseline[key] = s.findings;
      console.log(`ok   survey      baseline for ${key} written (${s.findings.length} findings)`);
      results.push({ tree, test: 'survey', ok: true });
      continue;
    }
    const known = new Set(baseline[key] || []);
    if (!baseline[key]) {
      console.log(`FAIL survey      no baseline for refpolicy ${key}: review these ${s.findings.length} findings, then run with --update-baseline`);
      for (const f of s.findings) console.log(`       ${f.slice(0, 220)}`);
      results.push({ tree, test: 'survey', ok: false });
      continue;
    }
    const added = s.findings.filter(f => !known.has(f)), gone = [...known].filter(f => !s.findings.includes(f));
    const ok = !added.length && !gone.length;
    console.log(`${ok ? 'ok  ' : 'FAIL'} survey      ${s.findings.length} findings${ok ? ', all known' : `: ${added.length} new, ${gone.length} gone`}`);
    for (const f of added) console.log(`       new:  ${f.slice(0, 220)}`);
    for (const f of gone) console.log(`       gone: ${f.slice(0, 220)}`);
    results.push({ tree, test: 'survey', ok });
  }
  if (update) fs.writeFileSync(BASELINE, JSON.stringify(baseline, null, 1) + '\n');
  const bad = results.filter(r => !r.ok);
  console.log(bad.length ? `\n${bad.length} of ${results.length} failed: ${bad.map(r => `${label(r.tree)} ${r.test}`).join(', ')}` : `\nall ${results.length} CLIP runs passed`);
  process.exit(bad.length ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
