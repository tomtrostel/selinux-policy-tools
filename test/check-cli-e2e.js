// The headless check runner on a real tree (Linux with the SELinux toolchain):
//   node test/check-cli-e2e.js [tree-dir]
// A copy of a CLIP tree (default: CLIP for RHEL 9 on the test host) laid out
// like CLIP (the spec and Makefile next to it, so the runner finds the build
// settings itself) is checked with a failing property check added: the build
// and every report run, the check fails the run with its line, the JSON holds
// each part. With the check fixed and the login reports skipped the run
// passes; --no-build and an unknown profile answer as they should; a
// standalone module folder is built on its own. Skips without the toolchain.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { tempDir } = require('./tmpdirs');
const { detectToolchain } = require('../server/build');
const { clipSpec } = require('./clip-args');

const tc = detectToolchain(null);
if (process.platform !== 'linux' || !tc.ok) { console.log(`SKIP: ${tc.reason || 'needs Linux'}`); process.exit(0); }
const src = path.resolve(process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy'));
if (!fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP: no tree at ${src}`); process.exit(0); }

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + (typeof extra === 'string' ? extra : JSON.stringify(extra, null, 1)).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
const CLI = path.join(__dirname, '..', 'bin', 'selinux-policy-check.js');
const run = (args, timeout = 1200000) => {
  const t0 = Date.now();
  const r = cp.spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout, maxBuffer: 64 << 20 });
  return { code: r.status, out: (r.stdout || '') + (r.stderr || ''), ms: Date.now() - t0 };
};

// The copy: <tmp>/pkg/{*.spec, Makefile, selinux-policy/}.
const pkg = tempDir('check-cli-e2e-');
const ws = path.join(pkg, 'selinux-policy');
cp.execFileSync('cp', ['-a', src, ws]);
fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
const spec = clipSpec(src);
if (spec) {
  for (const n of fs.readdirSync(path.dirname(spec))) if (n.endsWith('.spec') || n === 'Makefile') fs.copyFileSync(path.join(path.dirname(spec), n), path.join(pkg, n));
}
const checksFile = path.join(ws, 'selinux.checks');
const orig = fs.existsSync(checksFile) ? fs.readFileSync(checksFile, 'utf8') : '';
// init_t reads etc_t: the first check fails; the second holds (init_t does read etc_t files).
fs.writeFileSync(checksFile, `${orig.replace(/\n*$/, '\n')}# added by check-cli-e2e\nnever init_t may read etc_t:file\nrequire init_t may read etc_t:file\n`);
const failLine = fs.readFileSync(checksFile, 'utf8').split('\n').findIndex(l => /^never init_t may read etc_t/.test(l)) + 1;

(async () => {
  // 1. The whole run with a failing check.
  const json = path.join(pkg, 'out.json');
  let r = run(['--json', json, ws]);
  const res = fs.existsSync(json) ? JSON.parse(fs.readFileSync(json, 'utf8')) : null;
  console.log(r.out.split('\n').filter(l => /^(selinux-policy-check|Static|Build|Property|Login|Context|Dropped|Result)/.test(l)).map(l => `     ${l.slice(0, 200)}`).join('\n'));
  check(r.code === 1 && res && res.failed, `exit 1: the added check fails the run (${(r.ms / 1000).toFixed(0)} s)`, { code: r.code, tail: r.out.slice(-800) });
  check(res && res.mode === 'tree' && res.tree === ws && (spec ? /\.spec/.test(res.settings) : /build\.conf/.test(res.settings)), `the tree and its build settings (${res && res.settings})`, res && { mode: res.mode, tree: res.tree, settings: res.settings });
  check(res && res.parts.build && res.parts.build.ok && res.parts.build.builds[0].packages > 50 && /^Build: ok, \d+ packages \(\d+ s\)$/m.test(r.out), 'the tree builds (packages counted)', res && res.parts.build);
  check(res && res.parts.static && res.parts.static.files > 500 && !res.problems.some(p => p.part === 'static' && p.severity === 'error'), `static analysis over ${res && res.parts.static.files} files, no errors`, res && res.problems.filter(p => p.part === 'static').slice(0, 5));
  const c = res && res.parts.checks;
  check(c && c.total >= 2 && c.failed === 1 && c.items.length === 1 && c.items[0].l === failLine - 1 && /init_t/.test(c.items[0].msg) && c.items[0].related.length > 0,
    `property checks: ${c && c.total} checked, the added one fails at selinux.checks:${failLine} with the rule traced`, c);
  check(new RegExp(`^  error   selinux\\.checks:${failLine} .*init_t`, 'm').test(r.out) && /^Property checks: \d+ checks, 1 failing$/m.test(r.out), 'and the report says so', r.out.match(/^Property checks[\s\S]*?\n(?=\w)/m));
  check(res && res.parts.logins && !res.parts.logins.error && res.parts.logins.mappings > 0 && res.parts.logins.sessions > 0 && res.parts.contexts && !res.parts.contexts.error && res.parts.contexts.files > 5,
    `login contexts (${res && res.parts.logins.mappings} seusers lines, ${res && res.parts.logins.sessions} session starts) and context files (${res && res.parts.contexts.files}) ran`, res && { logins: res.parts.logins && res.parts.logins.error, contexts: res.parts.contexts && res.parts.contexts.error });
  check(res && res.parts.dropped && res.parts.dropped.items.length > 50 && res.parts.dropped.items.every(x => x.missing.length && /\.te(\.in)?$/.test(x.path)), `dropped optional blocks listed (${res && res.parts.dropped.items.length})`, res && res.parts.dropped && res.parts.dropped.items.slice(0, 2));
  const loginErrors = res ? res.problems.filter(p => p.part === 'logins' && p.severity === 'error') : [];
  console.log(`     (login problems in this tree: ${loginErrors.length} errors; they fail the run on their own, as they should)`);
  check(res && res.problems.every(p => p.fails === (p.severity === 'error')), 'without --strict, exactly the errors fail');

  // 2. The check fixed, login reports skipped: passes unless the tree's own static warnings fail it (they don't without --strict).
  fs.writeFileSync(checksFile, fs.readFileSync(checksFile, 'utf8').replace(/^never init_t may read etc_t:file\n/m, ''));
  const report = path.join(pkg, 'evidence.md');
  r = run(['--skip', 'logins,contexts', '--json', json, '--report', report, ws]);
  const res2 = fs.existsSync(json) ? JSON.parse(fs.readFileSync(json, 'utf8')) : null;
  check(r.code === 0 && res2 && !res2.failed && res2.parts.checks.failed === 0 && !res2.parts.logins && !res2.parts.contexts && /Result: OK$/m.test(r.out),
    `fixed and with --skip logins,contexts: exit 0, all checks hold (${(r.ms / 1000).toFixed(0)} s)`, { code: r.code, tail: r.out.slice(-600) });
  // The evidence report of the same build.
  const md = fs.existsSync(report) ? fs.readFileSync(report, 'utf8') : '';
  const heads = [...md.matchAll(/^## (.*)$/gm)].map(m => m[1]);
  check(md.length > 2000 && /^# SELinux policy evidence: Last build of/.test(md) && ['Summary', 'Policy', 'Modules', 'Static analysis', 'Property checks', 'Logins: contexts and session starts', 'Context files', 'SELinux users and what their sessions reach', 'Services', 'Levels and categories'].every(h => heads.includes(h)) && res2.parts.report && res2.parts.report.sections >= 10,
    `--report: ${path.basename(report)} with ${heads.length} sections (${md.length} bytes)`, heads);
  check(/\| Build settings \| .*NAME=mcs/.test(md) && /\| Built \| .*packages \|/.test(md) && /base modules?, \d+ loadable modules?, \d+ modules off/.test(md) && /\| ✓ holds \| `require init_t may read etc_t:file` \|/.test(md) && /seusers lines?, \d+ session starts? checked/.test(md) && /service modules?/.test(md),
    'the report has the build settings, modules, the checks with their results, logins and services', md.slice(0, 2500));
  const html = path.join(pkg, 'evidence.html');
  r = run(['--no-build', '--report', html, ws], 300000);
  check(r.code === 0 && /Evidence report: needs a build \(--no-build given\)/.test(r.out) && !fs.existsSync(html), '--report with --no-build: says it needs a build, nothing written, the run still passes', r.out.slice(-300));
  const warnings = res2 ? res2.problems.filter(p => p.severity === 'warning').length : 0;
  if (warnings) {
    r = run(['--skip', 'logins,contexts', '--strict', '--no-build', ws]);
    check(r.code === 1 && /--strict/.test(r.out), `--strict: the tree's ${warnings} static warnings fail it`, r.out.slice(-400));
  }

  // 3. --no-build: static only, fast; an unknown install profile: can't check (exit 2).
  r = run(['--no-build', ws], 300000);
  check(r.code === 0 && /Build: skipped \(--no-build\)/.test(r.out) && !/Property checks/.test(r.out) && r.ms < 120000, `--no-build: static only in ${(r.ms / 1000).toFixed(0)} s`, r.out.slice(-500));
  r = run(['--no-build', '--profile', 'no-such-profile', ws], 300000);
  check(r.code === 2 && /unable to check: .*(kickstart|profile)/.test(r.out), '--profile with no kickstarts above the copy: unable to check, exit 2', r.out.slice(-400));
  r = run(['--bogus', ws], 60000);
  check(r.code === 2 && /unknown option/.test(r.out), 'a bad option: usage, exit 2', r.out.slice(0, 300));

  // 4. A folder of standalone modules (the test host's ~/sepol-test/mymodule), built against the devel headers.
  const mod = path.join(os.homedir(), 'sepol-test/mymodule');
  if (fs.existsSync(mod) && fs.readdirSync(mod).some(n => n.endsWith('.te')) && fs.existsSync('/usr/share/selinux/devel/Makefile')) {
    const copy = path.join(tempDir('check-cli-e2e-mod-'), 'mods');
    cp.execFileSync('cp', ['-a', mod, copy]);
    r = run(['--json', json, copy], 900000);
    const res3 = fs.existsSync(json) ? JSON.parse(fs.readFileSync(json, 'utf8')) : null;
    check(res3 && res3.mode === 'module' && res3.parts.build && res3.parts.build.builds.length >= 1 && r.code !== 2 && /^Build: (ok|FAILED) \S+\.te/m.test(r.out),
      `standalone modules: ${res3 && res3.parts.build.builds.length} built (exit ${r.code}, ${(r.ms / 1000).toFixed(0)} s)`, { code: r.code, out: r.out.slice(-800) });
  } else console.log(`skip standalone part: no ${mod} or no devel Makefile`);

  console.log(failures ? `\n${failures} check CLI e2e checks FAILED` : '\nall check CLI e2e checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
