// The headless check runner (bin/selinux-policy-check.js): arguments, build
// settings, the report text, and a static-only run on the LSP e2e workspace
// when it exists. Any OS, in npm test.
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const { tempDir } = require('./tmpdirs');
const C = require('../bin/selinux-policy-check');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2000).replace(/\n/g, '\n     ')); }
};
const throws = (fn, re) => { try { fn(); return false; } catch (e) { return re.test(e.message); } };

// 1. Arguments.
let o = C.parseArgs(['--spec', 'x.spec', '--variant', 'mls', '--profile', 'clip-minimal', '--strict', '--skip', 'logins, dropped', '--json', 'out.json', '--timeout', '60', '-v', '/tree']);
check(o.spec === 'x.spec' && o.variant === 'mls' && o.profile === 'clip-minimal' && o.strict && o.skip.has('logins') && o.skip.has('dropped') && o.json === 'out.json' && o.timeout === 60 && o.verbose && o.target === '/tree' && o.build,
  'parseArgs: every option', o);
o = C.parseArgs(['--make', 'NAME=targeted TYPE=mcs  DISTRO=redhat', '--no-build', 'tree']);
check(o.make.join('|') === 'NAME=targeted|TYPE=mcs|DISTRO=redhat' && !o.build && o.target === 'tree', 'parseArgs: --make splits on spaces, --no-build', o);
check(throws(() => C.parseArgs([]), /usage/) && throws(() => C.parseArgs(['--bogus', 'x']), /unknown option/) && throws(() => C.parseArgs(['a', 'b']), /one workspace/) && throws(() => C.parseArgs(['--spec']), /needs a value/),
  'parseArgs errors: no target, unknown option, two targets, missing value');
check(C.parseArgs(['--help']).help, '--help');

// 2. Build settings: --make, none (build.conf), a missing spec, a spec with several variants.
const d = tempDir('check-cli-test-');
fs.mkdirSync(path.join(d, 'tree'));
let s = C.buildSettings({ make: ['NAME=x'] }, path.join(d, 'tree'));
check(s.makeArgs.join() === 'NAME=x' && /make arguments/.test(s.source), 'buildSettings: --make', s);
s = C.buildSettings({}, path.join(d, 'tree'));
check(!s.makeArgs.length && /build\.conf/.test(s.source), 'buildSettings: nothing next to the tree → build.conf', s);
check(throws(() => C.buildSettings({ spec: path.join(d, 'none.spec') }, path.join(d, 'tree')), /no such spec/), 'buildSettings: a missing --spec is an error');
// A RHEL-style spec with two variants next to the tree is NOT picked up by itself (only CLIP's is), and needs --variant when named.
fs.writeFileSync(path.join(d, 'tree', 'selinux-policy.spec'), [
  '%define common_params DISTRO=redhat UBAC=n DIRECT_INITRC=n MONOLITHIC=n MLS_CATS=1024 MCS_CATS=1024',
  '%build', '%makeCmds targeted mcs allow', '%makeCmds mls mls deny', '%install', '%makeModulesConf targeted mcs allow', '%makeModulesConf mls mls deny', ''].join('\n'));
const spec = path.join(d, 'tree', 'selinux-policy.spec');
// The overlay files the spec names (whatever specconfig derives): created until none is missing.
for (let i = 0; i < 8; i++) {
  try { C.buildSettings({ spec, variant: 'mls' }, path.join(d, 'tree')); C.buildSettings({ spec, variant: 'targeted' }, path.join(d, 'tree')); break; } catch (e) {
    const m = /missing (.*)$/.exec(e.message);
    if (!m) throw e;
    for (const f of m[1].split(', ')) fs.writeFileSync(f, '');
  }
}
check(throws(() => C.buildSettings({ spec }, path.join(d, 'tree')), /several variants.*targeted.*mls|several variants/), 'buildSettings: a spec with several variants needs --variant');
check(throws(() => C.buildSettings({ spec, variant: 'minimum' }, path.join(d, 'tree')), /no variant minimum/), 'buildSettings: an unknown variant is named');
s = C.buildSettings({ spec, variant: 'mls' }, path.join(d, 'tree'));
check(s.makeArgs.includes('NAME=mls') && s.makeArgs.includes('TYPE=mls') && Object.keys(s.files).length >= 1 && /selinux-policy\.spec \(mls\)/.test(s.source), 'buildSettings: --spec --variant mls → NAME=mls, overlays', s);

// 3. Standalone module files: top level and one folder down, not node_modules or dotdirs.
fs.mkdirSync(path.join(d, 'mods', 'a'), { recursive: true });
fs.mkdirSync(path.join(d, 'mods', 'node_modules'), { recursive: true });
fs.mkdirSync(path.join(d, 'mods', '.git'), { recursive: true });
for (const f of ['top.te', 'a/a.te', 'a/a.if', 'node_modules/x.te', '.git/y.te']) fs.writeFileSync(path.join(d, 'mods', f), '');
check(C.moduleFiles(path.join(d, 'mods')).map(p => path.relative(path.join(d, 'mods'), p).split(path.sep).join('/')).sort().join() === 'a/a.te,top.te', 'moduleFiles');

// 4. The report text.
const tree = path.join(d, 'tree');
const fake = {
  target: tree, tree, mode: 'tree', settings: 'selinux-policy.spec (targeted)', profile: 'clip-minimal', failed: true,
  parts: {
    static: { files: 1200, items: [] },
    build: { ok: true, ms: 91000, builds: [{ target: tree, ok: true, ms: 91000, packages: 90, diagnostics: [] }] },
    checks: { path: path.join(tree, 'selinux.checks'), total: 3, failed: 1, errors: 0, note: null, items: [] },
    logins: { policy: 'Last build', mappings: 4, sessions: 9, problems: [], notes: [] },
    contexts: { policy: 'Last build', files: 20, problems: [], notes: [] },
    dropped: { items: [{ path: path.join(tree, 'policy/modules/system/init.te'), l: 400, endL: 410, missing: [{ name: 'nscd_t', modules: ['nscd'] }] }], profile: 'clip-minimal' },
  },
  problems: [
    { part: 'static', severity: 'warning', path: path.join(tree, 'policy/modules/services/ssh.if'), l: 12, msg: '[missing-require] type sshd_t', related: [], fails: false },
    { part: 'static', severity: 'info', path: path.join(tree, 'policy/modules/services/ssh.te'), l: 3, msg: '[profile-not-installed] x', related: [], fails: false },
    { part: 'checks', severity: 'error', path: path.join(tree, 'selinux.checks'), l: 4, msg: 'init_t may read etc_t', related: [{ path: path.join(tree, 'policy/modules/system/init.te'), l: 99, msg: 'allow init_t etc_t:file read' }], fails: true },
    { part: 'logins', severity: 'warning', path: path.join(tree, 'config/appconfig-mcs/seusers'), l: 2, msg: 'session-nnp-other: alice by ssh: …', related: [], fails: false },
  ],
};
let txt = C.format(fake, {});
check(/^selinux-policy-check: .*policy tree, built with selinux-policy\.spec \(targeted\), install profile clip-minimal\)/.test(txt), 'header: tree, spec, profile', txt.split('\n')[0]);
check(/Static analysis: 1200 files, 1 warning, 1 info \(info with --verbose\)\n  warning policy\/modules\/services\/ssh\.if:13 \[missing-require\] type sshd_t\n/.test(txt), 'static: counts and the warning line (1-based line), info hidden', txt);
check(/\nBuild: ok, 90 packages \(91 s\)\n/.test(txt), 'build line', txt);
check(/Property checks: 3 checks, 1 failing\n  error   selinux\.checks:5 init_t may read etc_t\n/.test(txt) && !/↳/.test(txt), 'checks: counts, the failing line, no related lines without --verbose', txt);
check(/Login contexts and session starts: 4 seusers lines, 9 session starts checked, 1 warning\n  warning config\/appconfig-mcs\/seusers:3 session-nnp-other/.test(txt), 'logins line', txt);
check(/Context files: 20 files checked, nothing found/.test(txt) && /Dropped optional blocks: 1 block with install profile clip-minimal \(listed with --verbose\)/.test(txt) && /Result: FAIL \(1 problem\)$/.test(txt), 'contexts, dropped, result', txt);
txt = C.format(fake, { verbose: true, strict: true });
check(/info    policy\/modules\/services\/ssh\.te:4 \[profile-not-installed\]/.test(txt) && /↳ policy\/modules\/system\/init\.te:100 allow init_t etc_t:file read/.test(txt) && /  policy\/modules\/system\/init\.te:401 needs nscd_t/.test(txt) && /Result: FAIL \(1 problem, --strict\)/.test(txt),
  '--verbose: info lines, related lines, dropped blocks; --strict in the result', txt);
check(/Result: OK$/.test(C.format({ ...fake, failed: false, problems: fake.problems.filter(p => !p.fails) }, {})), 'Result: OK when nothing fails');
check(/unable to check: no toolchain$/.test(C.format({ target: tree, mode: 'tree', unable: 'no toolchain', parts: {}, problems: [] }, {})), 'unable: said instead of sections');
txt = C.format({ target: tree, mode: 'sources', parts: { static: { files: 3, items: [] } }, problems: [], failed: false }, {});
check(/Static analysis: 3 files, nothing found\nBuild: skipped \(--no-build\)\nResult: OK/.test(txt), '--no-build report', txt);

// 5. A static-only run on the LSP e2e workspace (a bare policy/ copy with the seeded myapp module), when present.
const ws = process.argv[2] || process.env.SELINUX_E2E_WS || path.join(os.tmpdir(), 'selinux-e2e-ws');
if (fs.existsSync(path.join(ws, 'policy', 'modules', 'local', 'myapp.te'))) {
  const cli = path.join(__dirname, '..', 'bin', 'selinux-policy-check.js');
  // myapp's mistakes (unknown interface, permission, class; a missing gen_require) are warnings: OK unless --strict.
  let r = cp.spawnSync(process.execPath, [cli, '--no-build', '--json', path.join(d, 'out.json'), ws], { encoding: 'utf8', timeout: 300000 });
  let out = r.stdout + r.stderr;
  const json = fs.existsSync(path.join(d, 'out.json')) ? JSON.parse(fs.readFileSync(path.join(d, 'out.json'), 'utf8')) : null;
  check(r.status === 0 && /Static analysis: \d+ files, \d+ warnings?/.test(out) && /warning policy\/modules\/local\/myapp\.te:\d+ \[unknown-/.test(out) && /Build: skipped/.test(out) && /Result: OK/.test(out),
    `--no-build on ${ws}: exit 0, myapp's mistakes in the report as warnings (${(r.stdout.match(/Static analysis.*/) || [''])[0]})`, out.slice(0, 1500));
  check(json && json.mode === 'sources' && json.parts.static.items.some(x => /myapp\.te$/.test(x.path) && x.severity === 'warning') && !json.parts.build && json.problems.every(p => p.part === 'static' && !p.fails),
    '--json: mode sources, the static items, no build part', json && Object.keys(json.parts));
  r = cp.spawnSync(process.execPath, [cli, '--no-build', '--strict', ws], { encoding: 'utf8', timeout: 300000 });
  out = r.stdout + r.stderr;
  check(r.status === 1 && /Result: FAIL \(\d+ problems?, --strict\)/.test(out), '--strict: the warnings fail it (exit 1)', out.slice(-300));
} else console.log(`skip static run: no e2e workspace at ${ws}`);

console.log(failures ? `\n${failures} check CLI checks FAILED` : '\nall check CLI checks passed');
process.exit(failures ? 1 : 0);
