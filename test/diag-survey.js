// Run all diagnostics across a policy tree and summarize, to measure false positives.
//   node test/diag-survey.js <policy-dir> [--make "NAME=targeted TYPE=mcs DISTRO=redhat ..."] [--modules <modules.conf>] [--loadable]
// --modules: which modules are base / loadable (enables the .te require check
// for loadable ones), e.g. dist/targeted/modules.conf; --loadable: treat every
// module as loadable (as standalone modules are).
// With --make, ifdef/ifndef branches on build flags are decided the way that
// build configuration would (flags asked from the tree's Makefile; Linux only).
const path = require('path');
const { PolicyIndex } = require('../server/indexer');
const { diagnose } = require('../server/diagnostics');

(async () => {
  const root = process.argv[2] || '/tmp/selinux-policy/policy';
  const idx = new PolicyIndex(() => {});
  idx.scanRoots([root]);
  const mi = process.argv.indexOf('--make');
  if (mi > 0) {
    const m4 = await require('../server/build').m4Defines({ cwd: path.dirname(path.resolve(root)), makeArgs: (process.argv[mi + 1] || '').split(/\s+/).filter(Boolean) });
    if (!m4) { console.error('could not get the m4 flags from the Makefile'); process.exit(1); }
    idx.setM4Defines(m4);
    idx.rebuild();
    let total = 0, off = 0, undecided = 0;
    for (const f of idx.files.values()) {
      total += (f.branches || []).length; off += idx.inactiveBranches(f).length;
      undecided += (f.branches || []).filter(b => idx.branchState(f, b).v === null).length;
    }
    console.log(`m4 flags: ${m4.flags}`);
    console.log(`ifdef/ifndef branches: ${total}, inactive in this configuration: ${off}, undecided: ${undecided}; definitions only in inactive branches: ${idx.inactiveDefs.size}`);
  }
  const mo = process.argv.indexOf('--modules');
  if (mo > 0) {
    const text = require('fs').readFileSync(process.argv[mo + 1], 'utf8');
    idx.moduleKinds = new Map([...text.matchAll(/^\s*([\w-]+)\s*=\s*(\w+)\s*$/gm)].map(m => [m[1], m[2]]));
    console.log(`modules: ${[...idx.moduleKinds.values()].filter(v => v === 'module').length} loadable, ${[...idx.moduleKinds.values()].filter(v => v === 'base').length} base`);
  }
  if (process.argv.includes('--loadable')) idx.allLoadable = true;
  const byCode = {}; const samples = {};
  const names = {};
  for (const f of idx.files.values()) {
    for (const d of diagnose(idx, f)) {
      byCode[d.code] = (byCode[d.code] || 0) + 1;
      (samples[d.code] = samples[d.code] || []).push(`${f.path.replace(root, '')}:${d.l + 1}: ${d.msg}`);
      const k = d.code + ' ' + (d.msg.match(/'([^']+)'/) || [])[1];
      names[k] = (names[k] || 0) + 1;
    }
  }
  console.log(byCode);
  for (const [k, v] of Object.entries(samples)) console.log('\n==', k, '\n' + v.slice(0, 6).join('\n'));
  console.log('\nTop names:', Object.entries(names).sort((a, b) => b[1] - a[1]).slice(0, 30));
})();
