// Run all diagnostics across a policy tree and summarize, to measure false positives.
const { PolicyIndex } = require('../server/indexer');
const { diagnose } = require('../server/diagnostics');
const root = process.argv[2] || '/tmp/selinux-policy/policy';
const idx = new PolicyIndex(() => {});
idx.scanRoots([root]);
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
