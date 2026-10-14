'use strict';
// Runs test/policy_query_test.py (server/policy_query.py against a fake
// setools) with whatever Python 3 this machine has; skips without one.
//   node test/policy-query-test.js
const cp = require('child_process');
const path = require('path');

const script = path.join(__dirname, 'policy_query_test.py');
for (const py of [['python3'], ['python'], ['py', '-3']]) {
  const v = cp.spawnSync(py[0], [...py.slice(1), '--version'], { encoding: 'utf8' });
  if (v.status !== 0 || !/Python 3\./.test(`${v.stdout}${v.stderr}`)) continue;
  const r = cp.spawnSync(py[0], [...py.slice(1), script], { stdio: 'inherit' });
  process.exit(r.status === null ? 1 : r.status);
}
console.log('SKIP: no Python 3 found (python3, python or py -3)');
process.exit(0);
