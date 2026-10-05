// ifelse inside definitions: branches are decided per call when the compared
// arguments are plain text (template expansion and the .te require analysis),
// and left active otherwise. Runs anywhere: node test/ifelse-test.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const { PolicyIndex } = require('../server/indexer');
const { callRequires } = require('../server/diagnostics');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-ifelse-'));
const mod = path.join(dir, 'policy/modules/system');
fs.mkdirSync(mod, { recursive: true });
fs.writeFileSync(path.join(mod, 'demo.if'), `## <summary>demo</summary>
template(\`demo_user_template',\`
	type $1_t;
	ifelse(\`$1',\`unconfined',\`',\`
		gen_tunable(\`$1_exec_content', true)
		type $1_exec_marker_t;
		gen_require(\`
			type confined_only_t;
		')
	')
	ifelse(\`$1',\`unconfined',\`
		type $1_special_t;
	')
	ifelse(eval($2 > 1),1,\`
		type $1_undecided_t;
	')
')
`);
fs.writeFileSync(path.join(mod, 'demo.te'), `policy_module(demo, 1.0)
demo_user_template(unconfined, 1)
demo_user_template(staff, 2)
`);

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra)); }
};
const idx = new PolicyIndex(() => {});
idx.scanRoots([dir]);
const has = (n) => idx.decls.has(n);
check(has('staff_t') && has('unconfined_t'), 'unconditional declarations for both calls');
check(has('staff_exec_content') && idx.decls.get('staff_exec_content')[0].kind === 'bool' && has('staff_exec_marker_t'),
  'else-branch declarations for staff (incl. the gen_tunable boolean)');
check(!has('unconfined_exec_content') && !has('unconfined_exec_marker_t'), 'no else-branch declarations for unconfined');
check(has('unconfined_special_t') && !has('staff_special_t'), 'then-branch declaration only for unconfined');
check(has('staff_undecided_t') && has('unconfined_undecided_t'), 'an ifelse on eval(...) stays undecided (both active)');
check(callRequires(idx, 'demo_user_template', ['staff', '2']).names.has('confined_only_t')
  && !callRequires(idx, 'demo_user_template', ['unconfined', '1']).names.has('confined_only_t'),
  'requires inside a branch count only for calls the branch applies to');
check(idx.whenHolds([{ a: '$1', b: 'x', then: true }], ['$2']) === true, 'an argument that is itself unresolved leaves the branch active');

fs.rmSync(dir, { recursive: true, force: true });
console.log(failures ? `\n${failures} check(s) failed` : '\nall ifelse checks passed');
process.exit(failures ? 1 : 0);
