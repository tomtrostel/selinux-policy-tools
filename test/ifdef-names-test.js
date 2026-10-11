// ifdef/ifndef on names that aren't build flags: decided from where the
// sources define them, in the order refpolicy feeds files to m4.
// Runs anywhere: node test/ifdef-names-test.js
const path = require('path');
const { PolicyIndex } = require('../server/indexer');

const root = path.join(path.sep, 'ws', 'policy');
const P = (rel) => path.join(root, rel);
const files = {
  'support/misc.spt': `
define(\`interface',\`ifdef(\`$1',\`',\`define(\`$1',__file__:__line__)')define(\`$1',\`$2')')
define(\`spt_macro',\`allow $1 self:process signal;')
define(\`dyn_wrapper',\`pushdef(\`dyn_flag')$1popdef(\`dyn_flag')')
ifdef(\`dyn_flag',\`
	define(\`spt_dyn_only')
')
`,
  'modules/contrib/ipa.if': `
ifndef(\`ipa_helper_noatsecure',\`
	interface(\`ipa_helper_noatsecure',\`
		allow $1 self:process noatsecure;
	')
')
interface(\`ipa_body',\`
	ifdef(\`spt_macro',\`
		type body_on_t;
	')
	ifdef(\`te_local_flag',\`
		type body_te_local_t;
	')
	ifdef(\`enable_mcs',\`
		type body_mcs_t;
	')
')
template(\`gen_template',\`
	interface(\`$1_generated_iface',\`
		allow $1 self:process fork;
	')
')
ifdef(\`ipa_body',\`
	define(\`if_order_dependent')
')
`,
  'modules/contrib/ipa.te': `
policy_module(ipa, 1.0)
ifdef(\`ipa_helper_noatsecure',\`
	type on_iface_t;
')
ifdef(\`TODO',\`
	type todo_t;
',\`
	type todo_else_t;
')
ifdef(\`distro_debian',\`define(\`local_flag')')
ifdef(\`enable_mcs',\`define(\`mcs_local_flag')')
ifdef(\`local_flag',\`
	type local_on_t;
')
ifdef(\`mcs_local_flag',\`
	type mcs_local_on_t;
')
ifdef(\`later_flag',\`
	type later_t;
')
define(\`later_flag')
ifdef(\`foo_generated_iface',\`
	type generated_t;
')
ifdef(\`other_module_flag',\`
	type other_t;
')
ifdef(\`spt_dyn_only',\`
	type dyn_t;
')
ifdef(\`self_contained_policy',\`
	type step_t;
')
ifdef(\`__file__',\`
	type builtin_t;
')
ifdef(\`dead_iface',\`
	type dead_iface_t;
')
`,
  'modules/contrib/other.te': `
policy_module(other, 1.0)
define(\`other_module_flag')
define(\`te_local_flag')
ifdef(\`TODO',\`
	interface(\`dead_iface',\`
		allow $1 self:process fork;
	')
')
`,
  'modules/contrib/ipa.fc': `
ifdef(\`spt_macro',\`
/fc/on	--	gen_context(system_u:object_r:fc_on_t,s0)
')
ifdef(\`ipa_body',\`
/fc/iface	--	gen_context(system_u:object_r:fc_iface_t,s0)
')
`,
};

const idx = new PolicyIndex();
for (const [rel, text] of Object.entries(files)) idx.setFile(P(rel), text, true);
idx.setM4Defines({ defined: new Set(['enable_mcs', 'distro_redhat']), universe: new Set(['enable_mcs', 'enable_mls']),
  patterns: [/^distro_\w+$/], stepOnly: new Set(['self_contained_policy']), flags: '-D enable_mcs -D distro_redhat' });
idx.rebuild();

let failed = 0;
const ok = (cond, msg) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) failed++; };
const declState = (name) => {
  for (const f of idx.files.values()) {
    const d = (f.decls || []).find(x => x.name === name);
    if (!d) continue;
    return idx.undecidedAt(f, d.l, d.c) ? 'undecided' : idx.isActive(f, d.l, d.c) ? 'on' : 'off';
  }
  return 'missing';
};
const expect = (name, want, why) => { const got = declState(name); ok(got === want, `${name}: ${got}${got === want ? '' : ` (want ${want})`}  ${why}`); };

expect('on_iface_t', 'on', 'interface defined in a .if (behind its own ifndef guard)');
ok(!idx.undecidedAt(idx.files.get(P('modules/contrib/ipa.if')), 3, 2) && idx.defs.has('ipa_helper_noatsecure'), 'the self-guarded interface itself stays defined and decided');
expect('todo_t', 'off', 'TODO is defined nowhere');
expect('todo_else_t', 'on', 'else branch of an undefined name');
expect('local_on_t', 'off', 'define() only in an inactive flag branch earlier in the file');
expect('mcs_local_on_t', 'on', 'define() in an active flag branch earlier in the file');
expect('later_t', 'off', 'define() later in the same file is not seen yet');
expect('generated_t', 'undecided', 'name matches a template-generated interface pattern');
expect('other_t', 'undecided', "another .te's define (base modules are concatenated)");
expect('dyn_t', 'undecided', 'defined only under a pushdef inside a macro');
expect('step_t', 'undecided', 'a flag only some build steps pass');
expect('builtin_t', 'on', 'm4 builtin');
expect('dead_iface_t', 'undecided', 'interface defined only in another .te (order unknown)');
expect('body_on_t', 'on', 'in an interface body: .spt macro is defined at expansion time');
expect('body_te_local_t', 'undecided', 'in an interface body: defined only by some .te');
expect('body_mcs_t', 'on', 'build flags still decide inside interface bodies');
expect('fc_on_t', 'missing', '(fc entries are not decls)');
const fc = idx.files.get(P('modules/contrib/ipa.fc'));
const fcState = (type) => { const e = fc.entries.find(x => x.type === type); return idx.undecidedAt(fc, e.l, e.c) ? 'undecided' : idx.isActive(fc, e.l, e.c) ? 'on' : 'off'; };
ok(fcState('fc_on_t') === 'on', `fc: .spt macro defined (${fcState('fc_on_t')})`);
ok(fcState('fc_iface_t') === 'off', `fc: interfaces are not part of the .fc m4 run (${fcState('fc_iface_t')})`);
const ifFile = idx.files.get(P('modules/contrib/ipa.if'));
const orderBranch = ifFile.branches.find(b => b.sym === 'ipa_body');
ok(idx.branchState(ifFile, orderBranch).v === true, 'top level of a .if: a definition earlier in the same file counts');
const todo = idx.files.get(P('modules/contrib/ipa.te')).branches.find(b => b.sym === 'TODO' && b.want);
ok(/nothing in the policy sources/.test(idx.branchReason(idx.files.get(P('modules/contrib/ipa.te')), todo)), 'reason says the name is defined nowhere');
const local = idx.files.get(P('modules/contrib/ipa.te')).branches.find(b => b.sym === 'local_flag' && b.want);
ok(/only in ifdef branches this configuration doesn't compile/.test(idx.branchReason(idx.files.get(P('modules/contrib/ipa.te')), local)), 'reason says the define sits in an inactive branch');
const noflags = new PolicyIndex();
for (const [rel, text] of Object.entries(files)) noflags.setFile(P(rel), text, true);
noflags.rebuild();
const nf = noflags.files.get(P('modules/contrib/ipa.te'));
ok(nf.branches.every(b => noflags.isActive(nf, b.s.l, b.s.c)), 'without build flags every branch stays active');

console.log(failed ? `\n${failed} ifdef name check(s) FAILED` : '\nall ifdef name checks passed');
process.exit(failed ? 1 : 0);
