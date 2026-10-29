'use strict';
// Source diagnostics on a small synthetic tree (any OS, no toolchain):
// unknown interfaces / classes / permissions, missing gen_require entries,
// missing requires in loadable .te files (scopes, interfaces that provide
// them, optional_policy, tunable_policy, unsure scopes), link failures from
// modules turned off, optional_policy blocks the linker drops, corenetwork port checks, and gen_user roles / levels /
// duplicates. Each check also has a "stays quiet" case.
//   node test/diagnostics-test.js
const fs = require('fs');
const os = require('os');
const { tempDir } = require('./tmpdirs');
const path = require('path');
const { PolicyIndex } = require('../server/indexer');
const { diagnose, globalRequirements, droppedOptionalBlocks } = require('../server/diagnostics');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

const dir = tempDir('selinux-diag-');
const P = (rel) => path.join(dir, 'policy', rel);
const write = (rel, text) => { fs.mkdirSync(path.dirname(P(rel)), { recursive: true }); fs.writeFileSync(P(rel), text); };

write('flask/security_classes', 'class file\nclass dir\nclass process\nclass tcp_socket\n');
write('flask/access_vectors', `common file
{
	ioctl read write create getattr setattr lock append unlink link rename open
}
class file inherits file
{
	execute_no_trans entrypoint execute
}
class dir inherits file
{
	add_name remove_name search
}
class process
{
	transition signal sigkill
}
class tcp_socket
{
	name_bind name_connect
}
`);
write('support/loadable_module.spt', `define(\`policy_module',\`module $1 $2;')
define(\`interface',\`define(\`$1',\`$2')')
define(\`template',\`define(\`$1',\`$2')')
define(\`gen_require',\`require { $1 }')
define(\`optional_policy',\`optional { $1 }')
define(\`declare_required_symbols',\`')
define(\`tunable_policy',\`declare_required_symbols(\`$1') if ($1) { $2 }')
define(\`gen_tunable',\`bool $1 $2;')
`);
write('support/misc_macros.spt', `define(\`gen_user',\`user $1 roles { $3 };')
define(\`gen_context',\`$1')
define(\`mcs_allcats',\`c0.c1023')
`);
write('support/obj_perm_sets.spt', "define(`read_file_perms',`{ getattr open read ioctl lock }')\n");
// kernel/files: the owner of etc_t, with an interface that requires it.
write('modules/kernel/files.te', 'policy_module(files, 1.0)\ntype etc_t;\ntype tmp_t;\n');
write('modules/kernel/files.if', `## <summary>files</summary>
interface(\`files_read_etc',\`
	gen_require(\`
		type etc_t;
	')
	allow $1 etc_t:file read_file_perms;
')
interface(\`files_broken',\`
	gen_require(\`
		type etc_t;
	')
	allow $1 etc_t:file read;
	allow $1 tmp_t:file read;
')
`);
// services/bar: a module that modules.conf turns off.
write('modules/services/bar.te', 'policy_module(bar, 1.0)\ntype bar_t;\ntype bar_exec_t;\n');
write('modules/services/bar.if', `## <summary>bar</summary>
interface(\`bar_domtrans',\`
	gen_require(\`
		type bar_t, bar_exec_t;
	')
	allow $1 bar_exec_t:file execute;
')
`);
// services/foo: the module under test.
const FOO = `policy_module(foo, 1.0)
type foo_t;
gen_tunable(foo_extra, false)

# fine: required through the interface
files_read_etc(foo_t)
allow foo_t etc_t:file read;

# missing: tmp_t is files', nothing here requires it
allow foo_t tmp_t:file read;

optional_policy(\`
	# fine: the interface in this block provides bar_t
	bar_domtrans(foo_t)
	allow foo_t bar_t:process signal;
')

optional_policy(\`
	# missing inside a block: bar_exec_t isn't required in this block
	allow foo_t bar_exec_t:file execute;
')

optional_policy(\`
	# an unknown call makes the block's requirements unsure: quiet
	nosuch_interface(foo_t)
	allow foo_t bar_exec_t:file read;
')

tunable_policy(\`foo_extra',\`
	allow foo_t self:process sigkill;
')

ifdef(\`TODO',\`
	allow foo_t tmp_t:file write;
')
`;
write('modules/services/foo.te', FOO);
// Typos (in a module of their own: an unknown top-level call makes a module's requirements unsure).
const TYPO = `policy_module(typo, 1.0)
type typo_t;
allow typo_t self:process { signal sigkil };
allow typo_t self:file read;
allow typo_t typo_t:fiel read;
files_read_etcc(typo_t)
optional_policy(\`
	nosuch_interface(typo_t)
')
allow typo_t tmp_t:file read;
`;
write('modules/services/typo.te', TYPO);
// a module whose top level hard-depends on bar (turned off): link failure.
const BAZ = `policy_module(baz, 1.0)
type baz_t;
bar_domtrans(baz_t)
optional_policy(\`
	bar_domtrans(baz_t)
')
`;
write('modules/services/baz.te', BAZ);
// optional_policy blocks dropped at link time (bar is off).
const QUX = `policy_module(qux, 1.0)
type qux_t;

optional_policy(\`
	gen_require(\`
		type bar_t;
	')
	allow qux_t bar_t:process signal;
	optional_policy(\`
		files_read_etc(qux_t)
	')
')

optional_policy(\`
	# its interface needs bar only inside an optional block of its own
	qux_soft_bar(qux_t)
	files_read_etc(qux_t)
')

optional_policy(\`
	bar_domtrans(qux_t)
',\`
	files_read_etc(qux_t)
')

ifdef(\`some_undecided_flag',\`
optional_policy(\`
	bar_domtrans(qux_t)
')
')

optional_policy(\`
	files_read_etc(qux_t)
	optional_policy(\`
		bar_domtrans(qux_t)
	')
')
`;
write('modules/services/qux.te', QUX);
write('modules/services/qux.if', `## <summary>qux</summary>
interface(\`qux_soft_bar',\`
	optional_policy(\`
		gen_require(\`
			type bar_t;
		')
		allow $1 bar_t:process signal;
	')
')
`);
const NET = `policy_module(corenetwork, 1.0)
network_port(http, tcp,80,s0, tcp,443,s0)
network_port(bogus, tcp,70000,s0)
network_port(backwards, udp,600-500,s0)
network_port(odd, icmp,7,s0)
network_port(dupe, tcp,443,s0)
ifdef(\`some_undecided_flag',\`
network_port(maybe, tcp,80,s0)
')
`;
write('modules/kernel/corenetwork.te.in', NET);
const USERS = `gen_user(system_u,, system_r, s0, s0 - mcs_allcats, mcs_allcats)
gen_user(staff_u, staff, staff_r nosuch_r, s0, s0 - s3, c2000)
gen_user(bad_u, user, staff_r, s0, s0 - bogus_level)
gen_user(staff_u, staff, staff_r, s0, s0)
`;
write('users', USERS);
write('modules/kernel/kernel.te', 'policy_module(kernel, 1.0)\nrole system_r;\nrole staff_r;\n');
// an interface file with a missing gen_require entry (and one that is fine)
// is files.if above: files_broken uses tmp_t without requiring it.

const idx = new PolicyIndex(() => {});
idx.scanRoots([path.join(dir, 'policy')]);
idx.moduleKinds = new Map([['kernel', 'base'], ['files', 'base'], ['corenetwork', 'base'], ['foo', 'module'], ['baz', 'module'], ['bar', 'off']]);
const diagOf = (rel) => diagnose(idx, idx.files.get(P(rel)));
const lineOf = (text, needle, from = 0) => text.split('\n').findIndex((l, i) => i >= from && l.includes(needle));
const codes = (ds) => ds.map(d => `${d.l + 1}:${d.code}`).join(' ');

/* ---------- unknown names ---------- */
let d = diagOf('modules/services/typo.te');
const on = (code, l) => d.filter(x => x.code === code && x.l === l);
check(on('unknown-macro', lineOf(TYPO, 'files_read_etcc')).length === 1, 'unknown interface (files_read_etcc): unknown-macro', codes(d));
check(on('unknown-macro-optional', lineOf(TYPO, 'nosuch_interface')).length === 1 && on('unknown-macro-optional', lineOf(TYPO, 'nosuch_interface'))[0].severity === 3,
  'unknown interface inside optional_policy: INFO only');
check(on('unknown-perm', lineOf(TYPO, 'sigkil }')).length === 1 && on('unknown-class', lineOf(TYPO, ':fiel')).length === 1, 'unknown permission and class');
check(!d.some(x => x.code === 'unknown-perm' && x.l === lineOf(TYPO, 'self:file read;')), 'known permissions are quiet');
check(!d.some(x => x.code === 'missing-te-require'), 'an unknown top-level call makes the module\'s requirements unsure: no missing-require (quiet when unsure)', codes(d));
d = diagOf('modules/services/foo.te');
check(!d.some(x => /^unknown-(macro|perm|class)$/.test(x.code)), 'a module without typos has no unknown-* warnings (only the INFO for its deliberate unknown call in a block)', codes(d));

/* ---------- .te requires ---------- */
const miss = d.filter(x => x.code === 'missing-te-require');
const missAt = (needle, from = 0) => miss.find(x => x.l === lineOf(FOO, needle, from));
check(missAt('tmp_t:file read;') && /'tmp_t' comes from the files module and isn't required in this module/.test(missAt('tmp_t:file read;').msg), 'a type of another module used without a require: missing-te-require', miss.map(x => x.msg));
check(!missAt('allow foo_t etc_t:file read;'), 'a type an interface call in the same scope requires: quiet');
check(!missAt('allow foo_t bar_t:process'), 'a type required by an interface inside the same optional_policy: quiet');
const inBlock = missAt('bar_exec_t:file execute;');
check(inBlock && /isn't required in this optional_policy block/.test(inBlock.msg) && inBlock.data.scope, 'a block whose calls don\'t provide it: missing, scoped to the block', inBlock && inBlock.msg);
check(!missAt('bar_exec_t:file read;'), 'a block with an unknown call: unsure, so quiet');
check(!miss.some(x => /foo_extra/.test(x.msg)), 'tunable_policy requires its condition\'s booleans itself: quiet');
check(!missAt('tmp_t:file write;'), 'code in an undecided/dead ifdef branch: quiet');
check(miss.length === 2, `exactly the two real missing requires (${miss.length})`, miss.map(x => `${x.l + 1}: ${x.msg.slice(0, 60)}`));
idx.moduleKinds.set('foo', 'base');
check(!diagOf('modules/services/foo.te').some(x => x.code === 'missing-te-require'), 'the same module as a base module: no require needed, quiet');
idx.moduleKinds.set('foo', 'module');

/* ---------- link failures ---------- */
d = diagOf('modules/services/baz.te');
const link = d.filter(x => x.code === 'link-missing');
check(link.length === 2 && link.every(x => x.l === lineOf(BAZ, 'bar_domtrans(baz_t)') && /only the bar module, which is off in modules\.conf, declares it/.test(x.msg) && /required by bar_domtrans\(\)/.test(x.msg))
  && link.map(x => x.data.name).sort().join() === 'bar_exec_t,bar_t',
  'a top-level call needing a type only an off module declares: link-missing on the call', link.map(x => x.msg));
const g = globalRequirements(idx, idx.files.get(P('modules/services/baz.te')));
check(g.names.has('bar_t') && g.names.get('bar_t').length === 1, 'global requirements: the optional_policy copy of the call doesn\'t count', [...g.names.keys()]);
idx.moduleKinds.set('bar', 'module');
check(!diagOf('modules/services/baz.te').some(x => x.code === 'link-missing'), 'with bar enabled: quiet');
idx.moduleKinds.set('bar', 'off');

/* ---------- optional_policy blocks the linker drops ---------- */
const loaded = (m) => idx.isEnabled(m) || m === 'qux';
const QF = () => idx.files.get(P('modules/services/qux.te'));
const blockLines = QUX.split('\n').map((l, i) => (/optional_policy\(/.test(l) ? i : -1)).filter(i => i >= 0);
let dr = droppedOptionalBlocks(idx, QF(), loaded);
const dropAt = (n) => dr.find(x => x.l === blockLines[n]);
check(dropAt(0) && dropAt(0).missing.length === 1 && dropAt(0).missing[0].name === 'bar_t' && dropAt(0).missing[0].via === null && dropAt(0).missing[0].modules.join() === 'bar',
  'a block whose gen_require names a type only an off module declares: dropped', dr);
check(dropAt(1) && dropAt(1).parent === dropAt(0) && !dropAt(1).missing.length, 'the block nested in it goes with it (parent set, nothing missing of its own)', dr);
check(!dropAt(2), 'an interface needing the module only inside its own optional block: kept');
check(!dropAt(3), 'a block with an else part: left alone');
check(!dropAt(4), 'a block in an undecided ifdef branch: left alone');
check(!dropAt(5) && dropAt(6) && dropAt(6).missing.some(m => m.name === 'bar_exec_t' && m.via === 'bar_domtrans'),
  'outer block kept, its inner block with bar_domtrans() dropped (requirement via the call)', dr);
check(dr.length === 3, `three dropped blocks in qux.te (${dr.length})`, dr.map(x => x.l + 1));
check(droppedOptionalBlocks(idx, QF(), (m) => (m === 'bar' ? null : loaded(m))).length === 0, 'bar unsure (loaded → null): nothing dropped');
idx.moduleKinds.set('bar', 'module');
check(droppedOptionalBlocks(idx, QF(), loaded).length === 0, 'bar enabled: nothing dropped');
idx.moduleKinds.set('bar', 'off');
dr = droppedOptionalBlocks(idx, idx.files.get(P('modules/services/foo.te')), loaded);
check(dr.length === 1 && dr[0].l === lineOf(FOO, 'optional_policy') && dr[0].missing.some(m => m.via === 'bar_domtrans'),
  'foo.te: only the block calling bar_domtrans() (rules without a require, or a block with an unknown call, decide nothing)', dr);

/* ---------- missing gen_require in interfaces ---------- */
d = diagOf('modules/kernel/files.if');
const gr = d.filter(x => x.code === 'missing-require');
check(gr.length === 1 && /'tmp_t' is used in files_broken but not declared in its gen_require block/.test(gr[0].msg), 'interface using a type it doesn\'t require: missing-require', gr.map(x => x.msg));

/* ---------- corenetwork ports ---------- */
d = diagOf('modules/kernel/corenetwork.te.in');
const net = (needle, code = 'net-port') => d.find(x => x.code === code && x.l === lineOf(NET, needle));
check(net('70000') && /out of range: ports go from 0 to 65535/.test(net('70000').msg), 'port out of range');
check(net('600-500') && /runs backwards/.test(net('600-500').msg), 'backwards range');
check(net('icmp') && /'icmp' is not a port protocol/.test(net('icmp').msg), 'unknown protocol');
check(net('dupe', 'net-port-duplicate') && /tcp 443 is already declared by network_port\(http\)/.test(net('dupe', 'net-port-duplicate').msg), 'exact duplicate port');
check(!net('network_port(http'), 'valid ports: quiet');

/* ---------- gen_user ---------- */
idx.setM4Defines({ defined: new Set(['enable_mcs']), universe: new Set(['enable_mcs', 'enable_mls', 'some_undecided_flag_never']), flags: '-D enable_mcs -D mcs_num_cats=1024' });
idx.rebuild();
d = diagOf('users');
const ul = (n) => lineOf(USERS, n);
const u = (code, line) => d.filter(x => x.code === code && x.l === line);
check(u('unknown-role', ul('staff_u, staff, staff_r nosuch_r')).some(x => /'nosuch_r'/.test(x.msg)), 'undeclared role');
check(u('mls-range', ul('staff_u, staff, staff_r nosuch_r')).some(x => /s3 doesn't exist: this MCS policy has only s0/.test(x.msg))
  && u('mls-range', ul('staff_u, staff, staff_r nosuch_r')).some(x => /c2000 is out of range: this MCS policy has c0 to c1023/.test(x.msg)), 'sensitivity and category beyond the MCS policy\'s', codes(d));
check(u('mls-token', ul('bad_u')).some(x => /'bogus_level'/.test(x.msg)), 'an unknown token in a range');
check(u('duplicate-user', ul('staff_u, staff, staff_r, s0, s0')).length === 1, 'the same user twice: duplicate-user');
check(!d.some(x => x.l === ul('system_u')), 'a correct line with macros (mcs_allcats): quiet', codes(d));
idx.setM4Defines(null);
idx.rebuild();
check(!diagOf('users').some(x => x.code === 'mls-range'), 'without build flags levels aren\'t judged');

fs.rmSync(dir, { recursive: true, force: true });
console.log(failures ? `\n${failures} check(s) failed` : '\nall diagnostics checks passed');
process.exit(failures ? 1 : 0);
