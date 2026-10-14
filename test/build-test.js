'use strict';
// The pure parts of server/build.js (any OS, no toolchain): tool output
// parsing, the m4 #line expansion map and expanded view, the generated
// corenetwork.te alignment and diagnostic mapping, modules.conf overlays,
// tree discovery, and the scratch copy sync.
//   node test/build-test.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const B = require('../server/build');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-build-test-'));
const write = (p, t, mode) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, t); if (mode) fs.chmodSync(p, mode); };

/* ---------- tool output ---------- */
const out = B.parseBuildOutput([
  "policy/modules/services/foo.te:12:ERROR 'unknown type bar_t' at token ';' on line 4033:",
  "policy/modules/services/foo.te:20:ERROR 'syntax error' at token 'foo_read_stuff' on line 4041:",
  "policy/modules/services/foo.te:7:WARNING 'duplicate declaration' at token 'x' on line 9:",
  'm4:policy/modules/services/foo.if:33: ERROR: end of file in argument list',
  'm4:policy/modules/services/foo.if:40: Warning: excess arguments to builtin `define\' ignored',
  'policy/modules/services/foo.if:55: Warning: foo_thing(): parameter 2 has no doc',
  "libsepol.print_missing_requirements: postfix's global requirements were not met: type/attribute mail_spool_t",
  'make: *** [Rules.modular:92: tmp/foo.mod] Error 1',
  'some other noise',
].join('\n'));
check(out.length === 7, `seven diagnostics from the output (${out.length})`, out);
check(out[0].file === 'policy/modules/services/foo.te' && out[0].l === 11 && out[0].severity === 'error' && out[0].msg === 'unknown type bar_t' && out[0].tool === 'checkmodule', 'checkmodule error: file, 0-based line, message', out[0]);
check(/syntax error at 'foo_read_stuff' \(if this is an interface call, it is not defined/.test(out[1].msg), 'a syntax error on a plain name says it may be an undefined interface', out[1].msg);
check(out[2].severity === 'warning', 'checkmodule warning');
check(out[3].tool === 'm4' && out[3].l === 32 && out[3].severity === 'error' && out[4].severity === 'warning', 'm4 error and warning');
check(out[5].tool === 'refpolicy' && out[5].severity === 'warning' && out[5].l === 54, 'refpolicywarn line');
check(out[6].tool === 'semodule_link' && out[6].linkModule === 'postfix' && out[6].token === 'mail_spool_t' && out[6].file === null, 'semodule_link: module and missing name, no line (the server places it)', out[6]);

/* ---------- m4 expansion map ---------- */
// As `m4 -s` writes it: every output line of a multi-line expansion is preceded
// by a #line marker for the call's line (file name only when it changes).
const at = (n, lines) => lines.flatMap(l => [`#line ${n}`, l]);
const M4OUT = [
  '#line 1 "policy/modules/services/foo.te"',
  'module foo 1.0;',
  ...at(1, ['require {', '  class file { read };', '}']),
  '#line 3',
  'type foo_t;',
  ...at(5, ['##### begin files_read_etc(foo_t) depth: 1', 'require {', '  type etc_t;', '}', 'allow foo_t etc_t:file { read getattr };',
    '##### begin nested_thing(foo_t) depth: 2', 'allow foo_t etc_t:dir search;', '##### end nested_thing depth: 1', '##### end files_read_etc depth: 0']),
  '#line 7 "policy/modules/services/foo.te"',
  'allow foo_t self:process signal;',
  '#line 1 "policy/support/obj_perm_sets.spt"',
  'ignored from a file that doesn\'t resolve',
].join('\n');
const resolve = (f) => (f.endsWith('.te') ? `/src/${f}` : null);
const exp = B.parseExpansion(M4OUT, resolve);
const foo = exp.get('/src/policy/modules/services/foo.te');
check(foo && foo.get(4).length >= 3 && foo.get(4).some(e => e.text === 'allow foo_t etc_t:file { read getattr };' && e.depth === 1 && e.via === 'files_read_etc(foo_t)'),
  'statements of a call land on the call\'s line, with depth and the call', foo && [...foo.get(4)]);
check(foo.get(4).some(e => e.text === 'allow foo_t etc_t:dir search;' && e.depth === 2 && e.via === 'nested_thing(foo_t)'), 'nested calls: deeper, named by the inner call');
check(foo.get(6) && foo.get(6)[0].text === 'allow foo_t self:process signal;', 'a #line with a file name moves to that line');
check(exp.size === 1, 'files that don\'t resolve to an editable source are left out');
const rules = B.rulesAt(exp, '/src/policy/modules/services/foo.te', 4);
check(rules.length === 2 && rules.every(r => /^allow/.test(r.text)), 'rulesAt: the statements of a line without require blocks', rules);
check(B.rulesAt(exp, '/src/policy/modules/services/foo.te', 0).length === 0, 'rulesAt: module / class boilerplate dropped');
const view = B.renderExpanded(M4OUT, resolve, () => ['policy_module(foo, 1.0)', '', 'type foo_t;', '', 'files_read_etc(foo_t)', '', 'allow foo_t self:process signal;'].join('\n'), '/src/policy/modules/services/foo.te');
check(/# ──── foo\.te:5: files_read_etc\(foo_t\)/.test(view) && /allow foo_t self:process signal;/.test(view) && !/# ──── foo\.te:7/.test(view), 'expanded view: a header for each expansion, plain statements as they are', view);

/* ---------- generated corenetwork.te ---------- */
const IN = [
  'policy_module(corenetwork, 1.0)',
  '',
  'type tun_tap_device_t;',
  'network_port(http, tcp,80,s0, tcp,443,s0)',
  'network_port(ssh, tcp,22,s0)',
  'network_interface(lo, lo, s0 - mls_systemhigh)',
  '',
  'allow foo_t bar_t:file read;',
].join('\n');
const GEN = [
  '#',
  '# This is a generated file!  Instead of modifying this file, the',
  '# corenetwork.te.in or corenetwork.te.m4 file should be modified.',
  'policy_module(corenetwork, 1.0)',
  '',
  'type tun_tap_device_t;',
  'type http_port_t, port_type;',
  'portcon tcp 80 gen_context(system_u:object_r:http_port_t,s0)',
  'portcon tcp 443 gen_context(system_u:object_r:http_port_t,s0)',
  'type ssh_port_t, port_type;',
  'portcon tcp 22 gen_context(system_u:object_r:ssh_port_t,s0)',
  'type lo_netif_t, netif_type;',
  'netifcon lo gen_context(system_u:object_r:lo_netif_t,s0 - mls_systemhigh)',
  '',
  'allow foo_t bar_t:file read;',
].join('\n');
const map = B.alignGenerated(GEN, IN);
const g = (needle) => GEN.split('\n').findIndex(l => l.includes(needle));
const s = (needle) => IN.split('\n').findIndex(l => l.includes(needle));
check(map[0] === -1 && map[1] === -1 && map[2] === -1, 'the generated-file header maps nowhere');
check(map[g('type tun_tap_device_t')] === s('type tun_tap_device_t') && map[g('allow foo_t bar_t')] === s('allow foo_t bar_t'), 'verbatim lines map to themselves');
check(map[g('portcon tcp 443')] === s('network_port(http') && map[g('portcon tcp 22')] === s('network_port(ssh') && map[g('lo_netif_t, netif_type')] === s('network_interface(lo'),
  'expanded lines map to the declaration whose name they use', { map, http: s('network_port(http') });
const work = path.join(tmp, 'work'), root = path.join(tmp, 'root');
write(path.join(work, 'policy/modules/kernel/corenetwork.te'), GEN);
write(path.join(work, 'policy/modules/kernel/corenetwork.te.in'), IN.replace('network_port(ssh, tcp,22,s0)', 'network_port(ssh, tcp,22,s0)'));
const diags = [
  { file: 'policy/modules/kernel/corenetwork.te', l: g('portcon tcp 22'), msg: 'some error' },
  { file: 'policy/modules/system/ubac.te', l: 2041, msg: 'duplicate portcon entry for tcp 443-443' },
  { file: 'policy/modules/services/foo.te', l: 3, msg: 'unrelated' },
];
B.mapGeneratedDiagnostics(diags, root, work);
const srcPath = path.join(root, 'policy/modules/kernel/corenetwork.te.in');
check(diags[0].path === srcPath && diags[0].l === s('network_port(ssh') && /in the generated corenetwork\.te, line \d+/.test(diags[0].msg), 'an error in the generated file moves to its .te.in line', diags[0]);
check(diags[1].path === srcPath && diags[1].l === s('network_port(http') && diags[1].token === 'network_port', 'a duplicate portcon reported against another file lands on the declaring network_port', diags[1]);
check(!diags[2].path, 'other diagnostics are left alone');

/* ---------- modules.conf overlays ---------- */
const CONF = '# comment\nkernel = base\nfoo = module\nbar = module\n\nbaz = off\n';
check(B.disableModules(CONF, new Set(['foo', 'kernel', 'baz'])) === '# comment\nkernel = base\nfoo = off\nbar = module\n\nbaz = off\n', 'disableModules: listed modules off, base modules kept, layout kept');
const files = { '/spec/modules.conf': CONF, '/spec/dropped.lst': '# dropped\nbar\n\n', '/spec/extra.lst': 'foo\n' };
const read = (p) => (p in files ? files[p] : null);
check(B.overlaySource('/spec/modules.conf', read).text === CONF && B.overlaySource('/nope', read).missing === '/nope', 'overlaySource: a plain file, or what is missing');
const ov = B.overlaySource({ from: '/spec/modules.conf', disable: ['/spec/dropped.lst', '/spec/extra.lst'] }, read);
check(String(ov.text) === '# comment\nkernel = base\nfoo = off\nbar = off\n\nbaz = off\n', 'overlaySource { from, disable }: the lists\' modules turned off', String(ov.text));
check(B.overlaySource({ from: '/spec/modules.conf', disable: ['/spec/missing.lst'] }, read).missing === '/spec/missing.lst', 'a missing list file is reported');

/* ---------- tree discovery ---------- */
const mkTree = (d) => { for (const f of ['Makefile', 'Rules.modular', 'build.conf']) write(path.join(d, f), ''); write(path.join(d, 'policy/support/obj_perm_sets.spt'), ''); };
const ws = path.join(tmp, 'ws');
mkTree(path.join(ws, 'rhel9'));
mkTree(path.join(ws, 'clip/packages/selinux-policy/selinux-policy'));
mkTree(path.join(ws, 'rhel9/policy/modules/nested')); // inside a tree: not searched
mkTree(path.join(ws, 'node_modules/x'));
write(path.join(ws, 'notatree/Makefile'), '');
const trees = B.findTrees([ws]);
check(trees.length === 2 && trees.some(t => t.endsWith('rhel9')) && trees.some(t => t.endsWith(path.join('selinux-policy', 'selinux-policy'))), 'findTrees: trees at any depth, not inside a tree or node_modules', trees);
check(B.findTrees([ws], 2).length === 1, 'findTrees stops at maxDepth');
check(B.treeRootOf(path.join(ws, 'rhel9/policy/support/obj_perm_sets.spt')) === path.join(ws, 'rhel9') && B.treeRootOf(path.join(ws, 'rhel9/policy/support/misc.spt')) === null, 'treeRootOf');
write(path.join(ws, 'rhel9/build.conf'), 'NAME = refpolicy\nTYPE = mcs\n');
check(B.treeOption(path.join(ws, 'rhel9'), ['TYPE=mls'], 'TYPE') === 'mls' && B.treeOption(path.join(ws, 'rhel9'), [], 'TYPE') === 'mcs' && B.treeOption(path.join(ws, 'rhel9'), [], 'NOPE') === null,
  'treeOption: make arguments win over build.conf');

/* ---------- scratch copy sync ---------- */
const tr = path.join(tmp, 'tree'), sc = path.join(tmp, 'scratch');
write(path.join(tr, 'Makefile'), 'all:\n');
write(path.join(tr, 'support/gen.sh'), '#!/bin/sh\n', 0o755);
write(path.join(tr, 'policy/modules/kernel/corenetwork.te.in'), 'in\n');
write(path.join(tr, 'policy/modules/kernel/corenetwork.te'), 'generated\n');
write(path.join(tr, 'policy/modules/a.te'), 'a\n');
write(path.join(tr, 'base.pp'), 'output');
write(path.join(tr, 'tmp/x.tmp'), 'build dir');
write(path.join(tr, '.git/HEAD'), 'ref');
const src = B.treeSources(tr).sort();
check(src.join() === ['Makefile', 'policy/modules/a.te', 'policy/modules/kernel/corenetwork.te.in', 'support/gen.sh'].join(), 'treeSources: no outputs, tmp/, dot dirs, or the generated corenetwork.te', src);
const readText = (p) => { try { return fs.readFileSync(p); } catch { return null; } };
let n = B.syncTree(tr, sc, readText, new Map([['policy/modules.conf', 'foo = module\n']]));
check(n === 5 && fs.readFileSync(path.join(sc, 'policy/modules.conf'), 'utf8') === 'foo = module\n', `first sync writes the sources and the overlay (${n})`);
if (process.platform !== 'win32') check((fs.statSync(path.join(sc, 'support/gen.sh')).mode & 0o111) !== 0, 'the execute bit is kept (the Makefile runs scripts directly)');
check(B.syncTree(tr, sc, readText, new Map([['policy/modules.conf', 'foo = module\n']])) === 0, 'an unchanged tree rewrites nothing (make\'s incremental build stays valid)');
const buffers = (p) => (p.endsWith('a.te') ? 'edited in the editor\n' : readText(p));
check(B.syncTree(tr, sc, buffers, new Map([['policy/modules.conf', 'foo = module\n']])) === 1 && fs.readFileSync(path.join(sc, 'policy/modules/a.te'), 'utf8') === 'edited in the editor\n', 'editor buffers win over disk; only that file is written');
fs.rmSync(path.join(tr, 'policy/modules/a.te'));
write(path.join(sc, 'policy/booleans.conf'), 'made by make conf\n');
write(path.join(sc, 'base.pp'), 'build output');
n = B.syncTree(tr, sc, readText, new Map());
check(!fs.existsSync(path.join(sc, 'policy/modules/a.te')) && fs.existsSync(path.join(sc, 'policy/booleans.conf')) && fs.existsSync(path.join(sc, 'base.pp')),
  'a file deleted from the tree goes; make conf\'s outputs and build outputs stay');
check(B.CONF_OUTPUTS.includes('policy/modules.conf') && fs.existsSync(path.join(sc, 'policy/modules.conf')), 'an overlay that is no longer set is kept as a make conf output');

/* ---------- stale module set ---------- */
const w2 = path.join(tmp, 'w2');
write(path.join(w2, 'policy/modules.conf'), 'foo = module\n');
B.forgetStaleModuleSet(w2, ['APPS_MODS=a']);
write(path.join(w2, 'foo.pp'), 'pp'); write(path.join(w2, 'tmp/all_mods.fc'), 'fc'); write(path.join(w2, 'tmp/foo.mod'), 'mod');
B.forgetStaleModuleSet(w2, ['APPS_MODS=a', 'UBAC=y']);
check(fs.existsSync(path.join(w2, 'foo.pp')) && fs.existsSync(path.join(w2, 'tmp/all_mods.fc')), 'the same module set: outputs kept (other variables don\'t count)');
B.forgetStaleModuleSet(w2, ['APPS_MODS=a b']);
check(!fs.existsSync(path.join(w2, 'foo.pp')) && !fs.existsSync(path.join(w2, 'tmp/all_mods.fc')) && fs.existsSync(path.join(w2, 'tmp/foo.mod')),
  'APPS_MODS changed: set-dependent outputs removed, per-module compiles kept');
write(path.join(w2, 'foo.pp'), 'pp');
write(path.join(w2, 'policy/modules.conf'), 'foo = off\n');
B.forgetStaleModuleSet(w2, ['APPS_MODS=a b']);
check(!fs.existsSync(path.join(w2, 'foo.pp')), 'modules.conf changed: packages removed too');

fs.rmSync(tmp, { recursive: true, force: true });
console.log(failures ? `\n${failures} check(s) failed` : '\nall build checks passed');
process.exit(failures ? 1 : 0);
