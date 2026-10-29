'use strict';
// Build settings from specs: CLIP's (%installCmds + the Makefile's
// SEPARATE_PKGS). Any OS.
const fs = require('fs');
const { tempDir } = require('./tmpdirs');
const path = require('path');
const { specBuildConfigs, makeVars } = require('../server/specconfig');

let failures = 0;
const check = (ok, what, extra) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`); if (!ok) { failures++; if (extra !== undefined) console.log('     ', JSON.stringify(extra, null, 1)); } };

const dir = tempDir('specconfig-test-');
const pkg = path.join(dir, 'packages/selinux-policy');
fs.mkdirSync(pkg, { recursive: true });
fs.writeFileSync(path.join(dir, 'CONFIG_BUILD'), 'CONFIG_BUILD_SELINUX_POL_TYPE := mcs\n');
fs.writeFileSync(path.join(pkg, 'Makefile'), [
  'PKGNAME ?= selinux-policy',
  'CONFIG_BUILD_SELINUX_POL_TYPE ?= mls',
  'ifneq ($(DISABLE_STD_SEPARATE_PKGS),y)',
  '# SEPARATE_PKGS += commented',
  'SEPARATE_PKGS += ssh',
  'SEPARATE_PKGS +=  logadm auditadm # staff sysadm',
  'SEPARATE_PKGS += samba \\',
  '\tntp',
  'endif # ifneq DISABLE_STD_SEPARATE_PKGS,y',
  'ifeq ($(DISABLE_STD_SEPARATE_PKGS),y)',
  'SEPARATE_PKGS += never',
  'endif',
  'ENABLE_MODULES += extra',
  'ENABLE_MODULES := $(ENABLE_MODULES) $(SEPARATE_PKGS)',
  'ifeq ($(strip $(SEPARATE_PKGS)),)',
  'SEPARATE_PKGS := %{nil}',
  'endif',
  'ifeq ($(strip $(ENABLE_MODULES)),)',
  'ENABLE_MODULES := %{nil}',
  'endif',
  '',
].join('\n'));
const spec = path.join(pkg, 'selinux-policy-cil.spec');
fs.writeFileSync(spec, [
  '%define distro redhat ',
  '%define monolithic n',
  'Name: %{pkgname}',
  '%define installCmds() \\',
  'make UNK_PERMS=%5 NAME=%1 TYPE=%2 DISTRO=%{distro} UBAC=y DIRECT_INITRC=%3 MONOLITHIC=%{monolithic} POLY=%4 MLS_CATS=1024 MCS_CATS=1024 APPS_MODS="%{enable_modules}  %{separatePkgs}" SEMOD_EXP="/usr/bin/semodule_expand" base.pp \\',
  'make %{?_smp_mflags} validate UNK_PERMS=%5 NAME=%1 APPS_MODS="%{enable_modules}" modules \\',
  'make DESTDIR=%{buildroot} install',
  '',
  '%build',
  '# installCmds NAME TYPE DIRECT_INITRC POLY UNKNOWN',
  '%installCmds %{type} %{type}  n y deny',
  '',
].join('\n'));

const v = makeVars(fs.readFileSync(path.join(pkg, 'Makefile'), 'utf8'));
check(v.get('SEPARATE_PKGS') === 'ssh logadm auditadm samba ntp', 'Makefile: += lines, comments, continuations, the default branch of ifneq/ifeq', v.get('SEPARATE_PKGS'));
const c = specBuildConfigs(spec);
check(c.length === 1 && c[0].clip && c[0].variant === 'mcs', 'one CLIP variant, named from CONFIG_BUILD\'s policy type', c);
const want = ['UNK_PERMS=deny', 'NAME=mcs', 'TYPE=mcs', 'DISTRO=redhat', 'UBAC=y', 'DIRECT_INITRC=n', 'MONOLITHIC=n', 'POLY=y', 'MLS_CATS=1024', 'MCS_CATS=1024',
  'APPS_MODS=extra ssh logadm auditadm samba ntp', 'SEMOD_EXP=/usr/bin/semodule_expand'];
check(c[0] && JSON.stringify(c[0].makeArgs) === JSON.stringify(want), 'make variables of the base.pp line, %N and macros filled in, APPS_MODS deduplicated', c[0] && c[0].makeArgs);
check(c[0] && !Object.keys(c[0].files).length && !c[0].missing.length, 'the tree\'s own modules.conf, booleans and users are used');
fs.rmSync(path.join(pkg, 'Makefile'));
const c2 = specBuildConfigs(spec);
check(c2[0] && c2[0].makeArgs.includes('APPS_MODS=') && /no Makefile/.test(c2[0].notes.join()), 'no Makefile: empty APPS_MODS and a note', c2[0]);
fs.rmSync(dir, { recursive: true, force: true });

/* ---------- RHEL 9 / older Fedora: config files next to the spec ---------- */
const d9 = tempDir('specconfig-rhel9-');
const spec9 = path.join(d9, 'selinux-policy.spec');
fs.writeFileSync(spec9, [
  '%define distro redhat',
  '%define monolithic n',
  'Source5: modules-mls-base.conf',
  'Source31: modules-targeted-contrib.conf',
  '%define common_params DISTRO=%{distro} UBAC=n DIRECT_INITRC=n MONOLITHIC=%{monolithic} MLS_CATS=1024 MCS_CATS=1024',
  '',
  '%define makeCmds() \\',
  '%make_build %common_params UNK_PERMS=%3 NAME=%1 TYPE=%2 bare \\',
  '%make_build %common_params UNK_PERMS=%3 NAME=%1 TYPE=%2 conf \\',
  'cp -f selinux_config/booleans-%1.conf ./policy/booleans.conf \\',
  'cp -f selinux_config/users-%1 ./policy/users \\',
  '#cp -f selinux_config/modules-%1-base.conf  ./policy/modules.conf \\',
  '',
  '%define makeModulesConf() \\',
  'cp -f selinux_config/modules-%1-%2.conf  ./policy/modules-base.conf \\',
  'cp -f selinux_config/modules-%1-%2.conf  ./policy/modules.conf \\',
  'if [ %3 == "contrib" ];then \\',
  '\tcp selinux_config/modules-%1-%3.conf ./policy/modules-contrib.conf; \\',
  '\tcat selinux_config/modules-%1-%3.conf >> ./policy/modules.conf; \\',
  'fi; \\',
  '',
  '%build',
  '%makeCmds targeted mcs allow',
  '%makeModulesConf targeted base contrib',
  '%installCmds targeted mcs allow',
  '%makeCmds minimum mcs allow',
  '%makeModulesConf targeted base contrib',
  '%installCmds minimum mcs allow',
  '%makeCmds mls mls deny',
  '%makeModulesConf mls base contrib',
  '%installCmds mls mls deny',
  '',
].join('\n'));
for (const f of ['booleans-targeted.conf', 'users-targeted', 'modules-targeted-base.conf', 'modules-targeted-contrib.conf', 'booleans-mls.conf', 'users-mls', 'modules-mls-base.conf']) fs.writeFileSync(path.join(d9, f), '');
const r9 = specBuildConfigs(spec9);
const v9 = (n) => r9.find(c => c.variant === n);
check(r9.map(c => c.variant).join() === 'targeted,minimum,mls' && !r9.some(c => c.clip), 'RHEL 9: one variant per %makeCmds', r9.map(c => c.variant));
check(JSON.stringify(v9('targeted').makeArgs) === JSON.stringify(['DISTRO=redhat', 'UBAC=n', 'DIRECT_INITRC=n', 'MONOLITHIC=n', 'MLS_CATS=1024', 'MCS_CATS=1024', 'UNK_PERMS=allow', 'NAME=targeted', 'TYPE=mcs']),
  'RHEL 9 targeted: %common_params expanded, then UNK_PERMS, NAME, TYPE', v9('targeted').makeArgs);
check(JSON.stringify(v9('targeted').files) === JSON.stringify({
  'policy/booleans.conf': [path.join(d9, 'booleans-targeted.conf')], 'policy/users': [path.join(d9, 'users-targeted')],
  'policy/modules.conf': [path.join(d9, 'modules-targeted-base.conf'), path.join(d9, 'modules-targeted-contrib.conf')] }), 'RHEL 9 targeted: booleans, users, modules.conf = base + contrib from the spec\'s directory', v9('targeted').files);
check(v9('minimum').files['policy/modules.conf'][0] === path.join(d9, 'modules-targeted-base.conf') && v9('minimum').files['policy/booleans.conf'][0] === path.join(d9, 'booleans-minimum.conf'),
  'RHEL 9 minimum: targeted\'s module lists, its own booleans');
check(v9('mls').makeArgs.includes('TYPE=mls') && v9('mls').makeArgs.includes('UNK_PERMS=deny') && v9('mls').missing.length === 1 && /modules-mls-contrib\.conf$/.test(v9('mls').missing[0]),
  'RHEL 9 mls: TYPE=mls, and the missing contrib list is reported', v9('mls').missing);
fs.rmSync(d9, { recursive: true, force: true });

/* ---------- RHEL 10 / newer Fedora: dist/NAME in the tree, filtered modules.conf ---------- */
const d10 = tempDir('specconfig-rhel10-');
const tree10 = path.join(d10, 'tree');
const spec10 = path.join(d10, 'selinux-policy.spec');
fs.writeFileSync(spec10, [
  '%define distro redhat',
  '%define monolithic n',
  'Source13: process-modules-filtered.py',
  'Source14: modules-extra.lst',
  'Source15: modules-dropped.lst',
  '%define common_params DISTRO=%{distro} UBAC=n DIRECT_INITRC=n MONOLITHIC=%{monolithic} MLS_CATS=1024 MCS_CATS=1024',
  '%define makeCmds() \\',
  '%make_build %common_params UNK_PERMS=%3 NAME=%1 TYPE=%2 bare \\',
  '%make_build %common_params UNK_PERMS=%3 NAME=%1 TYPE=%2 conf \\',
  'install -p -m0644 ./dist/%1/booleans.conf ./policy/booleans.conf \\',
  'install -p -m0644 ./dist/%1/users ./policy/users \\',
  '',
  '%define makeModulesConf() \\',
  '# install -p -m0644 ./dist/%1/modules.conf ./policy/modules.conf \\',
  '%{SOURCE13} %{SOURCE15} ./dist/%1/modules.conf disabled > ./policy/modules.conf \\',
  '',
  '%build',
  '%makeCmds targeted mcs allow',
  '%makeModulesConf targeted',
  '%installCmds targeted mcs allow',
  '%makeCmds minimum mcs allow',
  '%makeModulesConf targeted',
  'mv ./policy/modules.conf ./policy/modules.conf.dropped',
  '%{SOURCE13} %{SOURCE14} ./policy/modules.conf.dropped disabled > ./policy/modules.conf',
  '%installCmds minimum mcs allow',
  '',
].join('\n'));
for (const f of ['modules-dropped.lst', 'modules-extra.lst']) fs.writeFileSync(path.join(d10, f), '');
for (const f of ['dist/targeted/booleans.conf', 'dist/targeted/users', 'dist/targeted/modules.conf']) { fs.mkdirSync(path.dirname(path.join(tree10, f)), { recursive: true }); fs.writeFileSync(path.join(tree10, f), ''); }
const r10 = specBuildConfigs(spec10, tree10);
const t10 = r10.find(c => c.variant === 'targeted'), m10 = r10.find(c => c.variant === 'minimum');
check(JSON.stringify(t10.files) === JSON.stringify({ 'policy/booleans.conf': ['dist/targeted/booleans.conf'], 'policy/users': ['dist/targeted/users'],
  'policy/modules.conf': [{ from: 'dist/targeted/modules.conf', disable: [path.join(d10, 'modules-dropped.lst')] }] }), 'RHEL 10 targeted: tree-relative dist/ files, modules.conf with the dropped list turned off', t10.files);
check(JSON.stringify(m10.files['policy/modules.conf'][0].disable) === JSON.stringify([path.join(d10, 'modules-dropped.lst'), path.join(d10, 'modules-extra.lst')]),
  'RHEL 10 minimum: filtered again with modules-extra.lst', m10.files);
check(m10.missing.length === 2 && m10.missing.every(p => /dist\/minimum\/(booleans\.conf|users)$/.test(p)) && !t10.missing.length, 'missing tree files are reported against the tree root', m10.missing);
fs.rmSync(d10, { recursive: true, force: true });
check(JSON.stringify(specBuildConfigs((() => { const d = tempDir('specconfig-none-'); const p = path.join(d, 'x.spec'); fs.writeFileSync(p, 'Name: x\n%build\nmake\n'); return p; })())) === '[]',
  'a spec with neither %makeCmds nor %installCmds: no variants');

console.log(failures ? `\n${failures} check(s) failed` : '\nall specconfig checks passed');
process.exit(failures ? 1 : 0);
