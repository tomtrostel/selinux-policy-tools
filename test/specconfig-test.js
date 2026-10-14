'use strict';
// Build settings from specs: CLIP's (%installCmds + the Makefile's
// SEPARATE_PKGS). Any OS.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { specBuildConfigs, makeVars } = require('../server/specconfig');

let failures = 0;
const check = (ok, what, extra) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`); if (!ok) { failures++; if (extra !== undefined) console.log('     ', JSON.stringify(extra, null, 1)); } };

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'specconfig-test-'));
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

console.log(failures ? `\n${failures} check(s) failed` : '\nall specconfig checks passed');
process.exit(failures ? 1 : 0);
