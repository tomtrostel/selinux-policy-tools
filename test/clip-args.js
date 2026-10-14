'use strict';
// Build arguments for a CLIP tree (packages/selinux-policy/selinux-policy):
// read from the CLIP spec and Makefile next to it, as "Configure Build from
// Spec File…" does, so every CLIP branch (RHEL 8, RHEL 9) gets its own
// SEPARATE_PKGS. Trees without a CLIP spec get CLIP RHEL 9's arguments.
const fs = require('fs');
const path = require('path');
const { specBuildConfigs } = require('../server/specconfig');

const RHEL9_SEPARATE = 'ssh rhsmcertd oddjob rtkit aide postfix usbguard fapolicyd rngd logadm auditadm secadm sasl rpcbind rpc gssproxy kerberos certmonger pcscd apcupsd nut postgresql mysql apache bind openvpn samba ntp xserver accountsd colord geoclue gnome wm telepathy bluetooth devicekit';
const FALLBACK = ['NAME=mcs', 'TYPE=mcs', 'DISTRO=redhat', 'UBAC=y', 'DIRECT_INITRC=n', 'MONOLITHIC=n', 'POLY=y', 'UNK_PERMS=deny',
  'MLS_CATS=1024', 'MCS_CATS=1024', 'SEMOD_EXP=/usr/bin/semodule_expand', `APPS_MODS=${RHEL9_SEPARATE}`];

function clipSpec(treeDir) {
  const dir = path.dirname(path.resolve(treeDir));
  let names = [];
  try { names = fs.readdirSync(dir).filter(n => n.endsWith('.spec')); } catch (e) { return null; }
  // CLIP's Makefile picks -cil on RHEL >= 7.3.
  names.sort((a, b) => (b.includes('-cil') - a.includes('-cil')) || a.localeCompare(b));
  return names.length ? path.join(dir, names[0]) : null;
}

function clipArgs(treeDir) {
  const spec = clipSpec(treeDir);
  if (!spec) return FALLBACK;
  const c = specBuildConfigs(spec)[0];
  return c && c.clip ? c.makeArgs : FALLBACK;
}

module.exports = { clipArgs, clipSpec, FALLBACK };
