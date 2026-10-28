'use strict';
// Install profiles from kickstarts (server/kickstart.js), any OS: comps.xml
// groups, Mako conditions and templates, %packages with %include / .tmpl /
// @group / -exclusions, the separately packaged policy modules a profile
// installs, and finding CLIP's kickstart directory above a tree.
//   node test/kickstart-test.js
const path = require('path');
const ks = require('../server/kickstart');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2000).replace(/\n/g, '\n     ')); }
};

/* ---------- comps.xml ---------- */
const COMPS = `<?xml version="1.0"?>
<comps>
  <group>
    <id>core</id>
    <packagelist>
      <packagereq type="mandatory">bash</packagereq>
      <packagereq type="mandatory">selinux-policy-targeted</packagereq>
      <packagereq type="default">rsyslog</packagereq>
      <packagereq type="optional">selinux-policy-mls</packagereq>
      <packagereq requires="glusterfs" type="conditional">glusterfs-rdma</packagereq>
    </packagelist>
  </group>
  <group>
    <id>web</id>
    <packagelist>
      <packagereq>httpd</packagereq>
      <packagereq type="default">selinux-policy-mcs-apache</packagereq>
    </packagelist>
  </group>
  <environment>
    <id>server-env</id>
    <grouplist><groupid>core</groupid><groupid>web</groupid></grouplist>
  </environment>
</comps>`;
const comps = ks.parseComps(COMPS);
check(comps.size === 3 && comps.get('core').mandatory.join() === 'bash,selinux-policy-targeted' && comps.get('core').default.join() === 'rsyslog'
  && comps.get('core').optional.join() === 'selinux-policy-mls' && comps.get('core').conditional.join() === 'glusterfs-rdma', 'comps: groups with their package kinds', [...comps]);
check(comps.get('web').mandatory.join() === 'httpd' && comps.get('server-env').groups.join() === 'core,web', 'comps: packagereq without a type is mandatory; environments list groups');

/* ---------- Mako conditions ---------- */
const vars = { GUI: 'n', TOOR: 'y', OS_REL: '9.4' };
const E = (e) => ks.evalCondition(e, vars);
check(E('GUI == "y"') === false && E('TOOR == "y"') === true && E("TOOR != 'y'") === false, '== / != on CONFIG_BUILD values');
check(E('GUI == "y" or TOOR == "y"') === true && E('GUI == "y" and TOOR == "y"') === false && E('not GUI == "y"') === true, 'and / or / not');
check(E('float(OS_REL) >= 7.4') === true && E('float(OS_REL) < 9') === false && E('int(OS_REL) == 9') === true, 'float() / int() comparisons');
check(E('NOPE == "y"') === null && E('NOPE == "y" and TOOR == "y"') === null && E('NOPE == "y" or TOOR == "y"') === true && E('NOPE == "y" and GUI == "y"') === false,
  'unknown variables: undecided, except where and/or decide anyway');
check(E('len(X) > 2') === null && E('GUI == ') === null, 'unsupported syntax: undecided');

/* ---------- Mako templates ---------- */
const TMPL = `a
% if TOOR == "y":
toor
% endif
% if GUI == "y":
gui
% elif NOPE == "y":
maybe
% else:
nogui
% endif
## a mako comment
%if NOPE == "x":
unsure
%else:
unsure-else
%endif
z`;
const r = ks.renderMako(TMPL, vars);
const T = (t) => r.find(x => x.text === t);
check(T('a') && T('toor') && !T('gui') && T('z') && !r.some(x => /^\s*%/.test(x.text) || /mako comment/.test(x.text)), 'decided branches kept/dropped; control lines and ## comments left out', r);
check(T('maybe') && T('maybe').unsure && T('nogui') && T('nogui').unsure, 'after an undecided elif: the elif and the else are both unsure');
check(T('unsure').unsure && T('unsure-else').unsure && !T('toor').unsure && T('toor').line === 2, 'undecided if/else: both branches, unsure; line numbers kept');

/* ---------- kickstarts ---------- */
const files = {
  '/clip/kickstart/web/web.ks': `install
%include includes/storage
%packages --excludedocs
%include includes/packages
#CONFIG-BUILD-ADDTL-PACKAGES
selinux-policy-mcs
selinux-policy-mcs-ssh
#selinux-policy-mcs-ec2ssh
selinux-policy-mcs-bind # trailing comment
@web
-rsyslog
-selinux-policy-mcs-apache
%end
%post
selinux-policy-mcs-postfix
%end
`,
  '/clip/kickstart/includes/storage': 'selinux-policy-mcs-wrong\n',
  '/clip/kickstart/includes/packages.tmpl': `@core
% if TOOR == "y":
selinux-policy-mcs-toor
% endif
% if GUI == "y":
selinux-policy-mcs-xserver
% endif
% if NOPE == "y":
selinux-policy-mcs-colord
% endif
selinux-policy-mcs-aid*
%include /run/install/repo/extra
%include include-at-runtime/late
`,
};
const readFile = (p) => (Object.prototype.hasOwnProperty.call(files, p.split(path.sep).join('/')) ? files[p.split(path.sep).join('/')] : null);
const k = ks.readKickstart('/clip/kickstart/web/web.ks', { readFile, vars, comps });
const P = (n) => k.packages.get(n);
check(P('selinux-policy-mcs-ssh') && P('selinux-policy-mcs-bind') && !P('selinux-policy-mcs-ec2ssh') && !P('selinux-policy-mcs-postfix') && !P('selinux-policy-mcs-wrong'),
  'only %packages lines (comments, %post and includes outside %packages ignored)', [...k.packages.keys()]);
check(P('selinux-policy-mcs-toor') && P('selinux-policy-mcs-toor').file.endsWith('packages.tmpl') && !P('selinux-policy-mcs-xserver') && P('selinux-policy-mcs-colord').unsure,
  '%include rendered from its .tmpl with CONFIG_BUILD values (undecided lines unsure)');
check(P('bash') && P('bash').group === 'core' && P('httpd') && !P('rsyslog') && !P('selinux-policy-mcs-apache'), '@groups through comps; -name removes what groups bring in');
check(k.groups.map(g => g.id).sort().join() === 'core,web' && k.notes.some(n => /\/run\/install\/repo\/extra/.test(n)) && !k.notes.some(n => /include-at-runtime/.test(n)),
  'groups listed; an absolute %include noted; include-at-runtime ignored', k);
const k2 = ks.readKickstart('/clip/kickstart/web/web.ks', { readFile: (p) => (/web\.ks$/.test(p) ? files['/clip/kickstart/web/web.ks'].replace('-selinux-policy-mcs-apache\n', '-selinux-policy-mcs-ssh\n') : readFile(p)), vars, comps });
check(k2.packages.get('selinux-policy-mcs-ssh') && k2.packages.get('selinux-policy-mcs-apache'), 'a package named explicitly stays even when also excluded');
const nodef = ks.readKickstart('/x/kickstart/n/n.ks', { readFile: (p) => (/n\.ks$/.test(p) ? '%packages\n@core --nodefaults\n@core-x --optional\n%end\n' : null), vars, comps });
check(nodef.packages.has('bash') && !nodef.packages.has('rsyslog') && nodef.groups.find(g => g.id === 'core-x').missing, '--nodefaults: mandatory only; unknown groups marked missing');
check(ks.readKickstart('/nope.ks', { readFile: () => null }) === null, 'missing kickstart: null');

/* ---------- modules of a profile ---------- */
const mods = ks.profileModules(k, ['ssh', 'bind', 'apache', 'toor', 'xserver', 'colord', 'aide', 'postfix'], 'mcs');
const S = (m) => mods.get(m).state;
check(S('ssh') === 'installed' && S('bind') === 'installed' && S('toor') === 'installed' && S('apache') === 'absent' && S('xserver') === 'absent' && S('postfix') === 'absent',
  'installed / absent modules from selinux-policy-mcs-<module>', [...mods]);
check(S('colord') === 'unsure' && S('aide') === 'installed' && mods.get('aide').pkg === 'selinux-policy-mcs-aid*' && mods.get('ssh').line === 6,
  'undecided template line: unsure; a glob line counts for what it matches; where each comes from');

/* ---------- finding the profiles ---------- */
const dirs = new Set(['/clip/kickstart', '/clip/kickstart/web/web.ks', '/clip/kickstart/min/min.ks', '/clip/conf/yum/comps.xml', '/clip/CONFIG_BUILD']);
const norm = (p) => p.split(path.sep).join('/').replace(/^[A-Za-z]:/, '');
const found = ks.findProfiles('/clip/packages/selinux-policy/selinux-policy', {
  exists: (p) => dirs.has(norm(p)), list: (d) => (norm(d) === '/clip/kickstart' ? ['includes', 'min', 'web', 'README'] : []) });
check(found && norm(found.root) === '/clip' && found.profiles.map(p => p.name).join() === 'min,web' && norm(found.comps) === '/clip/conf/yum/comps.xml' && norm(found.config) === '/clip/CONFIG_BUILD',
  'kickstart/<name>/<name>.ks found three levels above the tree, with comps.xml and CONFIG_BUILD', found);
check(ks.findProfiles('/elsewhere/tree', { exists: () => false, list: () => [] }) === null, 'no kickstart directory: null');

console.log(failures ? `\n${failures} check(s) failed` : '\nall kickstart checks passed');
process.exit(failures ? 1 : 0);
