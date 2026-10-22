// Context files: file_contexts (+ home-directory lines as genhomedircon writes them,
// .local) and the application context files against a small fake policy
// (server/ctxfiles.js), and the Context Files webview. Any OS.
const C = require('../server/ctxfiles');
const filelabel = require('../server/filelabel');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

// The fake policy.
const USERS = {
  system_u: { roles: ['system_r'], range: 's0-s0:c0.c1023', level: 's0' },
  staff_u: { roles: ['staff_r', 'sysadm_r'], range: 's0-s0:c0.c1023', level: 's0' },
  user_u: { roles: ['user_r'], range: 's0', level: 's0' },
  rolep_u: { roles: ['rolep_r'], range: 's0', level: 's0' },
  lonely_u: { roles: ['lonely_r'], range: 's0', level: 's0' },
};
const ROLES = { object_r: [], system_r: ['init_t', 'initrc_t', 'sshd_t', 'sshd_net_t', 'xserver_t', 'system_dbusd_t', 'run_init_t'], staff_r: ['staff_t'], sysadm_r: ['sysadm_t'], user_r: ['user_t'], rolep_r: ['rolep_t'], lonely_r: [] };
const TYPES = new Set(['init_t', 'initrc_t', 'userhelper_t', 'sshd_t', 'sshd_net_t', 'xserver_t', 'system_dbusd_t', 'run_init_t', 'staff_t', 'sysadm_t', 'user_t', 'rolep_t',
  'etc_t', 'bin_t', 'user_home_t', 'user_home_dir_t', 'staff_home_t', 'xproperty_t', 'tty_device_t', 'removable_t', 'domainfile_t']);
const ALIASES = { old_etc_t: 'etc_t' };
const NO_ASSOC = new Set(['domainfile_t']);
const DYN = new Set(['sshd_t>sshd_net_t']);
const asked = [];
async function ask(items) {
  asked.push(...items);
  const out = {};
  for (const it of items) {
    let a;
    if (it.kind === 'info') a = { mls: true, users: USERS };
    else if (it.kind === 'resolve') a = /^s0(-s0(:c\d+(\.c\d+)?)?)?$/.test(it.range) ? { range: it.range } : { error: `${it.range} isn't a valid range for this policy` };
    else if (it.kind === 'valid') {
      const [u, r, t0, ...lv] = it.ctx.split(':');
      const t = ALIASES[t0] || t0;
      const reasons = [];
      if (!USERS[u]) reasons.push({ kind: 'user', text: `there is no SELinux user ${u}` });
      if (!ROLES[r]) reasons.push({ kind: 'role', text: `there is no role ${r}` });
      else if (USERS[u] && r !== 'object_r' && !USERS[u].roles.includes(r)) reasons.push({ kind: 'userrole', text: `${u} doesn't have role ${r}` });
      if (!TYPES.has(t)) reasons.push({ kind: 'type', text: `there is no type ${t}` });
      else if (ROLES[r] && r !== 'object_r' && !ROLES[r].includes(t)) reasons.push({ kind: 'roletype', text: `role ${r} isn't authorized for ${t}` });
      if (!/^s0(:c\d+)?$/.test(lv.join(':')) && !/^s0-s0/.test(lv.join(':'))) reasons.push({ kind: 'range', text: `${lv.join(':')} isn't a valid level` });
      a = { ok: !reasons.length, reasons };
    } else if (it.kind === 'roletype') {
      const reasons = [];
      if (!ROLES[it.role]) reasons.push({ kind: 'role', text: `there is no role ${it.role}` });
      if (!TYPES.has(it.type)) reasons.push({ kind: 'type', text: `there is no type ${it.type}` });
      else if (ROLES[it.role] && !ROLES[it.role].includes(it.type)) reasons.push({ kind: 'roletype', text: `role ${it.role} isn't authorized for ${it.type}` });
      a = { ok: !reasons.length, reasons };
    } else if (it.kind === 'types') a = { kinds: Object.fromEntries(it.names.map(n => [n, TYPES.has(n) ? 'type' : ALIASES[n] ? 'alias' : null])) };
    else if (it.kind === 'associate') a = { without: it.types.filter(t => NO_ASSOC.has(t)) };
    else if (it.kind === 'dyntrans') a = DYN.has(`${it.from}>${it.to}`) ? { ok: true, missing: [] } : TYPES.has(it.to) ? { ok: false, missing: [`allow ${it.from} ${it.to}:process dyntransition;`] } : { ok: false, unknown: [it.to] };
    out[it.id] = a;
  }
  return out;
}
const file = (name, text) => ({ def: C.FILES.find(f => f.name === name), path: `/c/${name}`, text });
const allFiles = (texts) => C.FILES.map(def => ({ def, path: `/c/${def.name}`, text: texts[def.name] == null ? null : texts[def.name] }));
const SEUSERS = { path: '/c/seusers', text: 'root:staff_u:s0\nbob:rolep_u:s0\n__default__:user_u:s0\n' };

(async () => {
  /* ---------- parsing ---------- */
  const dbus = C.parseFile(C.FILES.find(f => f.name === 'dbus_contexts'), '<busconfig>\n  <selinux>\n    <associate\n     own="org.x.A"\n     context="system_u:object_r:a_t:s0"/>\n    <associate own="org.x.B" context="system_u:object_r:b_t:s0"/>\n  </selinux>\n</busconfig>\n');
  check(dbus.length === 2 && dbus[0].l === 4 && dbus[0].ctx === 'system_u:object_r:a_t:s0' && dbus[0].key === 'org.x.A' && dbus[1].l === 5 && dbus[1].key === 'org.x.B'
    && '    <associate own="org.x.B" context="system_u:object_r:b_t:s0"/>'.substr(dbus[1].c, dbus[1].len) === dbus[1].ctx, 'parse: dbus_contexts associate lines, the context\'s line and column, the owned name', dbus);
  const lxc = C.parseFile(C.FILES.find(f => f.name === 'lxc_contexts'), 'process = "system_u:system_r:container_t:s0"\nfile="system_u:object_r:container_file_t:s0"\n# comment\nbroken line\n');
  check(lxc.length === 3 && lxc[0].key === 'process' && lxc[0].ctx === 'system_u:system_r:container_t:s0' && lxc[1].key === 'file' && lxc[2].bad, 'parse: key = "context" lines (quotes optional), comments skipped, malformed lines marked', lxc);
  const x = C.parseFile(C.FILES.find(f => f.name === 'x_contexts'), 'property _SELINUX_*\t\tsystem_u:object_r:xproperty_t:s0\nclient * system_u:object_r:remote_t:s0\n');
  check(x.length === 2 && x[0].cls === 'property' && x[0].key === 'property _SELINUX_*' && x[1].ctx === 'system_u:object_r:remote_t:s0', 'parse: x_contexts class, name, context', x);
  const dt = C.parseFile(C.FILES.find(f => f.name === 'default_type'), 'staff_r:staff_t\nsysadm_r:sysadm_t # admin\n');
  check(dt.length === 2 && dt[1].role === 'sysadm_r' && dt[1].type === 'sysadm_t' && dt[1].level == null, 'parse: default_type role:type lines', dt);
  const fsafe = C.parseFile(C.FILES.find(f => f.name === 'failsafe_context'), 'sysadm_r:sysadm_t:s0\n');
  check(fsafe[0].role === 'sysadm_r' && fsafe[0].type === 'sysadm_t' && fsafe[0].level === 's0', 'parse: failsafe_context role:type:level');
  check(JSON.stringify(C.parseUsersExtra('user staff_u prefix staff;\nuser root prefix sysadm;\n# x\n')) === '{"staff_u":"staff","root":"sysadm"}', 'parse: users_extra prefixes');
  const tk = (spec, ctx = 'system_u:object_r:user_home_t:s0') => C.templateKind({ spec, flag: null, context: ctx });
  check(tk('HOME_DIR/\\.ssh(/.*)?') === 'homedir' && tk('HOME_ROOT/\\.journal') === 'homeroot' && tk('/run/user/%{USERID}/dconf(/.*)?') === 'username' && tk('/var/spool/cron/USER') === 'user' && tk('/etc/passwd') === null,
    'genhomedircon template kinds: HOME_DIR / HOME_ROOT prefixes, %{USERNAME} or %{USERID}, USER anywhere');

  /* ---------- application files ---------- */
  asked.length = 0;
  const r = await C.analyze({ files: allFiles({
    initrc_context: 'system_u:system_r:initrc_t:s0\n',
    userhelper_context: 'system_u:sysadm_r:sysadm_t:s0\n',
    removable_context: 'system_u:object_r:removable_t:s0\n',
    x_contexts: 'property * system_u:object_r:xproperty_t:s0\nwidget * system_u:object_r:xproperty_t:s0\nselection PRIMARY system_u:object_r:clipboard_xselection_t:s0\n',
    dbus_contexts: '<associate own="org.x.Tuned" context="system_u:object_r:tuned_t:s0"/>\n<associate own="org.x.Bus" context="system_u:object_r:system_dbusd_t:s9"/>\n',
    lxc_contexts: 'process = "system_u:system_r:container_t:s0"\n',
    openssh_contexts: 'privsep_preauth=sshd_net_t\n',
    default_type: 'staff_r:staff_t\nuser_r:staff_t\nlonely_r:lonely_t\nghost_r:ghost_t\n',
    securetty_types: 'tty_device_t\nnosuch_tty_t\n',
    failsafe_context: 'staff_r:staff_t:s7\n',
  }), seusers: SEUSERS, fc: {} }, ask);
  const has = (kind, f, l, re) => r.problems.find(p => p.kind === kind && p.file === `/c/${f}` && (l == null || p.l === l) && (!re || re.test(p.text)));
  check(!r.problems.some(p => p.file === '/c/initrc_context') && !r.problems.some(p => p.file === '/c/removable_context'), 'valid process and object contexts: no problem (object_r needs no user role)');
  const uh = has('invalid', 'userhelper_context', 0, /system_u doesn't have role sysadm_r.*userhelper can't run programs/);
  check(uh && uh.severity === 'error', 'userhelper_context: a process context whose user lacks the role is an error, with what fails', r.problems);
  check(has('format', 'x_contexts', 1, /"widget" isn't a kind of X object/) && has('invalid', 'x_contexts', 2, /there is no type clipboard_xselection_t.*X server can't label/) && has('invalid', 'x_contexts', 2).severity === 'error',
    'x_contexts: an unknown object class (skipped) and a missing type (error: requests fail)');
  const tuned = has('invalid', 'dbus_contexts', 0), bus = has('invalid', 'dbus_contexts', 1);
  check(tuned && tuned.severity === 'info' && /no service of this policy owns that name/.test(tuned.text) && bus && bus.severity === 'warning' && /s9 isn't a valid level/.test(bus.text),
    'dbus_contexts: a name of a service the policy lacks is info, an invalid level a warning', [tuned, bus]);
  const lx = has('unused', 'lxc_contexts', 0);
  check(lx && lx.severity === 'info' && /nothing in it runs container runtimes \(no container_t or svirt_lxc_net_t\)/.test(lx.text) && !has('invalid', 'lxc_contexts') && r.files.find(f => f.name === 'lxc_contexts').unused,
    'lxc_contexts: nothing in the policy runs a container runtime, so its problems are one info', lx);
  check(!r.problems.some(p => p.file === '/c/openssh_contexts'), 'openssh_contexts: sshd_t may setcon to sshd_net_t: fine');
  const d1 = has('invalid', 'default_type', 1), d2 = has('invalid', 'default_type', 2), d3 = has('invalid', 'default_type', 3);
  check(d1 && d1.severity === 'error' && /role user_r isn't authorized for staff_t.*newrole -r/.test(d1.text) && d2 && d2.severity === 'warning' && /no seusers line maps a login/.test(d2.text) && d3 && d3.severity === 'info' && /No user has role ghost_r/.test(d3.text),
    'default_type: a mapped user\'s role → error, a role only unmapped users have → warning, a role no user has → info', [d1, d2, d3]);
  const nt = r.problems.find(p => p.kind === 'notype' && p.file === '/c/default_type');
  check(nt && /no line for rolep_r, sysadm_r/.test(nt.text) && nt.severity === 'info', 'default_type: users\' roles without a line (info)', nt);
  check(has('notype', 'securetty_types', 1, /no type nosuch_tty_t/) && has('notype', 'securetty_types', 1).severity === 'info', 'securetty_types: a missing type is info (the line never matches)');
  check(has('invalid', 'failsafe_context', 0, /s7 isn't a valid range/), 'failsafe_context: an invalid level');
  check(r.files.find(f => f.name === 'virtual_domain_context').exists === false && r.files.find(f => f.name === 'x_contexts').problems === 2, 'files: absent ones listed as such, problem counts');
  check(asked.filter(i => i.kind === 'valid').length === new Set(asked.filter(i => i.kind === 'valid').map(i => i.ctx)).size, 'each context asked about once');

  const r2 = await C.analyze({ files: [file('openssh_contexts', 'privsep_preauth=sysadm_t\n'), file('openrc_contexts', 'run_init=nosuch_t\n')], seusers: SEUSERS, fc: {} }, ask);
  const ssh = r2.problems.find(p => p.ctxFile === 'openssh_contexts');
  check(ssh && ssh.kind === 'invalid' && /role system_r isn't authorized for sysadm_t/.test(ssh.text) && ssh.severity === 'warning', 'openssh_contexts: system_r must be able to run the type', r2.problems);
  const r3 = await C.analyze({ files: [file('openssh_contexts', 'privsep_preauth=staff_t\n')], seusers: SEUSERS, fc: {} }, ask);
  check(r3.problems.length === 1 && /role system_r isn't authorized/.test(r3.problems[0].text), 'openssh_contexts: role checked before setcon');
  ROLES.system_r.push('staff_t');
  const r4 = await C.analyze({ files: [file('openssh_contexts', 'privsep_preauth=staff_t\n')], seusers: SEUSERS, fc: {} }, ask);
  ROLES.system_r.pop();
  check(r4.problems.length === 1 && r4.problems[0].kind === 'nodyntrans' && /allow sshd_t staff_t:process dyntransition/.test(r4.problems[0].text), 'openssh_contexts: sshd_t needs dyntransition to it', r4.problems);
  const orc = r2.problems.find(p => p.ctxFile === 'openrc_contexts');
  check(orc && orc.kind === 'notype' && orc.severity === 'info', 'openrc_contexts: Gentoo only, info');

  /* ---------- file contexts ---------- */
  const fcText = [
    '/etc(/.*)?\tsystem_u:object_r:etc_t:s0',
    '/etc/old\t--\tsystem_u:object_r:old_etc_t:s0',
    '/opt/x\t--\tsystem_u:object_r:nosuch_t:s0',
    '/opt/y\t--\tsystem_u:object_r:nosuch_t:s0',
    '/bin(/.*)?\tsystem_u:object_r:bin_t:s0',
    '/bin(/.*)?\tsystem_u:object_r:etc_t:s0',
    '/sbin\t-d\tsystem_u:object_r:bin_t:s0',
    '/sbin\t-d\tsystem_u:object_r:bin_t:s0',
    '/sbin\t--\tsystem_u:object_r:bin_t:s0',
    '/srv/odd\tsystem_u:object_r:domainfile_t:s0',
    '/dev/null\t<<none>>',
    'HOME_DIR\t-d\tsystem_u:object_r:user_home_dir_t:s0',
    'HOME_DIR/.+\tsystem_u:object_r:user_home_t:s0',
    'HOME_ROOT/lost\\+found\tsystem_u:object_r:etc_t:s0',
    '/run/user/%{USERID}/x\tsystem_u:object_r:user_home_t:s0',
  ].join('\n');
  const main = filelabel.parseSpecs(fcText, '/w/base.fc', 'base');
  const sourceOf = (s) => (s.spec === '/opt/x' ? { file: '/src/opt.fc', l: 4 } : null);
  const local = filelabel.parseSpecs('/data(/.*)?\tsystem_u:object_r:gone_t:s0\n', '/etc/selinux/x/contexts/files/file_contexts.local');
  asked.length = 0;
  // A ROLE line (genhomedircon puts the user's prefix there) only as a template: make validate would reject it as written.
  const roleLine = filelabel.parseSpecs('HOME_DIR/\\.ROLE\tsystem_u:object_r:ROLE_home_t:s0\n', '/w/tpl.fc', 'tpl');
  const SEUSERS2 = { path: '/c/seusers', text: 'root:staff_u:s0\nbob:rolep_u:s0\ncarol:lonely_u:s0\n__default__:user_u:s0\n' };
  const f = await C.analyze({ files: [], seusers: SEUSERS2, sourceOf, usersExtra: 'user staff_u prefix staff;\nuser root prefix sysadm;\nuser rolep_u prefix rolep_r;\nuser lonely_u prefix lonely;\n',
    fc: { main, templates: [...main.filter(s => C.templateKind(s)), ...roleLine], local, localLabel: 'file_contexts.local of this host\'s x policy', build: true } }, ask);
  const P = (kind) => f.problems.filter(p => p.kind === kind);
  const inv = P('fc-main');
  check(inv.length === 2 && inv[0].file === '/src/opt.fc' && inv[0].l === 4 && inv[1].file === '/w/base.fc' && inv[1].l === 3 && /no type nosuch_t.*make validate.*semodule would refuse/.test(inv[0].text) && inv.every(p => p.severity === 'error'),
    'file_contexts: invalid contexts are errors on their source .fc line (else the compiled line); aliases and <<none>> are fine', inv);
  const dup = P('fc-duplicate');
  check(dup.length === 2 && dup.some(p => p.l === 5 && /another line \(system_u:object_r:bin_t:s0\).*Multiple different specifications/.test(p.text) && p.related[0].l === 4)
    && dup.some(p => p.l === 7 && /the same line.*Multiple same specifications/.test(p.text)) && !dup.some(p => p.l === 8),
    'file_contexts: two lines for one spec and file kind (different or the same context) are errors; another file kind is not', dup);
  const loc = P('fc-local');
  check(loc.length === 1 && loc[0].file === '/etc/selinux/x/contexts/files/file_contexts.local' && /every semodule and semanage change fails/.test(loc[0].text) && loc[0].severity === 'error', 'file_contexts.local: a stale line fails every commit', loc);
  const as = P('fc-associate');
  check(as.length === 1 && as[0].type === 'domainfile_t' && as[0].l === 9 && /restorecon can't give \/srv\/odd that label/.test(as[0].text) && as[0].severity === 'warning', 'a type that may not be on a filesystem: restorecon can\'t apply it', as);
  check(asked.find(i => i.kind === 'associate').types.includes('staff_home_t') && !asked.find(i => i.kind === 'associate').types.includes('ROLE_home_t'), 'associate asked for every file type, home-directory lines as written for users');
  // genhomedircon per user.
  const homes = Object.fromEntries(f.homes.map(h => [h.user, h]));
  check(homes.user_u && homes.user_u.fallback && homes.user_u.prefix === 'user' && homes.user_u.logins.join() === '__default__' && homes.staff_u.prefix === 'staff' && homes.staff_u.logins.join() === 'root' && homes.rolep_u.role === 'rolep_r',
    'genhomedircon users: __default__ is the fallback, each other line its user; prefixes from users_extra ("user" without one); a prefix that is a role becomes the files\' role', f.homes);
  const hd = P('homedir');
  const rolep = hd.find(p => p.user === 'rolep_u'), lonely = hd.find(p => p.user === 'lonely_u');
  check(hd.length === 2 && homes.staff_u.dropped === 0 && homes.user_u.dropped === 0 && homes.staff_u.lines === 4,
    'genhomedircon: staff_u (ROLE → staff_home_t) and user_u (prefix "user" → user_home_t) keep all 4 lines', f.homes);
  check(lonely && lonely.file === '/c/seusers' && lonely.l === 2 && /leaves 1 of 4 home-directory lines out for carol \(lonely_u\)/.test(lonely.text) && /there is no type lonely_home_t/.test(lonely.text)
    && lonely.related[0].file === '/w/tpl.fc' && lonely.related[0].l === 0, 'genhomedircon: the prefix makes a ROLE line name a type the policy lacks: that line is left out, reported on the login\'s seusers line', lonely);
  check(rolep && homes.rolep_u.dropped === homes.rolep_u.lines && /role rolep_r isn't authorized/.test(rolep.text) && /prefix rolep_r is also one of its roles/.test(rolep.text) && rolep.severity === 'warning' && rolep.l === 1,
    'genhomedircon: a user whose prefix is one of its roles loses every home line (role not authorized for file types), with the fix', rolep);
  check(!f.homes.some(h => h.user === 'nosuch_u'), 'users the policy lacks are left to the login check');

  // An installed policy: the homedirs file genhomedircon wrote; no simulation.
  const inst = await C.analyze({ files: [], seusers: SEUSERS, fc: { main: main.slice(0, 2), homedirs: filelabel.parseSpecs('/home/[^/]+/x\tuser_u:object_r:gone_t:s0\n', '/e/file_contexts.homedirs') } }, ask);
  const ih = inst.problems.find(p => p.kind === 'fc-homedirs');
  check(ih && ih.severity === 'warning' && /restorecon can't apply it/.test(ih.text) && !inst.homes.length && !inst.problems.some(p => p.kind === 'fc-main'), 'installed: file_contexts.homedirs checked as written', inst.problems);

  /* ---------- webview ---------- */
  const fs = require('fs');
  const path = require('path');
  const vm = require('vm');
  class El {
    constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this._text = ''; this.nodeType = 1; }
    set textContent(v) { this.children = []; this._text = String(v); }
    get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
    set className(v) { this.attrs.class = v; } get className() { return this.attrs.class || ''; }
    append(...cs) { for (let c of cs) { if (typeof c === 'string') c = { nodeType: 3, textContent: c }; this.children.push(c); } }
    setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'value') this.value = String(v); }
    addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
    fire(ev) { for (const fn of this.listeners[ev] || []) fn({ target: this }); }
    all(pred, out = []) { for (const c of this.children) { if (c.tag && pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
  }
  const byId = {};
  for (const id of ['main', 'status', 'against', 'refresh']) byId[id] = new El(id);
  const posted = [], winListeners = [];
  const wctx = {
    acquireVsCodeApi: () => ({ postMessage: (msg) => posted.push(JSON.parse(JSON.stringify(msg))) }),
    document: { getElementById: (id) => byId[id], createElement: (tag) => new El(tag), createTextNode: (s) => ({ nodeType: 3, textContent: s }) },
    window: { addEventListener: (ev, fn) => winListeners.push(fn) },
  };
  vm.createContext(wctx);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/ctxfiles.js'), 'utf8'), wctx);
  const send = (data) => winListeners.forEach(fn => fn({ data }));
  check(posted[0] && posted[0].cmd === 'load' && /Checking/.test(byId.status.textContent), 'webview: asks for the report at once');
  const policies = [{ id: 'build', label: 'Last build of tree', build: true }, { id: 'installed:targeted', label: 'Installed targeted policy', active: true }];
  const both = { ...f, files: r.files, problems: [...f.problems, ...r.problems] };
  send({ cmd: 'result', key: posted[0].key, result: { ...both, policies, policy: policies[0] } });
  const page = byId.main.textContent;
  const ne = both.problems.filter(p => p.severity === 'error').length;
  check(new RegExp(`${ne} errors`).test(page) && /Multiple different specifications/.test(page) && byId.against.children.length === 2, 'webview: the verdict, the problems, the policy picker', page.slice(0, 500));
  check(/file_contexts\.local of this host's x policy/.test(page) && /rolep_u/.test(page) && /0 of 4 written/.test(page) && /\(role rolep_r\)/.test(page), 'webview: file-context sets and each user\'s home lines');
  check(/x_contexts.*the X server/.test(page) && /nothing in the policy reads it/.test(page) && /not in this policy/.test(page), 'webview: the application files with their readers and results');
  const link = byId.main.all(e => e.tag === 'button' && e.textContent === 'opt.fc:5')[0];
  link.fire('click');
  check(posted[posted.length - 1].cmd === 'open' && posted[posted.length - 1].loc.p === '/src/opt.fc' && posted[posted.length - 1].loc.l === 4, 'webview: a line link opens the source .fc line');
  send({ cmd: 'built', ok: false });
  const k = posted[posted.length - 1];
  check(k.cmd === 'load', 'webview: a build of the shown tree checks again, also one validate failed (an invalid file context fails it)');
  send({ cmd: 'result', key: k.key, result: { ...inst, problems: [], files: [], policies, policy: policies[0] } });
  check(/Every context loads/.test(byId.main.textContent), 'webview: a clean report says so');
  byId.against.value = 'installed:targeted';
  byId.against.fire('change');
  check(posted[posted.length - 1].cmd === 'load' && posted[posted.length - 1].against === 'installed:targeted', 'webview: picking another policy checks that one');

  console.log(failures ? `\n${failures} check(s) failed` : '\nall context file checks passed');
  process.exit(failures ? 1 : 0);
})();
