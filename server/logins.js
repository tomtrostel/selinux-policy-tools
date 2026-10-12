'use strict';
/**
 * Logins view (pure): who logs in as which SELinux user, where each way of
 * logging in lands, and what they can reach from there.
 *
 * Inputs are the login configuration a policy installs: seusers (Linux login
 * or %group → SELinux user [range]), default_contexts and the per-user
 * contexts/users/<user> files (for a source context: the contexts a session
 * may start in, in order of preference). What the sessions can reach comes
 * from policy_query.py's `reach` op; this module only reads and words it.
 */

/** Login programs' domains (the source context of a default_contexts line) → how a user gets in. */
const ENTRY_LABELS = {
  sshd_t: 'ssh',
  sshd_session_t: 'ssh',
  local_login_t: 'console login',
  remote_login_t: 'rlogin / telnet',
  xdm_t: 'graphical login',
  crond_t: 'cron jobs (their crontab)',
  init_t: 'systemd user session',
  sulogin_t: 'single-user mode',
  cockpit_session_t: 'Cockpit',
};
const ENTRY_ORDER = ['sshd_t', 'local_login_t', 'xdm_t', 'cockpit_session_t', 'crond_t', 'init_t', 'remote_login_t', 'sulogin_t'];

/**
 * Abilities worth flagging when a login can reach a domain that has them.
 * `attr`: a domain with this attribute; else an allow rule on type t.
 * Items whose type or attribute the policy lacks are skipped.
 */
const ABILITIES = [
  { id: 'unconfined', label: 'runs unconfined', attr: 'unconfined_domain_type', severity: 'high' },
  { id: 'loadPolicy', label: 'can load a new SELinux policy', t: 'security_t', classes: ['security'], perms: ['load_policy'], severity: 'high' },
  { id: 'setenforce', label: 'can switch SELinux to permissive', t: 'security_t', classes: ['security'], perms: ['setenforce'], severity: 'high' },
  { id: 'shadow', label: 'can read password hashes (/etc/shadow)', t: 'shadow_t', classes: ['file'], perms: ['read'], severity: 'medium' },
  { id: 'disk', label: 'can write raw disks', t: 'fixed_disk_device_t', classes: ['blk_file'], perms: ['write'], severity: 'medium' },
  { id: 'setbool', label: 'can change booleans', t: 'security_t', classes: ['security'], perms: ['setbool'], severity: 'low' },
];

const strip = (line) => line.replace(/#.*$/, '').trim();

/** seusers: [{ login, group, user, range, l }] in file order. */
function parseSeusers(text) {
  const out = [];
  String(text || '').split('\n').forEach((line, l) => {
    const m = /^([^:\s]+):([^:\s]+)(?::(.+))?$/.exec(strip(line));
    if (!m) return;
    const group = m[1].startsWith('%');
    out.push({ login: group ? m[1].slice(1) : m[1], group, user: m[2], range: m[3] ? m[3].trim() : null, l });
  });
  return out;
}

/** "role:type[:level]" → { role, type, level } (null when not one). */
function parseRoleType(s) {
  const m = /^([A-Za-z_]\w*):([A-Za-z_]\w*)(?::(.+))?$/.exec(s);
  return m ? { role: m[1], type: m[2], level: m[3] || null } : null;
}

/** default_contexts / contexts/users/<u>: [{ from: {role, type}, to: [{role, type, level}], l }]. */
function parseContexts(text) {
  const out = [];
  String(text || '').split('\n').forEach((line, l) => {
    const parts = strip(line).split(/\s+/).filter(Boolean);
    if (parts.length < 2) return;
    const from = parseRoleType(parts[0]);
    const to = parts.slice(1).map(parseRoleType).filter(Boolean);
    if (from && to.length) out.push({ from, to, l });
  });
  return out;
}

/**
 * Where each way of logging in lands for one SELinux user: the source
 * contexts of login programs (role system_r) from the user's own file, else
 * default_contexts (libselinux reads the user's file first). Each entry:
 * { source, label, contexts: [{role, type}] (allowed, in order), file, l };
 * contexts[0] is the session's default. `roleTypes(role)` = the role's types.
 */
function entries(userRoles, roleTypes, userFile, defaultFile) {
  const out = [];
  const sources = new Map();
  for (const [file, list] of [[userFile, userFile && userFile.list], [defaultFile, defaultFile && defaultFile.list]]) {
    for (const x of list || []) {
      if (x.from.role !== 'system_r') continue;
      if (!sources.has(x.from.type)) sources.set(x.from.type, { ...x, file: file.path });
    }
  }
  for (const [src, x] of sources) {
    const ok = x.to.filter(c => userRoles.includes(c.role) && roleTypes(c.role).has(c.type));
    out.push({ source: src, label: ENTRY_LABELS[src] || `started by ${src}`, contexts: ok.map(({ role, type }) => ({ role, type })), file: x.file, l: x.l });
  }
  const rank = (s) => { const i = ENTRY_ORDER.indexOf(s); return i < 0 ? ENTRY_ORDER.length : i; };
  return out.sort((a, b) => rank(a.source) - rank(b.source) || a.source.localeCompare(b.source));
}

/** /etc/passwd: [{ name, uid, home, shell }]. */
function parsePasswd(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const f = line.split(':');
    if (f.length < 7 || !f[0] || line.startsWith('#')) continue;
    out.push({ name: f[0], uid: +f[2], gid: +f[3], home: f[5], shell: f[6].trim() });
  }
  return out;
}

/** /etc/group: Map user → [groups] (supplementary members and primary groups by gid). */
function parseGroups(text, passwd) {
  const byGid = new Map();
  const out = new Map();
  const add = (u, g) => { if (!out.has(u)) out.set(u, []); if (!out.get(u).includes(g)) out.get(u).push(g); };
  for (const line of String(text || '').split('\n')) {
    const f = line.split(':');
    if (f.length < 4 || !f[0]) continue;
    byGid.set(f[2], f[0]);
    for (const u of f[3].split(',').map(s => s.trim()).filter(Boolean)) add(u, f[0]);
  }
  for (const p of passwd || []) if (p.gid != null && byGid.has(String(p.gid))) add(p.name, byGid.get(String(p.gid)));
  return out;
}

/** Shells that can't run commands for whoever logs in. */
const NO_LOGIN = /(^|\/)(nologin|false)$/;

/**
 * The seusers line that applies to a Linux login (as libselinux's
 * getseuserbyname: the login's own line, else the first %group line for a
 * group it is in, else __default__).
 */
function mappingFor(login, seusers, groupsOf) {
  const own = seusers.find(x => !x.group && x.login === login);
  if (own) return { ...own, how: 'own' };
  const gs = (groupsOf && groupsOf.get(login)) || [];
  const g = seusers.find(x => x.group && gs.includes(x.login));
  if (g) return { ...g, how: 'group' };
  const d = seusers.find(x => !x.group && x.login === '__default__');
  return d ? { ...d, how: 'default' } : null;
}

/**
 * Accounts a service runs as (system UIDs, below UID_MIN): their processes
 * run in the service's domain with system_u, whatever seusers says. seusers
 * matters only when the account logs in (ssh, su -, its crontab), so we say
 * which line would apply and whether it has a shell to log in with.
 */
function serviceAccounts(passwd, seusers, groupsOf, uidMin = 1000) {
  return passwd.filter(p => p.uid < uidMin && p.uid !== 0 || p.uid === 65534).map(p => {
    const m = mappingFor(p.name, seusers, groupsOf);
    const shell = p.shell || '';
    return { name: p.name, uid: p.uid, shell, canLogin: !!shell && !NO_LOGIN.test(shell) && !/(^|\/)(sync|shutdown|halt)$/.test(shell),
      special: /(^|\/)(sync|shutdown|halt)$/.test(shell), mapping: m ? { user: m.user, range: m.range, how: m.how, l: m.l } : null };
  });
}

/** Path from a start state to `key` in reach steps: [{ from, to, role, roleChange, entrypoints, conditional, dynamic }]. */
function pathTo(steps, key) {
  const out = [];
  let k = key;
  for (let i = 0; i < 40 && k && steps[k] && !steps[k].start; i++) {
    const s = steps[k];
    const f = steps[s.from];
    out.push({ from: f ? f.type : s.from, fromRole: f ? f.role : null, to: s.type, role: s.role, roleChange: s.roleChange || null,
      entrypoints: s.entrypoints || [], conditional: s.conditional || [], dynamic: !!s.dynamic });
    k = s.from;
  }
  return out.reverse();
}

/** The reached domain closest to the start among `domains` (keys of reach.reached). */
function nearest(reach, domains) {
  let best = null;
  for (const d of domains) {
    const k = reach.reached[d];
    const s = k && reach.steps[k];
    if (s && (!best || s.depth < best.depth || (s.depth === best.depth && d < best.d))) best = { d, depth: s.depth, key: k };
  }
  return best;
}

/** Words one path step: "staff_t → newrole_t (runs newrole_exec_t)". */
function stepText(s) {
  const how = s.dynamic ? 'changes its own domain' : `runs ${s.entrypoints.slice(0, 2).join(' or ')}`;
  const role = s.roleChange ? `, role → ${s.role}${s.roleChange === 'setexec' ? ' (asked for, e.g. newrole/sudo -r)' : ' (role_transition)'}` : '';
  const cond = s.conditional.length ? `, only when ${s.conditional.map(c => c.replace(/:true$/, '').replace(/:false$/, ' is off')).join(' / ')}` : '';
  return `${s.from} → ${s.to} (${how}${role}${cond})`;
}

/**
 * Warnings about a login mapping itself (not about what it reaches): a
 * mapping to an unconfined user, __default__ on a user with an admin role.
 */
function mappingNotes(m, user, adminRoles) {
  const out = [];
  if (!user) out.push({ severity: 'high', text: `${m.user} is not a user in this policy: logins mapped to it fail.` });
  if (m.user === 'unconfined_u') out.push({ severity: 'medium', text: 'Mapped to unconfined_u: SELinux does not confine these sessions.' });
  if (m.login === '__default__' && user && user.roles.some(r => adminRoles.includes(r))) out.push({ severity: 'high', text: `Every login without its own line gets ${m.user}, which has an admin role (${user.roles.filter(r => adminRoles.includes(r)).join(', ')}).` });
  return out;
}

module.exports = { ENTRY_LABELS, ABILITIES, parseSeusers, parseContexts, parseRoleType, entries, parsePasswd, parseGroups, mappingFor,
  serviceAccounts, pathTo, nearest, stepText, mappingNotes, NO_LOGIN };
