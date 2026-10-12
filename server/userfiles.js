'use strict';
/**
 * The user editor's files outside the role module (pure, minimal edits):
 *   policy/users          gen_user(NAME_u, prefix, roles, level, range[, categories])
 *   seusers               login:NAME_u[:range] lines (Linux login → SELinux user)
 *   NAME_u_default_contexts  where each way of logging in lands (installed as contexts/users/NAME_u)
 * Lines of other users are left as they are, except that users who get the new
 * role (model.grantUsers) have it added to their gen_user role list.
 */

/** Ways to log in: the login programs' domains (source contexts in default_contexts). */
const WAYS = [
  ['ssh', 'ssh', ['sshd_t', 'sshd_session_t'], 'Remote logins with ssh (sshd starts the session in the user’s domain).'],
  ['console', 'Console', ['local_login_t'], 'Logins on a text console (login on a virtual terminal or serial line).'],
  ['graphical', 'Graphical login', ['xdm_t'], 'Logins through the display manager (GDM and the like).'],
  ['cron', 'Cron jobs', ['crond_t'], 'Jobs in the user’s own crontab run in the user’s domain. Needs the cron role call (cron_role) too, added with it.'],
  ['rlogin', 'rlogin / telnet', ['remote_login_t'], 'Logins through rlogin or telnet (remote_login_t).'],
];
const WAY = Object.fromEntries(WAYS.map(([id, label, sources, help]) => [id, { id, label, sources, help }]));

/** gen_user lines: [{ name, prefix, roles (text), level, range, cats, l, endL, simple, c0, c1 }]. */
function parseGenUsers(text) {
  const out = [];
  const lines = String(text || '').split('\n');
  for (let l = 0; l < lines.length; l++) {
    const at = lines[l].indexOf('gen_user(');
    if (at < 0 || /^\s*#/.test(lines[l])) continue;
    // The call's text up to its closing parenthesis (nested ifdef(...) inside the roles).
    let depth = 0, endL = l, end = -1, s = lines[l].slice(at + 'gen_user'.length);
    let buf = '';
    for (let i = l; i < lines.length && end < 0; i++) {
      const part = i === l ? s : lines[i];
      for (let j = 0; j < part.length; j++) {
        const ch = part[j];
        if (ch === '(') depth++;
        else if (ch === ')') { depth--; if (depth === 0) { end = j; buf += part.slice(0, j + 1); endL = i; break; } }
      }
      if (end < 0) buf += part + '\n';
    }
    if (end < 0) continue;
    const inner = buf.slice(1, -1);
    // Split on top-level commas only.
    const args = [];
    let d = 0, cur = '';
    for (const ch of inner) {
      if (ch === '(' ) d++;
      if (ch === ')') d--;
      if (ch === ',' && d === 0) { args.push(cur); cur = ''; } else cur += ch;
    }
    args.push(cur);
    const t = args.map(a => a.trim());
    out.push({ name: t[0], prefix: t[1] || '', roles: t[2] || '', level: t[3] || '', range: t[4] || '', cats: t[5] || '', l, endL, simple: /^[\w\s]*$/.test(t[2] || '') && endL === l });
    l = endL;
  }
  return out;
}

/**
 * An existing user read back from the files (fills the model in place): its gen_user line
 * (model.userRoles, all roles as written; level, range, categories, prefix; genUser = { simple }),
 * its logins from seusers, the other users that have its role (grantUsers), and its ways in
 * from its own contexts file, or from default_contexts when it has none (waysFrom).
 */
function readUser(model, texts) {
  const U = `${model.name}_u`, R = `${model.name}_r`, D = `${model.name}_t`;
  const users = parseGenUsers(texts.users || '');
  const mine = users.filter(u => u.name === U);
  if (mine.length) {
    const u = mine[0];
    model.genUser = { exists: true, simple: mine.length === 1 && u.simple, count: mine.length };
    model.userRoles = u.simple ? u.roles.split(/\s+/).filter(Boolean) : null;
    Object.assign(model, { prefix: u.prefix, level: u.level, range: u.range, cats: u.cats });
  } else model.genUser = { exists: false };
  const roleRe = new RegExp(`(^|\\s)${R}(\\s|$)`);
  model.grantUsers = [...new Set(users.filter(u => u.name !== U && roleRe.test(u.roles)).map(u => u.name))];
  model.logins = parseSeusers(texts.seusers || '').filter(x => x.user === U).map(x => ({ login: x.login, range: x.range }));
  // Ways in: a source in its own file counts; one its file doesn't mention falls back to default_contexts
  // (libselinux reads the user's file first), where it counts when it offers NAME_r:NAME_t.
  const own = texts.contexts != null;
  const split = (t) => String(t || '').split('\n').map(l => l.replace(/#.*$/, '').trim().split(/\s+/).filter(Boolean)).filter(p => p.length >= 2);
  const ownLines = own ? split(texts.contexts) : [], defLines = split(texts.defaults);
  const isSrc = (p, s) => p[0].startsWith(`system_r:${s}:`) || p[0] === `system_r:${s}`;
  model.ways = WAYS.filter(([, , sources]) => sources.some(s => {
    if (ownLines.some(p => isSrc(p, s))) return true;
    return defLines.some(p => isSrc(p, s) && p.slice(1).some(c => c.startsWith(`${R}:${D}`)));
  })).map(w => w[0]);
  // Ways only default_contexts gives can't be taken away by its own file.
  model.waysDefault = WAYS.filter(([, , sources]) => sources.some(s => !ownLines.some(p => isSrc(p, s)) && defLines.some(p => isSrc(p, s) && p.slice(1).some(c => c.startsWith(`${R}:${D}`))))).map(w => w[0]);
  model.waysFrom = own ? 'own' : 'default';
  return model;
}

/** The gen_user line of a user model. */
function genUserLine(model, opts = {}) {
  const U = `${model.name}_u`;
  const roles = (model.userRoles || [`${model.name}_r`, ...(model.switchTo || [])]).join(' ');
  const prefix = model.prefix || opts.prefix || model.name;
  const level = (model.level || 's0').trim();
  const range = (model.range || level).trim();
  const cats = (model.cats || '').trim();
  return `gen_user(${U}, ${prefix}, ${roles}, ${level}, ${range}${cats ? `, ${cats}` : ''})`;
}

/**
 * The users file with the model's user: its line added (new user) or rewritten
 * (roles/level/range changed, simple lines only), and role R added to the
 * lines of the users in model.grantUsers (removed from those no longer in it,
 * opts.prevGrant).
 */
function editUsers(text, model, opts = {}) {
  const lines = String(text || '').split('\n');
  const users = parseGenUsers(text);
  const U = `${model.name}_u`, R = `${model.name}_r`;
  const mine = users.filter(u => u.name === U);
  // An existing user keeps the roles its line has; only switches added or removed in the form change them.
  if (opts.prev && model.userRoles) {
    const was = new Set(opts.prev.switchTo || []), now = new Set(model.switchTo || []);
    const roles = model.userRoles.filter(r => !(was.has(r) && !now.has(r)));
    for (const r of now) if (!was.has(r) && !roles.includes(r)) roles.push(r);
    model = { ...model, userRoles: roles };
  }
  const want = genUserLine(model, opts);
  if (!mine.length && opts.prev) {
    // An existing role without a user of its own (webadm_r): only other users' lines change.
  } else if (!mine.length) {
    let at = lines.length;
    while (at > 0 && lines[at - 1].trim() === '') at--;
    const head = opts.comment ? [`# ${opts.comment}`] : [];
    lines.splice(at, 0, ...(at ? [''] : []), ...head, want);
  } else if (mine.length === 1 && mine[0].simple) {
    // Rewritten only when one of its fields changed (so a no-op keeps its spacing).
    const u = mine[0];
    const cur = lines[u.l];
    const at = cur.indexOf('gen_user(');
    const close = cur.indexOf(')', at);
    const w = parseGenUsers(want)[0];
    const norm = (x) => [x.prefix, x.roles.split(/\s+/).filter(Boolean).join(' '), x.level, x.range.replace(/\s+/g, ' '), x.cats].join('|');
    if (norm(w) !== norm(u)) lines[u.l] = cur.slice(0, at) + want + cur.slice(close + 1);
  }
  // Other users that get (or no longer get) the role.
  const grant = new Set(model.grantUsers || []);
  const prev = new Set(opts.prevGrant || []);
  for (const u of parseGenUsers(lines.join('\n'))) {
    if (u.name === U) continue;
    const has = new RegExp(`(^|\\s)${R}(\\s|$)`).test(u.roles);
    if (grant.has(u.name) && !has) {
      const ln = lines[u.l];
      const m = /gen_user\(([^,]*,[^,]*,)/.exec(ln);
      if (!m || u.endL !== u.l) continue;
      const start = ln.indexOf(m[0]) + m[0].length;
      // Before an ifdef(...) in the roles, else at the end of the role list.
      const rest = ln.slice(start);
      const comma = (() => { let d = 0; for (let i = 0; i < rest.length; i++) { if (rest[i] === '(') d++; else if (rest[i] === ')') d--; else if (rest[i] === ',' && d === 0) return i; } return -1; })();
      if (comma < 0) continue;
      const rolesText = rest.slice(0, comma);
      const ifd = rolesText.indexOf('ifdef(');
      const ins = ifd >= 0 ? start + ifd : start + rolesText.replace(/\s+$/, '').length;
      lines[u.l] = ifd >= 0 ? `${ln.slice(0, ins)}${R} ${ln.slice(ins)}` : `${ln.slice(0, ins)} ${R}${ln.slice(ins)}`;
    } else if (!grant.has(u.name) && prev.has(u.name) && has && u.endL === u.l) {
      lines[u.l] = lines[u.l].replace(new RegExp(`\\s${R}(?=[\\s,])`), '');
    }
  }
  return lines.join('\n');
}

/**
 * kernel.te with `role R;` among the roles it declares: the users file is compiled into
 * the base module, so every role a gen_user line names must be declared there too (as
 * refpolicy does for staff_r, sysadm_r, …; the role's own module declares it again).
 * Added after the last top-level role declaration; unchanged when already there.
 */
function editKernelRoles(text, R) {
  const lines = String(text || '').split('\n');
  if (lines.some(l => new RegExp(`^\\s*role\\s+${R}\\s*;`).test(l))) return text;
  let at = -1;
  lines.forEach((l, i) => { if (/^role\s+\w+\s*;/.test(l)) at = i; });
  if (at < 0) return null;
  lines.splice(at + 1, 0, `role ${R};`);
  return lines.join('\n');
}

/** seusers lines: { login, user, range, l }. */
function parseSeusers(text) {
  const out = [];
  String(text || '').split('\n').forEach((line, l) => {
    const m = /^\s*([^#:\s]+):([^:\s]+)(?::(\S+))?\s*$/.exec(line);
    if (m) out.push({ login: m[1], user: m[2], range: m[3] || '', l });
  });
  return out;
}

/**
 * seusers with the model's logins: lines for NAME_u that are no longer wanted
 * go, changed ranges are rewritten, new logins are added before __default__.
 */
function editSeusers(text, model) {
  const U = `${model.name}_u`;
  const lines = String(text || '').split('\n');
  const have = parseSeusers(text);
  const want = (model.logins || []).filter(x => (x.login || '').trim()).map(x => ({ login: x.login.trim(), range: (x.range || '').trim() }));
  const line = (w) => `${w.login}:${U}${w.range ? `:${w.range}` : ''}`;
  const del = new Set();
  for (const h of have.filter(x => x.user === U)) {
    const w = want.find(x => x.login === h.login);
    if (!w) del.add(h.l);
    else if (w.range !== h.range) lines[h.l] = line(w);
  }
  const add = want.filter(w => !have.some(h => h.user === U && h.login === w.login));
  const def = have.find(h => h.login === '__default__');
  let out = lines.filter((_, l) => !del.has(l));
  if (add.length) {
    const at = def ? out.indexOf(lines[def.l]) : (() => { let a = out.length; while (a > 0 && out[a - 1].trim() === '') a--; return a; })();
    out.splice(at, 0, ...add.map(line));
  }
  return out.join('\n');
}

/**
 * The user's own default contexts (installed as contexts/users/NAME_u): for each
 * way in, the session's context; after sudo / su (when the user has those role
 * templates), the user's own context first, then the roles it may switch to.
 * typeExists(t) keeps sources the policy has.
 */
function contextsText(model, opts = {}) {
  const R = `${model.name}_r`, D = `${model.name}_t`;
  const has = opts.typeExists || (() => true);
  const level = opts.level || 's0';
  const ctx = (r, t) => `${r}:${t}:${level}`;
  const others = (model.switchTo || []).map(r => ctx(r, r.replace(/_r$/, '_t')));
  const out = [];
  for (const id of model.ways || []) {
    const w = WAY[id];
    if (!w) continue;
    for (const src of w.sources) if (has(src)) out.push(`system_r:${src}:${level}\t\t${ctx(R, D)}`);
  }
  for (const [call, dom] of [['sudo_role_template', 'sudo'], ['su_role_template', 'su']]) {
    if ((model.roleCalls || []).includes(call)) out.push(`${R}:${model.name}_${dom}_t:${level}\t\t${[ctx(R, D), ...others].join(' ')}`);
  }
  return out.length ? out.join('\n') + '\n' : '';
}

/**
 * An existing user's own contexts file after ways in or sudo/su were ticked or unticked
 * (prev = the model as read back): lines of ways turned off go, ways turned on get a line
 * landing in NAME_r:NAME_t, other lines stay. text null = it has no file yet (created only
 * when something is added). Returns the new text, or null for "no file".
 */
function editContexts(text, model, prev, opts = {}) {
  const R = `${model.name}_r`, D = `${model.name}_t`;
  const has = opts.typeExists || (() => true);
  const level = opts.level || 's0';
  const lines = text == null ? [] : String(text).split('\n');
  const src = (l) => (/^\s*(\S+)/.exec(l.replace(/#.*$/, '')) || [])[1] || '';
  const add = [], del = new Set();
  const was = new Set(prev.ways || []), now = new Set(model.ways || []);
  for (const [id, , sources] of WAYS) {
    if (now.has(id) && !was.has(id)) for (const s of sources) if (has(s) && !lines.some(l => src(l).startsWith(`system_r:${s}:`))) add.push(`system_r:${s}:${level}\t\t${R}:${D}:${level}`);
    if (was.has(id) && !now.has(id)) lines.forEach((l, i) => { if (sources.some(s => src(l).startsWith(`system_r:${s}:`))) del.add(i); });
  }
  const others = (model.switchTo || []).map(r => `${r}:${r.replace(/_r$/, '_t')}:${level}`);
  for (const [call, dom] of [['sudo_role_template', 'sudo'], ['su_role_template', 'su']]) {
    const key = `${R}:${model.name}_${dom}_t:`;
    const on = (model.roleCalls || []).includes(call), before = (prev.roleCalls || []).includes(call);
    if (on && !before && !lines.some(l => src(l).startsWith(key))) add.push(`${key}${level}\t\t${[`${R}:${D}:${level}`, ...others].join(' ')}`);
    if (!on && before) lines.forEach((l, i) => { if (src(l).startsWith(key)) del.add(i); });
  }
  if (!add.length && !del.size) return text;
  const out = lines.filter((_, i) => !del.has(i));
  if (!add.length) return out.join('\n');
  // New lines go after the last non-blank one.
  let at = out.length;
  while (at > 0 && out[at - 1].trim() === '') at--;
  out.splice(at, 0, ...add);
  const t = out.join('\n');
  return text == null || !/\n$/.test(t) ? `${t.replace(/\n*$/, '')}\n` : t;
}

/**
 * A standalone user's settings as its spec's %post creates them (packaging.specText's lines):
 * { userRoles, level, range, prefix, logins, grantUsers }; {} when the spec has none.
 */
function readSpecUser(spec, U, R) {
  const unq = (s) => (s || '').replace(/^'|'$/g, '').replace(/'\\''/g, "'");
  const out = {};
  const um = new RegExp(`^semanage user -a -R '([^']*)' -L '([^']*)' -r '([^']*)' -P '([^']*)' ${U}\\b`, 'm').exec(spec);
  if (um) Object.assign(out, { userRoles: um[1].split(/\s+/).filter(Boolean), level: um[2], range: um[3], prefix: um[4] });
  const logins = [];
  for (const m of spec.matchAll(new RegExp(`^semanage login -a -s ${U}(?: -r ('[^']*'))? ('(?:[^']|'\\\\'')*') 2>`, 'gm'))) logins.push({ login: unq(m[2]).replace(/%%/g, '%'), range: unq(m[1]) });
  if (um || logins.length) out.logins = logins;
  const grant = [...spec.matchAll(new RegExp(`case " \\$r " in \\*" ${R} "\\*\\) ;; \\*\\) \\[ -n "\\$r" \\] && semanage user -m -R "\\$r ${R}" (\\w+)`, 'g'))].map(m => m[1]);
  if (um) out.grantUsers = grant;
  return out;
}

/**
 * default_contexts after ways in were turned off: for a source the user's own file no longer
 * lists, libselinux falls back to default_contexts, so NAME_r:NAME_t comes off that source's
 * line there (the line goes when nothing is left). Other roles' contexts stay.
 */
function editDefaults(text, model, prev) {
  if (text == null) return text;
  const R = `${model.name}_r`, D = `${model.name}_t`;
  const off = (prev.ways || []).filter(w => !(model.ways || []).includes(w)).flatMap(w => (WAY[w] ? WAY[w].sources : []));
  if (!off.length) return text;
  const lines = String(text).split('\n');
  const out = [];
  let changed = false;
  for (const l of lines) {
    const code = l.replace(/#.*$/, '');
    const parts = code.trim().split(/\s+/).filter(Boolean);
    if (parts.length < 2 || !off.some(s => parts[0].startsWith(`system_r:${s}:`)) || !parts.slice(1).some(c => c.startsWith(`${R}:${D}:`) || c === `${R}:${D}`)) { out.push(l); continue; }
    changed = true;
    const keep = parts.slice(1).filter(c => !(c.startsWith(`${R}:${D}:`) || c === `${R}:${D}`));
    if (!keep.length) continue;
    // Remove the token in place, keeping the line's spacing.
    out.push(l.replace(new RegExp(`[ \\t]+${R}:${D}(:\\S*)?(?=\\s|$)`), ''));
  }
  return changed ? out.join('\n') : text;
}

/**
 * The user editor's additions to a tree context, from a PolicyIndex: params(n) (doc parameter
 * names), roleIfaces (role → { change, changeTo, module } from the *_role_change(_to) interfaces'
 * required role), roleExists, roleCalls ([{ n, s, m, g }]: sudo/su/ssh role templates, *_role
 * application roles, *_admin and <rolecap/> interfaces whose arguments the editor can fill).
 */
function userTreeCtx(idx, base) {
  const service = require('./service');
  const params = (n) => {
    const d = (idx.defs.get(n) || [])[0];
    return d && d.doc && d.doc.params && d.doc.params.length ? d.doc.params.map(p => p.name || '') : null;
  };
  const moduleOf = (d) => { const f = idx.files.get(d.path); return f ? f.module : ''; };
  const roleIfaces = {};
  for (const [n, list] of idx.defs) {
    const m = /^\w+_role_change(_to)?$/.exec(n);
    const d = list[0];
    if (!m || d.generated || !/\.if$/.test(d.path)) continue;
    const roles = (d.requires || []).filter(r => r.kind === 'role' && /^\w+_r$/.test(r.name)).map(r => r.name);
    if (roles.length !== 1) continue;
    const e = roleIfaces[roles[0]] || (roleIfaces[roles[0]] = { module: moduleOf(d) });
    e[m[1] ? 'changeTo' : 'change'] = n;
  }
  const ctx = { ...base, params, roleIfaces, roleExists: (r) => (idx.decls.get(r) || []).some(d => d.kind === 'role') };
  const probe = { user: { kind: 'unpriv' }, name: 'zzprobe' };
  const calls = [];
  for (const [n, list] of idx.defs) {
    const d = list[0];
    if (d.generated || !/\.if$/.test(d.path) || /_role_change(_to)?$/.test(n)) continue;
    const role = /_role(_template)?$/.test(n), admin = /_admin$/.test(n);
    if (!role && !admin && !(d.doc && d.doc.rolecap)) continue;
    if (!service.roleCallArgs(n, probe, ctx)) continue;
    if (!role && !(params(n) || []).some(p => /role/i.test(p) && !/prefix/i.test(p))) continue; // admin interfaces without a role argument aren't role calls
    const g = /^(sudo|su|ssh)_role_template$/.test(n) ? 'login' : admin ? 'admin' : role ? 'apps' : 'run';
    calls.push({ n, s: (d.doc && d.doc.summary || '').replace(/\s+/g, ' ').trim(), m: moduleOf(d), g });
  }
  ctx.roleCalls = calls.sort((a, b) => a.n.localeCompare(b.n));
  return ctx;
}

module.exports = { WAYS, WAY, userTreeCtx, parseGenUsers, readUser, readSpecUser, genUserLine, editUsers, editKernelRoles, parseSeusers, editSeusers, contextsText, editContexts, editDefaults };
