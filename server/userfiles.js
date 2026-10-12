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

/** The gen_user line of a user model. */
function genUserLine(model, opts = {}) {
  const U = `${model.name}_u`;
  const roles = [`${model.name}_r`, ...(model.switchTo || [])].join(' ');
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
  const want = genUserLine(model, opts);
  if (!mine.length) {
    let at = lines.length;
    while (at > 0 && lines[at - 1].trim() === '') at--;
    const head = opts.comment ? [`# ${opts.comment}`] : [];
    lines.splice(at, 0, ...(at ? [''] : []), ...head, want);
  } else if (mine.length === 1 && mine[0].simple) {
    const u = mine[0];
    const cur = lines[u.l];
    const at = cur.indexOf('gen_user(');
    const close = cur.indexOf(')', at);
    const now = cur.slice(at, close + 1);
    const same = (a, b) => a.replace(/\s+/g, ' ') === b.replace(/\s+/g, ' ');
    if (!same(now, want)) lines[u.l] = cur.slice(0, at) + want + cur.slice(close + 1);
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

module.exports = { WAYS, WAY, parseGenUsers, genUserLine, editUsers, editKernelRoles, parseSeusers, editSeusers, contextsText };
