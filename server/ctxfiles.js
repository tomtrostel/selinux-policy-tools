'use strict';
/**
 * Context files (pure): whether the contexts a policy's configuration files
 * name are ones the policy accepts, and what breaks when one isn't, before a
 * host finds out. The login files (seusers, default_contexts, users/*) are
 * server/loginctx.js; this is everything else:
 *
 *  - file_contexts: semodule runs `setfiles -c` on it and refuses the whole
 *    install on an invalid context or on two lines for the same path and file
 *    kind (refpolicy's `make validate` does the same);
 *  - file_contexts.local: libsemanage validates it on every commit, so one
 *    stale line (a type a new policy dropped) makes every semodule and
 *    semanage change fail;
 *  - file_contexts.homedirs, as genhomedircon writes it: the home-directory
 *    lines of the modules (HOME_DIR, HOME_ROOT, %{USERNAME}, %{USERID}, USER)
 *    once per seusers user, the context's user set to it, its level to the
 *    user's default level and, when the user's prefix is one of its roles, its
 *    role to the prefix. A line whose context isn't valid then is silently
 *    left out (libsemanage genhomedircon.c check_line);
 *  - any file_contexts type no rule lets be associated with a filesystem:
 *    restorecon can't give a file that type (setxattr is denied);
 *  - the application files in contexts/ (and files/media): each reader and
 *    what it does with an entry the policy rejects is in FILES.
 *
 * The policy questions go through ask(items) → answers by id (policy_query
 * op logincontexts: info, valid, roletype, types, associate, dyntrans,
 * resolve); this module asks and words.
 */
const logins = require('./logins');

const SEVERITY = ['error', 'warning', 'info'];

/**
 * The application context files: how each is written, which program reads it
 * (owners: its domains; when none exists, nothing in the policy reads the
 * file and its problems are one info), and what an entry the policy rejects
 * does there (sev, effect).
 */
const FILES = [
  { name: 'failsafe_context', format: 'partial', program: 'login programs', sev: 'warning',
    effect: 'a login none of whose listed contexts is valid has no failsafe to fall back to' },
  { name: 'default_type', format: 'roletype', program: 'newrole and sudo', sev: 'error',
    effect: 'newrole -r and sudo with ROLE= (no TYPE=) can\'t compute a context for that role' },
  { name: 'initrc_context', format: 'context', owners: ['initrc_t'], program: 'run_init', sev: 'error',
    effect: 'run_init can\'t start init scripts in it' },
  { name: 'userhelper_context', format: 'context', owners: ['userhelper_t'], program: 'userhelper (consolehelper)', sev: 'error',
    effect: 'userhelper can\'t run programs in it' },
  { name: 'removable_context', format: 'context', program: 'removable media labeling', sev: 'warning',
    effect: 'removable media can\'t get that label' },
  { name: 'virtual_domain_context', format: 'context', owners: ['svirt_t'], program: 'libvirt', sev: 'error',
    effect: 'libvirt can\'t start confined guests' },
  { name: 'virtual_image_context', format: 'context', owners: ['svirt_t', 'svirt_image_t'], program: 'libvirt', sev: 'error',
    effect: 'libvirt can\'t label guest images' },
  { name: 'lxc_contexts', format: 'keyed', owners: ['container_t', 'svirt_lxc_net_t'], program: 'container runtimes', sev: 'error',
    effect: 'containers can\'t be started or labeled with it' },
  { name: 'x_contexts', format: 'x', owners: ['xserver_t'], program: 'the X server', sev: 'error',
    effect: 'the X server can\'t label objects with that name, so clients\' requests on them fail (BadValue)' },
  { name: 'dbus_contexts', format: 'dbus', owners: ['system_dbusd_t'], program: 'dbus-daemon', sev: 'warning',
    effect: 'dbus-daemon warns and leaves the name with the default context' },
  { name: 'sepgsql_contexts', format: 'labels', owners: ['postgresql_t'], program: 'PostgreSQL (sepgsql)', sev: 'warning',
    effect: 'sepgsql can\'t label database objects with it' },
  { name: 'systemd_contexts', format: 'keyed', owners: ['init_t'], program: 'systemd', sev: 'warning',
    effect: 'systemd can\'t label its runtime unit files with it' },
  { name: 'openssh_contexts', format: 'typekey', owners: ['sshd_t'], program: 'sshd', sev: 'warning',
    effect: 'sshd\'s pre-authentication process stays in sshd_t' },
  { name: 'snapperd_contexts', format: 'keyed', owners: ['snapperd_t'], program: 'snapperd', sev: 'warning',
    effect: 'snapperd can\'t label its snapshots with it' },
  { name: 'openrc_contexts', format: 'typekey', owners: ['run_init_t'], program: 'OpenRC (Gentoo only)', sev: 'info',
    effect: 'OpenRC\'s run_init can\'t use it' },
  { name: 'media', format: 'labels', where: 'files', program: 'removable media labeling', sev: 'warning',
    effect: 'that kind of media can\'t get the label' },
  { name: 'securetty_types', format: 'types', program: 'newrole', sev: 'info',
    effect: 'the line never matches a terminal' },
  { name: 'customizable_types', format: 'types', program: 'restorecon', sev: 'info',
    effect: 'the line has no effect' },
];
const X_CLASSES = new Set(['property', 'extension', 'client', 'event', 'selection', 'poly_property', 'poly_selection']);

/** Lines without comments: [{ l, text, c }] (c: column of the text). */
function lines(text) {
  const out = [];
  String(text || '').split('\n').forEach((raw, l) => {
    const t = raw.replace(/#.*$/, '');
    const c = t.search(/\S/);
    if (c >= 0) out.push({ l, text: t.trim(), c });
  });
  return out;
}

/** Entries of one application context file: [{ l, c, len, ctx | role+type(+level) | type, key }]. */
function parseFile(def, text) {
  const out = [];
  const at = (x, s) => { const i = x.text.indexOf(s); return { c: x.c + Math.max(i, 0), len: s.length }; };
  if (def.format === 'dbus') {
    const src = String(text || '');
    const re = /context\s*=\s*"([^"]*)"/g;
    let m;
    while ((m = re.exec(src))) {
      const before = src.slice(0, m.index);
      const l = before.split('\n').length - 1;
      const own = /own(?:_prefix)?\s*=\s*"([^"]*)"[^>]*$/.exec(src.slice(Math.max(0, src.lastIndexOf('<', m.index)), m.index + m[0].length));
      out.push({ l, c: m.index - before.lastIndexOf('\n') - 1 + m[0].indexOf(m[1]), len: m[1].length, ctx: m[1], key: own ? own[1] : null });
    }
    return out;
  }
  for (const x of lines(text)) {
    let m;
    switch (def.format) {
      case 'context': { const ctx = x.text.split(/\s+/)[0]; out.push({ l: x.l, ...at(x, ctx), ctx }); break; }
      case 'partial': case 'roletype': {
        const tok = x.text.split(/\s+/)[0];
        const [role, type, ...lv] = tok.split(':');
        out.push({ l: x.l, ...at(x, tok), role, type: type || '', level: lv.length ? lv.join(':') : null, text: tok });
        break;
      }
      case 'keyed':
        if ((m = /^([\w.-]+)\s*=\s*"?([^"\s]+)"?$/.exec(x.text))) out.push({ l: x.l, ...at(x, m[2]), key: m[1], ctx: m[2] });
        else out.push({ l: x.l, c: x.c, len: x.text.length, bad: true, text: x.text });
        break;
      case 'typekey':
        if ((m = /^([\w.-]+)\s*=\s*(\S+)$/.exec(x.text))) out.push({ l: x.l, ...at(x, m[2]), key: m[1], type: m[2] });
        else out.push({ l: x.l, c: x.c, len: x.text.length, bad: true, text: x.text });
        break;
      case 'labels': case 'x': {
        const f = x.text.split(/\s+/);
        if (f.length < 2) { out.push({ l: x.l, c: x.c, len: x.text.length, bad: true, text: x.text }); break; }
        const ctx = f[f.length - 1];
        out.push({ l: x.l, ...at(x, ctx), key: f.slice(0, -1).join(' '), cls: f[0], ctx });
        break;
      }
      case 'types': { const t = x.text.split(/\s+/)[0]; out.push({ l: x.l, ...at(x, t), type: t }); break; }
      default: break;
    }
  }
  return out;
}

/** users_extra (`user staff_u prefix staff;`) → { user: prefix }. */
function parseUsersExtra(text) {
  const out = {};
  for (const m of String(text || '').matchAll(/^\s*user\s+(\S+)\s+prefix\s+([^;\s]+)\s*;/gm)) out[m[1]] = m[2];
  return out;
}

/** Which genhomedircon template a file-context line is (or null): homedir | homeroot | username | user. */
function templateKind(s) {
  if (s.spec.startsWith('HOME_ROOT')) return 'homeroot';
  if (s.spec.startsWith('HOME_DIR')) return 'homedir';
  const line = `${s.spec} ${s.flag || ''} ${s.context}`;
  if (line.includes('%{USERNAME}') || line.includes('%{USERID}')) return 'username';
  if (line.includes('USER')) return 'user';
  return null;
}

/**
 * genhomedircon's users: the fallback (from __default__, else user_u) and the
 * SELinux user of every other seusers line (logins and %groups), each with
 * the logins it stands for and its seusers line. users: policy users (info).
 */
function homeUsers(seusers, users, extra) {
  const out = new Map();
  const add = (u, who, l, fallback) => {
    if (!out.has(u)) {
      const known = !!users[u];
      // libsemanage: a user without users_extra gets prefix "user"; an unknown one its login's name.
      const prefix = known ? (extra[u] || 'user') : who;
      const roles = known ? users[u].roles || [] : [];
      out.set(u, { user: u, known, prefix, roles, level: known ? users[u].level || null : null,
        role: prefix === 'object_r' || roles.includes(prefix) ? prefix : null, logins: [], l, fallback: !!fallback });
    }
    out.get(u).logins.push(who);
  };
  const dflt = seusers.find(m => m.login === '__default__' && !m.group);
  add(dflt ? dflt.user : 'user_u', '__default__', dflt ? dflt.l : 0, true);
  for (const m of seusers) if (m.login !== '__default__') add(m.user, m.group ? `%${m.login}` : m.login, m.l);
  return [...out.values()];
}

/**
 * cfg: { files: [{ def, path, text }] (application context files, text null when absent),
 *   fc: { main: specs, local: specs | null, homedirs: specs | null, templates: specs | null,
 *         label, localLabel, build },  (specs as filelabel.parseSpecs: spec, flag, mode, context, type, l, file)
 *   sourceOf(spec) → { file, l } | null  (a compiled line's source .fc line),
 *   seusers: { path, text }, usersExtra: text | null }
 * ask(items) → Promise<{ [id]: answer }>.
 * → { mls, files: [...], fc: {...}, homes: [...], problems, notes }
 */
async function analyze(cfg, ask) {
  const notes = [];
  const problems = [];
  const info = (await ask([{ id: 'info', kind: 'info' }])).info || {};
  if (info.error) return { error: info.error };
  const mls = !!info.mls;
  const users = info.users || {};

  // Questions, deduplicated.
  const qs = new Map();
  const q = (key, item) => { if (!qs.has(key)) qs.set(key, { id: `q${qs.size}`, ...item }); return qs.get(key).id; };
  const valid = (ctx) => q(`v:${ctx}`, { kind: 'valid', ctx });

  // ----- application context files -----
  const files = [];
  const owners = new Set();
  for (const f of cfg.files || []) for (const o of f.def.owners || []) owners.add(o);
  for (const f of cfg.files || []) {
    if (f.text == null) { files.push({ name: f.def.name, path: f.path, exists: false, program: f.def.program }); continue; }
    const entries = parseFile(f.def, f.text);
    for (const e of entries) {
      if (e.bad) continue;
      if (e.ctx) e.q = valid(e.ctx);
      else if (f.def.format === 'partial' || f.def.format === 'roletype') {
        e.q = q(`rt:${e.role}:${e.type}`, { kind: 'roletype', role: e.role, type: e.type });
        if (e.level && mls) e.lq = q(`r:${e.level}`, { kind: 'resolve', range: e.level });
      } else if (e.type) {
        e.tq = 'types';
        if (f.def.name === 'openssh_contexts') {
          e.q = q(`rt:system_r:${e.type}`, { kind: 'roletype', role: 'system_r', type: e.type });
          e.dq = q(`d:sshd_t>${e.type}`, { kind: 'dyntrans', from: 'sshd_t', to: e.type });
        }
      }
    }
    files.push({ name: f.def.name, path: f.path, exists: true, program: f.def.program, def: f.def, entries });
  }
  const typeNames = new Set([...owners]);
  for (const f of files) for (const e of f.entries || []) if (e.tq) typeNames.add(e.type);

  // ----- file contexts -----
  const fc = cfg.fc || {};
  const sets = [
    { key: 'main', specs: fc.main || [], label: fc.label || 'file_contexts' },
    { key: 'local', specs: fc.local || [], label: fc.localLabel || 'file_contexts.local' },
    { key: 'homedirs', specs: fc.homedirs || [], label: 'file_contexts.homedirs' },
  ];
  const fcTypes = new Set();
  for (const s of sets) for (const x of s.specs) {
    if (x.context === '<<none>>') continue;
    x.q = valid(x.context);
    if (x.type) fcTypes.add(x.type);
  }
  // genhomedircon: every template line per user, rewritten as it would write it.
  const seusers = logins.parseSeusers(cfg.seusers && cfg.seusers.text);
  const extra = parseUsersExtra(cfg.usersExtra);
  const homes = [];
  const templates = (fc.templates || []).map(s => ({ ...s, tk: templateKind(s) })).filter(s => s.tk && s.tk !== 'homeroot' && s.context !== '<<none>>');
  if (templates.length) {
    if (cfg.usersExtra == null) notes.push('No users_extra (the users\' prefixes): every user is taken to have prefix "user".');
    for (const h of homeUsers(seusers, users, extra)) {
      if (!h.known) continue; // the login check reports a login mapped to a user the policy lacks
      const lines = templates.map(s => {
        const ctx = String(s.context).replace(/ROLE/g, h.prefix);
        const p = ctx.split(':');
        p[0] = h.user;
        if (h.role) p[1] = h.role;
        const out = mls && h.level ? [...p.slice(0, 3), h.level].join(':') : p.join(':');
        return { s, spec: s.spec.replace(/ROLE/g, h.prefix), ctx: out, q: valid(out) };
      }).filter(Boolean);
      homes.push({ ...h, lines });
    }
  }
  for (const h of homes) for (const x of h.lines) { const t = x.ctx.split(':')[2]; if (t) fcTypes.add(t); }
  const aq = fcTypes.size ? q('assoc', { kind: 'associate', types: [...fcTypes].sort() }) : null;
  const tq = typeNames.size ? q('types', { kind: 'types', names: [...typeNames].sort() }) : null;

  const ans = qs.size ? await ask([...qs.values()]) : {};
  const A = (id) => ans[id] || {};
  const kinds = tq ? A(tq).kinds || {} : {};
  const exists = (t) => kinds[t] === 'type' || kinds[t] === 'alias';
  const reasons = (a) => (a.reasons || []).map(r => r.text).join('; ') || a.error || 'not valid';
  const loc = (x) => (cfg.sourceOf && cfg.sourceOf(x)) || (x.file ? { file: x.file, l: x.l } : {});

  // ----- application files: problems -----
  const userRoles = new Set();
  for (const [u, x] of Object.entries(users)) if (u !== 'system_u') for (const r of x.roles || []) if (r !== 'system_r' && r !== 'object_r') userRoles.add(r);
  const mappedRoles = new Set();
  for (const m of seusers) for (const r of (users[m.user] || {}).roles || []) if (r !== 'system_r' && r !== 'object_r') mappedRoles.add(r);
  for (const f of files) {
    if (!f.exists) continue;
    const def = f.def;
    const own = def.owners && def.owners.length ? def.owners.filter(exists) : null;
    const found = [];
    const add = (e, sev, kind, text) => found.push({ severity: sev, kind, file: f.path, l: e.l, c: e.c, len: e.len, ctxFile: def.name, text });
    for (const e of f.entries) {
      if (e.bad) { add(e, 'warning', 'format', `${def.name} line ${e.l + 1} isn't in the form ${def.format === 'typekey' ? 'key=TYPE' : def.format === 'keyed' ? 'key = "context"' : 'name context'}; ${def.program} skips it.`); continue; }
      if (def.format === 'x' && !X_CLASSES.has(e.cls)) add(e, 'warning', 'format', `"${e.cls}" isn't a kind of X object (${[...X_CLASSES].join(', ')}); the X server skips the line.`);
      if (e.ctx) {
        const a = A(e.q);
        const onlyType = !a.ok && (a.reasons || []).length && a.reasons.every(r => r.kind === 'type');
        // A D-Bus name of a service the policy doesn't have (no such domain): nothing owns it.
        if (!a.ok && def.format === 'dbus' && onlyType) add(e, 'info', 'invalid', `${e.ctx}${e.key ? ` (${e.key})` : ''}: ${reasons(a)}, so no service of this policy owns that name; dbus-daemon warns about the line at startup.`);
        else if (!a.ok) add(e, def.sev, 'invalid', `${e.ctx}${e.key ? ` (${e.key})` : ''} isn't a valid context in this policy: ${reasons(a)}. So ${def.effect}.`);
      } else if (def.format === 'partial' || def.format === 'roletype') {
        const a = A(e.q);
        const lv = e.lq ? A(e.lq) : {};
        // default_type: a role no user has is never asked for; one only users no login is mapped to have, maybe later.
        const rt = def.format === 'roletype';
        const sev = !rt || mappedRoles.has(e.role) ? def.sev : userRoles.has(e.role) ? 'warning' : 'info';
        const tail = sev === def.sev ? `So ${def.effect}.` : sev === 'warning' ? `So ${def.effect} (no seusers line maps a login to a user with it yet).` : `No user has role ${e.role}, so nothing asks for it.`;
        if (!a.ok) add(e, sev, 'invalid', `${e.text}: ${reasons(a)}. ${tail}`);
        else if (lv.error) add(e, def.sev, 'invalid', `${e.text}: ${lv.error}. So ${def.effect}.`);
      } else if (e.type) {
        if (!exists(e.type)) add(e, def.sev, 'notype', `There is no type ${e.type} in this policy, so ${def.effect}.`);
        else if (e.dq) {
          const rt = A(e.q), d = A(e.dq);
          if (!rt.ok) add(e, def.sev, 'invalid', `system_u:system_r:${e.type} isn't a valid context: ${reasons(rt)}. So ${def.effect}.`);
          else if (!d.ok && !d.unknown) add(e, def.sev, 'nodyntrans', `sshd changes to ${e.type} with setcon(), which this policy doesn't allow (${(d.missing || []).join(' ')}), so ${def.effect}.`);
        }
      }
    }
    if (def.name === 'default_type') {
      const listed = new Set(f.entries.map(e => e.role));
      const missing = [...userRoles].filter(r => !listed.has(r)).sort();
      if (missing.length) found.push({ severity: 'info', kind: 'notype', file: f.path, l: 0, ctxFile: def.name,
        text: `default_type has no line for ${missing.join(', ')}: newrole -r and sudo ROLE= need a type given with them for ${missing.length > 1 ? 'these roles' : 'that role'}.` });
    }
    f.count = f.entries.length;
    if (own && !own.length && found.some(x => x.severity !== 'info')) {
      // Nothing in this policy runs the program: the file is never read.
      problems.push({ severity: 'info', kind: 'unused', file: f.path, l: found[0].l, ctxFile: def.name, related: found.slice(0, 8).map(x => ({ file: x.file, l: x.l, text: x.text })),
        text: `${def.name}: ${found.length} entr${found.length > 1 ? 'ies name' : 'y names'} contexts this policy doesn't accept, but nothing in it runs ${def.program} (no ${def.owners.join(' or ')}), so nothing reads the file. ${found[0].text}` });
      f.unused = true;
    } else problems.push(...found);
    f.problems = found.length;
    delete f.def;
    f.entries = f.entries.length;
  }

  // ----- file contexts: problems -----
  const fcEffect = {
    main: fc.build ? '`make validate` (setfiles -c) rejects file_contexts, and semodule would refuse to install the policy' : 'restorecon can\'t apply it (Invalid argument)',
    local: 'libsemanage validates file_contexts.local on every commit, so every semodule and semanage change fails until the line is removed (semanage fcontext -d)',
    homedirs: 'restorecon can\'t apply it (Invalid argument)',
  };
  const fcOut = {};
  for (const s of sets) {
    const bad = s.specs.filter(x => x.q && !A(x.q).ok);
    fcOut[s.key] = { count: s.specs.length, invalid: bad.length, label: s.label };
    const byCtx = new Map();
    for (const x of bad) { if (!byCtx.has(x.context)) byCtx.set(x.context, []); byCtx.get(x.context).push(x); }
    for (const [ctx, list] of byCtx) {
      const why = reasons(A(list[0].q));
      for (const x of list.slice(0, 50)) {
        problems.push({ severity: s.key === 'homedirs' ? 'warning' : 'error', kind: `fc-${s.key}`, ...loc(x), spec: x.spec, fcFile: s.label,
          text: `${x.spec}${x.flag ? ` ${x.flag}` : ''} ${ctx} (${s.label}): not a valid context in this policy: ${why}. So ${fcEffect[s.key]}.` });
      }
    }
  }
  // Two lines for the same path expression and file kind: setfiles -c refuses file_contexts.
  const seen = new Map();
  for (const x of fc.main || []) {
    const k = `${x.spec}\t${x.mode || ''}`;
    const first = seen.get(k);
    if (!first) { seen.set(k, x); continue; }
    const same = first.context === x.context;
    problems.push({ severity: 'error', kind: 'fc-duplicate', ...loc(x), spec: x.spec, related: [{ ...loc(first), text: `${first.spec} ${first.context}` }],
      text: `${x.spec}${x.flag ? ` ${x.flag}` : ''} has ${same ? 'the same line' : `another line (${first.context})`}${first.module && first.module !== x.module ? ` in ${first.module}` : ''}: setfiles -c reports "Multiple ${same ? 'same' : 'different'} specifications" and ${fc.build ? '`make validate` fails; semodule would refuse the policy' : 'semodule refuses the policy'}. Keep one.` });
  }
  // Types restorecon can't put on a file.
  const noAssoc = aq ? A(aq).without || [] : [];
  for (const t of noAssoc) {
    const uses = [];
    for (const s of sets) for (const x of s.specs) if (x.type === t) uses.push({ x, label: s.label });
    for (const h of homes) for (const y of h.lines) if (y.ctx.split(':')[2] === t) uses.push({ x: y.s, label: 'home directory template' });
    if (!uses.length) continue;
    const first = uses[0];
    problems.push({ severity: 'warning', kind: 'fc-associate', ...loc(first.x), type: t, related: uses.slice(1, 8).map(u => ({ ...loc(u.x), text: `${u.x.spec} (${u.label})` })),
      text: `No rule lets ${t} be associated with a filesystem: it isn't a file type (files_type() and the interfaces built on it make one; look for such a call inside an optional_policy whose module is off). So restorecon can't give ${uses[0].x.spec}${uses.length > 1 ? ` and ${uses.length - 1} more` : ''} that label: Permission denied.` });
  }
  // genhomedircon: lines left out per user.
  const homesOut = [];
  for (const h of homes) {
    const dropped = h.lines.filter(x => !A(x.q).ok);
    homesOut.push({ user: h.user, prefix: h.prefix, role: h.role, level: h.level, logins: h.logins, lines: h.lines.length, dropped: dropped.length, fallback: h.fallback });
    if (!dropped.length) continue;
    const who = h.logins.join(', ');
    const hint = h.role && h.role !== 'object_r'
      ? ` ${h.user}'s prefix ${h.prefix} is also one of its roles, so genhomedircon writes ${h.role} as the role of its home files, and ${h.role} isn't authorized for their types. Give ${h.user} a prefix that isn't a role (gen_user's second argument, or semanage user -P).`
      : '';
    problems.push({ severity: 'warning', kind: 'homedir', file: cfg.seusers && cfg.seusers.path, l: h.l, user: h.user,
      related: dropped.slice(0, 8).map(x => ({ ...loc(x.s), text: `${x.spec} ${x.ctx}: ${reasons(A(x.q))}` })),
      text: `genhomedircon leaves ${dropped.length} of ${h.lines.length} home-directory line${h.lines.length > 1 ? 's' : ''} out for ${who} (${h.user}): ${dropped.slice(0, 3).map(x => `${x.spec} ${x.ctx}: ${reasons(A(x.q))}`).join('; ')}${dropped.length > 3 ? '; …' : ''}. Their files there get the label of a more general line instead.${hint}` });
  }
  problems.sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity) || String(a.file || '').localeCompare(String(b.file || '')) || (a.l || 0) - (b.l || 0));
  return { mls, files, fc: { ...fcOut, templates: templates.length, associateChecked: fcTypes.size, build: !!fc.build }, homes: homesOut, problems, notes };
}

module.exports = { analyze, parseFile, parseUsersExtra, templateKind, homeUsers, FILES, X_CLASSES, SEVERITY };
