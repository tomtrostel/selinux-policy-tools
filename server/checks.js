'use strict';
/*
 * Property checks file (selinux.checks): one assertion per line, '#' comments.
 *
 *   only   <names> may <perms> <targets>[:<classes>]   nobody else may (attributes expanded)
 *   never  <names> may <perms> <targets>[:<classes>]   none of these may ('*' = every domain)
 *   never  <names> reaches <names> [except through <names>]
 *                                                      no domain-transition path, direct or indirect
 *                                                      (paths through the 'except through' domains allowed)
 *   never  <types> flows to <types> [except <types>] [weight N]
 *                                                      no information flow (reads and writes, through any
 *                                                      chain of domains and objects; 'except' types may
 *                                                      pass it on; weight: weakest permission counted, 1-10)
 *   require <names> may <perms> <targets>[:<classes>]  must stay allowed
 *   only|never <roles> may run <types>                 role → domain authorization
 *   only|never <users> may use <roles>                 user → role authorization
 *   only|never <users> may log in                      which SELinux users seusers maps logins to
 *   never login <logins> reaches <domains> [except through <domains>]
 *                                                      what a login's sessions can reach (seusers →
 *                                                      user → its ways in → domain transitions and role changes)
 *   never login <logins> may <perms> <targets>[:<classes>]
 *                                                      … and what they may do there
 *   never login <logins> maps to <users>               the SELinux user seusers gives a login
 *   only|never <domains> may ignore levels [on <classes>]
 *                                                      domains that pass MLS/MCS constraints whatever
 *                                                      the levels (MCS: not in mcs_constrained_type)
 *
 * logins: Linux login names (a name without a line of its own gets __default__'s), %group,
 * __default__, or '*' (every seusers line).
 * names: types or attributes, separated by spaces or commas.
 * perms: read | write | execute | any (groups), a single permission, or
 * { perm perm ... } (exactly these permissions; { read } is just read).
 * classes: a class or { class class ... }; default: the file-like classes
 * (require: file).
 */

const PERM_GROUPS = {
  read: ['read', 'open', 'map'],
  write: ['write', 'append', 'create', 'unlink', 'link', 'rename', 'setattr', 'add_name', 'remove_name', 'rmdir', 'reparent', 'relabelfrom', 'relabelto'],
  execute: ['execute', 'execute_no_trans', 'entrypoint'],
};
const FILE_CLASSES = ['file', 'dir', 'lnk_file', 'chr_file', 'blk_file', 'sock_file', 'fifo_file'];
const KEYWORDS = ['only', 'never', 'require', 'may', 'reaches', 'flows', 'to', 'except', 'through', 'weight', 'run', 'use', 'read', 'write', 'execute', 'any', 'login', 'log', 'in', 'maps', 'ignore', 'levels', 'on'];

/** Tokens with columns: words (incl. '*' and %group), braces, ':' and ','. */
function tokens(line) {
  const out = [];
  const re = /[{}:,]|%?[A-Za-z0-9_*.$-]+/g;
  let m;
  while ((m = re.exec(line))) out.push({ v: m[0], c: m.index });
  return out;
}

function parseChecks(text) {
  const checks = [], errors = [];
  text.split('\n').forEach((raw, l) => {
    const line = raw.replace(/#.*$/, '');
    if (!line.trim()) return;
    const tok = tokens(line);
    let i = 0;
    const err = (msg, t = tok[i]) => { errors.push({ l, c: t ? t.c : line.length, len: t ? t.v.length : 1, msg }); };
    const names = (stop) => {
      const out = [];
      while (i < tok.length && !stop.includes(tok[i].v)) { if (tok[i].v !== ',') out.push(tok[i].v); i++; }
      return out;
    };
    const set = () => {
      if (tok[i] && tok[i].v === '{') {
        i++;
        const out = [];
        while (i < tok.length && tok[i].v !== '}') { if (tok[i].v !== ',') out.push(tok[i].v); i++; }
        if (!tok[i]) return null;
        i++;
        return out;
      }
      return tok[i] ? [tok[i++].v] : null;
    };
    const kind = tok[i] && tok[i].v;
    if (!['only', 'never', 'require'].includes(kind)) { err(`Expected 'only', 'never' or 'require' at the start of a check`); return; }
    i++;
    // never login <logins> reaches <domains> | may <perms> <targets>[:<classes>] | maps to <users>
    if (tok[i] && tok[i].v === 'login') {
      if (kind !== 'never') { err(`'login' checks start with 'never' (never login alice reaches sysadm_t)`); return; }
      i++;
      const logins = names(['reaches', 'may', 'maps']);
      if (!logins.length) { err('Expected one or more Linux logins (a name, %group, __default__ or *)'); return; }
      const lv = tok[i] && tok[i].v;
      if (lv === 'reaches') {
        i++;
        const targets = names(['except']);
        if (!targets.length) { err('Expected the domain(s) its sessions must not reach'); return; }
        let through = [];
        if (tok[i] && tok[i].v === 'except') {
          i++;
          if (!tok[i] || tok[i].v !== 'through') { err(`Expected 'through' (never login %ro reaches passwd_t except through wrap_t)`); return; }
          i++;
          through = names([]);
          if (!through.length) { err(`Expected the domain(s) after 'except through'`); return; }
        }
        checks.push({ id: checks.length, line: l, kind: 'login-reaches', logins, targets, ...(through.length ? { through } : {}), text: raw.trim() });
        return;
      }
      if (lv === 'maps') {
        i++;
        if (!tok[i] || tok[i].v !== 'to') { err(`Expected 'to' (never login alice maps to unconfined_u)`); return; }
        i++;
        const users = names([]);
        if (!users.length) { err('Expected the SELinux user(s) it must not get'); return; }
        checks.push({ id: checks.length, line: l, kind: 'login-maps', logins, users, text: raw.trim() });
        return;
      }
      if (lv !== 'may') { err(`Expected 'reaches', 'may' or 'maps to'`); return; }
      i++;
      const braced = tok[i] && tok[i].v === '{';
      const p = set();
      if (!p || !p.length) { err('Expected permissions: read, write, execute, any, a permission, or { perm ... }'); return; }
      const perms = p.length === 1 && p[0] === 'any' && !braced ? '*' : braced ? [...new Set(p)] : PERM_GROUPS[p[0]] || p;
      const targets = names([':']);
      if (!targets.length) { err('Expected the target type(s) or attribute(s)'); return; }
      let classes = FILE_CLASSES;
      if (tok[i] && tok[i].v === ':') {
        i++;
        const cl = set();
        if (!cl || !cl.length) { err('Expected a class or { class ... } after ":"'); return; }
        classes = cl;
      }
      if (i < tok.length) { err(`Unexpected '${tok[i].v}'`); return; }
      checks.push({ id: checks.length, line: l, kind: 'login-may', logins, targets, classes, perms, permsLabel: p.join(' '), text: raw.trim() });
      return;
    }
    const sources = names(['may', 'reaches', 'flows']);
    if (!sources.length) { err('Expected one or more types or attributes'); return; }
    const verb = tok[i] && tok[i].v;
    if (verb === 'reaches') {
      if (kind !== 'never') { err(`'reaches' only works with 'never' (never X reaches Y)`); return; }
      i++;
      const targets = names(['except']);
      if (!targets.length) { err('Expected the domain(s) that must not be reachable'); return; }
      // except through <domains>: paths through these don't count (a wrapper is the only way in).
      let through = [];
      if (tok[i] && tok[i].v === 'except') {
        i++;
        if (!tok[i] || tok[i].v !== 'through') { err(`Expected 'through' (never user_t reaches passwd_t except through wrap_t)`); return; }
        i++;
        through = names([]);
        if (!through.length) { err(`Expected the domain(s) after 'except through'`); return; }
      }
      checks.push({ id: checks.length, line: l, kind: 'reaches', sources, targets, ...(through.length ? { through } : {}), text: raw.trim() });
      return;
    }
    if (verb === 'flows') {
      if (kind !== 'never') { err(`'flows to' only works with 'never' (never X flows to Y)`); return; }
      i++;
      if (!tok[i] || tok[i].v !== 'to') { err(`Expected 'to' (never X flows to Y)`); return; }
      i++;
      const targets = names(['except', 'weight']);
      if (!targets.length) { err('Expected the type(s) the data must not reach'); return; }
      let except = [], weight = 10;
      if (tok[i] && tok[i].v === 'except') {
        i++;
        except = names(['weight']);
        if (!except.length) { err(`Expected the type(s) allowed to pass the data on after 'except'`); return; }
      }
      if (tok[i] && tok[i].v === 'weight') {
        i++;
        weight = tok[i] && /^([1-9]|10)$/.test(tok[i].v) ? Number(tok[i++].v) : NaN;
        if (Number.isNaN(weight)) { err('Expected a weight from 1 (count every permission, even covert channels) to 10 (only reads and writes of data)'); return; }
      }
      if (i < tok.length) { err(`Unexpected '${tok[i].v}'`); return; }
      if (sources.includes('*') || targets.includes('*')) { err(`'*' doesn't work with 'flows to'`, tok.find(t => t.v === '*')); return; }
      checks.push({ id: checks.length, line: l, kind: 'flows', sources, targets, except, weight, text: raw.trim() });
      return;
    }
    if (verb !== 'may') { err(`Expected 'may', 'reaches' or 'flows to'`); return; }
    i++;
    // Levels: `only|never <domains> may ignore levels [on <classes>]`: the domains that pass
    // MLS/MCS constraints whatever the levels (e.g. not in mcs_constrained_type).
    if (tok[i] && tok[i].v === 'ignore') {
      if (kind === 'require') { err(`'may ignore levels' works with 'only' and 'never'`); return; }
      i++;
      if (!tok[i] || tok[i].v !== 'levels') { err(`Expected 'levels' (never container_t may ignore levels)`); return; }
      i++;
      let classes = [];
      if (tok[i] && tok[i].v === 'on') {
        i++;
        const cl = set();
        if (!cl || !cl.length) { err(`Expected a class or { class ... } after 'on'`); return; }
        classes = cl;
      }
      if (i < tok.length) { err(`Unexpected '${tok[i].v}'`); return; }
      checks.push({ id: checks.length, line: l, kind: `${kind}-levels`, sources, classes, text: raw.trim() });
      return;
    }
    // Users: `only|never <users> may log in` (the SELinux users seusers maps logins to).
    if (tok[i] && tok[i].v === 'log') {
      if (kind === 'require') { err(`'may log in' works with 'only' and 'never'`); return; }
      i++;
      if (!tok[i] || tok[i].v !== 'in') { err(`Expected 'in' (only staff_u user_u may log in)`); return; }
      i++;
      if (i < tok.length) { err(`Unexpected '${tok[i].v}'`); return; }
      checks.push({ id: checks.length, line: l, kind: `${kind}-login`, users: sources, text: raw.trim() });
      return;
    }
    // Roles and users: `<roles> may run <types>`, `<users> may use <roles>`.
    if (tok[i] && (tok[i].v === 'run' || tok[i].v === 'use')) {
      const what = tok[i].v;
      if (kind === 'require') { err(`'${what}' works with 'only' and 'never'`); return; }
      i++;
      const targets = names([]);
      if (!targets.length) { err(what === 'run' ? 'Expected the domain(s) the role(s) may run' : 'Expected the role(s)'); return; }
      checks.push({ id: checks.length, line: l, kind: `${kind}-${what}`, sources, targets, text: raw.trim() });
      return;
    }
    const braced = tok[i] && tok[i].v === '{';
    const p = set();
    if (!p || !p.length) { err('Expected permissions: read, write, execute, any, a permission, or { perm ... }'); return; }
    let perms;
    if (p.length === 1 && p[0] === 'any' && !braced) perms = '*';
    else if (braced) perms = [...new Set(p)]; // { read } is the permission, not the group
    else perms = PERM_GROUPS[p[0]] || p;
    const targets = names([':']);
    if (!targets.length) { err('Expected the target type(s) or attribute(s)'); return; }
    let classes = kind === 'require' ? ['file'] : FILE_CLASSES;
    if (tok[i] && tok[i].v === ':') {
      i++;
      const cl = set();
      if (!cl || !cl.length) { err('Expected a class or { class ... } after ":"'); return; }
      classes = cl;
    }
    if (i < tok.length) { err(`Unexpected '${tok[i].v}'`); return; }
    if (sources.includes('*') && kind !== 'never') { err(`'*' (every domain) only makes sense with 'never'`, tok.find(t => t.v === '*')); return; }
    checks.push({ id: checks.length, line: l, kind, sources, targets, classes, perms, permsLabel: p.join(' '), text: raw.trim() });
  });
  return { checks, errors };
}

module.exports = { parseChecks, PERM_GROUPS, FILE_CLASSES, KEYWORDS };
