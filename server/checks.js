'use strict';
/*
 * Property checks file (selinux.checks): one assertion per line, '#' comments.
 *
 *   only   <names> may <perms> <targets>[:<classes>]   nobody else may (attributes expanded)
 *   never  <names> may <perms> <targets>[:<classes>]   none of these may ('*' = every domain)
 *   never  <names> reaches <names>                     no domain-transition path, direct or indirect
 *   require <names> may <perms> <targets>[:<classes>]  must stay allowed
 *   only|never <roles> may run <types>                 role → domain authorization
 *   only|never <users> may use <roles>                 user → role authorization
 *
 * names: types or attributes, separated by spaces or commas.
 * perms: read | write | execute | any, a single permission, or { perm perm ... }.
 * classes: a class or { class class ... }; default: the file-like classes
 * (require: file).
 */

const PERM_GROUPS = {
  read: ['read', 'open', 'map'],
  write: ['write', 'append', 'create', 'unlink', 'link', 'rename', 'setattr', 'add_name', 'remove_name', 'rmdir', 'reparent', 'relabelfrom', 'relabelto'],
  execute: ['execute', 'execute_no_trans', 'entrypoint'],
};
const FILE_CLASSES = ['file', 'dir', 'lnk_file', 'chr_file', 'blk_file', 'sock_file', 'fifo_file'];
const KEYWORDS = ['only', 'never', 'require', 'may', 'reaches', 'run', 'use', 'read', 'write', 'execute', 'any'];

/** Tokens with columns: words (incl. '*'), braces, ':' and ','. */
function tokens(line) {
  const out = [];
  const re = /[{}:,]|[A-Za-z0-9_*.$-]+/g;
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
    const sources = names(['may', 'reaches']);
    if (!sources.length) { err('Expected one or more types or attributes'); return; }
    const verb = tok[i] && tok[i].v;
    if (verb === 'reaches') {
      if (kind !== 'never') { err(`'reaches' only works with 'never' (never X reaches Y)`); return; }
      i++;
      const targets = names([]);
      if (!targets.length) { err('Expected the domain(s) that must not be reachable'); return; }
      checks.push({ id: checks.length, line: l, kind: 'reaches', sources, targets, text: raw.trim() });
      return;
    }
    if (verb !== 'may') { err(`Expected 'may' (or 'reaches')`); return; }
    i++;
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
    const p = set();
    if (!p || !p.length) { err('Expected permissions: read, write, execute, any, a permission, or { perm ... }'); return; }
    let perms;
    if (p.length === 1 && p[0] === 'any') perms = '*';
    else perms = [...new Set(p.flatMap(x => PERM_GROUPS[x] || [x]))];
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
