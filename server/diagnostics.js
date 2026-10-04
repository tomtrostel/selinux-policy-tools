'use strict';
/*
 * Diagnostics computed from one file's parse plus the workspace index.
 * Each check is deliberately conservative: when the index can't be sure
 * (macro-provided class sets, $N parameters, generated names it couldn't
 * expand) it stays quiet rather than produce noise.
 */

const ERROR = 1, WARNING = 2, INFO = 3;

function diagnose(idx, f, settings = {}) {
  const out = [];
  if (!f || f.kind === 'flask') return out;

  // Support macro files use m4 quoting tricks (changequote, `'') that a
  // structural parser can't follow, so only check balance in policy files.
  if (!/\.(spt|m4)$/.test(f.path || '')) {
    for (const p of f.problems || []) out.push({ l: p.l, c: p.c, len: 1, severity: ERROR, msg: p.msg, code: 'syntax' });
  }

  // The index needs the support macros to judge unknown calls reliably.
  const haveSupport = idx.defs.has('gen_require') && idx.defs.has('interface');

  if (settings.unknownMacros !== false && haveSupport) {
    for (const c of f.calls || []) {
      if (c.name.includes('$') || /^\d/.test(c.name)) continue;
      if (idx.isMacro(c.name)) continue;
      // ifdef(`foo_iface', `foo_iface(...)'): m4 only expands it when defined.
      if (c.ifdefGuards && c.ifdefGuards.includes(c.name)) continue;
      if (c.inOptional) {
        out.push({ l: c.l, c: c.c, len: c.len, severity: INFO, code: 'unknown-macro-optional',
          msg: `'${c.name}' is not defined in the indexed sources. It is inside optional_policy, so the build skips it if the providing module is absent.` });
      } else {
        out.push({ l: c.l, c: c.c, len: c.len, severity: WARNING, code: 'unknown-macro',
          msg: `Unknown interface, template or macro '${c.name}'` });
      }
    }
  }

  if (settings.classPerms !== false && idx.classes.size > 0) {
    for (const r of f.avRules || []) checkAvRule(idx, r, out);
  }

  if (settings.genRequire !== false && f.path && f.path.endsWith('.if')) {
    for (const d of f.defs || []) checkGenRequire(idx, f, d, out);
  }
  return out;
}

function checkAvRule(idx, r, out) {
  const concrete = [];
  let opaque = false;
  for (const cl of r.classes) {
    if (cl.v.includes('$')) { opaque = true; continue; }
    if (idx.classes.has(cl.v)) { concrete.push(cl.v); continue; }
    if (idx.isMacro(cl.v)) { opaque = true; continue; } // e.g. file_class_set
    opaque = true;
    out.push({ l: cl.l, c: cl.c, len: cl.v.length, severity: WARNING, code: 'unknown-class',
      msg: `Unknown object class '${cl.v}'` });
  }
  if (opaque || !concrete.length) return;
  const perms = new Set();
  for (const c of concrete) for (const p of idx.permsOf(c) || []) perms.add(p);
  for (const p of r.perms) {
    if (p.v.includes('$') || perms.has(p.v) || idx.isMacro(p.v)) continue;
    out.push({ l: p.l, c: p.c, len: p.v.length, severity: WARNING, code: 'unknown-perm',
      msg: `Permission '${p.v}' is not defined for class${concrete.length > 1 ? 'es' : ''} ${concrete.join(', ')}`,
      data: { classes: concrete } });
  }
}

function checkGenRequire(idx, f, d, out) {
  if (!d.bodyEnd) return;
  const required = new Set(d.requires.map(r => r.name));
  const startL = d.l, endL = d.bodyEnd.l;
  const inBody = (l, c) => (l > startL || (l === startL && c > d.c)) && (l < endL || (l === endL && c < d.bodyEnd.c));
  const inRequireBlock = (l, c) => d.reqBlocks.some(b => (l > b.l || (l === b.l && c >= b.c)) && (l < b.endL || (l === b.endL && c <= b.endC)));
  for (const [name, positions] of f.refs) {
    if (required.has(name) || name.includes('$') || name === 'self' || name === d.name) continue;
    if (!idx.isTypeLike(name)) continue;
    if (idx.isMacro(name) || idx.classes.has(name)) continue;
    const hit = positions.find(([l, c]) => inBody(l, c) && !inRequireBlock(l, c));
    if (!hit) continue;
    const kind = (idx.decls.get(name) || []).some(x => x.kind === 'type') ? 'type' : 'attribute';
    out.push({ l: hit[0], c: hit[1], len: name.length, severity: WARNING, code: 'missing-require',
      msg: `'${name}' is used in ${d.name} but not declared in its gen_require block`,
      data: { def: d.name, name, kind } });
  }
}

module.exports = { diagnose, ERROR, WARNING, INFO };
