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
      // Code the build flags turn off is never compiled.
      if (!idx.isActive(f, c.l, c.c)) continue;
      const off = idx.inactiveDefs && idx.inactiveDefs.get(c.name);
      if (off) {
        const b = off[0].inactive;
        out.push({ l: c.l, c: c.c, len: c.len, severity: INFO, code: 'inactive-macro',
          msg: `'${c.name}' is only defined when ${b.sym} is ${b.want ? '' : 'not '}defined, which this build configuration ${b.want ? "doesn't do" : 'does'}.` });
        continue;
      }
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
    for (const r of f.avRules || []) {
      const at = r.classes[0] || { l: r.l, c: 0 };
      if (idx.isActive(f, at.l, at.c)) checkAvRule(idx, r, out);
    }
  }

  if (settings.genRequire !== false && f.path && f.path.endsWith('.if')) {
    for (const d of f.defs || []) checkGenRequire(idx, f, d, out);
  }
  if (settings.users !== false && haveSupport) checkUsers(idx, f, out);
  return out;
}

/**
 * gen_user(name, prefix, roles, default_level, range[, categories]):
 * roles must be declared somewhere; MLS/MCS levels must fit the build's
 * sensitivities and categories (only when the build flags are known);
 * a user defined twice in the same configuration. Quiet when unsure:
 * tokens in undecided ifdef branches and macros (mls_systemhigh, ...) are
 * not judged.
 */
function checkUsers(idx, f, out) {
  const calls = (f.calls || []).filter(c => c.name === 'gen_user' && c.argTokens && idx.isActive(f, c.l, c.c));
  if (!calls.length) return;
  const roles = idx.knownRoles();
  const flags = idx.m4 ? idx.m4.flags : '';
  const num = (n) => { const m = new RegExp(`-D\\s*${n}=(\\d+)`).exec(flags); return m ? +m[1] : null; };
  const mls = idx.m4 && idx.m4.defined.has('enable_mls'), mcs = idx.m4 && idx.m4.defined.has('enable_mcs');
  const maxSens = mls ? num('mls_num_sens') : mcs ? 1 : null;
  const maxCats = mls ? num('mls_num_cats') : mcs ? num('mcs_num_cats') : null;
  const kind = mls ? 'MLS' : 'MCS';
  const seen = new Map();
  for (const c of calls) {
    const [nameT = [], , rolesT = [], ...mlsArgs] = c.argTokens;
    // Roles (skipping a nested ifdef's name and condition, and inactive branches).
    for (let k = 0; k < rolesT.length; k++) {
      const t = rolesT[k];
      if (t.v === 'ifdef' || t.v === 'ifndef') { k++; continue; }
      if (t.v.includes('$') || !idx.isActive(f, t.l, t.c) || roles.has(t.v)) continue;
      out.push({ l: t.l, c: t.c, len: t.v.length, severity: WARNING, code: 'unknown-role',
        msg: `Role '${t.v}' is not declared anywhere in the indexed sources (role ${t.v}; or a template that generates it).` });
    }
    // MLS / MCS levels, ranges and categories.
    if (maxSens != null && maxCats != null) {
      mlsArgs.forEach((arg, ai) => {
        const sens = [];
        for (const t of arg || []) {
          if (t.v.includes('$') || !idx.isActive(f, t.l, t.c) || idx.undecidedAt(f, t.l, t.c)) continue;
          let m;
          if ((m = /^s(\d+)$/.exec(t.v))) {
            sens.push({ n: +m[1], t });
            if (+m[1] >= maxSens) out.push({ l: t.l, c: t.c, len: t.v.length, severity: ERROR, code: 'mls-range',
              msg: maxSens === 1 ? `${t.v} doesn't exist: this ${kind} policy has only s0.` : `${t.v} is out of range: this ${kind} policy has s0 to s${maxSens - 1} (mls_num_sens=${maxSens}).` });
          } else if ((m = /^c(\d+)$/.exec(t.v))) {
            if (+m[1] >= maxCats) out.push({ l: t.l, c: t.c, len: t.v.length, severity: ERROR, code: 'mls-range',
              msg: `${t.v} is out of range: this ${kind} policy has c0 to c${maxCats - 1}.` });
          } else if (!idx.defs.has(t.v)) {
            out.push({ l: t.l, c: t.c, len: t.v.length, severity: WARNING, code: 'mls-token',
              msg: `'${t.v}' is not a sensitivity (sN), a category (cN) or a defined MLS macro.` });
          }
        }
        if (ai === 1 && sens.length >= 2 && sens[0].n > sens[1].n) {
          out.push({ l: sens[1].t.l, c: sens[1].t.c, len: sens[1].t.v.length, severity: ERROR, code: 'mls-range',
            msg: `The range's high level (s${sens[1].n}) is below its low level (s${sens[0].n}).` });
        }
      });
    }
    // The same user twice in one configuration (only when both are certain).
    const name = nameT[0];
    if (name && !name.v.includes('$') && !idx.undecidedAt(f, c.l, c.c)) {
      const prev = seen.get(name.v);
      if (prev) out.push({ l: name.l, c: name.c, len: name.v.length, severity: WARNING, code: 'duplicate-user',
        msg: `User '${name.v}' is already defined on line ${prev.l + 1}; checkpolicy will reject the duplicate.` });
      else seen.set(name.v, name);
    }
  }
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
  if (!d.bodyEnd || d.inactive) return;
  const required = new Set(d.requires.map(r => r.name));
  const startL = d.l, endL = d.bodyEnd.l;
  const inBody = (l, c) => (l > startL || (l === startL && c > d.c)) && (l < endL || (l === endL && c < d.bodyEnd.c));
  const inRequireBlock = (l, c) => d.reqBlocks.some(b => (l > b.l || (l === b.l && c >= b.c)) && (l < b.endL || (l === b.endL && c <= b.endC)));
  for (const [name, positions] of f.refs) {
    if (required.has(name) || name.includes('$') || name === 'self' || name === d.name) continue;
    if (!idx.isTypeLike(name)) continue;
    if (idx.isMacro(name) || idx.classes.has(name)) continue;
    const hit = positions.find(([l, c]) => inBody(l, c) && !inRequireBlock(l, c) && idx.isActive(f, l, c));
    if (!hit) continue;
    const kind = (idx.decls.get(name) || []).some(x => x.kind === 'type') ? 'type' : 'attribute';
    out.push({ l: hit[0], c: hit[1], len: name.length, severity: WARNING, code: 'missing-require',
      msg: `'${name}' is used in ${d.name} but not declared in its gen_require block`,
      data: { def: d.name, name, kind } });
  }
}

module.exports = { diagnose, ERROR, WARNING, INFO };
