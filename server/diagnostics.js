'use strict';
/*
 * Diagnostics computed from one file's parse plus the workspace index.
 * Each check is deliberately conservative: when the index can't be sure
 * (macro-provided class sets, $N parameters, generated names it couldn't
 * expand) it stays quiet rather than produce noise.
 */

const path = require('path');

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
  if (settings.genRequire !== false && haveSupport && f.path && /\.te(\.in)?$/.test(f.path) && idx.isLoadable(f.module)) {
    checkTeRequires(idx, f, out);
    if (idx.moduleKinds) checkLinkRequires(idx, f, out);
  }
  if (settings.users !== false && haveSupport) checkUsers(idx, f, out);
  if (f.path && /corenetwork\.te\.in$/.test(f.path)) checkNetworkPorts(idx, f, out);
  return out;
}

/**
 * corenetwork.te.in: network_port(name, proto,port[-port],level, ...).
 * checkmodule accepts any number as a port, and reports a duplicate portcon
 * against an unrelated file; catch both where they're written. Ports that
 * aren't plain numbers (macros) and declarations in undecided ifdef
 * branches aren't judged.
 */
const PORT_PROTOCOLS = new Set(['tcp', 'udp', 'sctp', 'dccp']);
function checkNetworkPorts(idx, f, out) {
  const seen = new Map(); // "tcp 80-80" -> call
  for (const c of f.calls || []) {
    if (!/^network_port(_controlled)?$/.test(c.name) || c.inDef || !idx.isActive(f, c.l, c.c)) continue;
    const decided = !idx.undecidedAt(f, c.l, c.c);
    const at = (msg, code = 'net-port') => out.push({ l: c.l, c: c.c, len: c.len, severity: WARNING, code, msg });
    for (let k = 1; k + 1 < c.args.length; k += 3) {
      const proto = c.args[k].trim(), port = (c.args[k + 1] || '').trim();
      if (!/^[a-z]+$/.test(proto) || !/^\d+(-\d+)?$/.test(port)) continue;
      if (!PORT_PROTOCOLS.has(proto)) { at(`'${proto}' is not a port protocol (tcp, udp, sctp or dccp) in ${c.args[0]}'s ports.`); continue; }
      const [lo, hi = lo] = port.split('-').map(Number);
      if (lo > 65535 || hi > 65535) { at(`Port ${port} of ${c.args[0]} is out of range: ports go from 0 to 65535 (checkmodule doesn't catch this).`); continue; }
      if (lo > hi) { at(`Port range ${port} of ${c.args[0]} runs backwards (${lo} > ${hi}).`); continue; }
      if (!decided) continue;
      const key = `${proto} ${lo}-${hi}`;
      const prev = seen.get(key);
      if (prev) at(`${proto} ${port} is already declared by ${prev.name}(${prev.args[0]}) on line ${prev.l + 1}: checkpolicy rejects duplicate portcon entries (and reports it against another file).`, 'net-port-duplicate');
      else seen.set(key, c);
    }
  }
}

/*
 * .te files of loadable modules: every type or attribute from another module
 * must be required in the scope that uses it (checkmodule: "unknown type" /
 * "not within scope"). A scope is the module's top level or an
 * optional_policy block; requirements apply to the whole scope and the
 * scopes nested in it, wherever they appear, and come from `require { }` /
 * gen_require blocks or from the gen_require of any interface called in the
 * scope (transitively). Quiet when unsure: a call whose requirements can't
 * be worked out (unknown macro) silences its scope.
 */
const M4_BUILTINS = new Set(['ifdef', 'ifndef', 'ifelse', 'define', 'undefine', 'dnl', 'shift', 'patsubst', 'substr', 'translit',
  'incr', 'decr', 'eval', 'len', 'index', 'regexp', 'format', 'divert', 'errprint', 'esyscmd', 'syscmd', 'include', 'sinclude',
  'builtin', 'indir', 'pushdef', 'popdef', 'changequote', 'foreach']);
// Calls that are structure, not interfaces: their bodies' calls are recorded (and scoped) on their own.
const STRUCTURAL = new Set(['optional_policy', 'tunable_policy', 'boolean_policy', 'gen_require', 'policy_module', 'gen_tunable', 'gen_bool',
  'refpolicywarn', 'refpolicyerr']);
const ID = /^[A-Za-z_][A-Za-z0-9_]*$/;

function spliceArgs(raw, args) {
  const out = [];
  for (const a of raw) {
    if (a === '$*' || a === '$@') out.push(...args);
    else if (/^shift\(\$[*@]\)$/.test(a)) out.push(...args.slice(1));
    else out.push(a.replace(/\$(\d+)/g, (_, n) => (args[+n - 1] !== undefined ? args[+n - 1] : '')));
  }
  return out;
}

/** Names a required pattern stands for with these arguments ($1 = "{ a b }" gives a and b). */
function requiredNames(pattern, args) {
  const s = pattern.replace(/\$(\d+)/g, (_, n) => (args[+n - 1] !== undefined ? args[+n - 1] : ''));
  if (ID.test(s)) return [s];
  if (/^\$\d+$/.test(pattern)) return s.split(/[^A-Za-z0-9_]+/).filter(x => ID.test(x));
  return [];
}

/**
 * What calling `name(args)` requires, transitively: { names: Set, uncertain }.
 * mandatory: only what it always requires, leaving out requirements inside
 * optional_policy blocks and m4 conditionals of the interfaces' bodies.
 */
function callRequires(idx, name, args, depth = 0, mandatory = false) {
  if (!idx._teRequires) idx._teRequires = new Map();
  const key = `${mandatory ? 'M' : ''}${name}\0${args.join('\0')}`;
  const hit = idx._teRequires.get(key);
  if (hit) return hit;
  const res = { names: new Set(), uncertain: false };
  idx._teRequires.set(key, res); // placeholder breaks recursion cycles
  const defs = idx.defs.get(name);
  if (!defs) { res.uncertain = !M4_BUILTINS.has(name); return res; }
  if (depth > 12) { res.uncertain = true; return res; }
  for (const d of defs) {
    // Interfaces generated by a template call require what that call generates.
    if (d.generated) { for (const n of idx.generatedAt(d.path, d.l, d.c) || []) res.names.add(n); continue; }
    for (const r of d.requires || []) {
      if ((mandatory && r.cond) || !idx.whenHolds(r.when, args)) continue;
      for (const n of requiredNames(r.name, args)) res.names.add(n);
    }
    // Support macros (policy/support/*.spt: patterns, tunable_policy's
    // declare_required_symbols machinery) declare no requirements of their own.
    if (/\.spt$/.test(d.path || '')) continue;
    for (const bc of d.bodyCalls || []) {
      // tunable_policy(`$2', ...) in an interface requires the boolean passed in.
      if (bc.name === 'tunable_policy' && !(mandatory && bc.cond) && idx.whenHolds(bc.when, args) && autoRequiringTunables(idx)) {
        for (const n of (spliceArgs(bc.args.slice(0, 1), args)[0] || '').match(/[A-Za-z_]\w*/g) || []) res.names.add(n);
      }
      // Calls nested in structural macros (tunable_policy, ...) are body calls of their own.
      if (M4_BUILTINS.has(bc.name) || STRUCTURAL.has(bc.name) || (mandatory && bc.cond) || !idx.whenHolds(bc.when, args)) continue;
      const sub = callRequires(idx, bc.name, spliceArgs(bc.args, args), depth + 1, mandatory);
      for (const n of sub.names) res.names.add(n);
      if (sub.uncertain) res.uncertain = true;
    }
  }
  return res;
}

/** Scopes of a .te file: scopeOf(l, c) = innermost active optional_policy call (null: top level); inDef: inside a definition. */
function teScopes(idx, f) {
  const blocks = (f.calls || []).filter(c => c.name === 'optional_policy' && idx.isActive(f, c.l, c.c));
  const within = (b, l, c) => (l > b.l || (l === b.l && c > b.c)) && (l < b.endL || (l === b.endL && c < b.endC));
  const scopeOf = (l, c) => {
    let best = null;
    for (const b of blocks) if (within(b, l, c) && (!best || within(best, b.l, b.c))) best = b;
    return best;
  };
  const defRanges = (f.defs || []).filter(d => d.bodyEnd).map(d => ({ l: d.l, c: d.c, endL: d.bodyEnd.l, endC: d.bodyEnd.c }));
  const inDef = (l, c) => defRanges.some(r => within(r, l, c));
  return { scopeOf, inDef };
}

/**
 * A .te file's global requirements: what the module needs from other modules
 * outside any optional_policy block (where a missing requirement fails the
 * link instead of dropping the block). name -> [{ l, c, len, via }], where
 * `via` is the interface call that brings the requirement in (null for a
 * require entry). Code in undecided ifdef branches is left out; `uncertain`
 * is set when a top-level call's requirements can't be worked out.
 */
function globalRequirements(idx, f) {
  const { scopeOf, inDef } = teScopes(idx, f);
  const out = new Map();
  let uncertain = false;
  const add = (n, site) => { let a = out.get(n); if (!a) out.set(n, a = []); a.push(site); };
  const global = (l, c) => idx.isActive(f, l, c) && !idx.undecidedAt(f, l, c) && !inDef(l, c) && scopeOf(l, c) === null;
  for (const r of f.requires || []) {
    if (r.l !== undefined && global(r.l, r.c)) add(r.name, { l: r.l, c: r.c, len: r.name.length, via: null, kind: r.kind });
  }
  for (const c of f.calls || []) {
    if (c.inDef || STRUCTURAL.has(c.name) || M4_BUILTINS.has(c.name) || !global(c.l, c.c)) continue;
    const r = callRequires(idx, c.name, c.args, 0, true);
    if (r.uncertain) uncertain = true;
    for (const n of r.names) add(n, { l: c.l, c: c.c, len: c.len, via: c.name });
  }
  return { names: out, uncertain };
}

/**
 * Loadable modules of a tree: a global requirement that only modules turned
 * off in modules.conf declare makes the link fail (semodule_link reports one
 * such module per build; this finds them all, where they come from).
 */
function checkLinkRequires(idx, f, out) {
  const { names } = globalRequirements(idx, f);
  for (const [name, sites] of names) {
    const mods = idx.declaringModules(name);
    const site = sites[0];
    if (!mods && !(idx.decls.get(name) || []).length && (/^(type|attribute)$/.test(idx.requiredKind(name) || '') || sites.some(s => s.kind === 'type' || s.kind === 'attribute'))) {
      // Declared nowhere in the tree (e.g. RHEL 10 ships timidity.if without timidity.te).
      out.push({ l: site.l, c: site.c, len: site.len, severity: WARNING, code: 'link-missing',
        msg: `This module needs '${name}'${site.via ? ` (required by ${site.via}())` : ''} outside optional_policy, but no module in this tree declares it: linking will fail. Move this into an optional_policy block (or add the module that declares it).`,
        data: { name, modules: [] } });
      continue;
    }
    if (!mods || mods.has(f.module) || [...mods].some(m => idx.isEnabled(m))) continue;
    const list = [...mods].sort();
    const owners = list.length === 1 ? `the ${list[0]} module, which is` : `the modules ${list.join(', ')}, which are`;
    out.push({ l: site.l, c: site.c, len: site.len, severity: WARNING, code: 'link-missing',
      msg: `This module needs '${name}'${site.via ? ` (required by ${site.via}())` : ''} outside optional_policy, but only ${owners} off in modules.conf, declare${list.length === 1 ? 's' : ''} it: linking will fail. Enable ${list.length === 1 ? list[0] : 'one of them'}, or move this into an optional_policy block.`,
      data: { name, modules: list } });
  }
}

/** Does this tree's tunable_policy require its condition's booleans by itself? */
function autoRequiringTunables(idx) {
  return (idx.defs.get('tunable_policy') || []).some(d => (d.bodyCalls || []).some(b => b.name === 'declare_required_symbols'));
}

function checkTeRequires(idx, f, out) {
  const { scopeOf, inDef } = teScopes(idx, f);

  const provided = new Map(); // scope (block or null) -> Set of names
  const uncertain = new Set();
  const provide = (scope, n) => { let s = provided.get(scope); if (!s) provided.set(scope, s = new Set()); s.add(n); };
  const requirePos = new Set();
  for (const r of f.requires || []) {
    if (r.l === undefined) continue;
    requirePos.add(`${r.l}:${r.c}`);
    if (idx.isActive(f, r.l, r.c) && !inDef(r.l, r.c)) provide(scopeOf(r.l, r.c), r.name);
  }
  for (const c of f.calls || []) {
    if (c.inDef || STRUCTURAL.has(c.name) || M4_BUILTINS.has(c.name) || !idx.isActive(f, c.l, c.c)) continue;
    const scope = scopeOf(c.l, c.c);
    const r = callRequires(idx, c.name, c.args);
    for (const n of r.names) provide(scope, n);
    if (r.uncertain) uncertain.add(scope);
  }
  // tunable_policy requires the booleans of its condition itself when the
  // macro does so (declare_required_symbols in refpolicy since 2016).
  if (autoRequiringTunables(idx)) {
    for (const c of f.calls || []) {
      if (c.name !== 'tunable_policy' || c.inDef || !idx.isActive(f, c.l, c.c)) continue;
      for (const n of (c.args[0] || '').match(/[A-Za-z_]\w*/g) || []) provide(scopeOf(c.l, c.c), n);
    }
  }

  for (const [name, positions] of f.refs) {
    if (name.includes('$') || name === 'self' || idx.isMacro(name) || idx.classes.has(name)) continue;
    const decls = idx.decls.get(name) || [];
    if (decls.some(d => d.path === f.path)) continue; // declared here (or generated by a call here)
    const kind = decls.length ? (decls.some(d => d.kind === 'type') ? 'type' : decls.some(d => d.kind === 'attribute') ? 'attribute' : decls.some(d => d.kind === 'bool') ? 'bool' : null)
      : idx.requiredKind(name); // standalone modules: the devel headers only require names
    if (kind !== 'type' && kind !== 'attribute' && kind !== 'bool') continue;
    for (const [l, c] of positions) {
      // Not in ifdef branches the build flags don't decide (ifdef(`TODO', ...) is dead code).
      if (requirePos.has(`${l}:${c}`) || inDef(l, c) || !idx.isActive(f, l, c) || idx.undecidedAt(f, l, c)) continue;
      let s = scopeOf(l, c), ok = false;
      for (;;) {
        if ((provided.get(s) && provided.get(s).has(name)) || uncertain.has(s)) { ok = true; break; }
        if (s === null) break;
        s = scopeOf(s.l, s.c);
      }
      if (ok) continue;
      const scope = scopeOf(l, c);
      const global = decls.find(d => /global_(tunables|booleans)$/.test(d.path || ''));
      const owner = decls.map(d => idx.files.get(d.path)).find(x => x && x.module && /\.te(\.in)?$/.test(x.path || ''));
      const from = global ? `the policy's ${path.basename(global.path).replace('_', ' ')} (${path.basename(global.path)})`
        : owner ? `the ${owner.module} module` : 'another module';
      out.push({ l, c, len: name.length, severity: WARNING, code: 'missing-te-require',
        msg: `'${name}' comes from ${from} and isn't required ${scope ? 'in this optional_policy block' : 'in this module'}: add '${kind} ${name};' to a require block${scope ? ' inside the block' : ''} (or call an interface that grants the access). As a loadable module it won't compile otherwise.`,
        data: { name, kind, scope: scope ? { l: scope.l, c: scope.c } : null } });
      break;
    }
  }
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

module.exports = { diagnose, callRequires, globalRequirements, ERROR, WARNING, INFO };
