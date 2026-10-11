'use strict';
const fs = require('fs');
const path = require('path');
const ID_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const { parsePolicy, parseFc, parseFlask } = require('./parser');

const POLICY_EXT = ['.te', '.if', '.spt', '.m4', '.te.in', '.if.in'];
const FLASK_FILES = new Set(['security_classes', 'access_vectors']);
// Hidden directories (.git, .vscode, editor/agent worktrees like .kilo) are
// always skipped: they never hold policy source but may hold whole tree copies.
const SKIP_DIRS = new Set(['node_modules', 'tmp']);

const M4_BUILTINS = new Set(['define', 'undefine', 'defn', 'pushdef', 'popdef', 'indir', 'builtin',
  'ifdef', 'ifelse', 'shift', 'changequote', 'changecom', 'changeword', 'm4wrap', 'include',
  'sinclude', 'divert', 'undivert', 'divnum', 'len', 'index', 'regexp', 'substr', 'translit',
  'patsubst', 'format', 'incr', 'decr', 'eval', 'syscmd', 'esyscmd', 'sysval', 'mkstemp',
  'maketemp', 'errprint', 'm4exit', '__file__', '__line__', 'dumpdef', 'traceon', 'traceoff', 'debugmode', 'debugfile',
  '__program__', '__gnu__', '__unix__', 'unix']);

/**
 * How refpolicy feeds a file to m4, which decides which definitions an
 * ifdef at its top level can see: support .spt files come first, then all
 * .if files (in one run, without the build flags: all_interfaces.conf),
 * then one module's .te; .fc files see only the .spt files.
 */
function m4Role(p) {
  const base = path.basename(p);
  if (base.endsWith('.te')) return 'te';
  if (base.endsWith('.if') || base.endsWith('.if.in')) return 'if';
  if (base.endsWith('.spt')) return 'spt';
  if (base.endsWith('.fc')) return 'fc';
  return 'other';
}
const before = (a, b) => a.l < b.l || (a.l === b.l && a.c < b.c);
const inRange = (p, b) => !before(p, b.s) && before(p, b.e);
const UNDEFINING = new Set(['undefine', 'popdef']);

/**
 * Does definition site `s` decide ifdef branch `b` (of file `f`, evaluated
 * in `role`)? 'counts' when m4 has certainly read it by then, 'ignore' when
 * it certainly hasn't, 'unsure' when that depends on order or on the module.
 * Base modules' .te and .fc files are concatenated, so another file of the
 * same kind is 'unsure'.
 */
function siteRelevance(role, f, b, s) {
  const sr = m4Role(s.f.path);
  if (role === 'call') return sr === 'if' || sr === 'spt' ? 'counts' : 'unsure';
  if (s.f === f) return before(s, b.s) ? 'counts' : 'ignore';
  switch (role) {
    case 'te': return sr === 'if' || sr === 'spt' ? 'counts' : sr === 'fc' ? 'ignore' : 'unsure';
    case 'if': return sr === 'spt' ? 'counts' : sr === 'if' ? 'unsure' : 'ignore';
    case 'spt': return sr === 'spt' ? 'unsure' : 'ignore';
    case 'fc': return sr === 'spt' ? 'counts' : sr === 'fc' ? 'unsure' : 'ignore';
    default: return 'unsure';
  }
}

function classifyFile(p) {
  const base = path.basename(p);
  if (FLASK_FILES.has(base)) return 'flask';
  if (base.endsWith('.fc')) return 'fc';
  if (POLICY_EXT.some(e => base.endsWith(e))) return 'policy';
  if (['global_tunables', 'global_booleans', 'users', 'constraints', 'mls', 'mcs', 'policy_capabilities'].includes(base)) return 'policy';
  return null;
}

/** Classes from all_perms.spt: define(`all_<class>_perms',`{ perm ... }') */
function parseAllPerms(text) {
  const out = [];
  const re = /define\(`all_(\w+)_perms',\s*`\{([^}]*)\}'\)/g;
  let m, l = 0, pos = 0, lineStart = 0;
  while ((m = re.exec(text))) {
    for (; pos < m.index; pos++) if (text.charCodeAt(pos) === 10) { l++; lineStart = pos + 1; }
    const c = m.index - lineStart + 'define(`all_'.length;
    out.push({ name: m[1], l, c, perms: m[2].trim().split(/\s+/).filter(Boolean), inherits: null });
  }
  return out;
}

/** Module name and layer from a path like .../policy/modules/<layer>/<mod>.te */
function moduleInfo(p) {
  const m = /modules\/([^/]+)\/([^/]+?)\.(te|if|fc)(\.in|\.m4)?$/.exec(p.replace(/\\/g, '/'));
  if (m) return { layer: m[1], module: m[2] };
  const base = path.basename(p).replace(/\.(te|if|fc)(\.in|\.m4)?$/, '');
  return { layer: path.basename(path.dirname(p)), module: base };
}

class PolicyIndex {
  constructor(log) {
    this.files = new Map(); // fsPath -> parse result (+ path, kind)
    this.log = log || (() => {});
    this.built = false;
    this.m4 = null;         // build flags: { defined: Set, universe: Set } or null (all branches active)
    this.moduleKinds = null; // module -> 'base' | 'module' | 'off' from modules.conf (+ APPS_MODS), or null
    this.allLoadable = false; // standalone modules: always built as loadable modules
  }

  /**
   * Whether a module is built as a loadable module (where every name from
   * another module needs a require). Unknown (no modules.conf) → false, so
   * require checks stay quiet: base modules are compiled together and need none.
   */
  isLoadable(module) {
    if (this.allLoadable) return true;
    return !!(this.moduleKinds && module && this.moduleKinds.get(module) === 'module');
  }

  /**
   * The modules.conf `make conf` would write for the tree at `root` when it
   * has none (support/sedoctool.py): base for modules whose .if says
   * `<required val="true">`, module for the rest.
   */
  defaultModuleKinds(root) {
    const states = new Map();
    const prefix = root ? root + path.sep : '';
    for (const f of this.files.values()) {
      if (!f.module || !/\.if(\.in)?$/.test(f.path) || !f.path.startsWith(prefix)) continue;
      states.set(f.module, f.required ? 'base' : 'module');
    }
    return states;
  }

  /**
   * Whether a definition's ifelse branches (parser `when`: [{ a, b, then }])
   * apply for a call with these arguments. A comparison counts only when
   * both sides become plain text (no unresolved $N, no macro calls such as
   * eval(...)); otherwise the branch is taken to apply.
   */
  whenHolds(when, args) {
    if (!when) return true;
    const sub = (s) => s.replace(/\$(\d+)/g, (_, n) => (args[+n - 1] !== undefined ? args[+n - 1] : '')).replace(/[`']/g, '').trim();
    for (const w of when) {
      if (/\$[*@#]|\(/.test(w.a + w.b)) continue;
      const a = sub(w.a), b = sub(w.b);
      if (/[$()]/.test(a + b)) continue;
      if ((a === b) !== w.then) return false;
    }
    return true;
  }

  /** Whether modules.conf (+ APPS_MODS) builds a module at all (base or module). */
  isEnabled(module) {
    const k = this.moduleKinds && this.moduleKinds.get(module);
    return k === 'base' || k === 'module';
  }

  /**
   * Modules whose .te declares type/attribute `name` (directly or by a
   * template call), or null if unknown: not a type/attribute, or also
   * declared outside a module's .te (then it is always there).
   */
  declaringModules(name) {
    if (!this._declMods) this._declMods = new Map();
    if (this._declMods.has(name)) return this._declMods.get(name);
    let res = null;
    const decls = (this.decls.get(name) || []).filter(d => d.kind === 'type' || d.kind === 'attribute');
    if (decls.length) {
      res = new Set();
      for (const d of decls) {
        const f = this.files.get(d.path);
        if (!f || !f.module || !/\.te(\.in)?$/.test(d.path)) { res = null; break; }
        res.add(f.module);
      }
    }
    this._declMods.set(name, res);
    return res;
  }

  /** 'type' | 'attribute' | 'bool' if some interface requires `name` as such (the devel headers declare nothing), else null. */
  requiredKind(name) {
    if (!this._requiredKinds) {
      this._requiredKinds = new Map();
      for (const list of this.defs.values()) {
        for (const d of list) {
          for (const r of d.requires || []) {
            if ((r.kind === 'type' || r.kind === 'attribute' || r.kind === 'bool') && ID_RE.test(r.name) && !this._requiredKinds.has(r.name)) this._requiredKinds.set(r.name, r.kind);
          }
        }
      }
    }
    return this._requiredKinds.get(name) || null;
  }

  /** Names generated by template calls at a call site (path:line:col), for generated interfaces' requirements. */
  generatedAt(p, l, c) {
    if (!this._genSites) {
      this._genSites = new Map();
      for (const [n, list] of this.decls) {
        for (const d of list) {
          if (!d.generated) continue;
          const k = `${d.path}:${d.l}:${d.c}`;
          let s = this._genSites.get(k);
          if (!s) this._genSites.set(k, s = new Set());
          s.add(n);
        }
      }
    }
    return this._genSites.get(`${p}:${l}:${c}`) || null;
  }

  /* ----- ifdef/ifndef decisions ----- */

  /**
   * Set the m4 build flags of the current build configuration. Symbols in
   * `universe` (the -D flags the Makefile can pass) are decided by the flags;
   * other names by where the sources define them (branchState). Without
   * flags (no make), every branch stays active.
   */
  setM4Defines(m4) {
    this.m4 = m4 && m4.universe && m4.universe.size ? { patterns: [], stepOnly: new Set(), ...m4 } : null;
    this._branchState = null;
  }

  /** Is `sym` decided by the build flags (a Makefile -D flag not also defined in the sources)? */
  decides(sym) {
    if (!this.m4) return false;
    if (!this.m4.universe.has(sym) && !this.m4.patterns.some(re => re.test(sym))) return false;
    return !this.symSites().byName.has(sym);
  }

  /** Every place the sources (un)define an m4 macro: { byName: name -> [site], patterns: [RegExp] for `$N` names }. */
  symSites() {
    if (this._symSites) return this._symSites;
    const byName = new Map(), patterns = [];
    for (const f of this.files.values()) {
      for (const s of f.symDefs || []) {
        if (s.name.includes('$')) {
          // interface()/template() themselves define(`$1'); their call sites are the definitions.
          if (/^(\$(\d+|\*|@))+$/.test(s.name) && (s.inDef === 'interface' || s.inDef === 'template')) continue;
          patterns.push(new RegExp('^' + s.name.split(/\$(?:\d+|\*|@)/).map(x => x.replace(/\$/g, '\\$')).join('\\w*') + '$'));
          continue;
        }
        let a = byName.get(s.name);
        if (!a) byName.set(s.name, a = []);
        a.push({ ...s, f });
      }
    }
    return (this._symSites = { byName, patterns });
  }

  /**
   * Whether ifdef/ifndef branch `b` of file `f` sees its name defined:
   * { v: true | false | null (can't tell), kind, site? }. The branch is
   * compiled when v === b.want; null keeps it active but "undecided".
   */
  branchState(f, b) {
    if (!this._branchState) this._branchState = new Map();
    let st = this._branchState.get(b);
    if (st) return st;
    this._branchState.set(b, { v: null, kind: 'cycle' });
    st = this._decideBranch(f, b);
    this._branchState.set(b, st);
    return st;
  }

  _decideBranch(f, b) {
    const m4 = this.m4, sym = b.sym;
    if (!m4) return { v: null, kind: 'noflags' };
    // Where m4 evaluates the ifdef: in the body of a definition, wherever it
    // is expanded (a .te or another interface); otherwise as the file is read.
    const role = b.inDef ? 'call' : m4Role(f.path);
    if (m4.universe.has(sym) || m4.patterns.some(re => re.test(sym))) {
      if (!this.decides(sym)) return { v: null, kind: 'flag-defined' };
      // all_interfaces.conf is made without the flags; keep .if top level undecided.
      if (role === 'if') return { v: null, kind: 'flag-if' };
      return { v: m4.defined.has(sym), kind: 'flag' };
    }
    if (m4.stepOnly.has(sym)) return { v: null, kind: 'step' };
    if (M4_BUILTINS.has(sym)) return { v: true, kind: 'builtin' };
    const { byName, patterns } = this.symSites();
    if (patterns.some(re => re.test(sym))) return { v: null, kind: 'pattern' };
    const sites = byName.get(sym) || [];
    // ifndef(`X', `interface(`X', ...)'): the guard of X's own definition.
    if (!b.want && sites.some(s => s.f === f && !s.inDef && !UNDEFINING.has(s.op) && inRange(s, b))) return { v: false, kind: 'guard' };
    let found = null, defUnsure = false, undefUnsure = false, offOnly = false;
    for (const s of sites) {
      const rel = siteRelevance(role, f, b, s);
      if (rel === 'ignore') continue;
      const undef = UNDEFINING.has(s.op);
      if (rel === 'unsure' || s.inDef || undef) { if (undef) undefUnsure = true; else defUnsure = true; continue; }
      const at = this.siteState(s);
      if (at === 'inactive') { offOnly = true; continue; }
      if (at === 'unknown') { defUnsure = true; continue; }
      if (!found) found = s;
    }
    if (undefUnsure) return { v: null, kind: 'undefined-somewhere' };
    if (found) return { v: true, kind: 'defined', site: found };
    if (defUnsure) return { v: null, kind: 'maybe' };
    return { v: false, kind: offOnly ? 'inactive-only' : sites.length ? 'not-visible' : 'nowhere' };
  }

  /** 'active' | 'inactive' | 'unknown': whether a definition site is part of this configuration. */
  siteState(s) {
    let unknown = false;
    for (const br of s.f.branches || []) {
      if (!inRange(s, br)) continue;
      const st = this.branchState(s.f, br);
      if (st.v === null) unknown = true;
      else if (st.v !== br.want) return 'inactive';
    }
    return unknown ? 'unknown' : 'active';
  }

  /** The first inactive ifdef/ifndef branch of file `f` that contains (l, c), or null. */
  inactiveBranchAt(f, l, c) {
    if (!this.m4 || !f || !f.branches || !f.branches.length) return null;
    const p = { l, c };
    for (const b of f.branches) {
      if (!inRange(p, b)) continue;
      const st = this.branchState(f, b);
      if (st.v !== null && st.v !== b.want) return b;
    }
    return null;
  }

  isActive(f, l, c) { return !this.inactiveBranchAt(f, l, c); }

  /** Is (l, c) inside an ifdef/ifndef branch that can't be decided? */
  undecidedAt(f, l, c) {
    const p = { l, c };
    for (const b of (f && f.branches) || []) {
      if (inRange(p, b) && this.branchState(f, b).v === null) return true;
    }
    return false;
  }

  /** Why branch `b` of `f` is (not) compiled, as a sentence for the editor. */
  branchReason(f, b) {
    const st = this.branchState(f, b);
    const needs = `needs \`${b.sym}\` ${b.want ? 'defined' : 'not defined'}`;
    const rel = (p) => path.basename(p);
    switch (st.kind) {
      case 'flag': return `${needs}; it is a build flag, ${st.v ? 'passed' : 'not passed'} by this build configuration.`;
      case 'nowhere': return `${needs}; nothing in the policy sources or build flags defines it.`;
      case 'not-visible': return `${needs}; it is defined only where m4 hasn't read it yet at this point (later in the file, or another module).`;
      case 'inactive-only': return `${needs}; it is defined only in ifdef branches this configuration doesn't compile.`;
      case 'defined': return `${needs}; it is defined in ${rel(st.site.f.path)}:${st.site.l + 1}.`;
      case 'builtin': return `${needs}; it is an m4 builtin.`;
      case 'guard': return `${needs}; this is the guard around its own definition.`;
      default: return `${needs}.`;
    }
  }

  /** Role names declared anywhere in the sources (any branch, generated ones included), plus object_r. */
  knownRoles() {
    if (this._roles) return this._roles;
    const roles = new Set(['object_r']);
    for (const [n, list] of this.decls || []) if (list.some(d => d.kind === 'role')) roles.add(n);
    for (const f of this.files.values()) for (const d of f.decls || []) if (d.kind === 'role') roles.add(d.name);
    return (this._roles = roles);
  }

  /** Inactive branches of a file (for dimming in the editor). */
  inactiveBranches(f) {
    if (!this.m4 || !f || !f.branches) return [];
    return f.branches.filter(b => { const st = this.branchState(f, b); return st.v !== null && st.v !== b.want; });
  }

  /* ----- loading ----- */

  /** Index every policy file under `roots`, except in the `exclude` directories (other policy trees). */
  scanRoots(roots, exclude = []) {
    const found = [];
    const skip = new Set(exclude);
    const walk = (dir, depth) => {
      if (depth > 12 || skip.has(dir)) return;
      let ents;
      try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of ents) {
        if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) walk(path.join(dir, e.name), depth + 1); }
        else if (e.isFile() && classifyFile(e.name)) found.push(path.join(dir, e.name));
      }
    };
    for (const r of roots) walk(r, 0);
    for (const f of found) {
      try { this.setFile(f, fs.readFileSync(f, 'utf8'), true); } catch (e) { this.log(`read failed ${f}: ${e.message}`); }
    }
    this.rebuild();
    return found.length;
  }

  setFile(fsPath, text, deferRebuild) {
    const kind = classifyFile(fsPath);
    if (!kind) return;
    let r;
    if (kind === 'flask') r = parseFlask(text, path.basename(fsPath));
    else if (kind === 'fc') r = parseFc(text);
    else r = parsePolicy(text);
    if (path.basename(fsPath) === 'all_perms.spt') r.genClasses = parseAllPerms(text);
    r.path = fsPath;
    r.fileKind = kind;
    Object.assign(r, moduleInfo(fsPath));
    this.files.set(fsPath, r);
    if (!deferRebuild) this.rebuild();
  }

  removeFile(fsPath) {
    if (this.files.delete(fsPath)) this.rebuild();
  }

  /* ----- global tables ----- */

  rebuild() {
    const t0 = Date.now();
    this._genSites = null;
    this._symSites = null;
    this._branchState = null;
    this._teRequires = null;
    this._requiredKinds = null;
    this._declMods = null;
    const defs = new Map();   // name -> [def]
    const decls = new Map();  // name -> [decl]
    const classes = new Map();
    const commons = new Map();
    const fcByType = new Map();
    const push = (m, k, v) => { let a = m.get(k); if (!a) m.set(k, a = []); a.push(v); };

    for (const f of this.files.values()) {
      if (f.kind === 'flask') {
        for (const c of f.commons) commons.set(c.name, { ...c, path: f.path });
        for (const c of f.classes) {
          const prev = classes.get(c.name);
          if (prev && c.declOnly) continue; // access_vectors entry wins over security_classes
          classes.set(c.name, { ...c, path: f.path });
        }
        continue;
      }
      for (const d of f.defs) { d.path = f.path; push(defs, d.name, d); }
    }
    // Definitions in branches the build flags turn off don't exist in this
    // configuration. Decided in a second pass, so a flag that is itself
    // define()d somewhere stays undecided (decides() looks at this.defs).
    this.defs = defs;
    const inactiveDefs = new Map();
    for (const f of this.files.values()) {
      if (f.kind === 'flask') continue;
      if (f.kind === 'fc') for (const e of f.entries) if (this.isActive(f, e.l, e.c)) push(fcByType, e.type, { ...e, path: f.path });
      for (const d of f.defs) {
        const b = this.inactiveBranchAt(f, d.l, d.c);
        d.inactive = b || undefined;
        if (!b) continue;
        const list = defs.get(d.name);
        list.splice(list.indexOf(d), 1);
        if (!list.length) defs.delete(d.name);
        push(inactiveDefs, d.name, d);
      }
      for (const d of f.decls) {
        d.path = f.path;
        if (this.isActive(f, d.l, d.c)) push(decls, d.name, d);
      }
    }
    this.inactiveDefs = inactiveDefs;
    // The devel headers ship no flask files, but support/all_perms.spt
    // (generated from them at build time) lists every class with all its perms.
    if (!classes.size) {
      for (const f of this.files.values()) {
        for (const c of f.genClasses || []) if (!classes.has(c.name)) classes.set(c.name, { ...c, path: f.path });
      }
    }
    // Resolve inherited permissions
    for (const c of classes.values()) {
      c.allPerms = new Set(c.perms);
      if (c.inherits && commons.has(c.inherits)) for (const p of commons.get(c.inherits).perms) c.allPerms.add(p);
    }

    // Macros generated at build time by support/genclassperms.py (all_perms.spt)
    const synth = (name, cls, summary) => {
      if (defs.has(name)) return;
      defs.set(name, [{ kind: 'define', name, path: cls.path, l: cls.l, c: cls.c, len: cls.name.length, generated: true,
        via: 'genclassperms.py', doc: { summary, params: [] }, declPatterns: [], bodyCalls: [], requires: [], reqBlocks: [] }]);
    };
    for (const c of classes.values()) synth(`all_${c.name}_perms`, c, `All permissions of class ${c.name} (generated at build time).`);
    const anyClass = classes.values().next().value;
    if (anyClass) {
      synth('all_kernel_class_perms', anyClass, 'All kernel object classes with all permissions (generated at build time).');
      synth('all_userspace_class_perms', anyClass, 'All userspace object classes with all permissions (generated at build time).');
    }

    this.defs = defs;
    this.decls = decls;
    this._roles = null;
    this.classes = classes;
    this.commons = commons;
    this.fcByType = fcByType;
    this.expandGenerated();
    this.built = true;
    this.log(`index rebuilt: ${this.files.size} files, ${defs.size} macros, ${decls.size} declared names, ${classes.size} classes in ${Date.now() - t0} ms`);
  }

  /**
   * Expand templates/defines whose bodies declare $N-patterned names
   * (types, nested interfaces), so generated names resolve to the call site.
   */
  expandGenerated() {
    const defs = this.defs;
    const generative = new Set();
    for (const [name, list] of defs) if (list.some(d => d.declPatterns.length)) generative.add(name);
    let changed = true;
    while (changed) {
      changed = false;
      for (const [name, list] of defs) {
        if (generative.has(name)) continue;
        if (list.some(d => d.bodyCalls.some(bc => generative.has(bc.name)))) { generative.add(name); changed = true; }
      }
    }
    this.generative = generative;

    const subst = (s, args) => s.replace(/\$(\d+)/g, (_, n) => (args[+n - 1] !== undefined ? args[+n - 1] : ''));
    const spliceArgs = (raw, args) => {
      const out = [];
      for (const a of raw) {
        if (a === '$*' || a === '$@') out.push(...args);
        else if (/^shift\(\$[*@]\)$/.test(a)) out.push(...args.slice(1));
        else out.push(subst(a, args));
      }
      return out;
    };
    const valid = s => /^[A-Za-z0-9_]+$/.test(s);

    const genDecls = new Map();
    const genDefs = new Map();
    const push = (m, k, v) => { let a = m.get(k); if (!a) m.set(k, a = []); a.push(v); };

    const expand = (name, args, site, depth) => {
      if (depth > 5) return;
      for (const d of defs.get(name) || []) {
        for (const p of d.declPatterns) {
          if (!this.whenHolds(p.when, args)) continue;
          const n = subst(p.pattern, args);
          if (!valid(n)) continue;
          if (p.kind === 'interface' || p.kind === 'template' || p.kind === 'define') {
            const doc = p.doc ? substDoc(p.doc, args) : null;
            push(genDefs, n, { kind: p.kind, name: n, path: site.path, l: site.l, c: site.c, len: site.len, doc, generated: true, via: site.name, declPatterns: [], bodyCalls: [], requires: [], reqBlocks: [] });
          } else {
            push(genDecls, n, { kind: p.kind, name: n, path: site.path, l: site.l, c: site.c, len: site.len, attrs: [], generated: true, via: site.name });
          }
        }
        for (const bc of d.bodyCalls) {
          if (!generative.has(bc.name) || !this.whenHolds(bc.when, args)) continue;
          expand(bc.name, spliceArgs(bc.args, args), site, depth + 1);
        }
      }
    };
    const substDoc = (doc, args) => {
      const s = x => x.replace(/\$(\d+)/g, (_, n) => args[+n - 1] || `$${n}`);
      return { ...doc, summary: s(doc.summary || ''), desc: s(doc.desc || ''), params: (doc.params || []).map(p => ({ ...p, summary: s(p.summary) })) };
    };

    for (const f of this.files.values()) {
      if (!f.calls) continue;
      for (const c of f.calls) {
        if (!generative.has(c.name) || !this.isActive(f, c.l, c.c)) continue;
        if (c.inDef && c.args.some(a => a.includes('$'))) continue;
        expand(c.name, c.args, { path: f.path, l: c.l, c: c.c, len: c.len, name: c.name }, 0);
      }
    }
    const same = (a, b) => a.path === b.path && a.l === b.l;
    for (const [k, v] of genDecls) {
      const a = this.decls.get(k);
      const fresh = a ? v.filter(g => !a.some(x => same(x, g))) : v;
      if (!fresh.length) continue;
      if (a) a.push(...fresh); else this.decls.set(k, fresh);
    }
    for (const [k, v] of genDefs) { const a = this.defs.get(k); if (a) a.push(...v); else this.defs.set(k, v); }
  }

  /* ----- queries ----- */

  isMacro(name) { return this.defs.has(name) || M4_BUILTINS.has(name); }
  isBuiltin(name) { return M4_BUILTINS.has(name); }

  /** Everything that defines `name`: macros, declarations, classes. */
  definitionsOf(name) {
    const out = [];
    for (const d of this.defs.get(name) || []) out.push({ path: d.path, l: d.l, c: d.c, len: d.len, what: d });
    for (const d of this.decls.get(name) || []) out.push({ path: d.path, l: d.l, c: d.c, len: d.len, what: d });
    const cls = this.classes.get(name);
    if (cls) out.push({ path: cls.path, l: cls.l, c: cls.c, len: name.length, what: { kind: 'class', ...cls } });
    const com = this.commons.get(name);
    if (com) out.push({ path: com.path, l: com.l, c: com.c, len: name.length, what: { kind: 'common', ...com } });
    return out;
  }

  referencesOf(name) {
    const out = [];
    for (const f of this.files.values()) {
      const a = f.refs && f.refs.get(name);
      if (a) for (const [l, c] of a) out.push({ path: f.path, l, c, len: name.length });
    }
    return out;
  }

  /** Attributes a type has, from its declaration and typeattribute-style calls. */
  attributesOf(name) {
    const out = new Set();
    for (const d of this.decls.get(name) || []) for (const a of d.attrs || []) out.add(a);
    return [...out];
  }

  permsOf(cls) {
    const c = this.classes.get(cls);
    return c ? [...c.allPerms] : null;
  }

  /** Cheap check for "is this a type or attribute declared somewhere". */
  isTypeLike(name) {
    const a = this.decls.get(name);
    return !!(a && a.some(d => d.kind === 'type' || d.kind === 'attribute'));
  }

  /**
   * A file belongs to a module if it sits in a refpolicy modules/ tree, or
   * has a .te next to it (standalone module dirs, as the devel Makefile sees
   * them). Devel-header .if files have no .te and stay out of the list.
   */
  isModuleFile(p) {
    return /modules[\\/]/.test(p) || this.files.has(p.replace(/\.(if|fc)$/, '.te'));
  }

  modules() {
    const mods = new Map();
    for (const f of this.files.values()) {
      if (!/\.(te|if|fc)$/.test(f.path)) continue;
      if (!this.isModuleFile(f.path)) continue;
      const key = `${f.layer}/${f.module}`;
      let m = mods.get(key);
      if (!m) mods.set(key, m = { layer: f.layer, module: f.module, files: {} });
      m.files[path.extname(f.path).slice(1)] = f.path;
    }
    return [...mods.values()].sort((a, b) => a.layer.localeCompare(b.layer) || a.module.localeCompare(b.module));
  }

  moduleContents(teOrIfPath) {
    const base = teOrIfPath.replace(/\.(te|if|fc)$/, '');
    const te = this.files.get(base + '.te');
    const iff = this.files.get(base + '.if');
    const fc = this.files.get(base + '.fc');
    return {
      types: te ? te.decls.filter(d => d.kind === 'type').map(d => ({ name: d.name, path: te.path, l: d.l, c: d.c })) : [],
      attributes: te ? te.decls.filter(d => d.kind === 'attribute').map(d => ({ name: d.name, path: te.path, l: d.l, c: d.c })) : [],
      booleans: te ? te.decls.filter(d => d.kind === 'bool').map(d => ({ name: d.name, path: te.path, l: d.l, c: d.c })) : [],
      interfaces: iff ? iff.defs.map(d => ({ name: d.name, kind: d.kind, path: iff.path, l: d.l, c: d.c, summary: d.doc && d.doc.summary })) : [],
      fileContexts: fc ? fc.entries.map(e => ({ name: `${e.spec} → ${e.type}`, path: fc.path, l: e.l, c: e.c })) : [],
    };
  }

  stats() {
    let modules = 0, interfaces = 0, templates = 0, types = 0;
    for (const f of this.files.values()) if (f.path.endsWith('.te') && this.isModuleFile(f.path)) modules++;
    for (const list of this.defs.values()) for (const d of list) { if (d.kind === 'interface') interfaces++; else if (d.kind === 'template') templates++; }
    for (const list of this.decls.values()) if (list.some(d => d.kind === 'type')) types++;
    return { files: this.files.size, modules, interfaces, templates, types, classes: this.classes.size };
  }
}

module.exports = { PolicyIndex, classifyFile, M4_BUILTINS };
