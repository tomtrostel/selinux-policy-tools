'use strict';
/*
 * Install profiles from CLIP-style kickstarts (kickstart/<profile>/<profile>.ks):
 * which policy module packages (selinux-policy-<type>-<module>, one per
 * SEPARATE_PKGS module) a profile installs. A module packaged separately is
 * in the policy store only when its package is installed, so optional_policy
 * blocks that need it are dropped at link time on hosts of other profiles.
 *
 * %packages sections are read with their %include files (relative to the
 * kickstart directory; a missing file is rendered from its .tmpl, as CLIP's
 * kickstart/Makefile does with mako-render). Mako `% if` / `% elif` / `% else`
 * lines are decided with CONFIG_BUILD's values; an expression that can't be
 * decided keeps both branches, their lines marked unsure. @group lines are
 * resolved through comps.xml (mandatory + default packages; --nodefaults:
 * mandatory only; --optional adds optional ones). Pure: files come through
 * readFile(path) → text | null.
 */

const path = require('path');

/** comps.xml → Map id → { mandatory, default, optional, conditional, groups (environments) }. */
function parseComps(text) {
  const out = new Map();
  if (!text) return out;
  for (const m of text.matchAll(/<(group|environment)>([\s\S]*?)<\/\1>/g)) {
    const id = /<id>\s*([^<]+?)\s*<\/id>/.exec(m[2]);
    if (!id) continue;
    const g = { kind: m[1], mandatory: [], default: [], optional: [], conditional: [], groups: [] };
    for (const p of m[2].matchAll(/<packagereq\b([^>]*)>\s*([^<]+?)\s*<\/packagereq>/g)) {
      const t = (/type="([^"]+)"/.exec(p[1]) || [, 'mandatory'])[1];
      (g[t] || g.mandatory).push(p[2]);
    }
    for (const p of m[2].matchAll(/<groupid\b[^>]*>\s*([^<]+?)\s*<\/groupid>/g)) g.groups.push(p[1]);
    out.set(id[1], g);
  }
  return out;
}

/* ---------- Mako conditions: a small Python expression subset ---------- */

function tokenize(s) {
  const toks = [];
  const re = /\s*(?:("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(\d+(?:\.\d+)?)|([A-Za-z_]\w*)|(==|!=|>=|<=|>|<|\(|\)|,))/y;
  let m;
  while (re.lastIndex < s.length && (m = re.exec(s))) {
    if (m[1] != null) toks.push({ t: 'str', v: m[1].slice(1, -1) });
    else if (m[2] != null) toks.push({ t: 'num', v: +m[2] });
    else if (m[3] != null) toks.push({ t: 'id', v: m[3] });
    else toks.push({ t: 'op', v: m[4] });
  }
  if (s.slice(re.lastIndex).trim()) return null;
  return toks;
}

/**
 * Evaluates a Mako `% if` expression: true / false, or null when it can't be
 * decided (unknown variable, unsupported syntax). Unknown values propagate
 * (and/or as in three-valued logic).
 */
function evalCondition(expr, vars) {
  const toks = tokenize(expr);
  if (!toks) return null;
  let i = 0;
  const U = undefined; // unknown value
  const peek = () => toks[i];
  const take = (v) => (toks[i] && toks[i].v === v ? toks[i++] : null);
  function primary() {
    const t = toks[i++];
    if (!t) throw new Error('end');
    if (t.t === 'str' || t.t === 'num') return t.v;
    if (t.v === '(') { const v = orExpr(); if (!take(')')) throw new Error(')'); return v; }
    if (t.t === 'id') {
      if (t.v === 'True') return true;
      if (t.v === 'False') return false;
      if ((t.v === 'float' || t.v === 'int' || t.v === 'str') && take('(')) {
        const v = orExpr();
        if (!take(')')) throw new Error(')');
        if (v === U) return U;
        if (t.v === 'str') return String(v);
        const n = t.v === 'int' ? parseInt(v, 10) : parseFloat(v);
        return Number.isNaN(n) ? U : n;
      }
      return Object.prototype.hasOwnProperty.call(vars, t.v) ? vars[t.v] : U;
    }
    throw new Error('syntax');
  }
  function compare() {
    const a = primary();
    const op = peek();
    if (!op || op.t !== 'op' || !/^(==|!=|>=|<=|>|<)$/.test(op.v)) return a;
    i++;
    const b = primary();
    if (a === U || b === U) return U;
    switch (op.v) {
      case '==': return a == b; // eslint-disable-line eqeqeq
      case '!=': return a != b; // eslint-disable-line eqeqeq
      case '>=': return a >= b;
      case '<=': return a <= b;
      case '>': return a > b;
      default: return a < b;
    }
  }
  function notExpr() {
    if (take('not')) { const v = notExpr(); return v === U ? U : !truthy(v); }
    return compare();
  }
  const truthy = (v) => (v === U ? U : !!v && v !== '');
  // Values pass through unchanged unless and/or combine them (float(X) needs X's text).
  function andExpr() {
    let v = notExpr();
    while (take('and')) { const a = truthy(v), w = truthy(notExpr()); v = a === false || w === false ? false : a === U || w === U ? U : true; }
    return v;
  }
  function orExpr() {
    let v = andExpr();
    while (take('or')) { const a = truthy(v), w = truthy(andExpr()); v = a === true || w === true ? true : a === U || w === U ? U : false; }
    return v;
  }
  try {
    const v = orExpr();
    if (i !== toks.length) return null;
    const t = truthy(v);
    return t === U ? null : t;
  } catch { return null; }
}

/**
 * Lines of a Mako template that render, with `unsure` for lines inside a
 * branch whose condition couldn't be decided: [{ text, line, unsure }].
 * Control lines (% if …) and ## comments are left out.
 */
function renderMako(text, vars) {
  const out = [];
  const stack = []; // { taken: true|false|null (some earlier branch), cur: true|false|null }
  const state = () => {
    let unsure = false;
    for (const s of stack) { if (s.cur === false) return false; if (s.cur === null) unsure = true; }
    return unsure ? null : true;
  };
  text.split('\n').forEach((raw, n) => {
    const ctl = /^\s*%\s*(if|elif|else|endif|for|endfor)\b\s*(.*?)\s*:?\s*$/.exec(raw);
    if (ctl) {
      const [, kw, rest] = ctl;
      if (kw === 'if') { const v = evalCondition(rest, vars); stack.push({ taken: v, cur: v }); }
      else if (kw === 'elif' && stack.length) {
        const s = stack[stack.length - 1];
        const v = evalCondition(rest, vars);
        // taken: whether an earlier branch was taken (null: maybe).
        if (s.taken === true) s.cur = false;
        else if (s.taken === false) { s.cur = v; s.taken = v; }
        else { s.cur = v === false ? false : null; s.taken = v === true ? true : null; }
      } else if (kw === 'else' && stack.length) {
        const s = stack[stack.length - 1];
        s.cur = s.taken === true ? false : s.taken === false ? true : null;
      } else if (kw === 'endif') stack.pop();
      else if (kw === 'for') stack.push({ taken: null, cur: null });
      else if (kw === 'endfor') stack.pop();
      return;
    }
    if (/^\s*##/.test(raw)) return;
    const st = state();
    if (st === false) return;
    out.push({ text: raw, line: n, unsure: st === null });
  });
  return out;
}

/**
 * A kickstart's package selection: { packages: Map name → { file, line,
 * unsure, group? }, excluded: Map name → { file, line }, groups: [{ id,
 * file, line, unsure, nodefaults, optional, missing }], notes }.
 * `base` is the directory %include paths are relative to.
 */
function readKickstart(ksPath, { readFile, vars = {}, comps = new Map(), base = path.dirname(path.dirname(ksPath)) }) {
  const packages = new Map(), excluded = new Map(), groups = [], notes = [];
  const explicit = new Set();
  const seen = new Set();
  const linesOf = (file) => {
    let text = readFile(file);
    if (text != null) return { file, lines: text.split('\n').map((t, line) => ({ text: t, line, unsure: false })) };
    text = readFile(`${file}.tmpl`);
    if (text != null) return { file: `${file}.tmpl`, lines: renderMako(text, vars) };
    return null;
  };
  const addGroup = (id, opts, at, unsure, depth = 0) => {
    const g = comps.get(id.replace(/^\^/, ''));
    groups.push({ id, file: at.file, line: at.line, unsure, nodefaults: opts.nodefaults, optional: opts.optional, missing: !g });
    if (!g || depth > 5) return;
    for (const sub of g.groups) addGroup(sub, opts, at, unsure, depth + 1);
    const names = [...g.mandatory, ...(opts.nodefaults ? [] : g.default), ...(opts.optional ? g.optional : [])];
    for (const n of names) if (!packages.has(n)) packages.set(n, { file: at.file, line: at.line, unsure, group: id });
  };
  const inPackages = (file, lines, depth) => {
    for (const { text, line, unsure } of lines) {
      const s = text.replace(/\s+#.*$/, '').trim();
      if (!s || s.startsWith('#')) continue;
      const inc = /^%include\s+(\S+)/.exec(s);
      if (inc) { include(inc[1], { file, line }, depth, unsure); continue; }
      if (/^%end\b/.test(s)) return true;
      if (s.startsWith('%')) continue;
      if (s.startsWith('@')) {
        const [id, ...flags] = s.slice(1).split(/\s+/);
        addGroup(id, { nodefaults: flags.includes('--nodefaults'), optional: flags.includes('--optional') }, { file, line }, unsure);
        continue;
      }
      if (s.startsWith('-')) { excluded.set(s.slice(1).trim(), { file, line, unsure }); continue; }
      const name = s.split(/\s+/)[0];
      packages.set(name, { file, line, unsure });
      explicit.add(name);
    }
    return false;
  };
  const include = (rel, at, depth, unsure) => {
    if (path.isAbsolute(rel)) { notes.push(`${rel} (included at ${path.basename(at.file)}:${at.line + 1}) is read at install time, not from the sources`); return; }
    const p = path.join(base, rel);
    if (depth > 8 || seen.has(p)) return;
    seen.add(p);
    const got = linesOf(p);
    if (!got) { if (!/^include-at-runtime\//.test(rel)) notes.push(`missing %include ${rel}`); return; }
    inPackages(got.file, unsure ? got.lines.map(l => ({ ...l, unsure: true })) : got.lines, depth + 1);
  };
  const top = linesOf(ksPath);
  if (!top) return null;
  let inSection = false;
  const sectionLines = [];
  for (const l of top.lines) {
    if (/^%packages\b/.test(l.text.trim())) { inSection = true; continue; }
    if (inSection && /^%end\b/.test(l.text.trim())) { inSection = false; continue; }
    if (inSection) sectionLines.push(l);
  }
  inPackages(top.file, sectionLines, 0);
  // -name removes what groups bring in; a package named explicitly stays (CLIP relies on that).
  for (const [n] of excluded) if (!explicit.has(n)) packages.delete(n);
  return { packages, excluded, groups, notes };
}

const globRe = (g) => new RegExp(`^${g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`);

/**
 * Policy modules a kickstart installs among the separately packaged ones:
 * Map module → { state: 'installed' | 'unsure' | 'absent', file, line, pkg }.
 * Packages are selinux-policy-<type>-<module>; glob lines (selinux-policy-*)
 * count for every module they match.
 */
function profileModules(ks, separate, type) {
  const out = new Map();
  const pkgOf = (m) => `selinux-policy-${type}-${m}`;
  const entries = [...ks.packages];
  for (const m of separate) {
    const want = pkgOf(m);
    let hit = ks.packages.get(want);
    let pkg = want;
    if (!hit) {
      const g = entries.find(([n]) => /[*?]/.test(n) && globRe(n).test(want));
      if (g) { hit = g[1]; pkg = g[0]; }
    }
    if (!hit) { out.set(m, { state: 'absent', pkg: want }); continue; }
    const ex = ks.excluded.get(want);
    out.set(m, { state: hit.unsure ? 'unsure' : 'installed', file: hit.file, line: hit.line, pkg, group: hit.group, excludedToo: !!ex });
  }
  return out;
}

/**
 * CLIP's layout around a policy tree: the directory above it with
 * kickstart/<name>/<name>.ks files. → { root, kickstartDir, profiles: [{ name, path }],
 * comps, config } or null.
 */
function findProfiles(treeRoot, { exists, list }) {
  let dir = treeRoot;
  for (let i = 0; i < 6 && dir; i++) {
    const ksDir = path.join(dir, 'kickstart');
    if (exists(ksDir)) {
      const profiles = [];
      for (const name of list(ksDir) || []) {
        const ks = path.join(ksDir, name, `${name}.ks`);
        if (exists(ks)) profiles.push({ name, path: ks });
      }
      if (profiles.length) {
        profiles.sort((a, b) => a.name.localeCompare(b.name));
        const comps = path.join(dir, 'conf', 'yum', 'comps.xml');
        const config = path.join(dir, 'CONFIG_BUILD');
        return { root: dir, kickstartDir: ksDir, profiles, comps: exists(comps) ? comps : null, config: exists(config) ? config : null };
      }
    }
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return null;
}

module.exports = { parseComps, evalCondition, renderMako, readKickstart, profileModules, findProfiles };
