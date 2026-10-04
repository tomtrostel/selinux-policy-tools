'use strict';
/*
 * Explain compiled-policy changes in terms of source lines.
 *
 * A build's m4 output (tmp/<mod>.tmp, base.conf / policy.conf) carries `#line`
 * markers back to the .te/.if sources and refpolicy's `##### begin/end` call
 * markers. We index its rule-like statements (allow & co, type_transition &
 * co, typeattribute, `type T, attrs`) with their source line and the
 * interface call they came through, then, for each changed compiled rule, find
 * the statements that produce it, including attribute rules plus the
 * statement that put the type into the attribute.
 *
 * This reads statements the real m4 produced; it doesn't expand anything.
 */
const fs = require('fs');

const AV = new Set(['allow', 'dontaudit', 'auditallow', 'neverallow']);
const TT = new Set(['type_transition', 'type_change', 'type_member']);

/** Tokens of one statement line: words, braces, ':', ';', '~', '*', '-'. */
const tokenize = (s) => s.match(/"[^"]*"|[{}:;,~*]|-(?=\w)|[^\s{}:;,~*"]+/g) || [];

/** A name or a { set } at tokens[i] (nested sets flattened); '-x' and '~' mark exclusions. */
function readSet(tok, i) {
  const items = [];
  let neg = false;
  if (tok[i] === '~') { neg = true; i++; }
  if (tok[i] !== '{') return { items: tok[i] !== undefined ? [tok[i]] : [], i: i + 1, neg };
  let depth = 0;
  for (; i < tok.length; i++) {
    const t = tok[i];
    if (t === '{') depth++;
    else if (t === '}') { if (--depth === 0) return { items, i: i + 1, neg }; }
    else if (t === '-') { neg = true; }
    else if (t !== ',') items.push(t);
  }
  return { items, i, neg };
}

/** Parse one statement line into { rt, srcs, tgts, classes, perms } or { rt:'typeattribute', type, attrs }. */
function parseStatement(line) {
  const s = line.trim();
  const m = /^(\w+)\s/.exec(s);
  if (!m || !s.endsWith(';')) return null;
  const rt = m[1];
  const tok = tokenize(s.slice(rt.length, -1));
  if (AV.has(rt) || TT.has(rt)) {
    const a = readSet(tok, 0), b = readSet(tok, a.i);
    if (tok[b.i] !== ':') return null;
    const c = readSet(tok, b.i + 1), p = readSet(tok, c.i);
    return { rt, srcs: a.items, tgts: b.items, classes: c.items, perms: p.items, loose: a.neg || b.neg || c.neg || p.neg || p.items.includes('*') };
  }
  if (rt === 'typeattribute') {
    const [type, ...rest] = tok;
    return { rt, type, attrs: rest.filter(t => t !== ',') };
  }
  if (rt === 'type') {
    // type T [alias {..}] [, attr, attr];
    const comma = tok.indexOf(',');
    if (comma < 0) return null;
    return { rt: 'typeattribute', type: tok[0], attrs: tok.slice(comma + 1).filter(t => t !== ',') };
  }
  return null;
}

/**
 * Index the statements of one m4 output file.
 * Returns [{ ...statement, path, line (0-based), via: 'outer_call(args)' | null, chain: [...] }].
 */
// Names, permissions and classes recur hundreds of thousands of times across a
// build's output: keep one copy of each (and no slices pinning whole files).
const interned = new Map();
const intern = (s) => { let v = interned.get(s); if (v === undefined) { v = (' ' + s).slice(1); interned.set(v, v); } return v; };

function indexOutput(text, resolveFile, outputPath) {
  const out = [];
  let real = null, next = 0;
  const stack = [];
  let chain = null; // shared by consecutive statements under the same calls
  const lines = text.split('\n');
  for (let k = 0; k < lines.length; k++) {
    const raw = lines[k];
    if (raw.charCodeAt(0) === 35) { // '#'
      const d = /^#line (\d+)(?: "(.*)")?$/.exec(raw);
      if (d) { if (d[2] !== undefined) real = resolveFile(d[2]); next = +d[1]; continue; }
      if (raw.startsWith('##### begin ')) { stack.push(intern(raw.slice(12, raw.lastIndexOf(' depth:')))); chain = null; next++; continue; }
      if (raw.startsWith('##### end ')) { stack.pop(); chain = null; next++; continue; }
    }
    const line = next++;
    if (!real) continue;
    const st = /^\s*(allow|dontaudit|auditallow|neverallow|type_transition|type_change|type_member|typeattribute|type)\s/.test(raw) && parseStatement(raw);
    if (!st) continue;
    for (const f of ['srcs', 'tgts', 'classes', 'perms', 'attrs']) if (st[f]) st[f] = st[f].map(intern);
    if (st.type) st.type = intern(st.type);
    st.rt = intern(st.rt);
    if (stack.length && !chain) chain = stack.slice();
    st.path = real;
    st.line = line - 1;
    st.chain = stack.length ? chain : null;
    st.out = outputPath;   // where to read the statement text back from
    st.oline = k;
    out.push(st);
  }
  return out;
}

/** The text of a statement, read back from its output file (only done for the few shown). */
function statementText(st, fileCache = new Map()) {
  if (!st.out) return '';
  let lines = fileCache.get(st.out);
  if (!lines) { try { lines = fs.readFileSync(st.out, 'utf8').split('\n'); } catch { lines = []; } fileCache.set(st.out, lines); }
  return (lines[st.oline] || '').trim();
}

const cache = new Map(); // output path -> { mtimeMs, statements }
/** Drop all indexed statements (the server does this when comparisons go idle). */
const dropCache = () => { cache.clear(); interned.clear(); textCache.clear(); };

/** Statements of all outputs of a build (cached per file by mtime). */
function indexBuild(outputs, resolveFile) {
  const all = [];
  for (const p of outputs) {
    let st;
    try { st = fs.statSync(p); } catch { continue; }
    let c = cache.get(p);
    if (!c || c.mtimeMs !== st.mtimeMs) {
      c = { mtimeMs: st.mtimeMs, statements: indexOutput(fs.readFileSync(p, 'utf8'), resolveFile, p) };
      cache.set(p, c);
    }
    for (const s of c.statements) all.push(s);
  }
  return all;
}

/**
 * Index statements by the names they mention, for quick lookup.
 */
function byName(statements) {
  const m = new Map();
  const add = (k, s) => { let a = m.get(k); if (!a) m.set(k, a = []); a.push(s); };
  for (const s of statements) {
    if (s.rt === 'typeattribute') { add(s.type, s); continue; }
    for (const n of new Set([...s.srcs, ...s.tgts])) add(n, s);
  }
  return m;
}

const textCache = new Map(); // output file -> lines, only while explaining one diff
const origin = (s) => ({ path: s.path, line: s.line, text: statementText(s, textCache), via: s.chain ? s.chain[0] : null, chain: s.chain });
/** Forget output file contents read for statement texts (call after explaining a diff). */
const releaseTexts = () => textCache.clear();

/**
 * Explain one changed compiled rule from one side's statements.
 * side: { index: byName map, attrs: { type: [attrs] }, gained: Map(type -> Set(attrs)) , changedFiles: Set(paths) }
 * perms: the permissions (or default types) that changed on this side.
 * Returns { origins: [{ path, line, text, via, chain, because: [origin] }], more }.
 */
function explainRule(rule, perms, side, max = 6) {
  const sNames = new Set([rule.s, ...(side.attrs[rule.s] || [])]);
  const tNames = new Set([rule.t, ...(side.attrs[rule.t] || [])]);
  const isTT = TT.has(rule.rt);
  const want = new Set(perms);
  const seen = new Set();
  const hits = [];
  for (const n of sNames) {
    for (const st of side.index.get(n) || []) {
      if (seen.has(st)) continue;
      seen.add(st);
      if (st.rt !== rule.rt || !st.classes.includes(rule.c)) continue;
      if (!st.srcs.some(x => sNames.has(x))) continue;
      if (!(st.tgts.some(x => tNames.has(x)) || (st.tgts.includes('self') && rule.t === rule.s))) continue;
      if (!st.loose && !isTT && !st.perms.some(p => want.has(p))) continue;
      if (isTT && !st.perms.some(p => want.has(p))) continue;
      hits.push(st);
    }
  }
  const direct = (st) => st.srcs.includes(rule.s) && (st.tgts.includes(rule.t) || st.tgts.includes('self'));
  const changed = (st) => side.changedFiles && side.changedFiles.has(st.path);
  hits.sort((a, b) => (changed(b) - changed(a)) || (direct(b) - direct(a)) || a.path.localeCompare(b.path) || a.line - b.line);
  const origins = hits.slice(0, max).map((st) => {
    const o = origin(st);
    // An attribute rule: say why the type is in the attribute, if that changed.
    const because = [];
    for (const [type, attrsUsed] of [[rule.s, st.srcs], [rule.t, st.tgts]]) {
      const gained = side.gained && side.gained.get(type);
      if (!gained) continue;
      for (const a of attrsUsed) if (gained.has(a)) because.push(...membershipOrigins(type, a, side, 2));
    }
    if (because.length) o.because = because;
    return o;
  });
  return { origins, more: Math.max(0, hits.length - max) };
}

/** Statements that put `type` into attribute `attr` (typeattribute / type T, attr). */
function membershipOrigins(type, attr, side, max = 4) {
  const hits = (side.index.get(type) || []).filter(st => st.rt === 'typeattribute' && st.type === type && st.attrs.includes(attr));
  const changed = (st) => side.changedFiles && side.changedFiles.has(st.path);
  hits.sort((a, b) => (changed(b) - changed(a)) || a.path.localeCompare(b.path) || a.line - b.line);
  return hits.slice(0, max).map(origin);
}

module.exports = { parseStatement, indexOutput, indexBuild, byName, explainRule, membershipOrigins, releaseTexts, dropCache };
