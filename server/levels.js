'use strict';
/*
 * MLS/MCS levels: canonical form, setrans.conf names (mcstrans), and plain
 * descriptions. Pure.
 *
 * A level is a sensitivity with optional categories (s0, s0:c1,c5,
 * s2:c0.c9); a range is low-high (s0-s0:c0.c1023). Canonical form is what
 * the kernel and setools print: categories sorted, runs of two or more
 * written cA.cB (c1,c2 → c1.c2).
 */

/** Categories of "c1,c3.c5" as a sorted array of numbers, or null if malformed. */
function parseCats(s) {
  const out = new Set();
  for (const part of s.split(',')) {
    const m = /^c(\d+)(?:\.c(\d+))?$/.exec(part.trim());
    if (!m) return null;
    const a = +m[1], b = m[2] != null ? +m[2] : a;
    if (b < a || b - a > 65536) return null;
    for (let i = a; i <= b; i++) out.add(i);
  }
  return [...out].sort((x, y) => x - y);
}

function catsText(nums) {
  const out = [];
  for (let i = 0; i < nums.length; i++) {
    let j = i;
    while (j + 1 < nums.length && nums[j + 1] === nums[j] + 1) j++;
    out.push(j > i ? `c${nums[i]}.c${nums[j]}` : `c${nums[i]}`);
    i = j;
  }
  return out.join(',');
}

/** { sens, cats: [numbers] } for one level, or null. */
function parseLevel(s) {
  const m = /^\s*(s\d+)(?::(.+?))?\s*$/.exec(s || '');
  if (!m) return null;
  const cats = m[2] != null ? parseCats(m[2]) : [];
  return cats ? { sens: m[1], cats } : null;
}

const levelText = (l) => (l.cats.length ? `${l.sens}:${catsText(l.cats)}` : l.sens);

/** Canonical text of a level or range ("s0 - s0:c0,c1" → "s0-s0:c0.c1"), or null if it isn't one. */
function canon(s) {
  if (typeof s !== 'string') return null;
  const parts = s.split(/\s*-\s*/);
  if (parts.length > 2) return null;
  const ls = parts.map(parseLevel);
  if (ls.some(l => !l)) return null;
  return ls.map(levelText).join('-');
}

/**
 * setrans.conf: `raw=Name` lines (mcstrans' simple format). Advanced lines
 * (Base=, ModifierGroup=, Include=, Domain=, …) are counted, not used.
 */
function parseSetrans(text) {
  const entries = [], skipped = [];
  (text || '').split('\n').forEach((raw, l) => {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) return;
    const m = /^([^=]+?)\s*=\s*(.+)$/.exec(line);
    const key = m && canon(m[1]);
    if (!key) { skipped.push({ l, text: line }); return; }
    entries.push({ raw: key, written: m[1].trim(), name: m[2].trim(), l });
  });
  const byRaw = new Map(), byName = new Map();
  for (const e of entries) { if (!byRaw.has(e.raw)) byRaw.set(e.raw, e); if (!byName.has(e.name)) byName.set(e.name, e); }
  return { entries, skipped, byRaw, byName };
}

/**
 * The name setrans gives a level or range, as mcstrans shows it: the whole
 * range if it has a line, else each end ("SystemLow-SystemHigh"); null when
 * neither has one.
 */
function translate(s, st) {
  if (!st) return null;
  const c = canon(s);
  if (!c) return null;
  const whole = st.byRaw.get(c);
  if (whole) return whole.name;
  const parts = c.split('-');
  if (parts.length === 2) {
    const a = st.byRaw.get(parts[0]), b = st.byRaw.get(parts[1]);
    if (a || b) return `${a ? a.name : parts[0]}-${b ? b.name : parts[1]}`;
  }
  return null;
}

/** Plain words: "s0:c1,c5" → "sensitivity s0 with categories c1, c5". */
function describe(s, max = { sens: null, cats: null }) {
  const c = canon(s);
  if (!c) return null;
  const one = (t) => {
    const l = parseLevel(t);
    const n = l.cats.length;
    const all = max.cats && n === max.cats;
    const cats = !n ? 'no categories' : all ? `all ${n} categories` : n === 1 ? `category c${l.cats[0]}` : `${n} categories (${catsText(l.cats)})`;
    return `${l.sens} with ${cats}`;
  };
  const parts = c.split('-');
  return parts.length === 2 ? `from ${one(parts[0])} up to ${one(parts[1])}` : one(parts[0]);
}

/**
 * Problems with a level or range for a policy with `sens` sensitivities and
 * `cats` categories: out of range, high below low.
 */
function problems(s, { sens, cats } = {}) {
  const c = canon(s);
  if (!c) return [`${s} isn't a level or range (s0, s0:c1,c2, s0-s0:c0.c1023)`];
  const out = [];
  const ls = c.split('-').map(parseLevel);
  for (const l of ls) {
    const n = +l.sens.slice(1);
    if (sens != null && n >= sens) out.push(sens === 1 ? `${l.sens} doesn't exist: this policy has only s0` : `${l.sens} doesn't exist: this policy has s0 to s${sens - 1}`);
    const over = cats != null ? l.cats.filter(x => x >= cats) : [];
    if (over.length) out.push(`c${over[0]} is out of range: this policy has c0 to c${cats - 1}`);
  }
  if (ls.length === 2) {
    const [lo, hi] = ls;
    const dominates = +hi.sens.slice(1) >= +lo.sens.slice(1) && lo.cats.every(x => hi.cats.includes(x));
    if (!dominates) out.push(`the high level ${levelText(hi)} doesn't cover the low level ${levelText(lo)}`);
  }
  return out;
}

/** Does level a cover (dominate) level b? */
function covers(a, b) {
  const x = parseLevel(a), y = parseLevel(b);
  if (!x || !y) return null;
  return +x.sens.slice(1) >= +y.sens.slice(1) && y.cats.every(c => x.cats.includes(c));
}

const LEVEL_RE = /^s\d+(:c\d+(\.c\d+)?(,c\d+(\.c\d+)?)*)?(-s\d+(:c\d+(\.c\d+)?(,c\d+(\.c\d+)?)*)?)?$/;

module.exports = { parseCats, catsText, parseLevel, canon, parseSetrans, translate, describe, problems, covers, LEVEL_RE };
