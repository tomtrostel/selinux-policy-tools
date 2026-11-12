'use strict';
/*
 * Booleans (pure): what a policy's booleans are, where each value comes from
 * (the tunable's declaration, booleans.conf, the compiled policy, the running
 * policy) and what each switches on. The server gathers the facts; assemble()
 * makes the rows the Booleans panel shows.
 */

/** booleans.conf text → Map name → { value, line } (`name = true|false`, comments and blanks skipped). */
function parseConf(text) {
  const out = new Map();
  String(text || '').split('\n').forEach((raw, line) => {
    const s = raw.replace(/#.*$/, '').trim();
    const m = /^([\w.-]+)\s*=\s*(true|false|1|0|on|off)\s*$/i.exec(s);
    if (m) out.set(m[1], { value: /^(true|1|on)$/i.test(m[2]), line });
  });
  return out;
}

/** The value as written in gen_tunable(`name', VALUE) / gen_bool: true|false|null. */
const parseDefault = (s) => (/^(true|1|on)$/i.test(String(s || '').trim()) ? true : /^(false|0|off)$/i.test(String(s || '').trim()) ? false : null);

/**
 * Rows: decls = Map name → { path, l, c, module, desc, tunable, default (text) } (the tree's sources,
 * empty for an installed policy); conf = parseConf() of booleans.conf (+ confPath); compiled = { name:
 * bool } (the policy's defaults); running = { name: bool } | null (the running policy's current values);
 * effects = { name: { on: { count, domains, rules }, off: {...}, mixed } } (policy_query booleans).
 * → { rows: [{ name, desc, module, loc, tunable, source, conf, compiled, running, effective, changed,
 *   on, off, mixed }], summary }
 */
function assemble({ decls = new Map(), conf = new Map(), compiled = {}, running = null, effects = {} }) {
  const names = new Set([...Object.keys(compiled), ...decls.keys(), ...conf.keys()]);
  const rows = [];
  for (const name of [...names].sort()) {
    const d = decls.get(name) || null;
    const c = conf.get(name) || null;
    const inPolicy = Object.prototype.hasOwnProperty.call(compiled, name);
    const compiledV = inPolicy ? !!compiled[name] : null;
    const runningV = running && Object.prototype.hasOwnProperty.call(running, name) ? !!running[name] : null;
    const source = d ? parseDefault(d.default) : null;
    const effective = runningV != null ? runningV : compiledV != null ? compiledV : c ? c.value : source;
    const e = effects[name] || null;
    rows.push({
      name, desc: d ? d.desc || '' : '', module: d ? d.module || null : null, loc: d ? { p: d.path, l: d.l, c: d.c || 0 } : null, tunable: d ? !!d.tunable : null,
      source, conf: c ? c.value : null, confLine: c ? c.line : null, compiled: compiledV, running: runningV, effective,
      inPolicy, declared: !!d,
      // Changed: booleans.conf sets it away from the source's default, or the running value differs from the compiled default.
      changed: (c && source != null && c.value !== source) || (runningV != null && compiledV != null && runningV !== compiledV),
      on: e ? e.on : null, off: e ? e.off : null, mixed: e ? e.mixed || 0 : 0, exprs: e ? e.exprs || [] : [],
    });
  }
  const summary = { total: rows.length, on: rows.filter(r => r.effective === true).length, off: rows.filter(r => r.effective === false).length,
    changed: rows.filter(r => r.changed).length, confOnly: rows.filter(r => !r.inPolicy && r.conf != null).length, undeclared: rows.filter(r => r.inPolicy && !r.declared && decls.size > 0).length };
  return { rows, summary };
}

/** The booleans.conf text with name = value (its line rewritten, or a new line at the end). */
function setInConf(text, name, value) {
  const want = `${name} = ${value ? 'true' : 'false'}`;
  const crlf = /\r\n/.test(text || '');
  const ls = String(text || '').split(/\r?\n/);
  const i = ls.findIndex(x => new RegExp(`^\\s*${name}\\s*=`).test(x));
  if (i >= 0) { if (ls[i].trim() === want) return null; ls[i] = want; return { text: ls.join(crlf ? '\r\n' : '\n'), line: i }; }
  let end = ls.length;
  while (end > 0 && !ls[end - 1].trim()) end--;
  ls.splice(end, 0, want);
  return { text: ls.join(crlf ? '\r\n' : '\n'), line: end };
}

module.exports = { parseConf, parseDefault, assemble, setInConf };
