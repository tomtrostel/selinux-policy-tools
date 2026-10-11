'use strict';
/*
 * Denial assistant, pure part: parse audit records (raw audit.log /
 * `ausearch --raw`, `ausearch -i`, kernel/journal lines), join the records of
 * one event (AVC + SYSCALL + CWD + PATH), group denials by source type,
 * target type and class, and turn the policy and label findings for a group
 * into a verdict: what is really wrong and what to do about it.
 */

const path = require('path');

// Fields audit may hex-encode (unquoted, uppercase hex) in raw records.
const HEX_FIELDS = new Set(['name', 'exe', 'comm', 'cwd', 'path', 'proctitle', 'cmdline']);
// tclass → matchpathcon -m file type (classes whose objects carry a file label).
const FILE_MODES = { file: 'file', dir: 'dir', lnk_file: 'lnk_file', chr_file: 'chr_file', blk_file: 'blk_file', sock_file: 'sock_file', fifo_file: 'pipe' };
// Types that mean "nobody gave this file a proper label".
const GENERIC_TYPES = new Set(['default_t', 'file_t', 'unlabeled_t', 'var_t', 'var_lib_t', 'usr_t', 'root_t', 'mnt_t', 'etc_runtime_t']);

function decodeHex(s) {
  if (!/^(?:[0-9A-F]{2})+$/.test(s)) return s;
  const b = Buffer.from(s, 'hex');
  return b.toString('utf8').replace(/\0/g, ' ').trim();
}

/** key=value fields of one record; first occurrence wins; quoted values unquoted, raw hex decoded. */
function fields(text) {
  const out = {};
  const re = /([A-Za-z_][\w-]*)=("[^"]*"|'[^']*'|\S*)/g;
  let m;
  while ((m = re.exec(text))) {
    const k = m[1];
    if (k in out) continue;
    let v = m[2];
    if (/^["']/.test(v)) v = v.slice(1, -1);
    else if (HEX_FIELDS.has(k)) v = decodeHex(v);
    out[k] = v;
  }
  return out;
}

/** user:role:type:level → parts (level may itself contain colons). */
function parseContext(s) {
  if (!s) return null;
  const p = s.split(':');
  if (p.length < 3) return null;
  return { user: p[0], role: p[1], type: p[2], level: p.slice(3).join(':') || null, raw: s };
}

const KERNEL_TYPES = { 1400: 'AVC', 1107: 'USER_AVC', 1401: 'SELINUX_ERR', 1300: 'SYSCALL', 1302: 'PATH', 1307: 'CWD', 1327: 'PROCTITLE' };

/**
 * Records of a log text: [{ type, event, time, text }]. Accepts audit.log
 * lines (type=AVC msg=audit(1728650000.123:4521): …), ausearch -i lines
 * (msg=audit(10/11/2026 14:33:20.123:4521) : …), kernel/journal lines
 * (audit: type=1400 audit(…): avc: …) and bare "avc: denied …" text.
 */
function records(text) {
  const out = [];
  for (let line of text.split(/\r?\n/)) {
    line = line.split('\x1d')[0]; // RHEL's ENRICHED format appends interpreted fields after GS
    if (!line.trim() || line.startsWith('----')) continue;
    let type = null;
    const t = /\btype=([A-Z_]+|\d+)\b/.exec(line);
    if (t) type = /^\d+$/.test(t[1]) ? (KERNEL_TYPES[t[1]] || t[1]) : t[1];
    else if (/\bAVC\b.*\bavc:\s+denied\b/.test(line)) type = 'AVC';
    else if (/\bavc:\s+denied\b/.test(line)) type = 'AVC';
    if (!type) continue;
    const a = /audit\(([^)]*?)(?:\.(\d+))?:(\d+)\)/.exec(line);
    const event = a ? `${a[1]}:${a[3]}` : null;
    const time = a ? a[1] : null;
    // The record's own text: after the "audit(…):" stamp (or the whole line).
    const body = a ? line.slice(a.index + a[0].length).replace(/^\s*:\s*/, '') : line;
    out.push({ type, event, time, text: body });
  }
  return out;
}

/** "{ read write }" of an avc message. */
function avcPerms(text) {
  const m = /avc:\s+(denied|granted)\s+\{([^}]*)\}/.exec(text);
  return m ? { verdict: m[1], perms: m[2].trim().split(/\s+/).filter(Boolean) } : null;
}

/** Time of an event stamp as epoch ms ('1728650000.123' or '10/11/2026 14:33:20'), or null. */
function stampMs(time) {
  if (!time) return null;
  if (/^\d+$/.test(time)) return Number(time) * 1000;
  const d = Date.parse(time);
  return Number.isNaN(d) ? null : d;
}

/**
 * Denials in a log text: [{ event, time, kind: 'avc' | 'user_avc' | 'error',
 * perms, scontext, tcontext, tclass, permissive, comm, exe, name, path, pid }].
 * Records of one event (same stamp) are joined: SYSCALL gives exe/comm, PATH
 * (+ CWD) the full path of a name the AVC only gives as a basename.
 */
function parseDenials(text) {
  const recs = records(text);
  const byEvent = new Map();
  for (const r of recs) if (r.event) { if (!byEvent.has(r.event)) byEvent.set(r.event, []); byEvent.get(r.event).push(r); }
  const out = [];
  for (const r of recs) {
    if (r.type !== 'AVC' && r.type !== 'USER_AVC' && r.type !== 'SELINUX_ERR') continue;
    const same = r.event ? byEvent.get(r.event) : [r];
    let f;
    if (r.type === 'USER_AVC') {
      // The AVC text is inside msg='…'; the outer fields describe the reporting process.
      const m = /msg='([^']*)'/.exec(r.text);
      f = fields(m ? m[1] : r.text);
    } else f = fields(r.text);
    const sys = same.find(x => x.type === 'SYSCALL');
    const sf = sys ? fields(sys.text) : {};
    const cwd = (() => { const c = same.find(x => x.type === 'CWD'); return c ? fields(c.text).cwd : null; })();
    const pathRecs = same.filter(x => x.type === 'PATH').map(x => fields(x.text));
    const sctx = parseContext(f.scontext), tctx = parseContext(f.tcontext);
    if (!sctx || !tctx) continue;
    const base = { event: r.event, time: r.time, at: stampMs(r.time), scontext: sctx, tcontext: tctx, tclass: f.tclass || null,
      permissive: f.permissive === '1', pid: f.pid || sf.pid || null, comm: f.comm || sf.comm || null, exe: f.exe || sf.exe || null };
    if (r.type === 'SELINUX_ERR') {
      out.push({ ...base, kind: 'error', perms: [], op: f.op || null, invalid: f.invalid_context || null, message: r.text.trim() });
      continue;
    }
    const p = avcPerms(r.text);
    if (!p || p.verdict !== 'denied') continue;
    let full = f.path && f.path.startsWith('/') ? f.path : null;
    if (!full && f.name) {
      // The PATH item for the AVC's name (NORMAL/CREATE first), relative names resolved against CWD.
      const cand = pathRecs.filter(x => x.name && path.posix.basename(x.name) === f.name);
      const pick = cand.find(x => /NORMAL|CREATE/.test(x.nametype || '')) || cand[0];
      if (pick) full = pick.name.startsWith('/') ? pick.name : (cwd ? path.posix.join(cwd, pick.name) : null);
    }
    out.push({ ...base, kind: r.type === 'USER_AVC' ? 'user_avc' : 'avc', perms: p.perms, name: f.name || null, path: full, dev: f.dev || null, ino: f.ino || null });
  }
  return out;
}

const groupKey = (d) => `${d.kind === 'error' ? 'error' : 'deny'}|${d.scontext.type}|${d.tcontext.type}|${d.tclass}`;

/**
 * Denials grouped by source type, target type and class:
 * [{ key, kind, source, target, tclass, perms, count, permissive (all
 * permissive), enforcing (any not), comms, exes, paths, names, first, last,
 * scontext, tcontext, sample }], most frequent first.
 */
function groupDenials(denials) {
  const map = new Map();
  for (const d of denials) {
    const k = groupKey(d);
    let g = map.get(k);
    if (!g) {
      g = { key: k, kind: d.kind === 'error' ? 'error' : 'deny', source: d.scontext.type, target: d.tcontext.type, tclass: d.tclass,
        perms: [], count: 0, permissive: true, enforcing: false, comms: [], exes: [], paths: [], names: [], first: null, last: null,
        scontext: d.scontext.raw, tcontext: d.tcontext.raw, ops: [], userspace: false, events: new Set() };
      map.set(k, g);
    }
    // One event can repeat the same AVC (e.g. a USER_AVC also logged by the kernel): count events once.
    if (!d.event || !g.events.has(d.event)) g.count++;
    if (d.event) g.events.add(d.event);
    for (const p of d.perms) if (!g.perms.includes(p)) g.perms.push(p);
    if (d.permissive) { /* keep */ } else g.permissive = false;
    if (!d.permissive) g.enforcing = true;
    if (d.kind === 'user_avc') g.userspace = true;
    const add = (list, v, max = 8) => { if (v && !list.includes(v) && list.length < max) list.push(v); };
    add(g.comms, d.comm); add(g.exes, d.exe); add(g.paths, d.path, 20); add(g.names, d.name);
    if (d.op) add(g.ops, d.op);
    if (d.at != null) { g.first = g.first == null ? d.at : Math.min(g.first, d.at); g.last = g.last == null ? d.at : Math.max(g.last, d.at); }
  }
  const out = [...map.values()].map(g => { const { events, ...rest } = g; return rest; });
  out.sort((a, b) => b.count - a.count || a.source.localeCompare(b.source) || a.target.localeCompare(b.target));
  return out;
}

/**
 * The verdict for a group, from
 *   te:     policy_query `avc` result { unknown?, unknownClass?, perms: {p: {status, rules, options}}, permissiveDomain }
 *   labels: [{ path, expected, current }] (matchpathcon / stat) for the group's paths, or null
 * → { verdict, title, detail, fixes: [{ text, command? }], notes }.
 * Order: unknown types, wrong label, boolean, already allowed, generic label, missing rule.
 */
function verdict(g, te, labels, policyName) {
  const notes = [];
  if (g.permissive) notes.push(g.userspace ? 'Logged in permissive mode: the access was allowed this time, and will be denied when enforcing.' : 'Logged in permissive mode (permissive=1): the access was allowed this time, and will be denied when enforcing.');
  if (te && te.permissiveDomain) notes.push(`${g.source} is a permissive domain in ${policyName}: its denials are logged, not enforced.`);
  const allow = `allow ${g.source} ${g.source === g.target ? 'self' : g.target}:${g.tclass} { ${g.perms.join(' ')} };`;
  if (g.kind === 'error') {
    return { verdict: 'error', title: 'SELinux error', detail: `The kernel refused ${g.ops.length ? g.ops.join(', ') : 'an operation'} for ${g.source} → ${g.target} (${g.tclass}). This is not an access denial: typically a domain transition into a context the policy doesn't allow (invalid_context), or a bounded transition. Check the role and user allow the target type.`, fixes: [], notes };
  }
  if (te && te.unknown && te.unknown.length) {
    return { verdict: 'unknown', title: 'Not in this policy', detail: `${te.unknown.join(' and ')} ${te.unknown.length > 1 ? "aren't types" : "isn't a type"} in ${policyName}. The denial came from a host running a different policy; check it against that policy (Check against).`, fixes: [], notes };
  }
  if (te && te.unknownClass) {
    return { verdict: 'unknown', title: 'Unknown class', detail: `${policyName} has no class ${g.tclass}; the denial came from a host running a different policy.`, fixes: [], notes };
  }
  const wrong = (labels || []).filter(l => l.expected && l.expected !== g.target);
  if (wrong.length) {
    const creating = g.perms.every(p => p === 'create');
    const fixed = wrong.filter(l => l.current && l.current === l.expected);
    const paths = wrong.map(l => l.path);
    const fixes = fixed.length === wrong.length ? [] : [{ text: `Relabel ${paths.length > 1 ? 'them' : 'it'} with the policy's file contexts`, command: `restorecon -v ${paths.map(shellQuote).join(' ')}` }];
    const list = wrong.map(l => `${l.path}: labeled ${g.target}, the policy says ${l.expected}${l.current && l.current !== g.target ? ` (now ${l.current})` : ''}`).join('\n');
    if (fixed.length === wrong.length) notes.push('The files have been relabeled since; the denial predates that. Try again.');
    return { verdict: 'label', title: creating ? 'New file would get the wrong type' : 'Wrong label',
      detail: creating
        ? `${g.source} tried to create a file that would be labeled ${g.target}, but the policy's file contexts say ${wrong[0].expected}. Either the directory is mislabeled (relabel it) or the policy lacks a type transition for ${g.source} there.\n${list}`
        : `The file${wrong.length > 1 ? 's' : ''} ${g.source} wanted ${wrong.length > 1 ? 'have' : 'has'} a different label than the policy assigns. Relabeling fixes the denial without changing the policy (typical after copying or moving files: they keep the old label).\n${list}`,
      fixes, notes };
  }
  const per = (te && te.perms) || {};
  const status = (p) => (per[p] ? per[p].status : 'missing');
  const missing = g.perms.filter(p => status(p) === 'missing');
  const viaBool = g.perms.filter(p => status(p) === 'boolean');
  const allowed = g.perms.filter(p => status(p) === 'allowed');
  if (te && viaBool.length && !missing.length) {
    // One boolean setting that covers every permission, preferring the fewest changes.
    const opts = viaBool.map(p => per[p].options || []);
    const sets = new Map();
    for (const o of opts.flat()) sets.set(JSON.stringify(o), o);
    const covers = (o) => opts.every(list => list.some(x => Object.entries(x).every(([b, v]) => o[b] === v)));
    const best = [...sets.values()].filter(covers).sort((a, b) => Object.keys(a).length - Object.keys(b).length)[0] || opts[0][0] || {};
    const bools = Object.entries(best);
    return { verdict: 'boolean', title: bools.length > 1 ? 'Allowed under booleans that are off' : 'Allowed under a boolean that is off',
      detail: `${policyName} allows this when ${bools.map(([b, v]) => `${b} is ${v ? 'on' : 'off'}`).join(' and ')}. No policy change is needed if the site wants this behaviour; leave it as it is otherwise (the denial is the policy working).`,
      fixes: [{ text: `Set ${bools.length > 1 ? 'them' : 'it'} permanently (on the host that logged the denial)`, command: `setsebool -P ${bools.map(([b, v]) => `${b} ${v ? 'on' : 'off'}`).join(' ')}` }],
      rules: viaBool.flatMap(p => per[p].rules || []).slice(0, 4), notes };
  }
  if (te && !missing.length && !viaBool.length) {
    return { verdict: 'allowed', title: 'Already allowed', detail: `${policyName} allows ${g.perms.join(', ')} for ${g.source} on ${g.target} (${g.tclass}). The denial is probably from before the policy was loaded or a boolean was changed; if it keeps happening, a constraint or an MLS/MCS rule denied it (compare the levels of the two contexts).`,
      fixes: [], rules: allowed.flatMap(p => per[p].rules || []).slice(0, 4), notes };
  }
  if (viaBool.length) notes.push(`${viaBool.join(', ')} would also be allowed with a boolean (${[...new Set(viaBool.flatMap(p => (per[p].options || []).flatMap(o => Object.keys(o))))].join(', ')}).`);
  if (allowed.length) notes.push(`${allowed.join(', ')} ${allowed.length > 1 ? 'are' : 'is'} already allowed; ${missing.join(', ')} ${missing.length > 1 ? 'are' : 'is'} not.`);
  if (GENERIC_TYPES.has(g.target) && FILE_MODES[g.tclass]) {
    return { verdict: 'generic', title: 'Generic label', detail: `${g.target} is a catch-all type: allowing ${g.source} to use it would let it use every file with that label. Give the files a type of their own instead (a file context in the module that owns them, or a file type in the service editor), relabel, and allow access to that type.${g.paths.length ? `\nFiles: ${g.paths.slice(0, 5).join(', ')}` : ''}`,
      fixes: [], needed: allow, notes };
  }
  return { verdict: 'missing', title: 'Missing rule', detail: `${policyName} doesn't allow ${(missing.length ? missing : g.perms).join(', ')} for ${g.source} on ${g.target} (${g.tclass}). Grant it with an interface of the module that owns ${g.target}, in the module of ${g.source}, rather than with this raw rule.`,
    fixes: [], needed: allow, notes };
}

const shellQuote = (s) => (/^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

module.exports = { parseDenials, groupDenials, verdict, records, fields, parseContext, FILE_MODES, GENERIC_TYPES, shellQuote };
