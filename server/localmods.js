'use strict';
/*
 * A host's local SELinux changes (what `semanage` and `semodule -i` changed
 * on it), compared with a policy, and turned into policy source. Pure.
 *
 * Input is `semanage export` output, optionally followed by
 * `semodule --list-modules=full` after a "#### modules" line. The export
 * format (policycoreutils seobject.py `customized()`):
 *   boolean -m -1 NAME | -m -0 NAME
 *   login -a -s USER [-r 'RANGE'] LOGIN           (LOGIN may be %group)
 *   user -a [-L LEVEL -r RANGE] -R 'ROLES' NAME
 *   port -a -t TYPE [-r 'RANGE'] -p PROTO PORT[-PORT]
 *   interface -a -t TYPE [-r 'RANGE'] NAME
 *   node -a -M MASK -p PROTO -t TYPE [-r 'RANGE'] ADDR
 *   fcontext -a -f FTYPE -t TYPE [-r 'RANGE'] 'SPEC' | fcontext -a -e SOURCE TARGET
 *   module -d NAME                                  (disabled)
 *   permissive -a TYPE
 *   ibpkey -a -t TYPE [-r 'RANGE'] -x SUBNET PKEY | ibendport -a -t TYPE [-r 'RANGE'] -z DEVICE PORT
 * and "OBJECT -D" lines first (delete all local changes of that kind), which
 * carry nothing to compare.
 */

/** Shell-like words: single and double quotes group (and are removed). */
function words(line) {
  const out = [];
  const re = /'([^']*)'|"([^"]*)"|(\S+)/g;
  let m;
  while ((m = re.exec(line))) out.push(m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : m[3]);
  return out;
}

/** -x VALUE options and the positional arguments of an export line's words (after the object name). */
function options(ws) {
  const opt = {}, pos = [];
  for (let i = 0; i < ws.length; i++) {
    const w = ws[i];
    if (/^-[a-zA-Z]$/.test(w)) {
      // Flags without a value: -a -m -d -D and boolean -1 / -0.
      if (['-a', '-m', '-d', '-D'].includes(w)) { opt[w[1]] = true; continue; }
      opt[w[1]] = ws[++i];
    } else if (/^-[01]$/.test(w)) opt.value = w === '-1';
    else pos.push(w);
  }
  return { opt, pos };
}

const FTYPE_FLAG = { a: '', f: '--', d: '-d', c: '-c', b: '-b', s: '-s', l: '-l', p: '-p' };
const KINDS = ['boolean', 'login', 'user', 'port', 'interface', 'node', 'fcontext', 'module', 'permissive', 'ibpkey', 'ibendport'];

/**
 * Parse export text (+ module list). Returns { items, modules, unknown }:
 * items [{ kind, …fields, raw, l }], modules [{ priority, name, lang, disabled }]
 * from the module list, unknown [{ l, text }] for lines that aren't either.
 */
function parseExport(text) {
  const items = [], modules = [], unknown = [];
  let inModules = false;
  String(text || '').split(/\r?\n/).forEach((raw, l) => {
    const line = raw.trim();
    if (!line) return;
    if (/^#+\s*modules\b/i.test(line)) { inModules = true; return; }
    if (line.startsWith('#')) return;
    // semodule --list-modules=full: "PRIORITY NAME LANG [disabled]"
    const mm = /^(\d{3})\s+(\S+)\s+(\S+)(?:\s+(disabled))?$/.exec(line);
    if (mm && (inModules || !KINDS.includes(line.split(/\s+/)[0]))) { modules.push({ priority: +mm[1], name: mm[2], lang: mm[3], disabled: !!mm[4], l }); return; }
    const ws = words(line);
    const kind = ws[0];
    if (!KINDS.includes(kind)) { unknown.push({ l, text: line }); return; }
    const { opt, pos } = options(ws.slice(1));
    if (opt.D) return; // "-D": the export's reset line
    const base = { raw: line, l };
    const range = opt.r || '';
    let it = null;
    switch (kind) {
      case 'boolean': if (opt.m && opt.value !== undefined && pos[0]) it = { kind, name: pos[0], value: opt.value }; break;
      case 'login': if (opt.s && pos[0]) it = { kind, name: pos[0], user: opt.s, range }; break;
      case 'user': if (opt.R && pos[0]) it = { kind, name: pos[0], roles: opt.R.split(/\s+/).filter(Boolean), level: opt.L || '', range }; break;
      case 'port': {
        const m = /^(\d+)(?:-(\d+))?$/.exec(pos[0] || '');
        if (opt.t && opt.p && m) it = { kind, type: opt.t, proto: opt.p, low: +m[1], high: +(m[2] || m[1]), range };
        break;
      }
      case 'interface': if (opt.t && pos[0]) it = { kind, name: pos[0], type: opt.t, range }; break;
      case 'node': if (opt.t && opt.M && pos[0]) it = { kind, addr: pos[0], mask: opt.M, proto: opt.p || 'ipv4', type: opt.t, range }; break;
      case 'fcontext':
        if (opt.e && pos[0]) it = { kind: 'equivalence', source: opt.e, target: pos[0] };
        else if (opt.t && pos[0]) it = { kind, spec: pos[0], ftype: opt.f || 'a', type: opt.t, range };
        break;
      case 'module': if (opt.d && opt.d !== true) it = { kind: 'module-disabled', name: opt.d }; else if (opt.d && pos[0]) it = { kind: 'module-disabled', name: pos[0] }; break;
      case 'permissive': if (opt.a && pos[0]) it = { kind, type: pos[0] }; break;
      case 'ibpkey': if (opt.t && opt.x && pos[0]) it = { kind, type: opt.t, subnet: opt.x, pkey: pos[0], range }; break;
      case 'ibendport': if (opt.t && opt.z && pos[0]) it = { kind, type: opt.t, device: opt.z, port: pos[0], range }; break;
      default: break;
    }
    if (it) items.push({ ...it, ...base });
    else unknown.push({ l, text: line });
  });
  return { items, modules, unknown };
}

const portText = (it) => `${it.proto} ${it.low === it.high ? it.low : `${it.low}-${it.high}`}`;

/** One line describing a change, as semanage would list it. */
function describe(it) {
  switch (it.kind) {
    case 'boolean': return `${it.name} = ${it.value ? 'on' : 'off'}`;
    case 'login': return `${it.name} → ${it.user}${it.range ? ` (${it.range})` : ''}`;
    case 'user': return `${it.name}: roles ${it.roles.join(' ')}${it.range ? `, range ${it.range}` : ''}`;
    case 'port': return `${portText(it)} → ${it.type}`;
    case 'interface': return `${it.name} → ${it.type}`;
    case 'node': return `${it.addr}/${it.mask} (${it.proto}) → ${it.type}`;
    case 'fcontext': return `${it.spec}${FTYPE_FLAG[it.ftype] ? ` ${FTYPE_FLAG[it.ftype]}` : ''} → ${it.type}`;
    case 'equivalence': return `${it.target} labeled like ${it.source}`;
    case 'module-disabled': return `module ${it.name} disabled`;
    case 'permissive': return `${it.type} permissive`;
    case 'local-module': return `module ${it.name} (priority ${it.priority}${it.disabled ? ', disabled' : ''})`;
    case 'ibpkey': return `pkey ${it.pkey} on ${it.subnet} → ${it.type}`;
    case 'ibendport': return `${it.device} port ${it.port} → ${it.type}`;
    default: return it.raw || it.kind;
  }
}

/**
 * Compare each change with a policy. `facts`:
 *   types: Set of types (and attributes) in the policy; users: { name: { roles, range } }; roles: Set;
 *   bools: { name: default }; ports: [{ proto, low, high, type }]; netifs: { name: type };
 *   nodes: [{ addr, mask, proto, type }]; fc(spec, flag) → type | null (the policy's line for exactly
 *   that spec and file kind); subs: { target: source } (equivalences); seusers: [{ login, user, range }];
 *   modules: Map name → 'base' | 'module' | 'off' (null: unknown); builtModules: Set (null: unknown).
 * Each item gets { state, note, severity? }:
 *   local (only on the host), present (the policy has it already), override (the host changes
 *   something the policy sets differently), redundant (same as the policy's default), broken (it
 *   names something the policy doesn't have), info.
 */
function compare(items, facts) {
  const has = (t) => !!(facts.types && facts.types.has(t));
  const out = [];
  for (const it of items) {
    let state = 'local', note = '', severity = null, was = null; // was: what the policy has instead (overrides)
    const missingType = it.type && facts.types && !has(it.type);
    switch (it.kind) {
      case 'boolean': {
        const d = facts.bools ? facts.bools[it.name] : undefined;
        if (facts.bools && d === undefined) { state = 'broken'; note = `Your policy has no boolean ${it.name}.`; }
        else if (d === it.value) { state = 'redundant'; note = `Your policy's default is already ${d ? 'on' : 'off'}.`; }
        else { state = 'override'; note = `Your policy defaults to ${d ? 'on' : 'off'}; the host turns it ${it.value ? 'on' : 'off'}.`; }
        break;
      }
      case 'port': {
        if (missingType) { state = 'broken'; note = `${it.type} isn't a type in your policy.`; break; }
        const same = (facts.ports || []).find(p => p.proto === it.proto && p.low === it.low && p.high === it.high);
        const overlap = (facts.ports || []).filter(p => p.proto === it.proto && p.low <= it.high && it.low <= p.high && p !== same);
        if (same && same.type === it.type) { state = 'present'; note = 'Your policy has this port already.'; }
        else if (same) { state = 'override'; note = `Your policy gives ${portText(it)} to ${same.type}.`; was = same.type; }
        else { note = overlap.length ? `Overlaps ${overlap.slice(0, 3).map(p => `${portText(p)} (${p.type})`).join(', ')} in your policy; the more specific one wins.` : 'Only on the host.'; }
        break;
      }
      case 'fcontext': {
        if (missingType) { state = 'broken'; note = `${it.type} isn't a type in your policy: restorecon would fail with it.`; break; }
        const t = facts.fc ? facts.fc(it.spec, FTYPE_FLAG[it.ftype]) : null;
        if (t === it.type) { state = 'present'; note = 'Your policy has this line already.'; }
        else if (t) { state = 'override'; note = `Your policy labels ${it.spec} ${t}.`; was = t; }
        else note = 'Only on the host.';
        break;
      }
      case 'equivalence': {
        const s = facts.subs ? facts.subs[it.target] : undefined;
        if (s === it.source) { state = 'present'; note = 'Your policy has this equivalence already.'; }
        else if (s) { state = 'override'; note = `Your policy labels ${it.target} like ${s}.`; }
        else note = 'Only on the host.';
        break;
      }
      case 'login': {
        if (facts.users && !facts.users[it.user]) { state = 'broken'; note = `Your policy has no SELinux user ${it.user}.`; break; }
        const line = (facts.seusers || []).find(x => x.login === it.name);
        if (line && line.user === it.user && (line.range || '') === (it.range || '')) { state = 'present'; note = 'Your policy\'s seusers has this mapping already.'; }
        else if (line) { state = 'override'; note = `Your policy maps ${it.name} to ${line.user}${line.range ? ` (${line.range})` : ''}.`; }
        else note = 'Only on the host.';
        if (it.user === 'unconfined_u') { severity = 'warn'; note += ' unconfined_u is not confined at all.'; }
        break;
      }
      case 'user': {
        const u = facts.users && facts.users[it.name];
        const missingRoles = facts.roles ? it.roles.filter(r => !facts.roles.has(r)) : [];
        if (missingRoles.length) { state = 'broken'; note = `Your policy has no role ${missingRoles.join(', ')}.`; break; }
        if (u) {
          const add = it.roles.filter(r => !u.roles.includes(r)), drop = u.roles.filter(r => !it.roles.includes(r));
          if (!add.length && !drop.length) { state = 'present'; note = 'Your policy has this user with these roles.'; }
          else { state = 'override'; note = `Roles in your policy: ${u.roles.join(' ')}${add.length ? `; the host adds ${add.join(' ')}` : ''}${drop.length ? `; the host drops ${drop.join(' ')}` : ''}.`; }
        } else note = 'A user only the host has.';
        if (it.roles.some(r => /^(sysadm|secadm|auditadm|unconfined)_r$/.test(r))) severity = 'warn';
        break;
      }
      case 'interface': {
        if (missingType) { state = 'broken'; note = `${it.type} isn't a type in your policy.`; break; }
        const t = facts.netifs ? facts.netifs[it.name] : undefined;
        if (t === it.type) { state = 'present'; note = 'Your policy has this interface already.'; }
        else if (t) { state = 'override'; note = `Your policy labels ${it.name} ${t}.`; }
        else note = 'Only on the host.';
        break;
      }
      case 'node': {
        if (missingType) { state = 'broken'; note = `${it.type} isn't a type in your policy.`; break; }
        const n = (facts.nodes || []).find(x => x.addr === it.addr && x.mask === it.mask);
        if (n && n.type === it.type) { state = 'present'; note = 'Your policy has this node already.'; }
        else if (n) { state = 'override'; note = `Your policy labels it ${n.type}.`; }
        else note = 'Only on the host.';
        break;
      }
      case 'module-disabled': {
        const k = facts.modules ? facts.modules.get(it.name) : undefined;
        const built = facts.builtModules ? facts.builtModules.has(it.name) : undefined;
        // Base modules are compiled into base.pp (no .pp of their own), so check them first.
        if (k === 'base') { state = 'info'; note = `${it.name} is a base module in your policy: it can't be disabled there.`; }
        else if (k === 'off' || built === false) { state = 'present'; note = 'Your policy doesn\'t ship this module either.'; }
        else if (k === 'module' || built) { state = 'override'; note = 'Your policy ships this module; the host turns it off.'; }
        else { state = 'info'; note = 'Not known whether your policy ships it.'; }
        break;
      }
      case 'permissive':
        if (missingType) { state = 'broken'; note = `${it.type} isn't a type in your policy.`; }
        else { note = `${it.type} runs permissive on the host: its denials are only logged, nothing is enforced.`; severity = 'warn'; }
        break;
      case 'local-module': {
        const k = facts.modules ? facts.modules.get(it.name) : undefined;
        const built = facts.builtModules ? facts.builtModules.has(it.name) : undefined;
        if ((k && k !== 'off') || built) { state = 'override'; note = `Your policy has a module ${it.name} too; the host's (priority ${it.priority}) replaces it.`; }
        else note = it.priority === 200 ? 'Installed from a package (priority 200), not part of your policy.' : 'Installed on the host (semodule -i), not part of your policy.';
        if (it.priority >= 400) severity = 'warn';
        break;
      }
      default:
        note = missingType ? `${it.type} isn't a type in your policy.` : 'Only on the host.';
        if (missingType) state = 'broken';
    }
    out.push({ ...it, state, note, severity, was, text: describe(it) });
  }
  return out;
}

/** Modules from `semodule --list-modules=full` that aren't the distribution's (priority 100). */
function localModules(modules) {
  return (modules || []).filter(m => m.priority !== 100 && !/^permissive_/.test(m.name) && m.name !== 'permissivedomains')
    .map(m => ({ kind: 'local-module', name: m.name, priority: m.priority, lang: m.lang, disabled: m.disabled, raw: `${m.priority} ${m.name} ${m.lang}`, l: m.l }));
}

/* ---------- into the policy source ---------- */

const lines = (t) => String(t).replace(/\r\n/g, '\n').split('\n');
const join = (ls, crlf) => (crlf ? ls.join('\r\n') : ls.join('\n'));
/** Insert `newLines` at index `at` of the text's lines: { text, line } (line = first inserted). */
function insertAt(text, at, newLines) {
  const crlf = /\r\n/.test(text);
  const ls = lines(text);
  ls.splice(at, 0, ...newLines);
  return { text: join(ls, crlf), line: at };
}
/** Index after the last non-blank line (where an appended line goes). */
const endOf = (ls) => { let i = ls.length; while (i > 0 && !ls[i - 1].trim()) i--; return i; };

/** The .fc line for a file-context change (refpolicy form). */
function fcLine(it) {
  const flag = FTYPE_FLAG[it.ftype] || '';
  const level = (it.range || 's0').split('-')[0].trim() || 's0';
  return `${it.spec}${flag ? `\t${flag}` : '\t'}\tgen_context(system_u:object_r:${it.type},${level})`;
}

/** Append the change's line to a module's .fc: { text, line, inserted } (null if it is there already). */
function fcontextFix(fcText, it) {
  const line = fcLine(it);
  const ls = lines(fcText || '');
  const norm = (s) => s.replace(/\s+/g, ' ').trim();
  if (ls.some(x => norm(x) === norm(line))) return null;
  const r = insertAt(fcText || '', endOf(ls), [line]);
  return { ...r, inserted: [line] };
}

/** file_contexts.subs_dist: "TARGET SOURCE" (TARGET labeled like SOURCE), appended unless there. */
function subsFix(subsText, it) {
  const line = `${it.target} ${it.source}`;
  const ls = lines(subsText || '');
  if (ls.some(x => x.trim().split(/\s+/).join(' ') === line)) return null;
  const r = insertAt(subsText || '', endOf(ls), [line]);
  return { ...r, inserted: [line] };
}

/** booleans.conf: set NAME = true|false (rewrite its line, or append one). */
function booleanFix(confText, it) {
  const ls = lines(confText || '');
  const want = `${it.name} = ${it.value ? 'true' : 'false'}`;
  const i = ls.findIndex(x => new RegExp(`^\\s*${it.name}\\s*=`).test(x));
  if (i >= 0) {
    if (ls[i].trim() === want) return null;
    const crlf = /\r\n/.test(confText);
    ls[i] = want;
    return { text: join(ls, crlf), line: i, inserted: [want] };
  }
  const r = insertAt(confText || '', endOf(ls), [want]);
  return { ...r, inserted: [want] };
}

/** seusers: LOGIN:USER[:RANGE], replacing the login's line or before __default__. */
function loginFix(seusersText, it) {
  const ls = lines(seusersText || '');
  const want = `${it.name}:${it.user}${it.range ? `:${it.range}` : ''}`;
  const i = ls.findIndex(x => x.split(':')[0].trim() === it.name);
  if (i >= 0) {
    if (ls[i].trim() === want) return null;
    const crlf = /\r\n/.test(seusersText);
    ls[i] = want;
    return { text: join(ls, crlf), line: i, inserted: [want] };
  }
  const d = ls.findIndex(x => /^__default__:/.test(x.trim()));
  const r = insertAt(seusersText || '', d >= 0 ? d : endOf(ls), [want]);
  return { ...r, inserted: [want] };
}

/**
 * corenetwork.te.in: add the port number to the network_port(...) line that
 * declares the port's type (NAME_port_t). When the policy gives the number to
 * another type (it.was), the number moves: it leaves that type's line, since
 * checkpolicy refuses two portcon entries for one port. null when a line
 * isn't there (the type isn't declared by network_port) or nothing changes.
 */
function portFix(cnText, it) {
  const ls = lines(cnText || '');
  const lineOf = (type) => {
    const name = (/^(\w+)_port_t$/.exec(type || '') || [])[1];
    return name ? ls.findIndex(x => new RegExp(`^\\s*network_port\\(\\s*${name}\\s*[,)]`).test(x)) : -1;
  };
  const i = lineOf(it.type);
  if (i < 0) return null;
  const num = it.low === it.high ? `${it.low}` : `${it.low}-${it.high}`;
  const numRe = new RegExp(`\\s*,\\s*${it.proto}\\s*,\\s*${num}\\s*,\\s*[^,)]+`);
  if (numRe.test(ls[i])) return null;
  let j = -1;
  if (it.was) {
    j = lineOf(it.was);
    if (j < 0 || !numRe.test(ls[j])) return null; // the other type's number isn't where we can take it from
    ls[j] = ls[j].replace(numRe, '');
  }
  const level = (it.range || 's0').split('-')[0].trim() || 's0';
  const m = /^(\s*network_port\(\s*\w+)(.*?)(\)\s*(#.*)?)$/.exec(ls[i]);
  if (!m) return null;
  const crlf = /\r\n/.test(cnText);
  ls[i] = `${m[1]}${m[2]}, ${it.proto},${num},${level}${m[3]}`;
  return { text: join(ls, crlf), line: i, inserted: [ls[i]], removedFrom: j >= 0 ? { line: j, text: ls[j] } : null };
}

/**
 * An override of a path the policy labels otherwise: change the type on the
 * policy's own .fc line (line0, 0-based) instead of adding a second line for
 * the same path, which setfiles would reject as conflicting.
 */
function fcontextReplace(fcText, it, line0) {
  const ls = lines(fcText || '');
  const cur = ls[line0];
  if (cur === undefined || !it.was || !cur.includes(`:${it.was},`) && !cur.includes(`:${it.was})`)) return null;
  const crlf = /\r\n/.test(fcText);
  ls[line0] = cur.replace(new RegExp(`(object_r:)${it.was}\\b`), `$1${it.type}`);
  if (ls[line0] === cur) return null;
  return { text: join(ls, crlf), line: line0, inserted: [ls[line0]] };
}

/** modules.conf: NAME = off (null if absent or already off; base modules aren't touched). */
function moduleOffFix(confText, name) {
  const ls = lines(confText || '');
  const i = ls.findIndex(x => new RegExp(`^\\s*${name}\\s*=`).test(x));
  if (i < 0) return null;
  const m = /^(\s*[\w-]+\s*=\s*)(\w+)\s*$/.exec(ls[i]);
  if (!m || m[2] === 'off' || m[2] === 'base') return null;
  const crlf = /\r\n/.test(confText);
  ls[i] = `${m[1]}off`;
  return { text: join(ls, crlf), line: i, inserted: [ls[i]] };
}

/** Text to add by hand where the editor has no file to edit for it. */
function snippet(it) {
  switch (it.kind) {
    case 'fcontext': return fcLine(it);
    case 'equivalence': return `${it.target} ${it.source}    # config/file_contexts.subs_dist`;
    case 'boolean': return `${it.name} = ${it.value ? 'true' : 'false'}    # policy/booleans.conf`;
    case 'login': return `${it.name}:${it.user}${it.range ? `:${it.range}` : ''}    # config/appconfig-TYPE/seusers`;
    case 'user': return `gen_user(${it.name},, ${it.roles.join(' ')}, ${it.level || 's0'}, ${it.range || it.level || 's0'})    # policy/users`;
    case 'port': return `network_port(NAME, ${it.proto},${it.low === it.high ? it.low : `${it.low}-${it.high}`},s0)    # corenetwork.te.in, NAME_port_t = ${it.type}`;
    case 'interface': return `network_interface(${it.name}, ${it.name}, s0 - mls_systemhigh)    # corenetwork.te.in (type ${it.type})`;
    case 'node': return `network_node(NAME, ${it.addr}, ${it.mask}, s0)    # corenetwork.te.in (type ${it.type})`;
    case 'module-disabled': return `${it.name} = off    # policy/modules.conf`;
    case 'permissive': return `permissive ${it.type};    # in its module's .te`;
    default: return null;
  }
}

module.exports = { words, parseExport, compare, describe, localModules, fcLine, fcontextFix, fcontextReplace, subsFix, booleanFix, loginFix, portFix, moduleOffFix, snippet, FTYPE_FLAG, KINDS };
