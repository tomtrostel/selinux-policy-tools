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
    // SELINUX_ERR op=security_bounded_transition / security_validate_transition name the change as
    // oldcontext → newcontext (a process changing domain, or a file being relabeled).
    const err = r.type === 'SELINUX_ERR';
    const sctx = parseContext(f.scontext || (err ? f.oldcontext : null)), tctx = parseContext(f.tcontext || (err ? f.newcontext : null));
    if (!sctx || !tctx) continue;
    const base = { event: r.event, time: r.time, at: stampMs(r.time), scontext: sctx, tcontext: tctx, tclass: f.tclass || (err && f.oldcontext ? 'process' : null),
      permissive: f.permissive === '1', pid: f.pid || sf.pid || null, comm: f.comm || sf.comm || null, exe: f.exe || sf.exe || null };
    if (err) {
      // Older kernels: "security_compute_sid:  invalid context U:R:T for scontext=…".
      const inv = f.invalid_context || (/invalid context (\S+) for/.exec(r.text) || [])[1] || null;
      const op = f.op || (/security_compute_sid/.test(r.text) ? 'security_compute_sid' : /security_bounded_transition/.test(r.text) ? 'security_bounded_transition' : null);
      out.push({ ...base, kind: 'error', perms: f.perms ? f.perms.split(/[\s,]+/).filter(Boolean) : [], op, invalid: inv, reason: f.reason || null,
        task: f.taskcontext ? parseContext(f.taskcontext) : null, message: r.text.trim() });
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

/*
 * The login programs' own messages: when libselinux finds no context for a login, or the program
 * can't set it, nothing reaches the audit log (RHEL 8's kernel computes the contexts without
 * auditing); only sshd, login, crond or systemd say so in the journal / /var/log/secure.
 */
const LOGIN_LOG = [
  // pam_selinux (sshd, login, systemd-user, gdm…): "pam_selinux(sshd:session): Unable to get valid context for alice"
  { re: /pam_selinux\((\S+?):\w+\):\s+Unable to get valid context for (\S+)/, kind: 'nocontext', svc: 1, login: 2 },
  { re: /pam_selinux\((\S+?):\w+\):\s+(?:Security context \S+ is not allowed for|Error getting default context for) (\S+)/, kind: 'nocontext', svc: 1, login: 2 },
  { re: /pam_selinux\((\S+?):\w+\):\s+(?:Could not set|Unable to set) (?:executable )?(?:context|exec context)[^\n]*?(?: for (\S+))?\s*$/, kind: 'setexec', svc: 1, login: 2 },
  // sshd's own SELinux code.
  { re: /(sshd)(?:-session)?\[\d+\]:.*ssh_selinux_getctxbyname: Failed to get default SELinux security context for (\S+)/, kind: 'nocontext', svc: 1, login: 2 },
  { re: /(sshd)(?:-session)?\[\d+\]:.*ssh_selinux_setup_exec_context: (?:Failed to set SELinux exec context for (\S+)|.*)/, kind: 'setexec', svc: 1, login: 2 },
  { re: /(sshd)(?:-session)?\[\d+\]:.*ssh_selinux_setup_pty: (?:security_compute_relabel|setfilecon)[^\n]*/, kind: 'pty', svc: 1 },
  // cronie.
  { re: /(crond)\[\d+\]: \((\S+)\) ERROR \((?:failed to change SELinux context|failed to get security context|No SELinux security context)\)/, kind: 'nocontext', svc: 1, login: 2 },
  { re: /(crond)\[\d+\]: (?:No SELinux security context|NULL security context for user) \(?(\S+?)\)?$/, kind: 'nocontext', svc: 1, login: 2 },
];
const SERVICE_SOURCE = { sshd: 'sshd_t', login: 'local_login_t', remote: 'remote_login_t', crond: 'crond_t', 'systemd-user': 'init_t', gdm: 'xdm_t', 'gdm-password': 'xdm_t', lightdm: 'xdm_t', su: null, sudo: null };

/**
 * Login refusals in a log text: [{ program (login program's PAM service or name), source (its domain,
 * when known), login, kind: 'nocontext' | 'setexec' | 'pty', count, text (one line) }] grouped by
 * program, login and kind.
 */
function loginRefusals(text) {
  const map = new Map();
  for (const line of String(text || '').split(/\r?\n/)) {
    if (/\btype=[A-Z_0-9]+\b.*\bmsg=audit\(/.test(line)) continue;
    for (const p of LOGIN_LOG) {
      const m = p.re.exec(line);
      if (!m) continue;
      const program = m[p.svc];
      const login = p.login && m[p.login] ? m[p.login].replace(/[.,)]+$/, '') : null;
      const k = `${program}|${login}|${p.kind}`;
      if (!map.has(k)) map.set(k, { program, source: Object.prototype.hasOwnProperty.call(SERVICE_SOURCE, program) ? SERVICE_SOURCE[program] : null, login, kind: p.kind, count: 0, text: line.trim().slice(0, 300) });
      map.get(k).count++;
      break;
    }
  }
  return [...map.values()];
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
        scontext: d.scontext.raw, tcontext: d.tcontext.raw, ops: [], invalids: [], reasons: [], userspace: false, events: new Set() };
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
    if (d.invalid) add(g.invalids, d.invalid);
    if (d.reason) add(g.reasons, d.reason);
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
 * Order: unknown types, a program outside its domain (te.transition), wrong label, boolean,
 * a constraint (te.constraints: allowed by the rules, denied by constrain/mlsconstrain),
 * already allowed, generic label, missing rule.
 */
/**
 * SELINUX_ERR records: the kernel refused something the rules alone don't decide. te.err (from the
 * server) = { nnp: policy_query nnp answer, valid: context_valid of the computed context, bounds:
 * { parent, masked } }. Groups the build now handles get 'allowed' (so a fix shows as resolved).
 */
function errorVerdict(g, te, policyName, notes) {
  const err = (te && te.err) || {};
  const ops = g.ops || [];
  const S = g.source, T = g.target;
  if (ops.includes('security_bounded_transition')) {
    const n = err.nnp || null;
    const ok = (p) => n && n[p] && n[p].status === 'allowed';
    if (n && (n.bounded || ok('nnp_transition') || ok('nosuid_transition'))) {
      return { verdict: 'allowed', title: 'Allowed now', detail: `${policyName} lets ${S} start ${T} under NoNewPrivileges or from a nosuid mount (${n.bounded ? `${T} is bounded by ${S}` : `process2 ${['nnp_transition', 'nosuid_transition'].filter(ok).join(' and ')}`}), so this refusal won't recur with it. If it still happens, the host runs a different policy.`, fixes: [], notes };
    }
    const perms = n ? ['nnp_transition', 'nosuid_transition'].filter(p => !ok(p)) : ['nnp_transition', 'nosuid_transition'];
    const needed = `allow ${S} ${T}:process2 { ${perms.join(' ')} };`;
    return { verdict: 'nnp', title: 'Domain change refused: NoNewPrivileges or nosuid',
      detail: `${S} ran a program that starts ${T}, while the process had NoNewPrivileges set (a systemd unit's NoNewPrivileges=yes, or options that imply it for units with User=) or the program was on a nosuid mount. The kernel then takes the change only if ${T} has no rights ${S} lacks (typebounds) or the policy allows process2 nnp_transition / nosuid_transition, so exec failed ("Operation not permitted" / "Permission denied"). For a login this is the session that closes right after the password. The policy compiles either way: this is checked only when the program starts.`,
      fixes: [{ text: `Either allow the change (below: an interface of this policy, or the rule), or stop setting NoNewPrivileges for this program (and options that imply it) / mount its filesystem without nosuid.` }],
      needed, need: { source: S, target: T, tclass: 'process2', perms }, attrs: n ? (n.nnpTo || []).filter(x => x.attribute && !(n.attrs || []).includes(x.name)).map(x => x.name) : [], notes };
  }
  if (ops.includes('security_compute_sid') && (g.invalids || []).length) {
    const ctx = parseContext(g.invalids[0]);
    const v = err.valid;
    if (v && v.ok) {
      return { verdict: 'allowed', title: 'Valid now', detail: `${g.invalids[0]} is a valid context in ${policyName}, so starting it won't fail this way any more.`, fixes: [], notes };
    }
    const reasons = v ? v.reasons.map(r => r.text) : [];
    const role = reasons.some(r => /isn't authorized for/.test(r));
    const userRole = reasons.some(r => /doesn't have role/.test(r));
    return { verdict: 'invalid', title: "Program can't start: invalid context",
      detail: `${S} ran a program labeled ${T}${g.tclass && g.tclass !== 'process' ? ` (${g.tclass})` : ''}, and the policy's type_transition computes ${g.invalids[0]} for it${reasons.length ? `, which isn't valid: ${reasons.join('; ')}` : ', which this policy doesn\'t accept'}. The kernel refuses such an exec (security_compute_sid: invalid context) although every rule is there. ${role && ctx ? `Authorize role ${ctx.role} for ${ctx.type}: the program's *_run interface does that and the transition together (below), or role ${ctx.role} types ${ctx.type}; in its module.` : userRole && ctx ? `Give the SELinux user ${ctx.user} role ${ctx.role} (users file / semanage user -R), or keep the old role with a role_transition.` : ''}`,
      fixes: [], needed: role && ctx ? `role ${ctx.role} types ${ctx.type};` : null, role: ctx ? { role: ctx.role, type: ctx.type, user: ctx.user } : null, notes };
  }
  if (ops.includes('security_compute_av') && (g.reasons || []).includes('bounds')) {
    const b = err.bounds;
    const P = b ? b.parent : null;
    return { verdict: 'bounds', title: 'Masked by typebounds',
      detail: `${S} is bounded${P ? ` by ${P}` : ''} (typebounds): the kernel gives it only what ${P || 'its parent'} has, so its rule for ${T}:${g.tclass} { ${g.perms.join(' ')} } is masked at run time, although it compiles. Give ${P || 'the parent'} the same access, or remove the rule from ${S}.`,
      fixes: [], needed: P ? `allow ${P} ${T}:${g.tclass} { ${g.perms.join(' ')} };` : null, need: P ? { source: P, target: T, tclass: g.tclass, perms: g.perms } : null, notes };
  }
  if (ops.includes('security_validate_transition')) {
    return { verdict: 'error', title: 'Relabel refused by a validatetrans rule', detail: `A validatetrans constraint (mlsvalidatetrans in MLS policies) refused relabeling a ${g.tclass} from ${g.scontext} to ${g.tcontext}. Check the policy's validatetrans rules for ${g.tclass}; the type rules aren't involved.`, fixes: [], notes };
  }
  return { verdict: 'error', title: 'SELinux error', detail: `The kernel refused ${ops.length ? ops.join(', ') : 'an operation'} for ${S} → ${T} (${g.tclass}). This is not an access denial; the record itself (Evidence) says what was refused.`, fixes: [], notes };
}

function verdict(g, te, labels, policyName) {
  const notes = [];
  if (g.permissive) notes.push(g.userspace ? 'Logged in permissive mode: the access was allowed this time, and will be denied when enforcing.' : 'Logged in permissive mode (permissive=1): the access was allowed this time, and will be denied when enforcing.');
  if (te && te.permissiveDomain) notes.push(`${g.source} is a permissive domain in ${policyName}: its denials are logged, not enforced.`);
  const allow = `allow ${g.source} ${g.source === g.target ? 'self' : g.target}:${g.tclass} { ${g.perms.join(' ')} };`;
  if (g.kind === 'error') return errorVerdict(g, te, policyName, notes);
  if (te && te.unknown && te.unknown.length) {
    return { verdict: 'unknown', title: 'Not in this policy', detail: `${te.unknown.join(' and ')} ${te.unknown.length > 1 ? "aren't types" : "isn't a type"} in ${policyName}. The denial came from a host running a different policy; check it against that policy (Check against).`, fixes: [], notes };
  }
  if (te && te.unknownClass) {
    return { verdict: 'unknown', title: 'Unknown class', detail: `${policyName} has no class ${g.tclass}; the denial came from a host running a different policy.`, fixes: [], notes };
  }
  const tr = te && te.transition;
  if (tr) {
    const D = tr.domains[0];
    if (D && tr.current && tr.expected && tr.current !== tr.expected) {
      return { verdict: 'transition', title: 'Program has the wrong label', detail: `${tr.exe} is labeled ${tr.current}, but the policy labels it ${tr.expected}, the program type of ${D}. With the wrong label it doesn't enter ${D} and runs as ${g.source}, so this denial isn't about missing rules: relabel the program and restart the service.`,
        fixes: [{ text: 'Relabel the program, then restart the service', command: `restorecon -v ${shellQuote(tr.exe)}` }], notes };
    }
    if (D) {
      return { verdict: 'transition', title: `Not running in ${D}`, detail: `${tr.exe} is labeled ${tr.expected || tr.current}, the program type of ${D}, but it runs as ${g.source}. ${g.source === 'unconfined_t'
        ? `It was started from a login shell, where it stays unconfined: start it as a service (systemctl start …) so it enters ${D}.`
        : `It was started without the transition into ${D}: check that the service starts this program directly (not through a script or interpreter with another label) and was started by systemd${tr.current ? '' : `, and that the file on the host is labeled ${tr.expected} (ls -Z: a copied-in program keeps its old label)`}.`} Don't give ${g.source} more rights: the denial goes away once it runs in ${D}.`,
        fixes: tr.current ? [] : [{ text: 'If the program has another label on the host, relabel it, then restart the service', command: `restorecon -v ${shellQuote(tr.exe)}` }], notes };
    }
    if (tr.generic) {
      return { verdict: 'transition', title: 'No policy for this program', detail: `${tr.exe} has the generic label ${tr.current || tr.expected || 'of ordinary programs'}, so no confined domain exists for it and it runs as ${g.source}. Rules for ${g.source} aren't the fix: to confine the program, write a service policy for it (its own domain and program type), install it and relabel the program.`,
        fixes: [{ text: 'Create a service policy for this program', action: { cmd: 'newService', exec: tr.exe } }], notes };
    }
  }
  const per0 = (te && te.perms) || {};
  const allAllowed = !!te && g.perms.length > 0 && g.perms.every(p => per0[p] && per0[p].status === 'allowed');
  if (allAllowed && te.constraints && te.constraints.length) return constraintVerdict(g, te.constraints, policyName, notes);
  // With the rules already allowing the access as labeled, a label that differs from the file contexts didn't cause it.
  const wrong = allAllowed ? [] : (labels || []).filter(l => l.expected && l.expected !== g.target);
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
  if (te && !missing.length && !viaBool.length && te.constraints && te.constraints.length) {
    return constraintVerdict(g, te.constraints, policyName, notes);
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
  if (g.tclass === 'process2' && g.perms.some(p => p === 'nnp_transition' || p === 'nosuid_transition')) {
    notes.push(`${g.source} started a program in ${g.target} under NoNewPrivileges (nnp_transition) or from a nosuid mount (nosuid_transition): the kernel refused the change of domain and exec failed (see the security_bounded_transition record of the same event). Allowing it is the fix when ${g.target} is meant to start there; otherwise drop NoNewPrivileges for that program or remount without nosuid.`);
  }
  return { verdict: 'missing', title: 'Missing rule', detail: `${policyName} doesn't allow ${(missing.length ? missing : g.perms).join(', ')} for ${g.source} on ${g.target} (${g.tclass}). Grant it with an interface of the module that owns ${g.target}, in the module of ${g.source}, rather than with this raw rule.`,
    fixes: [], needed: allow, notes };
}

/**
 * Allowed by the rules but denied by a constraint: which comparisons failed,
 * in words (MCS/MLS levels, SELinux users (UBAC), roles), and what to do.
 */
function constraintVerdict(g, failing, policyName, notes) {
  const bad = failing.flatMap(c => c.leaves.filter(l => !l.ok));
  const mls = bad.filter(l => /^(l|h)[12] /.test(l.text));
  const users = bad.filter(l => /^u1 /.test(l.text));
  const roles = bad.filter(l => /^r1 /.test(l.text));
  const levelOf = (raw) => (raw || '').split(':').slice(3).join(':');
  const lines = failing.map(c => `${c.kind} ${g.tclass} { ${c.perms.join(' ')} }: ${c.text}`).join('\n');
  const fixes = [];
  const p = g.paths[0];
  let title, why;
  if (mls.length) {
    const l = mls[0];
    title = 'Denied by MCS/MLS levels';
    why = `The process's level ${levelOf(g.scontext) || l.a} doesn't satisfy ${l.text} for the object's ${levelOf(g.tcontext) || l.b}${/dom/.test(l.text) ? ' (the process must have every category the object has)' : ''}. The rules allow the access; the categories don't.`;
    if (p) fixes.push({ text: `Give the file the process's categories (if it should share them)`, command: `chcon -l ${levelOf(g.scontext).split('-').pop()} ${shellQuote(p)}` });
    notes.push('If the domain really must use objects of every category, it needs an MCS/MLS exemption interface (e.g. mcs_file_read_all, mcs_file_write_all) rather than a relabel.');
  } else if (users.length) {
    const u = g.scontext.split(':')[0], o = g.tcontext.split(':')[0];
    title = 'Denied by SELinux user separation (UBAC)';
    why = `The process's SELinux user ${u} differs from the object's ${o}, and ${g.source} isn't exempt from user-based access control.`;
    if (p) fixes.push({ text: `Give the file the process's SELinux user (if it belongs to it)`, command: `chcon -u ${u} ${shellQuote(p)}` });
  } else if (roles.length) {
    title = 'Denied by a role constraint';
    why = `The process's role ${g.scontext.split(':')[1]} doesn't satisfy ${roles[0].text}.`;
  } else {
    title = 'Denied by a constraint';
    why = 'A constraint on this class denies it although the rules allow it.';
  }
  return { verdict: 'constraint', title, detail: `${why}\n${lines}\nFailed: ${bad.map(l => `${l.text} (${l.b !== undefined ? `${l.a} vs ${l.b}` : l.a})`).join('; ')}`, fixes, notes, constraints: failing };
}

/* ---------- interface suggestions ---------- */

/**
 * Statements of each top-level call in an m4-expanded probe module
 * (build.expandCalls): Map "name(args)" → [{ rt, s: [names], t: [names],
 * c: [names], perms: [names] ('*' = all), cond }] for allow-like rules, and
 * { rt: 'typeattribute', s: [type], attrs: [names] }. require blocks are
 * skipped; rules inside `if (…) { }` (tunable_policy) are marked cond.
 */
function probeStatements(text) {
  const out = new Map();
  let cur = null, own = [], nested = [], depth = 0;
  const flush = () => {
    if (cur) out.set(cur, [...parseStatements(own.join('\n')), ...parseStatements(nested.join('\n')).map(s => ({ ...s, nested: true }))]);
    cur = null; own = []; nested = [];
  };
  for (const line of text.split('\n')) {
    const b = /^#####\s+begin\s+(.+?)\s+depth:\s*(\d+)\s*$/.exec(line);
    if (b) { if (b[2] === '1') { flush(); cur = b[1]; } depth = +b[2]; continue; }
    const e = /^#####\s+end\s+.+?\s+depth:\s*(\d+)\s*$/.exec(line);
    if (e) { depth = +e[1]; if (depth === 0) flush(); continue; }
    // Statements of the interface itself (depth 1) vs of the interfaces it calls (marked nested).
    if (cur && !line.startsWith('#')) (depth > 1 ? nested : own).push(line.replace(/#.*$/, ''));
  }
  flush();
  return out;
}

function parseStatements(text) {
  const toks = text.match(/[A-Za-z0-9_$.*~-]+|[{}():;,]/g) || [];
  const out = [];
  let i = 0;
  const blocks = []; // 'cond' | 'opt' | 'other'
  const set = () => {
    // name | { names, nested } | ~set | *
    const names = [];
    let comp = false;
    if (toks[i] === '~') { comp = true; i++; }
    if (toks[i] === '{') {
      let depth = 0;
      do {
        const t = toks[i++];
        if (t === '{') depth++;
        else if (t === '}') depth--;
        else if (t !== undefined) names.push(t);
      } while (depth > 0 && i < toks.length);
    } else if (toks[i] !== undefined) {
      let t = toks[i++];
      if (t.startsWith('~')) { comp = true; t = t.slice(1); }
      names.push(t);
    }
    return comp || names.includes('*') ? ['*'] : names.filter(n => !n.startsWith('-'));
  };
  const skipTo = (tok) => { while (i < toks.length && toks[i] !== tok) i++; i++; };
  const skipBlock = () => { let d = 0; do { if (toks[i] === '{') d++; else if (toks[i] === '}') d--; i++; } while (d > 0 && i < toks.length); };
  while (i < toks.length) {
    const k = toks[i];
    if (k === '}') { blocks.pop(); i++; continue; }
    if (k === 'require') { i++; skipBlock(); continue; }
    if (k === 'if') { i++; let d = 0; do { if (toks[i] === '(') d++; else if (toks[i] === ')') d--; i++; } while (d > 0 && i < toks.length); if (toks[i] === '{') { i++; blocks.push('cond'); } continue; }
    if (k === 'else' || k === 'optional') { i++; if (toks[i] === '{') { i++; blocks.push(k === 'else' ? 'cond' : 'opt'); } continue; }
    if (k === '{') { i++; blocks.push('other'); continue; }
    if (k === 'allow' || k === 'auditallow' || k === 'dontaudit' || k === 'neverallow') {
      i++;
      const s = set(), t = set();
      if (toks[i] !== ':') { skipTo(';'); continue; }
      i++;
      const c = set(), perms = set();
      skipTo(';');
      out.push({ rt: k, s, t, c, perms, cond: blocks.includes('cond') });
      continue;
    }
    if (k === 'typeattribute') {
      i++;
      const s = [toks[i++]];
      const attrs = [];
      while (i < toks.length && toks[i] !== ';') { if (toks[i] !== ',') attrs.push(toks[i]); i++; }
      i++;
      out.push({ rt: 'typeattribute', s, attrs, cond: blocks.includes('cond') });
      continue;
    }
    skipTo(';');
  }
  return out;
}

/**
 * Rank candidate interfaces for one denial group.
 *   need:   { domain, target, tclass, perms }
 *   cands:  [{ name, call ("name(args)"), owner (defined in the target's module), off, summary, loc }]
 *   stmts:  probeStatements() result
 *   types:  typeinfo info { name: { attr, size, attrs } } (target's attrs; attribute sizes)
 *   attrRules: { attr: [compiled allow rules with that attribute as source] }
 * → [{ ...cand, covers (all perms), missing: [perms], extra (other rights:
 *   types × classes × perms beyond the need), cond (rules under a boolean), attrs (added to the domain) }],
 * full covers first, fewest extra rights first.
 */
function rankInterfaces(need, cands, stmts, types, attrRules = {}) {
  const tAttrs = new Set([need.target, ...((types[need.target] && types[need.target].attrs) || [])]);
  const size = (n) => (n === 'self' ? 1 : types[n] ? Math.max(types[n].size, 1) : 1);
  const out = [];
  for (const c of cands) {
    const list = stmts.get(c.call);
    if (!list) continue;
    const added = new Set(list.filter(s => s.rt === 'typeattribute' && s.s[0] === need.domain && !s.cond).flatMap(s => s.attrs));
    const mine = (src) => src.some(n => n === need.domain || added.has(n));
    const rules = [];
    let cond = 0;
    for (const s of list) {
      if (s.rt !== 'allow' || !mine(s.s)) continue;
      if (s.cond) { cond++; continue; }
      rules.push({ t: s.t, c: s.c, perms: s.perms });
    }
    // Rights that come with the attributes the call adds (rules written for the attribute elsewhere).
    for (const a of added) for (const r of attrRules[a] || []) if (!r.cond) rules.push({ t: [r.t], c: [r.c], perms: r.perms });
    const got = new Set();
    const granted = new Map(); // "type|class" → Set(perms): rights counted once however often repeated
    for (const r of rules) {
      for (const t of r.t) for (const cl of r.c) {
        const k = `${t}|${cl}`;
        if (!granted.has(k)) granted.set(k, new Set());
        for (const p of r.perms) granted.get(k).add(p);
        const hitsTarget = tAttrs.has(t) || (t === 'self' && need.domain === need.target) || t === '*';
        if (hitsTarget && (cl === need.tclass || cl === '*')) for (const p of need.perms) if (r.perms.includes(p) || r.perms.includes('*')) got.add(p);
      }
    }
    // Extra rights: per type (attributes count their members) and permission, writes and
    // executes weighing more than reads; the denied permissions themselves don't count.
    let total = 0;
    const byType = new Map(); // type → { classes: Set, perms: Set, weight }
    for (const [k, perms] of granted) {
      const t = k.slice(0, k.indexOf('|')), cl = k.slice(k.indexOf('|') + 1);
      const n = t === '*' ? 5000 : size(t);
      const isNeed = (tAttrs.has(t) || (t === 'self' && need.domain === need.target)) && cl === need.tclass;
      let w = 0;
      for (const p of perms) if (!(isNeed && need.perms.includes(p) && n === 1)) w += permWeight(p);
      if (perms.has('*')) w += 60;
      total += n * w;
      if (!w) continue;
      const e = byType.get(t) || { classes: new Set(), perms: new Set(), weight: 0, size: n };
      e.classes.add(cl);
      for (const p of perms) e.perms.add(p);
      e.weight += n * w;
      byType.set(t, e);
    }
    const missing = need.perms.filter(p => !got.has(p));
    if (missing.length === need.perms.length) continue;
    const grants = [...byType].sort((a, b) => b[1].weight - a[1].weight).slice(0, 4).map(([t, e]) =>
      `${t}${types[t] && types[t].attr ? ` (${e.size} types)` : ''} ${[...e.classes].join(', ')}: ${[...e.perms].sort((a, b) => permWeight(b) - permWeight(a)).slice(0, 8).join(' ')}${e.perms.size > 8 ? ' …' : ''}`);
    // Writes, creates or executes anything (beyond the need): matters when only reading was denied.
    let writes = false;
    for (const [k, perms] of granted) {
      const t = k.slice(0, k.indexOf('|')), cl = k.slice(k.indexOf('|') + 1);
      const isNeed = (tAttrs.has(t) || (t === 'self' && need.domain === need.target)) && cl === need.tclass;
      if ([...perms].some(p => permWeight(p) > 1 && !(isNeed && need.perms.includes(p)))) { writes = true; break; }
    }
    out.push({ ...c, covers: !missing.length, missing, extra: total, grants, cond, attrs: [...added], writes });
  }
  // Only reading was denied: an interface that can also change things ranks as if its extra
  // rights were 20 times larger (a read-only one over many types can still lose to it).
  const readOnly = need.perms.every(p => permWeight(p) === 1);
  const score = (x) => x.extra * (x.owner ? 0.8 : 1) * (readOnly && x.writes ? 20 : 1) + (x.off ? 1e7 : 0);
  out.sort((a, b) => (b.covers - a.covers) || (a.missing.length - b.missing.length) || (score(a) - score(b)) || a.name.length - b.name.length || a.name.localeCompare(b.name));
  // Far broader than the best: shown, but flagged.
  const best = out.length ? out[0].extra : 0;
  for (const x of out) x.broad = x.extra > 50 * best + 300;
  // No single interface covers it all: the narrowest pairs that do together.
  out.combos = [];
  if (!out.some(x => x.covers)) {
    const parts = out.slice(0, 40);
    for (let i = 0; i < parts.length; i++) {
      for (let j = i + 1; j < parts.length; j++) {
        const a = parts[i], b = parts[j];
        if (need.perms.every(p => !a.missing.includes(p) || !b.missing.includes(p))) out.combos.push({ items: [a, b], extra: a.extra + b.extra });
      }
    }
    out.combos.sort((x, y) => x.extra - y.extra);
    out.combos = out.combos.slice(0, 3);
  }
  return out;
}

const READ_PERMS = new Set(['read', 'getattr', 'open', 'lock', 'ioctl', 'map', 'search', 'watch', 'watch_reads']);
const MANAGE_PERMS = new Set(['create', 'unlink', 'rename', 'add_name', 'remove_name', 'rmdir', 'reparent', 'link']);

/**
 * A new interface for the module that owns `target`, granting a domain
 * exactly the denied permissions, named the refpolicy way
 * (<module>_<verb>_<object>, e.g. notesd_read_var_lib_files), with its
 * XML doc comment. exists(name) says whether a name is taken.
 * → { name, text (to append to the .if), summary }.
 */
function newInterfaceText({ module, target, tclass, perms }, exists = () => false) {
  const fileLike = !!FILE_MODES[tclass];
  const verb = fileLike
    ? (perms.every(p => READ_PERMS.has(p)) ? 'read' : perms.some(p => MANAGE_PERMS.has(p)) ? 'manage' : 'rw')
    : (perms.length === 1 ? perms[0] : 'use');
  const plural = tclass === 'dir' ? 'dirs' : `${tclass}s`;
  const bare = target.replace(/_t$/, '');
  const stem = bare === module ? '' : bare.startsWith(`${module}_`) ? bare.slice(module.length + 1) : bare;
  const base = [module, verb, stem, plural].filter(Boolean).join('_');
  let name = base;
  for (let n = 2; exists(name); n++) name = `${base}_${n}`;
  const words = (x) => x.replace(/_/g, ' ');
  const summary = `${verb[0].toUpperCase()}${verb.slice(1)} ${stem ? `${words(stem)} ` : ''}${words(plural)} (${target}).`;
  const text = `
########################################
## <summary>
##	${summary}
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(\`${name}',\`
	gen_require(\`
		type ${target};
	')

	allow $1 ${target}:${tclass} { ${perms.join(' ')} };
')
`;
  return { name, text, summary };
}

const WRITE_PERMS = new Set(['write', 'append', 'create', 'unlink', 'rename', 'link', 'setattr', 'add_name', 'remove_name', 'rmdir', 'reparent', 'relabelfrom', 'relabelto', 'mounton', 'quotaon', 'swapon', 'setfscreate', 'audit_access', 'sendto', 'connectto', 'name_bind', 'node_bind', 'kill', 'sigkill', 'ptrace', 'setsched', 'setrlimit']);
const EXEC_PERMS = new Set(['execute', 'execute_no_trans', 'entrypoint', 'transition', 'dyntransition', 'setexec', 'setcurrent', 'execmod', 'execmem', 'execstack', 'execheap', 'relabelto', 'mmap_zero']);
/** How much a granted permission weighs in the "extra rights" count: reads 1, writes 3, executes/transitions 5. */
const permWeight = (p) => (EXEC_PERMS.has(p) ? 5 : WRITE_PERMS.has(p) ? 3 : 1);

/* ---------- writing the fix ---------- */

const LOCAL_HEADER = /^#\s*(\S.*\s)?local polic(y|ies)\s*$/i;

/**
 * Insert an interface call (or a plain allow rule) for `domain` into a .te
 * text, the way refpolicy modules are laid out:
 *   - a call: among the domain's top-level calls in alphabetical order, or,
 *     when `optional`, inside the module's existing optional_policy block for
 *     that interface's module (calls of `module`_*), else in a new block
 *     placed alphabetically among the other optional blocks;
 *   - a rule: after the domain's last top-level allow rule.
 * Returns { text, line (first inserted line, 0-based), inserted: [lines] }
 * or { already: true } when the call/rule is there already (top level or optional).
 */
function insertFix(text, { domain, call, rule, optional, module }) {
  const service = require('./service');
  const crlf = text.includes('\r\n');
  const src = crlf ? text.replace(/\r\n/g, '\n') : text;
  const lines = src.split('\n');
  const sc = service.scanTe(src);
  const indent = /^\t/m.test(src) || !/^ {2,}\S/m.test(src) ? '\t' : src.match(/^( +)\S/m)[1];
  const local = Math.max(0, lines.findIndex(l => LOCAL_HEADER.test(l)));
  const name = call ? call.slice(0, call.indexOf('(')) : null;
  const mentions = sc.stmts.filter(s => s.top && s.l >= local && ((s.args && s.args.includes(domain)) || s.src === domain || s.name === domain || (s.text && new RegExp(`\\b${domain}\\b`).test(s.text))));
  const afterMentions = () => (mentions.length ? Math.max(...mentions.map(s => s.endL)) + 1 : lines.length);
  // After the call whose name comes right before this one alphabetically (modules are only roughly sorted).
  const afterPredecessor = (list) => { const p = list.filter(x => x.name < name).sort((a, b) => (a.name < b.name ? 1 : a.name > b.name ? -1 : b.endL - a.endL))[0]; return p ? p.endL + 1 : null; };
  let at, insert;
  if (rule) {
    // A role statement: already there when the module says it (as written).
    const rr = /^role\s+(\w+)\s+types\s+(\w+)\s*;$/.exec(rule.trim());
    if (rr && new RegExp(`^\\s*role\\s+${rr[1]}\\s+types\\s+(\\{[^}]*\\b${rr[2]}\\b[^}]*\\}|${rr[2]})\\s*;`, 'm').test(src)) return { already: true };
    const m = /^allow\s+(\S+)\s+(\S+):(\S+)\s+\{?\s*([^};]*?)\s*\}?\s*;$/.exec(rule.trim());
    const want = m ? m[4].split(/\s+/) : [];
    if (m && sc.stmts.some(s => s.kind === 'allow' && !s.bool && s.src === m[1] && s.tgt === m[2] && s.cls === m[3] && want.every(p => s.perms.includes(p)))) return { already: true };
    const allows = sc.stmts.filter(s => s.top && (s.kind === 'allow' || s.kind === 'rule') && (s.src === domain || (s.text && new RegExp(`^allow\\s+${domain}\\b`).test(s.text))));
    at = allows.length ? Math.max(...allows.map(s => s.endL)) + 1 : afterMentions();
    insert = [rule.trim()];
  } else {
    if (sc.stmts.some(s => s.kind === 'call' && s.name === name && s.args[0] === domain && (s.top || s.opt) && !s.bool)) return { already: true };
    const blocks = sc.blocks.filter(b => b.name === 'optional_policy' && b.l >= local && !sc.blocks.some(o => o !== b && o.l < b.l && o.endL >= b.endL));
    const innerOf = (b) => sc.stmts.filter(s => s.kind === 'call' && s.opt === b);
    if (optional) {
      const prefix = module ? `${module}_` : name.slice(0, name.indexOf('_') + 1);
      const mine = blocks.find(b => { const inner = innerOf(b); return inner.length && inner.every(s => s.name.startsWith(prefix)) && inner.some(s => s.args[0] === domain); });
      if (mine) {
        const inner = innerOf(mine).filter(s => s.args[0] === domain);
        const p = afterPredecessor(inner);
        at = p != null ? p : inner[0].l;
        insert = [`${indent}${call}`];
      } else {
        const keyOf = (b) => (innerOf(b)[0] || { name: '~' }).name;
        const before = blocks.filter(b => keyOf(b) < name);
        if (before.length) { at = Math.max(...before.map(b => b.endL)) + 1; insert = ['', 'optional_policy(`', `${indent}${call}`, "')"]; }
        else if (blocks.length) { at = blocks[0].l; insert = ['optional_policy(`', `${indent}${call}`, "')", '']; }
        else { at = afterMentions(); insert = ['', 'optional_policy(`', `${indent}${call}`, "')"]; }
      }
    } else {
      // The domain's one-argument interface calls (pattern macros and file type transitions stay where they are).
      const calls = sc.stmts.filter(s => s.top && s.kind === 'call' && s.args.length === 1 && s.args[0] === domain && s.l >= local && local > 0);
      const p = afterPredecessor(calls);
      if (p != null) at = p;
      else if (calls.length) at = calls[0].l;
      else at = afterMentions();
      insert = [call];
      // A call after a blank-line group of rules reads better with a blank line before it.
      if (!calls.length && at > 0 && lines[at - 1] && lines[at - 1].trim()) insert = ['', call];
    }
  }
  // No doubled blank lines where the new lines meet the old ones (the rest of the file stays as it is).
  const blank = (s) => s !== undefined && !s.trim();
  if (insert[0] === '' && (at === 0 || blank(lines[at - 1]))) insert = insert.slice(1);
  if (insert[insert.length - 1] === '' && blank(lines[at])) insert = insert.slice(0, -1);
  if (insert[insert.length - 1] === "')" && lines[at] !== undefined && lines[at].trim()) insert = [...insert, ''];
  const out = [...lines.slice(0, at), ...insert, ...lines.slice(at)];
  let joined = out.join('\n');
  if (crlf) joined = joined.replace(/\n/g, '\r\n');
  return { text: joined, line: at + (insert[0] === '' ? 1 : 0), inserted: insert.filter(l => l !== '') };
}

/** A new standalone module that adds `call` for a domain of the installed policy. */
function localModuleText(name, domain, call) {
  return `policy_module(${name}, 1.0.0)

########################################
#
# Local policy for ${domain}, added with the denial assistant
#

gen_require(\`
\ttype ${domain};
')

${call}
`;
}

const shellQuote = (s) => (/^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

module.exports = { loginRefusals, permWeight, parseDenials, groupDenials, verdict, probeStatements, parseStatements, rankInterfaces, insertFix, localModuleText, newInterfaceText, records, fields, parseContext, FILE_MODES, GENERIC_TYPES, shellQuote };
