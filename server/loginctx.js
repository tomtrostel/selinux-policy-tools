'use strict';
/**
 * Login contexts (pure): whether each login of a policy's seusers gets a
 * valid context for each way in, the way libselinux and the kernel decide it
 * when a session starts, so "Unable to get valid context for <user>" shows up
 * before a host is locked out.
 *
 * What libselinux does (get_ordered_context_list, called by pam_selinux, sshd,
 * crond, gdm with the login's seusers level):
 *  - the caller's context ("fromcon": system_u:system_r:sshd_t, its range
 *    replaced by the login's level) picks the first line of the user's own
 *    file (contexts/users/<seuser>) whose first field has the caller's
 *    role:type, then the first such line of default_contexts; their entries,
 *    own file first, without duplicates, are the candidates;
 *  - libselinux 3.x (RHEL 9, 10): each candidate becomes
 *    seuser:role:type:<the login's level> and is kept when it is a valid
 *    context (security_check_context). The session then starts there: the
 *    caller needs process transition permission to it, or starting the shell
 *    fails;
 *  - libselinux 2.x (RHEL 8): the kernel computes the contexts the caller may
 *    transition to (security_compute_user: valid, process transition allowed,
 *    the range from the user's range within the caller's); the file entries
 *    only order them;
 *  - nothing kept: the failsafe_context line (seuser:<line>) when it is
 *    valid, else the login fails ("Unable to get valid context").
 * A login without a seusers line uses __default__'s; without one, its own name
 * as the SELinux user.
 *
 * The policy questions go through ask(items) → answers by id (policy_query
 * op logincontexts); this module asks and words.
 */
const logins = require('./logins');

/** Problem severities, most serious first. */
const SEVERITY = ['error', 'warning', 'info'];
/**
 * Programs that start login sessions: a failure there locks people out (error). Other callers
 * with lines (initrc_t for runuser in init scripts, unconfined_t) only get info.
 */
const LOGIN_PROGRAMS = new Set([...Object.keys(logins.ENTRY_LABELS), 'rshd_t']);
const LABELS = { rshd_t: 'rsh' };

/**
 * cfg: { seusers: {path, text}, defaults: {path, text}, userFile(seuser) → {path, text} | null,
 * failsafe: {path, text} | null }. ask(items) → Promise<{ [id]: answer }>.
 * → { mls, mappings: [{ login, group, user, range, l, level, ways: [...] }], problems: [...], notes }
 */
async function analyze(cfg, ask) {
  const notes = [];
  const info = (await ask([{ id: 'info', kind: 'info' }])).info || {};
  if (info.error) return { error: info.error };
  const mls = !!info.mls;
  const users = info.users || {};
  const seText = cfg.seusers && cfg.seusers.text;
  const seusers = logins.parseSeusers(seText);
  const defaults = { path: cfg.defaults && cfg.defaults.path, list: logins.parseContexts(cfg.defaults && cfg.defaults.text) };
  const files = new Map();
  const ownFile = (u) => {
    if (!files.has(u)) {
      const f = cfg.userFile ? cfg.userFile(u) : null;
      files.set(u, f && f.text != null ? { path: f.path, list: logins.parseContexts(f.text) } : null);
    }
    return files.get(u);
  };
  const failsafeLine = cfg.failsafe && cfg.failsafe.text != null
    ? String(cfg.failsafe.text).split('\n').map(s => s.replace(/#.*$/, '').trim()).find(Boolean) || null : null;
  const problems = [];
  const at = (file, l) => ({ file, l });
  if (seText == null) notes.push(`No seusers file${cfg.seusers && cfg.seusers.path ? ` at ${cfg.seusers.path}` : ''}: every login uses its own name as the SELinux user.`);
  else if (!seusers.some(m => m.login === '__default__' && !m.group)) {
    problems.push({ severity: 'error', kind: 'nodefault', ...at(cfg.seusers.path, 0), login: '__default__',
      text: 'seusers has no __default__ line: a login without a line of its own uses its own name as the SELinux user, which the policy doesn\'t have, so it can\'t log in. Add e.g. "__default__:user_u:s0".' });
  }
  // Duplicate lines: the first one counts for a login, the first matching one for a group.
  const seen = new Map();
  for (const m of seusers) {
    const k = `${m.group ? '%' : ''}${m.login}`;
    if (seen.has(k)) problems.push({ severity: 'warning', kind: 'duplicate', ...at(cfg.seusers.path, m.l), login: k, text: `${k} has another line above (line ${seen.get(k) + 1}); only that one counts.` });
    else seen.set(k, m.l);
  }

  // Users with a contexts file of their own that no seusers line maps (their logins come from
  // semanage login on the hosts, e.g. %rousers): checked as a login mapped to them at their default level.
  const targets = seusers.map(m => ({ ...m, file: cfg.seusers.path }));
  for (const u of Object.keys(users).sort()) {
    if (u === 'system_u' || seusers.some(m => m.user === u) || !ownFile(u)) continue;
    targets.push({ login: `a login mapped to ${u}`, group: false, user: u, range: mls ? users[u].level || null : null, l: 0, file: ownFile(u).path, hypothetical: true });
  }

  // Ranges as the policy reads them (m4 macros of a tree's seusers resolved).
  const sysRange = mls && users.system_u ? users.system_u.range : null;
  const want = [];
  if (mls) targets.forEach((m, i) => { if (m.range) want.push({ id: `r${i}`, kind: 'resolve', range: m.range }); });
  const ranges = want.length ? await ask(want) : {};

  // Every (mapping, source) and the contexts to ask about.
  const plans = [];
  const qs = new Map(); // question key → item
  const q = (key, item) => { if (!qs.has(key)) qs.set(key, { id: `q${qs.size}`, ...item }); return qs.get(key).id; };
  const urq = new Map();
  targets.forEach((m, i) => {
    const r = mls && m.range ? ranges[`r${i}`] || {} : {};
    const plan = { m, level: mls ? (m.range ? r.range || null : null) : null, rangeError: r.error || null, sources: [] };
    plans.push(plan);
    if (plan.rangeError || !users[m.user]) return;
    const own = ownFile(m.user);
    const level = plan.level || sysRange;
    const lv = (x) => (mls ? `:${x}` : '');
    const types = [];
    for (const f of [own, defaults]) for (const x of (f && f.list) || []) if (x.from.role === 'system_r' && !types.includes(x.from.type)) types.push(x.from.type);
    for (const S of types) {
      const fromcon = `system_u:system_r:${S}${lv(level)}`;
      const lines = [];
      for (const f of [own, defaults]) {
        const x = f && f.list.find(e => e.from.role === 'system_r' && e.from.type === S);
        if (x) lines.push({ file: f.path, l: x.l, own: f === own, to: x.to });
      }
      const cands = [];
      for (const ln of lines) for (const c of ln.to) if (!cands.some(o => o.role === c.role && o.type === c.type)) cands.push({ role: c.role, type: c.type, file: ln.file, l: ln.l, own: ln.own });
      const roles = users[m.user].roles || [];
      const meant = lines.some(x => x.own) || cands.some(c => roles.includes(c.role));
      if (!meant) continue;
      if (mls) {
        const k = `${m.user}|${level}`;
        if (!urq.has(k)) urq.set(k, q(`ur:${k}`, { kind: 'userrange', user: m.user, from: level }));
      }
      const src = { S, label: logins.ENTRY_LABELS[S] || LABELS[S] || `programs in ${S}`, login: LOGIN_PROGRAMS.has(S), fromcon, lines, cands, urKey: mls ? urq.get(`${m.user}|${level}`) : null,
        // A line for a context no process can have (system_r:sysadm_su_t: su runs as sysadm_r) is never used.
        fromValid: q(`v:${fromcon}`, { kind: 'valid', ctx: fromcon }) };
      for (const c of cands) {
        c.ctx3 = `${m.user}:${c.role}:${c.type}${lv(level)}`;
        c.v3 = q(`v:${c.ctx3}`, { kind: 'valid', ctx: c.ctx3 });
        c.t3 = q(`t:${fromcon}>${c.ctx3}`, { kind: 'transition', from: fromcon, to: c.ctx3 });
      }
      if (failsafeLine) {
        src.fsCtx = `${m.user}:${failsafeLine}`;
        src.fsValid = q(`v:${src.fsCtx}`, { kind: 'valid', ctx: src.fsCtx });
        src.fsTrans = q(`t:${fromcon}>${src.fsCtx}`, { kind: 'transition', from: fromcon, to: src.fsCtx });
      }
      plan.sources.push(src);
    }
  });
  let ans = qs.size ? await ask([...qs.values()]) : {};
  for (const p of plans) p.sources = p.sources.filter(s => (ans[s.fromValid] || {}).ok);
  // libselinux 2.x: the same candidates at the kernel's session range.
  const more = new Map();
  for (const p of plans) for (const s of p.sources) {
    const r = s.urKey ? ans[s.urKey] || {} : {};
    s.v2range = mls ? r.range || null : null;
    s.v2rangeError = mls ? r.error || null : null;
    for (const c of s.cands) {
      c.ctx2 = mls ? (s.v2range ? `${p.m.user}:${c.role}:${c.type}:${s.v2range}` : null) : c.ctx3;
      if (!c.ctx2) continue;
      const vk = `v:${c.ctx2}`, tk = `t:${s.fromcon}>${c.ctx2}`;
      c.v2 = qs.has(vk) ? qs.get(vk).id : (more.has(vk) ? more.get(vk).id : (more.set(vk, { id: `m${more.size}`, kind: 'valid', ctx: c.ctx2 }), more.get(vk).id));
      c.t2 = qs.has(tk) ? qs.get(tk).id : (more.has(tk) ? more.get(tk).id : (more.set(tk, { id: `m${more.size}`, kind: 'transition', from: s.fromcon, to: c.ctx2 }), more.get(tk).id));
    }
  }
  if (more.size) ans = { ...ans, ...(await ask([...more.values()])) };

  // Results and problems.
  const mappings = [];
  for (const p of plans) {
    const { m } = p;
    const who = m.group ? `%${m.login}` : m.login;
    const out = { login: m.login, group: m.group, hypothetical: !!m.hypothetical, user: m.user, range: m.range, level: p.level, file: m.file, l: m.l, ways: [] };
    mappings.push(out);
    const here = at(m.file, m.l);
    if (p.rangeError) {
      problems.push({ severity: 'error', kind: 'range', ...here, login: who, text: `${who}'s range ${m.range}: ${p.rangeError}. libselinux can't build a context with it, so ${who} can't log in.` });
      continue;
    }
    if (!users[m.user]) {
      problems.push({ severity: 'error', kind: 'nouser', ...here, login: who,
        text: `${who} is mapped to ${m.user}, which this policy doesn't have, so ${who} can't log in. Map it to one of: ${Object.keys(users).filter(u => u !== 'system_u').sort().join(', ')}.` });
      continue;
    }
    const hyp = [];
    const emit = (x) => (m.hypothetical ? hyp.push(x) : problems.push(x));
    if (mls && !m.range) notes.push(`${who} has no range in seusers: its sessions take the calling program's range (assumed ${sysRange}).`);
    if (!p.sources.length && m.user !== 'system_u') {
      const progs = [...new Set([...((ownFile(m.user) || {}).list || []), ...defaults.list].filter(x => x.from.role === 'system_r').map(x => x.from.type))];
      problems.push({ severity: 'warning', kind: 'noway', ...here, login: who,
        text: `No contexts file offers ${m.user} (roles ${(users[m.user].roles || []).join(' ')}) a context for any login program${progs.length ? ` (${progs.join(', ')})` : ''}, so ${who} can't log in at all. Give ${m.user} a contexts file with lines for the ways it should use, or add its role to default_contexts.` });
    }
    for (const s of p.sources) {
      const roles = users[m.user].roles || [];
      const cands = s.cands.map(c => {
        const v3 = ans[c.v3] || {}, t3 = ans[c.t3] || {}, v2 = c.v2 ? ans[c.v2] || {} : null, t2 = c.t2 ? ans[c.t2] || {} : null;
        return { role: c.role, type: c.type, file: c.file, l: c.l, own: c.own, ctx: c.ctx3, valid: !!v3.ok, reasons: v3.reasons || (v3.error ? [{ kind: 'error', text: v3.error }] : []),
          transition: transitionOf(t3, s.S, c.type), ctx2: c.ctx2, valid2: !!(v2 && v2.ok), transition2: t2 ? transitionOf(t2, s.S, c.type) : null, reasons2: v2 ? v2.reasons || [] : [] };
      });
      const fs = s.fsCtx ? { ctx: s.fsCtx, valid: !!(ans[s.fsValid] || {}).ok, reasons: (ans[s.fsValid] || {}).reasons || [], transition: transitionOf(ans[s.fsTrans] || {}, s.S, s.fsCtx.split(':')[2]) } : null;
      // libselinux 3.x: the first valid candidate, else the failsafe.
      const p3 = cands.find(c => c.valid) || null;
      const v3 = p3 ? { ctx: p3.ctx, how: 'listed', transition: p3.transition } : fs && fs.valid ? { ctx: fs.ctx, how: 'failsafe', transition: fs.transition } : null;
      // libselinux 2.x: the first candidate the kernel lets the caller reach.
      const p2 = cands.find(c => c.valid2 && c.transition2 && c.transition2.ok) || null;
      // The failsafe skips the kernel's computation, so its transition is checked when the shell starts.
      const v2 = p2 ? { ctx: p2.ctx2, how: 'listed', transition: p2.transition2 } : fs && fs.valid ? { ctx: fs.ctx, how: 'failsafe', transition: fs.transition } : null;
      const works3 = !!(v3 && v3.transition.ok), works2 = !!(v2 && v2.transition.ok);
      const way = { source: s.S, label: s.label, fromcon: s.fromcon, lines: s.lines.map(({ file, l, own }) => ({ file, l, own })), candidates: cands, failsafe: fs, v3, v2, works3, works2, v2range: s.v2range, v2rangeError: s.v2rangeError };
      out.ways.push(way);
      const mine = cands.filter(c => roles.includes(c.role));
      const related = (mine.length ? mine : cands).slice(0, 6).map(c => ({ ...at(c.file, c.l), text: `${c.ctx}: ${whyNot(c) || 'valid'}` }));
      const by = m.hypothetical ? who : `${who} (${m.user})`;
      // Login programs lock people out; other callers (initrc_t, unconfined_t) are worth knowing only.
      const sev = s.login ? 'error' : 'info';
      const cant = s.login ? `can't log in by ${s.label}` : `gets no session started from ${s.S} (not a login program)`;
      if (!works3 && !works2) {
        emit({ severity: sev, kind: 'nocontext', ...here, login: who, way: s.label, source: s.S, related,
          text: `${by} ${cant}: unable to get a valid context from ${s.S}. ${summary(cands, roles, m.user, s, fs, v3)}` });
      } else if (!works3) {
        emit({ severity: sev, kind: 'nocontext3', ...here, login: who, way: s.label, source: s.S, related,
          text: `${by} ${cant} on RHEL 9 and later (libselinux 3.x): ${v3 ? `${v3.ctx} is chosen, but ${v3.transition.text}, so the session can't start` : `unable to get a valid context from ${s.S}. ${summary(cands, roles, m.user, s, fs, v3)}`}. On RHEL 8 it gets ${v2.ctx}.` });
      } else if (!works2) {
        emit({ severity: sev, kind: 'nocontext2', ...here, login: who, way: s.label, source: s.S, related,
          text: `${by} ${cant} on RHEL 8 (libselinux 2.x, where the kernel computes the contexts): ${s.v2rangeError ? s.v2rangeError : cands.map(c => `${c.ctx2 || c.ctx}: ${whyNot2(c) || 'valid'}`).slice(0, 3).join('; ')}. On RHEL 9 and later it gets ${v3.ctx}.` });
      }
      if ((works3 && v3.how === 'failsafe') || (works2 && v2.how === 'failsafe')) {
        emit({ severity: s.login ? 'warning' : 'info', kind: 'failsafe', ...here, login: who, way: s.label, source: s.S, related,
          text: `${by} logs in by ${s.label} only through the failsafe context ${fs.ctx}: none of the contexts listed for ${s.S} is valid for it. ${summary(cands, roles, m.user, s, null, null)}` });
      }
      // Meant for this user (its role) but passed over for a later entry.
      const first = cands.find(c => roles.includes(c.role));
      if (works3 && v3.how === 'listed' && first && first !== p3 && !first.valid) {
        emit({ severity: 'info', kind: 'skipped', ...at(first.file, first.l), login: who, way: s.label, source: s.S,
          text: `${by} by ${s.label} lands in ${p3.ctx}, not ${first.ctx} listed before it: ${whyNot(first)}.` });
      }
    }
    if (hyp.length) {
      const fails = hyp.filter(x => x.kind.startsWith('nocontext') && x.severity !== 'info');
      if (fails.length) {
        problems.push({ severity: 'info', kind: 'unmapped', ...here, login: who, user: m.user, related: fails[0].related,
          text: `No seusers line maps a login to ${m.user} (on the hosts, semanage login would add one). If one is mapped, it can't log in by ${[...new Set(fails.map(x => x.way))].join(', ')}: ${fails[0].text.replace(/^[^:]*: /, '')}` });
      }
    }
  }
  problems.sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity) || (a.l || 0) - (b.l || 0));
  return { mls, mappings, problems, notes, failsafe: failsafeLine };
}

/** A transition answer → { ok, text } (text says why not). */
function transitionOf(t, S, T) {
  if (t.error) return { ok: false, text: t.error };
  if (t.ok) return { ok: true, text: '' };
  const why = [];
  if (t.te === 'missing') why.push(`no rule lets ${S} transition to ${T} (allow ${S} ${T}:process transition)`);
  else if (t.te === 'boolean') why.push(`${S} may transition to ${T} only with ${(t.options || [])[0] ? Object.entries(t.options[0]).map(([b, v]) => `${b} ${v ? 'on' : 'off'}`).join(', ') : 'a boolean set otherwise'}`);
  for (const c of t.constraints || []) {
    const bad = (c.leaves || []).filter(x => !x.ok).map(x => (x.b != null ? `${x.text} (${x.a} vs ${x.b})` : `${x.text} (${x.a})`));
    why.push(`a ${c.kind} on process transition fails${bad.length ? ` (${bad.slice(0, 3).join(', ')})` : `: ${c.text}`}`);
  }
  return { ok: false, te: t.te, constraints: t.constraints || [], text: why.join('; ') || `${S} may not transition to ${T}` };
}

/** Why libselinux 3.x passes over a candidate ('' when it doesn't). */
function whyNot(c) {
  return c.valid ? '' : c.reasons.map(r => r.text).join('; ');
}

/** Why the kernel (libselinux 2.x) leaves a candidate out. */
function whyNot2(c) {
  if (!c.ctx2) return 'no session range';
  if (!c.valid2) return c.reasons2.map(r => r.text).join('; ');
  return c.transition2 && !c.transition2.ok ? c.transition2.text : '';
}

/** The reasons behind "unable to get a valid context", shortest useful form. */
function summary(cands, roles, user, s, fs, v3) {
  const mine = cands.filter(c => roles.includes(c.role));
  const parts = [];
  if (!mine.length) parts.push(`The lines for ${s.S} list only roles ${user} doesn't have (${[...new Set(cands.map(c => c.role))].join(' ')}; it has ${roles.join(' ')}).`);
  for (const c of mine.slice(0, 3)) parts.push(`${c.ctx}: ${whyNot(c) || (c.transition.ok ? 'valid' : c.transition.text)}.`);
  if (fs && !(v3 && v3.how === 'failsafe')) parts.push(fs.valid ? `The failsafe ${fs.ctx} is valid but ${fs.transition.text || 'not reachable'}.` : `The failsafe ${fs.ctx} isn't valid either: ${fs.reasons.map(r => r.text).join('; ')}.`);
  else if (!fs) parts.push('There is no failsafe_context to fall back to.');
  return parts.join(' ');
}

module.exports = { analyze, transitionOf, SEVERITY };
