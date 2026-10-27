'use strict';
/**
 * Sessions that start and then die (pure): after a login program has picked
 * a valid context (server/loginctx.js), the kernel still checks the start of
 * the session, and a policy that compiles can fail there. The login "bounces":
 * the connection closes right after the password.
 *
 * What the kernel checks when the login program (S) runs the session's first
 * program in the user's domain (D):
 *  - D may enter through the program's type (file entrypoint) and the loader
 *    can map its libraries (read open execute map as D);
 *  - the open files it inherits are checked again (flush_unauthorized_files):
 *    without fd use on S and read/write on the terminal's type, stdin/stdout
 *    are replaced by /dev/null and the shell exits at once. The terminal is the
 *    pty S created (type_transition S devpts_t:chr_file) or the console tty,
 *    relabeled for the user by type_change D <old>:chr_file when S may relabel
 *    it;
 *  - under NoNewPrivileges (systemd units) or from a nosuid mount the change
 *    of domain needs process2 nnp_transition / nosuid_transition, or D bounded
 *    by S (typebounds). Otherwise exec fails: SELINUX_ERR
 *    op=security_bounded_transition ("the new domain has more rights");
 *  - programs the session's domains then run with an automatic transition get
 *    a computed context (role kept unless role_transition); one the user or
 *    role may not have makes that exec fail (security_compute_sid: invalid
 *    context);
 *  - typebounds: a bounded domain gets only what its parent has; the rest is
 *    masked at run time (op=security_compute_av reason=bounds).
 *
 * analyze(report, facts, ask): report = loginctx.analyze()'s result; facts =
 * this host's view { host, shellOf(login, group), libsOf(path), labels(paths,
 * mode) → Promise<Map path → context>, nosuidMount(path), nnpUnit(S) };
 * ask(items) → answers by id (policy_query logincontexts kinds avc, computed,
 * nnp, autoinvalid, bounds).
 */

const AT = require('./audittrace');

/** The terminal a login program hands the session: how it is created. */
const TERMINALS = {
  sshd_t: { kind: 'pty', base: 'devpts_t' },
  sshd_session_t: { kind: 'pty', base: 'devpts_t' },
  local_login_t: { kind: 'tty', base: 'tty_device_t' },
};

/** Login programs that run a forced command instead of the shell (sshd's ForceCommand). */
const FORCED_COMMAND = new Set(['sshd_t', 'sshd_session_t']);

/** The program a login program runs in the user's domain; 'shell' = the login's shell. */
const FIRST_PROGRAM = {
  sshd_t: 'shell', sshd_session_t: 'shell', local_login_t: 'shell', remote_login_t: 'shell',
  crond_t: '/bin/sh',
  init_t: '/usr/lib/systemd/systemd',
};

const ENTRY_PERMS = ['entrypoint'];
const LIB_PERMS = ['read', 'open', 'getattr', 'execute', 'map'];
/** The loader's cache is mapped, not executed. */
const libPerms = (p) => (/\.cache$/.test(p) ? LIB_PERMS.filter(x => x !== 'execute') : LIB_PERMS);
const TTY_PERMS = ['read', 'write', 'ioctl', 'getattr'];

const typeOf = (ctx) => (ctx ? String(ctx).split(':')[2] || null : null);
/** A failed check's text ends with what the host logs when it isn't an AVC. */
const quiet = (tr) => (tr && tr.record === 'none' ? ' (no AVC: dontaudit hides it)' : '');

/**
 * → { sessions: [{ login, user, way, source, ctx, domain, role, checks: [{ id, ok, text }] }],
 *     problems: [...], bounds: [...], invalid: [{ user, items, more }] }
 */
async function analyze(report, facts, ask) {
  const problems = [];
  const sessions = [];
  if (!report || report.error || !report.mappings) return { sessions, problems, bounds: [], invalid: [] };

  // The session contexts that start: per mapping and way, what RHEL 9 (and RHEL 8, when different) picks.
  const starts = [];
  for (const m of report.mappings) {
    for (const w of m.ways || []) {
      const picked = [];
      if (w.works3 && w.v3) picked.push({ ctx: w.v3.ctx, on: w.works2 && w.v2 && w.v2.ctx === w.v3.ctx ? 'both' : 'RHEL 9+' });
      if (w.works2 && w.v2 && !(w.works3 && w.v3 && w.v3.ctx === w.v2.ctx)) picked.push({ ctx: w.v2.ctx, on: 'RHEL 8' });
      for (const p of picked) starts.push({ m, w, ...p, D: typeOf(p.ctx), role: String(p.ctx).split(':')[1] });
    }
  }

  // How each login's session is set up: its shell, a command sshd forces instead (ForceCommand),
  // and the chroot it runs in (settings, the wrapper modules, this host's passwd).
  const setupOf = (m, role) => (facts.setupOf ? facts.setupOf(m, role) || {} : {});
  // The first program and its type, per login program and login.
  const programOf = (m, S, setup) => {
    const f = FIRST_PROGRAM[S];
    if (!f) return null;
    if (f !== 'shell') return f;
    if (setup.shell) return setup.shell;
    const sh = !m.group && !m.hypothetical && facts.shellOf ? facts.shellOf(m.login) : null;
    return sh || '/bin/bash';
  };
  // exec follows symlinks (/bin/sh → bash), so the label that counts is the target's. In a chroot,
  // the program is the chroot's file.
  const real = (p, chroot) => { const q2 = chroot ? `${chroot.replace(/\/+$/, '')}${p}` : p; return facts.realpath ? facts.realpath(q2) || q2 : q2; };
  const programs = new Set();
  const extra = new Set();
  for (const s of starts) {
    const setup = setupOf(s.m, s.role);
    s.setup = setup;
    const p = programOf(s.m, s.w.source, setup);
    if (p) { s.program = p; s.real = real(p, setup.chroot); programs.add(s.real); }
    // Programs only a terminal login runs: the forced command, and what the startup scripts run.
    if (FORCED_COMMAND.has(s.w.source) && setup.command) { s.command = setup.command; s.commandReal = real(setup.command, setup.chroot); extra.add(s.commandReal); }
    if (TERMINALS[s.w.source] && facts.startupPrograms) {
      s.startup = (facts.startupPrograms(setup.chroot || null) || []).slice(0, 60).map(x => ({ ...x, real: real(x.path, setup.chroot) }));
      for (const x of s.startup) extra.add(x.real);
    }
  }
  // A chrooted program loads the chroot's copies of its libraries.
  const chrootOf = new Map(starts.filter(s => s.real && s.setup.chroot).map(s => [s.real, s.setup.chroot.replace(/\/+$/, '')]));
  const libs = new Map();
  for (const p of programs) {
    const c = chrootOf.get(p);
    libs.set(p, ((facts.libsOf && facts.libsOf(p)) || []).map(l => (c && !l.startsWith(`${c}/`) ? `${c}${l}` : l)));
  }
  const allPaths = [...new Set([...programs, ...[...libs.values()].flat(), ...extra])];
  const labels = allPaths.length && facts.labels ? await facts.labels(allPaths, 'file') : new Map();
  const labelOf = (p) => typeOf(labels.get(p));

  // Questions, deduplicated.
  const qs = new Map();
  const q = (key, item) => { if (!qs.has(key)) qs.set(key, { id: `s${qs.size}`, ...item }); return qs.get(key).id; };
  const avc = (s, t, c, perms) => q(`a:${s}|${t}|${c}|${perms.join(' ')}`, { kind: 'avc', s, t, c, perms });
  const pairs = new Map(); // S|D → per-pair question ids
  const sessionDomains = [...new Set(starts.map(s => s.D))].sort();
  for (const s of starts) {
    const S = s.w.source, D = s.D;
    const k = `${S}|${D}`;
    if (!pairs.has(k)) {
      const p = { nnp: q(`n:${k}`, { kind: 'nnp', from: S, to: D, domains: sessionDomains }) };
      const term = TERMINALS[S];
      if (term) {
        p.oldQ = term.kind === 'pty' ? q(`c:tt:${S}`, { kind: 'computed', rt: 'type_transition', s: S, t: term.base, c: 'chr_file' }) : null;
        p.fd = avc(D, S, 'fd', ['use']);
      }
      pairs.set(k, p);
    }
    s.pair = pairs.get(k);
    if (s.program) {
      const T = labelOf(s.real);
      if (T) {
        s.entryQ = avc(D, T, 'file', ENTRY_PERMS);
        s.libQ = [];
        for (const l of libs.get(s.real) || []) {
          const L = labelOf(l);
          if (L && !s.libQ.some(x => x.L === L && x.perms === libPerms(l))) s.libQ.push({ L, path: l, perms: libPerms(l), id: avc(D, L, 'file', libPerms(l)) });
        }
      }
      s.programType = T;
    }
  }
  // Programs the session's own domains run with an automatic transition into a context it can't have.
  const perUser = new Map();
  for (const s of starts) {
    const u = s.m.user;
    if (!perUser.has(u)) perUser.set(u, { user: u, starts: [], m: s.m });
    const pu = perUser.get(u);
    if (!pu.starts.some(x => x.role === s.role && x.type === s.D)) pu.starts.push({ role: s.role, type: s.D });
  }
  const boundsQ = q('bounds', { kind: 'bounds' });
  let ans = qs.size ? await ask([...qs.values()]) : {};

  // Terminal types: created by S, then relabeled for D.
  const more = new Map();
  // Ids stay unique across the follow-up batches (answers are merged into one map).
  const later = new Map();
  const q2 = (key, item) => {
    if (qs.has(key)) return qs.get(key).id;
    if (!later.has(key)) { const id = `t${later.size}`; later.set(key, id); more.set(key, { id, ...item }); }
    return later.get(key);
  };
  for (const s of starts) {
    const term = TERMINALS[s.w.source];
    if (!term) continue;
    const S = s.w.source, D = s.D;
    s.oldT = term.kind === 'pty' ? (ans[s.pair.oldQ] || {}).type || term.base : term.base;
    s.newQ = q2(`c:tc:${D}|${s.oldT}`, { kind: 'computed', rt: 'type_change', s: D, t: s.oldT, c: 'chr_file' });
  }
  if (more.size) { ans = { ...ans, ...(await ask([...more.values()])) }; more.clear(); }
  for (const s of starts) {
    if (!s.oldT) continue;
    s.newT = (ans[s.newQ] || {}).type || s.oldT;
    if (s.newT !== s.oldT) {
      s.relFrom = q2(`a:${s.w.source}|${s.oldT}|chr_file|relabelfrom`, { kind: 'avc', s: s.w.source, t: s.oldT, c: 'chr_file', perms: ['relabelfrom'] });
      s.relTo = q2(`a:${s.w.source}|${s.newT}|chr_file|relabelto`, { kind: 'avc', s: s.w.source, t: s.newT, c: 'chr_file', perms: ['relabelto'] });
    }
  }
  if (more.size) { ans = { ...ans, ...(await ask([...more.values()])) }; more.clear(); }
  for (const s of starts) {
    if (!s.oldT) continue;
    const ok = (id) => !id || allowed(ans[id]);
    s.relabeled = s.newT !== s.oldT && ok(s.relFrom) && ok(s.relTo);
    s.tty = s.relabeled || s.newT === s.oldT ? s.newT : s.oldT;
    s.ttyQ = q2(`a:${s.D}|${s.tty}|chr_file|${TTY_PERMS.join(' ')}`, { kind: 'avc', s: s.D, t: s.tty, c: 'chr_file', perms: TTY_PERMS });
  }
  // What the sessions run: every automatic transition from the user's domains (and, for a restricted
  // user, from the domains it reaches in RUN_DEPTH steps: wrappers and what they start), with the
  // terminals its logins hand over; the forced command and the startup scripts' programs.
  const termsOf = new Map();
  for (const s of starts) {
    if (!s.tty) continue;
    if (!termsOf.has(s.m.user)) termsOf.set(s.m.user, []);
    const l = termsOf.get(s.m.user);
    if (!l.some(x => x.opener === s.w.source && x.tty === s.tty)) l.push({ opener: s.w.source, tty: s.tty });
  }
  for (const pu of perUser.values()) {
    pu.terms = termsOf.get(pu.user) || [];
    pu.q = q2(`r:${pu.user}|${pu.starts.map(x => `${x.role}:${x.type}`).sort().join(',')}`, { kind: 'runs', user: pu.user, starts: pu.starts, depth: RUN_DEPTH, terms: pu.terms, restrict: pu.m.hypothetical ? -1 : RESTRICTED_REACH });
  }
  const execQ = (s, e) => q2(`x:${s.m.user}|${s.role}|${s.D}|${e}|${s.w.source}|${s.tty || ''}`, { kind: 'exec', user: s.m.user, role: s.role, s: s.D, e, terms: s.tty ? [{ opener: s.w.source, tty: s.tty }] : [] });
  for (const s of starts) {
    if (s.commandReal) { s.commandType = labelOf(s.commandReal); if (s.commandType) s.cmdQ = execQ(s, s.commandType); }
    for (const x of s.startup || []) { x.type = labelOf(x.real); if (x.type) x.q = execQ(s, x.type); }
  }
  if (more.size) ans = { ...ans, ...(await ask([...more.values()])) };


  // Results.
  const emitted = new Set();
  for (const s of starts) {
    const { m, w, D, role } = s;
    const S = w.source;
    const who = m.group ? `%${m.login}` : m.login;
    const by = m.hypothetical ? who : `${who} (${m.user})`;
    const here = { file: m.file, l: m.l };
    const related = (w.lines || []).map(x => ({ file: x.file, l: x.l, text: `${S}'s line: ${s.ctx} is the session context` }));
    const checks = [];
    const out = { login: m.login, group: !!m.group, hypothetical: !!m.hypothetical, user: m.user, way: w.label, source: S, ctx: s.ctx, on: s.on, domain: D, role, program: s.program || null, programType: s.programType || null, checks };
    sessions.push(out);
    // Login programs lock people out; other callers (initrc_t, unconfined_t) are worth knowing only.
    const sev = LOGIN_SOURCES.has(S) ? 'error' : 'info';
    const add = (kind, severity, text, need, extra = {}) => {
      const key = `${kind}|${who}|${S}|${D}|${need ? `${need.target}:${need.tclass}` : ''}`;
      if (emitted.has(key)) return;
      emitted.add(key);
      problems.push({ severity: m.hypothetical ? 'info' : severity, kind, ...here, login: who, user: m.user, way: w.label, source: S, domain: D, ctx: s.ctx, on: s.on, need: need || null, related, text, ...extra });
    };
    const onText = s.on === 'both' ? '' : ` (on ${s.on})`;
    const prog = s.real && s.real !== s.program ? `${s.program} (${s.real})` : s.program;
    const ends = END_TEXT[S] || 'so the session never starts';

    // 1. The first program.
    if (s.program) {
      if (!s.programType) {
        checks.push({ id: 'program', ok: null, text: `${s.program}: no file context labels it here, not checked.` });
      } else {
        const a = ans[s.entryQ];
        const miss = missing(a, ENTRY_PERMS);
        const tr = miss.length ? AT.avcTrace(a, miss) : null;
        checks.push({ id: 'entry', ok: !miss.length, trace: tr, text: `${D} enters by ${prog} (${s.programType}): ${miss.length ? why(a, miss) + quiet(tr) : 'allowed'}` });
        if (miss.length) {
          add('session-entry', sev, `${by} can't log in by ${w.label}${onText}: ${s.ctx} is picked, but ${D} may not be entered by running ${prog} (${s.programType}; ${why(a, miss)}): exec fails, ${ends}.`,
            { source: D, target: s.programType, tclass: 'file', perms: miss, path: s.real }, { trace: tr, label: { path: s.real, type: s.programType } });
        }
        const badLibs = [];
        for (const x of s.libQ || []) {
          const la = ans[x.id];
          const lm = missing(la, x.perms);
          if (lm.length) badLibs.push({ ...x, miss: lm, a: la });
        }
        for (const b of badLibs) b.trace = AT.avcTrace(b.a, b.miss);
        checks.push({ id: 'libs', ok: !badLibs.length, trace: badLibs.length ? badLibs[0].trace : null, text: (s.libQ || []).length ? `${D} loads ${s.program}'s libraries (${(s.libQ || []).map(x => x.L).join(', ')}): ${badLibs.length ? badLibs.map(b => `${b.L}: ${why(b.a, b.miss)}${quiet(b.trace)}`).join('; ') : 'allowed'}` : `${s.program}'s libraries: not known here (ldd on the host), not checked.` });
        for (const b of badLibs) {
          add('session-libs', sev, `${by} can't log in by ${w.label}${onText}: ${D} can't load ${b.path} (${b.L}; ${why(b.a, b.miss)}), which ${prog} needs: the program dies as it starts, ${ends}.`,
            { source: D, target: b.L, tclass: 'file', perms: b.miss, path: b.path }, { trace: b.trace, label: { path: b.path, type: b.L } });
        }
      }
    }

    // 2. The inherited terminal.
    if (s.tty) {
      const fa = ans[s.pair.fd];
      const fm = missing(fa, ['use']);
      const ta = ans[s.ttyQ];
      const tm = missing(ta, TTY_PERMS);
      const how = s.newT === s.oldT ? `${s.oldT}, not relabeled for ${D} (no type_change ${D} ${s.oldT}:chr_file)` : s.relabeled ? `${s.oldT} relabeled to ${s.newT}` : `${s.oldT}: ${S} may not relabel it to ${s.newT}, so it stays ${s.oldT}`;
      const ftr = fm.length ? AT.avcTrace(fa, fm) : null;
      const ttr = tm.length ? AT.avcTrace(ta, tm) : null;
      checks.push({ id: 'tty', ok: !fm.length && !tm.length, trace: ftr || ttr, text: `Terminal: ${how}. ${D} uses ${S}'s descriptors: ${fm.length ? why(fa, fm) + quiet(ftr) : 'allowed'}; reads and writes ${s.tty}: ${tm.length ? why(ta, tm) + quiet(ttr) : 'allowed'}.` });
      if (fm.length) {
        add('session-fd', sev, `${by} can't log in by ${w.label}${onText}: the session (${D}) may not use the descriptors ${S} hands it (allow ${D} ${S}:fd use is missing), so the kernel closes its terminal when the shell starts and the session ends at once.`,
          { source: D, target: S, tclass: 'fd', perms: fm }, { trace: ftr });
      }
      if (tm.length) {
        // The rules that decide the terminal's type: the pty sshd creates, and the type it is relabeled to.
        const causes = [];
        const created = s.pair.oldQ && ans[s.pair.oldQ] && ans[s.pair.oldQ].rule;
        const changed = s.newT !== s.oldT && ans[s.newQ] && ans[s.newQ].rule;
        if (changed && s.relabeled) causes.push({ rule: changed, perms: [s.newT], what: `gives ${D}'s terminal the type ${s.newT}` });
        else if (created) causes.push({ rule: created, perms: [s.oldT], what: `gives the terminal ${S} creates the type ${s.oldT}` });
        add('session-tty', sev, `${by} can't log in by ${w.label}${onText}: the terminal is ${s.tty} (${how}) and ${D} may not ${tm.join('/')} it, so the kernel closes it when the shell starts: the session ends at once and the connection closes.${s.newT === s.oldT ? ` Users normally get a terminal type of their own that ${S} relabels to (type_change ${D} ${s.oldT}:chr_file …, which the userdom templates set up); granting ${s.oldT} works but lets the session use other sessions' terminals too.` : ''}`,
          { source: D, target: s.tty, tclass: 'chr_file', perms: tm }, { trace: ttr, causes });
      }
      if (s.newT !== s.oldT && !s.relabeled) {
        const rp = allowed(ans[s.relFrom]) ? 'relabelto' : 'relabelfrom';
        add('session-relabel', 'info', `${by}: ${S} may not relabel the terminal from ${s.oldT} to ${s.newT} for ${D}${tm.length ? '' : `; the session still works with ${s.oldT}, but other users' sessions may read it`}.`,
          { source: S, target: rp === 'relabelto' ? s.newT : s.oldT, tclass: 'chr_file', perms: [rp] }, { trace: AT.avcTrace(ans[rp === 'relabelto' ? s.relTo : s.relFrom], [rp]) });
      }
    }

    // 3. The forced command (sshd's ForceCommand): the session is that program.
    if (s.command) {
      if (!s.commandType) checks.push({ id: 'command', ok: null, text: `${s.command}: no file context labels it here, not checked.` });
      else {
        const x = ans[s.cmdQ] || {};
        const bad = (x.fails || []).filter(f => !['terminal', 'pipes'].includes(f.kind));
        const lost = (x.fails || []).filter(f => f.kind === 'terminal');
        const into = x.to && x.to !== D ? ` in ${x.to}` : '';
        checks.push({ id: 'command', ok: !bad.length && !lost.length, trace: bad.length ? traceOf(bad[0]) : lost.length ? traceOf(lost[0]) : null,
          text: `The forced command ${s.command} (${s.commandType}) runs${into}: ${bad.length ? bad.map(f => f.text).join('; ') : lost.length ? lost.map(f => f.text).join('; ') : 'allowed'}` });
        for (const f of bad.concat(lost).slice(0, 3)) {
          add(f.kind === 'terminal' ? 'session-command-tty' : 'session-command', sev, `${by} can't use ${w.label}${onText}: the session runs ${s.command} (${s.commandType})${into ? ` and that program would run${into}` : ''}, but ${f.text}${f.kind === 'terminal' ? '' : `: exec fails and ${ends.replace(/^so /, '')}`}.`,
            f.need || null, fixExtra(f, s.D));
        }
      }
    }
    // 4. What the startup scripts (/etc/profile, profile.d, bashrc) run: a failure prints an error at each login.
    const startBad = [];
    for (const x of s.startup || []) {
      const r = x.q ? ans[x.q] : null;
      const bad = ((r && r.fails) || []).filter(f => !['terminal', 'pipes'].includes(f.kind));
      if (bad.length && !startBad.some(y => y.type === x.type)) startBad.push({ ...x, r, bad });
    }
    if ((s.startup || []).length) {
      checks.push({ id: 'startup', ok: !startBad.length, text: `Startup scripts run ${(s.startup || []).length} program${(s.startup || []).length > 1 ? 's' : ''}${startBad.length ? `; these fail: ${startBad.map(x => `${x.path} (${x.type}): ${x.bad[0].text}`).join('; ')}` : ': all allowed'}` });
      for (const x of startBad.slice(0, 4)) {
        add('session-startup', 'warning', `${by} by ${w.label}${onText}: ${x.script} runs ${x.path} (${x.type}) at every login, and that fails: ${x.bad[0].text}. The login goes on, with an error printed.`,
          x.bad[0].need || null, fixExtra(x.bad[0], s.D));
      }
    }

    // 5. NoNewPrivileges / nosuid.
    const n = ans[s.pair.nnp] || {};
    if (n.process2 && n.cap !== false && !n.error) {
      const nnpOk = n.bounded || ok2(n.nnp_transition);
      const nosuidOk = n.bounded || ok2(n.nosuid_transition);
      const unit = facts.nnpUnit ? facts.nnpUnit(S) : null;
      const mount = s.real && facts.nosuidMount ? facts.nosuidMount(s.real) : null;
      checks.push({ id: 'nnp', ok: (nnpOk || !(unit && unit.nnp)) && (nosuidOk || !mount),
        text: `Started under NoNewPrivileges: ${nnpOk ? (n.bounded ? `allowed (${D} is bounded by ${S})` : 'allowed') : 'refused (no process2 nnp_transition)'}${unit ? `; ${unit.unit} ${unit.nnp ? 'sets' : "doesn't set"} NoNewPrivileges on this host` : ''}. From a nosuid mount: ${nosuidOk ? 'allowed' : 'refused (no process2 nosuid_transition)'}${mount ? `; ${s.program} is on ${mount}, mounted nosuid here` : ''}.` });
      const fixText = `allow ${S} ${D}:process2 { nnp_transition nosuid_transition }`;
      if (!nnpOk && unit && unit.nnp) {
        add('session-nnp', sev, `${by} can't log in by ${w.label}${onText}: ${unit.unit} runs ${S} with NoNewPrivileges, so starting the session in ${D} needs process2 nnp_transition (or ${D} bounded by ${S}). Without it exec fails with "Operation not permitted" and SELINUX_ERR op=security_bounded_transition.`,
          { source: S, target: D, tclass: 'process2', perms: ['nnp_transition'] }, { attrs: attrsWithRule(n, D), trace: AT.selinuxErrTrace('security_bounded_transition', true) });
      } else if (!nosuidOk && mount) {
        add('session-nosuid', sev, `${by} can't log in by ${w.label}${onText}: ${s.program} is on ${mount}, which is mounted nosuid, so entering ${D} from it needs process2 nosuid_transition (or ${D} bounded by ${S}). Without it exec fails, ${ends}.`,
          { source: S, target: D, tclass: 'process2', perms: ['nosuid_transition'] }, { attrs: [], trace: AT.selinuxErrTrace('security_bounded_transition', true) });
      } else if (!nnpOk) {
        // The policy lets S start other sessions under NoNewPrivileges, but not this one.
        // The nnp rules for other sessions' domains show what the policy's authors expect (RHEL: login_userdomain).
        const others = (n.nnpTo || []).filter(x => (x.attribute ? (x.holds || []).some(h => h !== D) : sessionDomains.includes(x.name)) && x.name !== D);
        const viaAttr = others.filter(x => x.attribute);
        const viaType = others.filter(x => !x.attribute);
        if (viaAttr.length || viaType.length) {
          add('session-nnp-other', 'warning', `${by} by ${w.label}${onText}: the policy lets ${S} start sessions under NoNewPrivileges in ${[...viaAttr.map(x => `${x.name} domains`), ...viaType.map(x => x.name)].slice(0, 4).join(', ')}, but not in ${D}. Where ${S} runs with NoNewPrivileges, this login bounces (exec fails, SELINUX_ERR op=security_bounded_transition) while others work.`,
            { source: S, target: D, tclass: 'process2', perms: ['nnp_transition'] }, { attrs: viaAttr.map(x => x.name), fix: fixText, trace: AT.selinuxErrTrace('security_bounded_transition', true) });
        }
      }
    }
  }

  // What the sessions run. A restricted user (it reaches few domains) gets warnings for every
  // program on its way, from its own domain and the ones it reaches (wrappers and what they start);
  // others notes for their own domain's programs only (the rest is the admins' daily business).
  const invalid = [];
  const runs = [];
  for (const pu of perUser.values()) {
    const a = ans[pu.q] || {};
    // A login no seusers line maps yet is only checked for its own domain's programs.
    const restricted = !pu.m.hypothetical && a.reached != null && a.reached <= RESTRICTED_REACH;
    const all = (a.items || []).filter(x => restricted || x.depth === 0);
    const m = pu.m;
    const who = m.group ? `%${m.login}` : m.login;
    runs.push({ user: pu.user, login: who, restricted, reached: a.reached, checked: a.checked, items: all, more: !!a.more });
    const sevRun = m.hypothetical ? 'info' : restricted ? 'warning' : 'info';
    const emittedRun = new Set();
    // Only a restricted user's runs are problems; the others are in the report's list.
    for (const x of restricted ? all : []) {
      const via = x.depth ? ` (reached ${x.depth === 1 ? 'directly' : `in ${x.depth} steps`}: ${x.state.split(':')[1]})` : '';
      for (const f of x.fails) {
        if (f.kind === 'invalid') continue; // below, grouped
        const k = `${f.kind}|${x.s}|${x.e}|${x.to}|${f.need ? `${f.need.target}:${f.need.tclass}` : ''}`;
        if (emittedRun.has(k)) continue;
        emittedRun.add(k);
        const lost = f.kind === 'terminal' || f.kind === 'pipes';
        const what = lost ? `${x.to}, which ${x.s} runs through ${x.e}${via}, ${f.text.replace(/^\S+ /, '')}` : `${x.s} can't run ${x.e}${x.to !== x.s ? ` (into ${x.to})` : ''}${via}: ${f.text}`;
        problems.push({ severity: sevRun, kind: lost ? 'run-terminal' : 'run-fails', file: m.file, l: m.l, login: who, user: pu.user, domain: x.to, need: f.need || null,
          text: `${who}${m.hypothetical ? '' : ` (${pu.user})`}: ${what}.${lost ? '' : ' Running it fails.'}`,
          trace: traceOf(f), causes: f.rule ? [{ rule: f.rule, perms: [x.to], what: `makes ${x.s} run ${x.e} in ${x.to}` }] : [], ...fixExtra(f, x.s) });
      }
    }
    const items = all.filter(x => x.fails.some(f => f.kind === 'invalid')).map(x => { const f = x.fails.find(y => y.kind === 'invalid'); return { domain: x.s, entry: x.e, target: x.to, reason: f.reason || f.text, rule: x.rule, depth: x.depth, role: f.role }; });
    if (!items.length) continue;
    invalid.push({ user: pu.user, items, more: !!a.more });
    // One cause per target domain (sysadm_u without system_r: every init script → initrc_t).
    const byTarget = new Map();
    for (const x of items) { const k = `${x.domain}|${x.target}|${x.reason}`; if (!byTarget.has(k)) byTarget.set(k, { ...x, entries: [] }); byTarget.get(k).entries.push(x.entry); }
    const groups = [...byTarget.values()];
    const list = groups.slice(0, 4).map(x => `${x.domain} running ${x.entries.length > 1 ? `${x.entries.length} program types (${x.entries.slice(0, 2).join(', ')}, …)` : x.entries[0]} → ${x.target} (${x.reason})`).join('; ');
    problems.push({ severity: sevRun, kind: 'session-invalid', file: m.file, l: m.l, login: who, user: pu.user, roleFix: groups[0].role ? { ...groups[0].role, domain: groups[0].domain } : null,
      text: `${pu.user}'s sessions can't run ${items.length}${a.more ? '+' : ''} program type${items.length > 1 ? 's' : ''}${restricted ? '' : ' directly'}: the kernel computes a context the user can't have, so exec fails (SELINUX_ERR security_compute_sid: invalid context). ${list}${groups.length > 4 ? '; …' : ''}. Usually the program's *_run interface (it authorizes the role too) instead of *_domtrans, or leave it if users shouldn't run it.`,
      items: groups.slice(0, 20), trace: AT.selinuxErrTrace('security_compute_sid'),
      causes: groups.slice(0, 4).filter(x => x.rule).map(x => ({ rule: x.rule, perms: [x.target], what: `makes ${x.domain} run ${x.entries[0]} in ${x.target}, but ${x.reason}` })) });
  }

  // typebounds masking.
  const bounds = ((ans[boundsQ] || {}).bounds) || [];
  for (const b of bounds) {
    problems.push({ severity: 'warning', kind: 'bounds', file: null, l: 0, child: b.child, parent: b.parent, trace: AT.selinuxErrTrace('security_compute_av reason=bounds'),
      text: `${b.child} is bounded by ${b.parent} (typebounds), so the kernel masks ${b.count} of its rule${b.count > 1 ? 's' : ''} that ${b.parent} lacks (SELINUX_ERR op=security_compute_av reason=bounds): ${b.masked.slice(0, 3).map(x => `${x.t}:${x.c} { ${x.perms.join(' ')} }`).join(', ')}${b.count > 3 ? ', …' : ''}. Give ${b.parent} the same, or drop the rule from ${b.child}.` });
  }

  problems.sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity) || (a.l || 0) - (b.l || 0));
  return { sessions, problems, bounds, invalid, runs };
}

/** How far a restricted user's programs are followed, and what counts as restricted (domains reached in that many steps). */
const RUN_DEPTH = 2;
const RESTRICTED_REACH = 12;
/** What a host logs for an exec_check failure. */
function traceOf(f) {
  if (f.selinuxErr) return AT.selinuxErrTrace(f.selinuxErr);
  if (f.dontaudit && f.dontaudit.length) return AT.avcTrace({ perms: Object.fromEntries((f.need ? f.need.perms : ['x']).map(p => [p, { dontaudit: f.dontaudit }])) }, f.need ? f.need.perms : ['x']);
  return AT.avcTrace(null, []);
}
/** Fix hints for an exec_check failure: the role to authorize (invalid context) or the rule (need). */
function fixExtra(f, domain) {
  const out = { trace: traceOf(f) };
  if (f.kind === 'invalid' && f.role) out.roleFix = { ...f.role, domain };
  if (f.roleAllow) out.fix = `allow ${f.roleAllow[0]} ${f.roleAllow[1]};`;
  return out;
}

const SEVERITY = ['error', 'warning', 'info'];
/** What a failed start means, per login program. */
const END_TEXT = {
  sshd_t: 'so the connection closes right after the password', sshd_session_t: 'so the connection closes right after the password',
  local_login_t: 'so the console returns to the login prompt', remote_login_t: 'so the connection closes right after the password',
  crond_t: 'so the job never runs', init_t: "so the user's systemd instance doesn't start (no user services, and logins wait for it)",
  xdm_t: 'so the graphical login returns to the greeter',
};
/** Login programs: their failures lock people out. */
const LOGIN_SOURCES = new Set(['sshd_t', 'sshd_session_t', 'local_login_t', 'remote_login_t', 'xdm_t', 'crond_t', 'init_t', 'cockpit_session_t', 'sulogin_t', 'rshd_t']);

/** A process2 permission answer ({ status }) of the nnp question. */
const ok2 = (x) => !!x && x.status === 'allowed';
const allowed = (a) => !!a && !a.unknown && !a.unknownClass && Object.values(a.perms || {}).every(x => x.status === 'allowed');
/** The permissions an avc answer doesn't allow (unknown types: all). */
function missing(a, perms) {
  if (!a || a.unknown || a.unknownClass) return perms.slice();
  return Object.entries(a.perms || {}).filter(([, x]) => x.status !== 'allowed').map(([p]) => p);
}
/** Why: missing rule or a boolean that would allow it. */
function why(a, miss) {
  if (!a) return 'not checked';
  if (a.unknown) return `${a.unknown.join(', ')} isn't a type in this policy`;
  const b = miss.map(p => (a.perms || {})[p]).find(x => x && x.status === 'boolean' && (x.options || [])[0]);
  if (b) return `${miss.join(' ')} only with ${Object.entries(b.options[0]).map(([k, v]) => `${k} ${v ? 'on' : 'off'}`).join(', ')}`;
  return `no rule allows ${miss.join(' ')}`;
}
/** Attributes that S may nnp_transition to (D could join one). */
function attrsWithRule(n, D) {
  return (n.nnpTo || []).filter(x => x.attribute && !(n.attrs || []).includes(x.name)).map(x => x.name);
}

module.exports = { analyze, TERMINALS, FIRST_PROGRAM, SEVERITY, RUN_DEPTH, RESTRICTED_REACH };
