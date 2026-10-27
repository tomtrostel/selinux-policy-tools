// Session starts: what the kernel checks after a login program picked a context
// (server/sessions.js), against a small fake policy and fake host facts. Any OS.
const S = require('../server/sessions');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

/* A fake policy: allow rules as "s|t|class|perm", computed types, nnp answers, invalid automatic transitions, typebounds. */
function policy(over = {}) {
  const allow = new Set([
    // staff_t: enters by the shell, loads libc and the cache, uses sshd's / login's descriptors and its terminals.
    'staff_t|shell_exec_t|file|entrypoint', 'staff_t|init_exec_t|file|entrypoint',
    ...['read', 'open', 'getattr', 'execute', 'map'].map(p => `staff_t|lib_t|file|${p}`),
    ...['read', 'open', 'getattr', 'map'].map(p => `staff_t|ld_so_cache_t|file|${p}`),
    'staff_t|sshd_t|fd|use', 'staff_t|local_login_t|fd|use',
    ...['read', 'write', 'ioctl', 'getattr'].flatMap(p => [`staff_t|user_devpts_t|chr_file|${p}`, `staff_t|user_tty_device_t|chr_file|${p}`]),
    'sshd_t|sshd_devpts_t|chr_file|relabelfrom', 'sshd_t|user_devpts_t|chr_file|relabelto',
    'local_login_t|tty_device_t|chr_file|relabelfrom', 'local_login_t|user_tty_device_t|chr_file|relabelto',
    'cronjob_t|shell_exec_t|file|entrypoint', ...['read', 'open', 'getattr', 'execute', 'map'].map(p => `cronjob_t|lib_t|file|${p}`),
    ...['read', 'open', 'getattr', 'map'].map(p => `cronjob_t|ld_so_cache_t|file|${p}`),
    ...(over.add || []),
  ]);
  for (const x of over.remove || []) allow.delete(x);
  const computed = { 'type_transition|sshd_t|devpts_t|chr_file': 'sshd_devpts_t', 'type_change|staff_t|sshd_devpts_t|chr_file': 'user_devpts_t',
    'type_change|staff_t|tty_device_t|chr_file': 'user_tty_device_t', ...(over.computed || {}) };
  const nnp = over.nnp || {};
  const asked = [];
  const runsAsked = [];
  const ask = async (items) => {
    asked.push(...items);
    const out = {};
    for (const it of items) {
      let a;
      if (it.kind === 'avc') {
        const perms = {};
        for (const p of it.perms) {
          const k = `${it.s}|${it.t}|${it.c}|${p}`;
          perms[p] = { status: allow.has(k) ? 'allowed' : (over.bool && over.bool[k]) ? 'boolean' : 'missing', options: over.bool ? [over.bool[k]].filter(Boolean) : undefined };
          // dontaudit "s|t|class|perm" → the rule that hides the refusal.
          if (!allow.has(k) && (over.dontaudit || []).includes(k)) perms[p].dontaudit = [{ rt: 'dontaudit', s: it.s, t: it.t, c: it.c, perms: [p], cond: '' }];
        }
        a = { perms };
      } else if (it.kind === 'computed') {
        const ty = computed[`${it.rt}|${it.s}|${it.t}|${it.c}`] || null;
        a = { type: ty, rule: ty ? { rt: it.rt, s: it.s, t: it.t, c: it.c, perms: [ty], cond: '' } : null };
      }
      else if (it.kind === 'nnp') {
        const n = nnp[`${it.from}>${it.to}`] || {};
        a = { process2: true, cap: true, bounded: !!n.bounded, nnp_transition: { status: n.nnp ? 'allowed' : 'missing' }, nosuid_transition: { status: n.nosuid ? 'allowed' : 'missing' }, nnpTo: n.nnpTo || [], attrs: n.attrs || [] };
      } else if (it.kind === 'runs') {
        // over.invalid: [{ depth, domain, entry, target, reason, rule }] as exec_check results; over.runs: raw items.
        const inv = ((over.invalid || {})[it.user] || []).map(x => ({ s: x.domain, e: x.entry, to: x.target, rule: x.rule || null, depth: x.depth, state: `r:${x.domain}`,
          fails: [{ kind: 'invalid', reason: x.reason, text: `the computed context is invalid: ${x.reason}`, selinuxErr: 'security_compute_sid', rule: x.rule || null, role: { role: 'staff_r', type: x.target }, dontaudit: [] }] }));
        a = { items: inv.concat((over.runs || {})[it.user] || []), more: false, reached: (over.reached || {})[it.user] != null ? over.reached[it.user] : 30, checked: 5 };
        runsAsked.push(it);
      } else if (it.kind === 'exec') a = (over.exec || {})[it.e] || { s: it.s, e: it.e, to: it.s, fails: [], ok: true };
      else if (it.kind === 'bounds') a = { bounds: over.bounds || [] };
      out[it.id] = a;
    }
    return out;
  };
  return { ask, asked, runsAsked };
}

const facts = (over = {}) => ({
  shellOf: (login) => (over.shells || {})[login] || null,
  realpath: (p) => ({ '/bin/sh': '/usr/bin/bash', '/bin/bash': '/usr/bin/bash' }[p] || p),
  libsOf: (p) => (p === '/usr/bin/bash' || p === '/usr/lib/systemd/systemd' ? ['/lib64/libc.so.6', '/etc/ld.so.cache'] : []),
  labels: async (paths) => new Map(paths.map(p => [p, `system_u:object_r:${({ '/usr/bin/bash': 'shell_exec_t', '/usr/bin/rosh': 'rosh_exec_t', '/lib64/libc.so.6': 'lib_t', '/etc/ld.so.cache': 'ld_so_cache_t', '/usr/lib/systemd/systemd': 'init_exec_t' })[p] || 'bin_t'}:s0`])),
  nosuidMount: (p) => (over.nosuid || {})[p] || null,
  nnpUnit: (src) => (over.units || {})[src] || null,
});

const way = (source, label, ctx, extra = {}) => ({ source, label, works3: true, works2: true, v3: { ctx }, v2: { ctx }, lines: [{ file: '/c/default_contexts', l: 0, own: false }], ...extra });
const report = (ways, m = {}) => ({ mappings: [{ login: 'alice', group: false, user: 'staff_u', file: '/c/seusers', l: 0, ways, ...m }] });
const STAFF = 'staff_u:staff_r:staff_t:s0';
const kinds = (r) => r.problems.map(p => `${p.severity}:${p.kind}`).sort();

(async () => {
  // A session that starts: the shell, its libraries, the relabeled pty and sshd's descriptors.
  let p = policy();
  let r = await S.analyze(report([way('sshd_t', 'ssh', STAFF), way('local_login_t', 'console login', STAFF)]), facts(), p.ask);
  check(!r.problems.length && r.sessions.length === 2 && r.sessions.every(s => s.checks.every(c => c.ok)), 'ssh and console sessions start: entry, libraries, terminal, NoNewPrivileges', r);
  const ssh = r.sessions[0];
  check(ssh.program === '/bin/bash' && ssh.programType === 'shell_exec_t' && /sshd_devpts_t relabeled to user_devpts_t/.test(ssh.checks.find(c => c.id === 'tty').text), 'the shell through its symlink (shell_exec_t); sshd\'s pty sshd_devpts_t relabeled to user_devpts_t', ssh);
  check(!p.asked.some(q => q.kind === 'avc' && q.t === 'ld_so_cache_t' && q.perms.includes('execute')), 'the loader cache is mapped, not executed');

  // The shell can't start the domain.
  p = policy({ remove: ['staff_t|shell_exec_t|file|entrypoint'] });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), p.ask);
  let e = r.problems.find(x => x.kind === 'session-entry');
  check(e && e.severity === 'error' && /alice \(staff_u\) can't log in by ssh/.test(e.text) && /\/bin\/bash \(\/usr\/bin\/bash\)/.test(e.text) && /connection closes right after the password/.test(e.text)
    && e.need.source === 'staff_t' && e.need.target === 'shell_exec_t' && e.need.perms.join() === 'entrypoint' && e.file === '/c/seusers', 'no entrypoint on the shell: error on the seusers line, with the need for a fix', r.problems);
  check(e && e.related.length === 1 && e.related[0].file === '/c/default_contexts', 'the contexts line is related');

  // A login's own shell (host passwd), e.g. a restricted shell.
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts({ shells: { alice: '/usr/bin/rosh' } }), p.ask);
  e = r.problems.find(x => x.kind === 'session-entry');
  check(e && e.need.target === 'rosh_exec_t' && /\/usr\/bin\/rosh/.test(e.text), "the login's own shell from passwd", r.problems);

  // A library the domain can't map.
  p = policy({ remove: ['staff_t|lib_t|file|map'] });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), p.ask);
  e = r.problems.find(x => x.kind === 'session-libs');
  check(e && e.need.target === 'lib_t' && e.need.perms.join() === 'map' && /libc\.so\.6/.test(e.text), 'a library it may not map: error, need map on lib_t', r.problems);

  // The terminal: no descriptor use, then no access to the relabeled pty.
  p = policy({ remove: ['staff_t|sshd_t|fd|use'] });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), p.ask);
  e = r.problems.find(x => x.kind === 'session-fd');
  check(e && e.need.target === 'sshd_t' && e.need.tclass === 'fd' && /closes its terminal/.test(e.text), "sshd's descriptors unusable: error (the kernel closes the terminal)", r.problems);
  p = policy({ remove: ['staff_t|user_devpts_t|chr_file|write'] });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), p.ask);
  e = r.problems.find(x => x.kind === 'session-tty');
  check(e && e.need.target === 'user_devpts_t' && e.need.perms.join() === 'write', 'the relabeled pty not writable: error', r.problems);
  // sshd may not relabel: the pty stays sshd_devpts_t, which the user can't use.
  p = policy({ remove: ['sshd_t|user_devpts_t|chr_file|relabelto'] });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), p.ask);
  check(kinds(r).join() === 'error:session-tty,info:session-relabel' && r.problems.find(x => x.kind === 'session-tty').need.target === 'sshd_devpts_t', 'no relabel: the pty stays sshd_devpts_t (error) and the relabel itself is noted', r.problems);
  // No type_change: the console tty is used as tty_device_t.
  p = policy({ computed: { 'type_change|staff_t|tty_device_t|chr_file': null } });
  r = await S.analyze(report([way('local_login_t', 'console login', STAFF)]), facts(), p.ask);
  e = r.problems.find(x => x.kind === 'session-tty');
  check(e && e.need.target === 'tty_device_t' && /not relabeled for staff_t/.test(e.text) && /returns to the login prompt/.test(r.problems[0].text + e.text) === /returns to the login prompt/.test(e.text), 'no type_change: tty_device_t needed', r.problems);

  // cron runs /bin/sh in cronjob_t: no terminal check.
  p = policy();
  r = await S.analyze(report([way('crond_t', 'cron jobs', 'staff_u:staff_r:cronjob_t:s0')]), facts(), p.ask);
  check(!r.problems.length && r.sessions[0].program === '/bin/sh' && !r.sessions[0].checks.some(c => c.id === 'tty'), 'cron: /bin/sh as cronjob_t, no terminal', r.sessions);
  p = policy({ remove: ['cronjob_t|shell_exec_t|file|entrypoint'] });
  r = await S.analyze(report([way('crond_t', 'cron jobs', 'staff_u:staff_r:cronjob_t:s0')]), facts(), p.ask);
  check(/the job never runs/.test((r.problems[0] || {}).text), 'cron: the job never runs', r.problems);

  // NoNewPrivileges: the unit sets it, the policy has no nnp_transition → error; bounded or allowed → fine.
  p = policy();
  const nnpUnit = { units: { sshd_t: { unit: 'sshd.service', nnp: true } } };
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(nnpUnit), p.ask);
  e = r.problems.find(x => x.kind === 'session-nnp');
  check(e && e.severity === 'error' && /sshd\.service runs sshd_t with NoNewPrivileges/.test(e.text) && e.need.tclass === 'process2' && e.need.perms.join() === 'nnp_transition', 'NoNewPrivileges on the unit, no nnp_transition: error', r.problems);
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(nnpUnit), policy({ nnp: { 'sshd_t>staff_t': { nnp: true } } }).ask);
  check(!r.problems.length, 'nnp_transition allowed: fine', r.problems);
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(nnpUnit), policy({ nnp: { 'sshd_t>staff_t': { bounded: true } } }).ask);
  check(!r.problems.length && /bounded by sshd_t/.test(r.sessions[0].checks.find(c => c.id === 'nnp').text), 'staff_t bounded by sshd_t: fine', r.sessions[0].checks);
  // nosuid mount holding the shell.
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts({ nosuid: { '/usr/bin/bash': '/jail' } }), policy().ask);
  e = r.problems.find(x => x.kind === 'session-nosuid');
  check(e && /on \/jail, which is mounted nosuid/.test(e.text) && e.need.perms.join() === 'nosuid_transition', 'the shell on a nosuid mount: error, nosuid_transition needed', r.problems);
  // The policy lets the login program start other users' sessions under NoNewPrivileges (RHEL: login_userdomain), not this one.
  p = policy({ nnp: { 'local_login_t>ro_t': { nnpTo: [{ name: 'login_userdomain', attribute: true, holds: ['staff_t'] }, { name: 'container_domain', attribute: true, holds: [] }] } }, add: ['ro_t|shell_exec_t|file|entrypoint', 'ro_t|local_login_t|fd|use', ...['read', 'write', 'ioctl', 'getattr'].map(x => `ro_t|tty_device_t|chr_file|${x}`), ...['read', 'open', 'getattr', 'execute', 'map'].map(x => `ro_t|lib_t|file|${x}`), ...['read', 'open', 'getattr', 'map'].map(x => `ro_t|ld_so_cache_t|file|${x}`)] });
  r = await S.analyze(report([way('local_login_t', 'console login', 'ro_u:ro_r:ro_t:s0')], { user: 'ro_u' }), facts(), p.ask);
  e = r.problems.find(x => x.kind === 'session-nnp-other');
  check(p.asked.some(x => x.kind === 'nnp' && x.domains.join() === 'ro_t'), "the nnp question names the sessions' domains");
  check(e && e.severity === 'warning' && /login_userdomain domains/.test(e.text) && !/container_domain/.test(e.text) && e.attrs.join() === 'login_userdomain' && e.need.source === 'local_login_t' && e.need.target === 'ro_t', 'others may start under NoNewPrivileges (login_userdomain), this one not: warning with the attribute to join', r.problems);

  // RHEL 8 and RHEL 9 pick different contexts: both are checked and named.
  p = policy({ add: ['sysadm_t|shell_exec_t|file|entrypoint'] });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF, { v2: { ctx: 'staff_u:sysadm_r:sysadm_t:s0' } })]), facts(), p.ask);
  check(r.sessions.length === 2 && r.sessions[0].on === 'RHEL 9+' && r.sessions[1].on === 'RHEL 8' && r.problems.some(x => x.domain === 'sysadm_t' && / \(on RHEL 8\)/.test(x.text)), 'different picks on RHEL 8 / 9+: each checked, problems say which', r.problems.map(x => x.text));

  // A hypothetical login (no seusers line) only gets info.
  p = policy({ remove: ['staff_t|shell_exec_t|file|entrypoint'] });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)], { login: 'a login mapped to staff_u', hypothetical: true }), facts(), p.ask);
  check(r.problems.length && r.problems.every(x => x.severity === 'info'), 'hypothetical logins: info only', r.problems);

  // Programs the session runs into an invalid context: one note per user, grouped by target.
  const inv = [1, 2, 3].map(i => ({ depth: 0, domain: 'sysadm_t', entry: `svc${i}_initrc_exec_t`, target: 'initrc_t', reason: "staff_u doesn't have role system_r" }))
    .concat([{ depth: 0, domain: 'staff_t', entry: 'passwd_exec_t', target: 'passwd_t', reason: "role staff_r isn't authorized for passwd_t" }, { depth: 1, domain: 'x_t', entry: 'y', target: 'z', reason: 'deeper' }]);
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), policy({ invalid: { staff_u: inv } }).ask);
  e = r.problems.find(x => x.kind === 'session-invalid');
  check(e && e.severity === 'info' && /can't run 4 program types/.test(e.text) && /sysadm_t running 3 program types/.test(e.text) && /passwd_t/.test(e.text) && !/deeper/.test(e.text) && e.items.length === 2, 'invalid computed contexts: info, grouped by target, only programs the session runs itself', e);

  // What a host logs: an AVC, nothing (dontaudit), or SELINUX_ERR.
  p = policy({ remove: ['staff_t|sshd_t|fd|use'] });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), p.ask);
  e = r.problems.find(x => x.kind === 'session-fd');
  check(e && e.trace && e.trace.record === 'avc' && /AVC denial is logged/.test(e.trace.text), 'a refusal no dontaudit covers: an AVC is logged', e && e.trace);
  p = policy({ remove: ['staff_t|sshd_t|fd|use'], dontaudit: ['staff_t|sshd_t|fd|use'] });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), p.ask);
  e = r.problems.find(x => x.kind === 'session-fd');
  check(e && e.trace.record === 'none' && e.trace.hidden.length === 1 && /dontaudit staff_t sshd_t:fd use;/.test(e.trace.text) && /semodule -DB/.test(e.trace.text), 'covered by dontaudit: no AVC, the rule that hides it and how to see it', e && e.trace);
  const tty = r.sessions[0].checks.find(c => c.id === 'tty');
  check(tty.ok === false && /no AVC: dontaudit hides it/.test(tty.text) && tty.trace.record === 'none', 'the failed check says so too', tty);
  // Only some refused permissions hidden: the others still make an AVC.
  p = policy({ remove: ['staff_t|user_devpts_t|chr_file|write', 'staff_t|user_devpts_t|chr_file|ioctl'], dontaudit: ['staff_t|user_devpts_t|chr_file|ioctl'] });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), p.ask);
  e = r.problems.find(x => x.kind === 'session-tty');
  check(e && e.trace.record === 'avc', 'write refused and logged, ioctl hidden: still an AVC (for write)', e && e.trace);
  check(e && e.causes.length === 1 && e.causes[0].rule.rt === 'type_change' && e.causes[0].rule.perms[0] === 'user_devpts_t' && /gives staff_t's terminal the type user_devpts_t/.test(e.causes[0].what),
    "the terminal problem's cause: the type_change that gives the session its terminal type", e && e.causes);
  // NoNewPrivileges and invalid contexts: SELINUX_ERR, with the rule that makes the invalid one.
  p = policy({ remove: [] });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts({ units: { sshd_t: { unit: 'sshd.service', nnp: true } } }), p.ask);
  e = r.problems.find(x => x.kind === 'session-nnp');
  check(e && e.trace.record === 'selinux_err' && /security_bounded_transition/.test(e.trace.text) && /ausearch -m SELINUX_ERR/.test(e.trace.text), 'NoNewPrivileges refusal: SELINUX_ERR', e && e.trace);
  const tt = { rt: 'type_transition', s: 'staff_t', t: 'hostname_exec_t', c: 'process', perms: ['hostname_t'], cond: '' };
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), policy({ invalid: { staff_u: [{ depth: 0, domain: 'staff_t', entry: 'hostname_exec_t', target: 'hostname_t', reason: "role staff_r isn't authorized for hostname_t", rule: tt }] } }).ask);
  e = r.problems.find(x => x.kind === 'session-invalid');
  check(e && e.trace.record === 'selinux_err' && e.causes.length === 1 && e.causes[0].rule === tt && /makes staff_t run hostname_exec_t in hostname_t, but role staff_r isn't authorized/.test(e.causes[0].what),
    'invalid context: SELINUX_ERR, caused by the type_transition', e && { trace: e.trace, causes: e.causes });

  // What a restricted user runs: wrappers and what they start (warnings), a non-restricted one: notes.
  const wrapTT = { rt: 'type_transition', s: 'staff_t', t: 'wrap_exec_t', c: 'process', perms: ['wrap_t'], cond: '' };
  const runItems = [
    { s: 'staff_t', e: 'wrap_exec_t', to: 'wrap_t', rule: wrapTT, depth: 0, state: 'staff_r:staff_t',
      fails: [{ kind: 'terminal', text: "wrap_t may not use sshd_t's descriptors (the terminal), so it runs without the terminal (stdin/stdout become /dev/null)", need: { source: 'wrap_t', target: 'sshd_t', tclass: 'fd', perms: ['use'] }, dontaudit: [], rule: wrapTT }] },
    { s: 'wrap_t', e: 'rpm_exec_t', to: 'rpm_t', rule: { ...wrapTT, s: 'wrap_t', t: 'rpm_exec_t', perms: ['rpm_t'] }, depth: 1, state: 'staff_r:wrap_t',
      fails: [{ kind: 'transition', text: 'the automatic transition to rpm_t is refused: wrap_t may not transition to it', need: { source: 'wrap_t', target: 'rpm_t', tclass: 'process', perms: ['transition'] },
        dontaudit: [{ rt: 'dontaudit', s: 'wrap_t', t: 'rpm_t', c: 'process', perms: ['transition'], cond: '' }], rule: { ...wrapTT, s: 'wrap_t', t: 'rpm_exec_t', perms: ['rpm_t'] } }] },
  ];
  p = policy({ runs: { staff_u: runItems }, reached: { staff_u: 4 } });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF), way('local_login_t', 'console login', STAFF)]), facts(), p.ask);
  const rq = p.runsAsked[0];
  check(rq && rq.depth === S.RUN_DEPTH && rq.terms.some(t => t.opener === 'sshd_t' && t.tty === 'user_devpts_t') && rq.terms.some(t => t.opener === 'local_login_t' && t.tty === 'user_tty_device_t'),
    'runs is asked with the terminals the logins hand over', rq);
  const rt = r.problems.find(x => x.kind === 'run-terminal');
  check(rt && rt.severity === 'warning' && /alice \(staff_u\): wrap_t, which staff_t runs through wrap_exec_t, may not use sshd_t's descriptors/.test(rt.text) && rt.need.target === 'sshd_t' && rt.causes[0].rule === wrapTT,
    'restricted user: a wrapper that loses the terminal is a warning, with the need and the type_transition as cause', rt);
  const rf = r.problems.find(x => x.kind === 'run-fails');
  check(rf && rf.severity === 'warning' && /wrap_t can't run rpm_exec_t \(into rpm_t\) \(reached directly: wrap_t\)/.test(rf.text) && rf.trace.record === 'none' && /dontaudit wrap_t rpm_t:process transition;/.test(rf.trace.text),
    'restricted user: what a wrapper starts fails silently (dontaudit) — warning, no AVC', rf);
  check(r.runs[0].restricted && r.runs[0].items.length === 2, 'the report lists the runs per user', r.runs);
  p = policy({ runs: { staff_u: runItems }, reached: { staff_u: 40 } });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), p.ask);
  check(!r.problems.some(x => /^run-/.test(x.kind)) && r.runs[0].items.length === 1 && r.runs[0].items[0].depth === 0 && !r.runs[0].restricted,
    'a user reaching many domains: only its own domain\'s programs, listed in the report, not as problems', { problems: r.problems.map(x => `${x.severity}:${x.kind}`), runs: r.runs });
  p = policy({ invalid: { staff_u: [{ depth: 0, domain: 'staff_t', entry: 'wrap_exec_t', target: 'wrap_t', reason: "role staff_r isn't authorized for wrap_t", rule: wrapTT }] }, reached: { staff_u: 3 } });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), p.ask);
  e = r.problems.find(x => x.kind === 'session-invalid');
  check(e && e.severity === 'warning' && e.roleFix && e.roleFix.role === 'staff_r' && e.roleFix.type === 'wrap_t' && e.roleFix.domain === 'staff_t', 'restricted user: an invalid computed context is a warning with the role to authorize', e);

  // The login path: a forced command, a chroot, the startup scripts.
  const execs = {
    rosh_exec_t: { s: 'staff_t', e: 'rosh_exec_t', to: 'rosh_t', ok: false, fails: [{ kind: 'invalid', text: "the computed context staff_u:staff_r:rosh_t:s0 is invalid: role staff_r isn't authorized for rosh_t", reason: "role staff_r isn't authorized for rosh_t", selinuxErr: 'security_compute_sid', role: { role: 'staff_r', type: 'rosh_t' }, dontaudit: [] }] },
    hostname_exec_t: { s: 'staff_t', e: 'hostname_exec_t', to: 'hostname_t', ok: false, fails: [{ kind: 'entrypoint', text: 'hostname_t may not be entered through hostname_exec_t', need: { source: 'hostname_t', target: 'hostname_exec_t', tclass: 'file', perms: ['entrypoint'] }, dontaudit: [] }] },
  };
  const lab = facts().labels;
  const fx2 = { ...facts(), setupOf: (m) => (m.login === 'alice' ? { command: '/usr/bin/rosh', chroot: '/r', from: 'setting' } : {}),
    startupPrograms: (chroot) => [{ path: '/usr/bin/hostname', script: `${chroot || ''}/etc/profile` }, { path: '/usr/bin/id', script: `${chroot || ''}/etc/profile.d/x.sh` }],
    labels: async (paths, m) => { const out = await lab(paths, m); for (const q3 of paths) { if (/rosh$/.test(q3)) out.set(q3, 'system_u:object_r:rosh_exec_t:s0'); if (/hostname$/.test(q3)) out.set(q3, 'system_u:object_r:hostname_exec_t:s0'); } return out; },
    realpath: (q3) => q3 };
  p = policy({ exec: execs });
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), fx2, p.ask);
  const ses2 = r.sessions[0];
  check(ses2.program === '/bin/bash' && p.asked.some(q3 => q3.kind === 'exec' && q3.e === 'rosh_exec_t' && q3.terms[0].opener === 'sshd_t'), 'the forced command is checked from the session domain, with the terminal', p.asked.filter(q3 => q3.kind === 'exec'));
  e = r.problems.find(x => x.kind === 'session-command');
  check(e && e.severity === 'error' && /alice \(staff_u\) can't use ssh: the session runs \/usr\/bin\/rosh \(rosh_exec_t\) and that program would run in rosh_t, but the computed context/.test(e.text) && e.trace.record === 'selinux_err' && e.roleFix && e.roleFix.type === 'rosh_t',
    'a forced command into a domain the role can\'t have: error (the session ends), SELINUX_ERR, the role to authorize', e);
  check(/\/r\/usr\/bin\/rosh|rosh_exec_t/.test(ses2.checks.find(c => c.id === 'command').text), 'the command is looked up in the chroot', ses2.checks);
  e = r.problems.find(x => x.kind === 'session-startup');
  check(e && e.severity === 'warning' && /\/r\/etc\/profile runs \/usr\/bin\/hostname \(hostname_exec_t\) at every login, and that fails: hostname_t may not be entered/.test(e.text) && e.need.target === 'hostname_exec_t',
    'a startup script program that can\'t run: warning (the login goes on with an error)', e);
  check(ses2.checks.find(c => c.id === 'startup' && c.ok === false), 'the startup check fails in the session list', ses2.checks);

  // typebounds: masked permissions.
  r = await S.analyze(report([way('sshd_t', 'ssh', STAFF)]), facts(), policy({ bounds: [{ child: 'web_t', parent: 'httpd_t', count: 1, masked: [{ t: 'shadow_t', c: 'file', perms: ['read'] }] }] }).ask);
  e = r.problems.find(x => x.kind === 'bounds');
  check(e && e.severity === 'warning' && /web_t is bounded by httpd_t/.test(e.text) && /shadow_t:file \{ read \}/.test(e.text), 'typebounds masking: warning', r.problems);

  // No report, or a report error: nothing.
  r = await S.analyze({ error: 'x' }, facts(), policy().ask);
  check(!r.problems.length && !r.sessions.length, 'no login report: nothing checked');

  /* ---------- webview: Session starts and How to fix ---------- */
  const fs = require('fs');
  const path = require('path');
  const vm = require('vm');
  class El {
    constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this._text = ''; this.nodeType = 1; }
    set textContent(v) { this.children = []; this._text = String(v); }
    get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
    set className(v) { this.attrs.class = v; } get className() { return this.attrs.class || ''; }
    append(...cs) { for (let c of cs) { if (typeof c === 'string') c = { nodeType: 3, textContent: c }; this.children.push(c); } }
    setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'value') this.value = String(v); }
    addEventListener(ev, f) { (this.listeners[ev] = this.listeners[ev] || []).push(f); }
    fire(ev) { for (const f of this.listeners[ev] || []) f({ target: this }); }
    all(pred, out = []) { for (const c of this.children) { if (c.tag && pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
  }
  const byId = {};
  for (const id of ['main', 'status', 'against', 'refresh']) byId[id] = new El(id);
  const posted = [], winListeners = [];
  const wctx = {
    acquireVsCodeApi: () => ({ postMessage: (msg) => posted.push(JSON.parse(JSON.stringify(msg))) }),
    document: { getElementById: (id) => byId[id], createElement: (tag) => new El(tag), createTextNode: (s) => ({ nodeType: 3, textContent: s }) },
    window: { addEventListener: (ev, f) => winListeners.push(f) },
  };
  vm.createContext(wctx);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/loginctx.js'), 'utf8'), wctx);
  const send = (data) => winListeners.forEach(f => f({ data }));
  p = policy({ remove: ['staff_t|sshd_t|fd|use'] });
  const rep = report([way('sshd_t', 'ssh', STAFF)]);
  r = await S.analyze(rep, facts(), p.ask);
  const policies = [{ id: 'build', label: 'Last build of tree', build: true }];
  rep.mappings[0].ways[0].candidates = [];
  send({ cmd: 'result', key: posted[0].key, result: { ...rep, problems: r.problems, sessions: r.sessions, notes: [], policies, policy: policies[0] } });
  let page = byId.main.textContent;
  check(/Session starts/.test(page) && /1 failing/.test(page) && /✗ tty/.test(page) && /✓ entry/.test(page), 'webview: Session starts with each check', page.slice(0, 600));
  const how = byId.main.all(e => e.tag === 'button' && e.textContent === 'How to fix')[0];
  how.fire('click');
  const q = posted[posted.length - 1];
  check(q.cmd === 'sessionFix' && q.need.source === 'staff_t' && q.need.target === 'sshd_t' && q.need.tclass === 'fd' && q.against === 'build', 'webview: How to fix asks for the need', q);
  send({ cmd: 'sessionFix', key: q.key, result: { rule: 'allow staff_t sshd_t:fd { use };', canEdit: true, notes: [],
    suggest: { list: [{ name: 'ssh_use_fds', call: 'ssh_use_fds(staff_t)', module: 'ssh', owner: true, covers: true, summary: 'Use sshd file descriptors.', loc: { p: '/t/ssh.if', l: 3, c: 0 } }] },
    joins: [{ name: 'userdom_login_userdomain', call: 'userdom_login_userdomain(staff_t)', attr: 'login_userdomain', pure: true, domain: 'staff_t', loc: { p: '/t/userdomain.if', l: 9, c: 0 } }] } });
  page = byId.main.textContent;
  check(/ssh_use_fds\(staff_t\)/.test(page) && /narrowest/.test(page) && /owner module/.test(page) && /userdom_login_userdomain\(staff_t\)/.test(page) && /puts it in login_userdomain/.test(page) && /allow staff_t sshd_t:fd \{ use \};/.test(page), 'webview: the policy\'s interfaces, narrowest first, the attribute to join, and the raw rule', page.slice(-900));
  const add = byId.main.all(e => e.tag === 'button' && e.textContent === 'Add…')[0];
  add.fire('click');
  const fx = posted[posted.length - 1];
  check(fx.cmd === 'fix' && fx.domain === 'staff_t' && fx.call === 'ssh_use_fds(staff_t)', 'webview: Add… plans the call in the domain\'s module', fx);
  send({ cmd: 'fixPlan', key: fx.key, plan: { path: '/t/staff.te', line: 40, inserted: ['ssh_use_fds(staff_t)'], text: '' } });
  const apply = byId.main.all(e => e.tag === 'button' && /^Apply to staff\.te$/.test(e.textContent))[0];
  check(!!apply, 'webview: the plan offers Apply to the module file');
  apply.fire('click');
  const ap = posted[posted.length - 1];
  check(ap.cmd === 'applyFix' && ap.plan.path === '/t/staff.te', 'webview: Apply writes the plan', ap);
  send({ cmd: 'applied', key: ap.key });
  check(/✓ added to staff\.te; building/.test(byId.main.textContent), 'webview: applied, building');
  send({ cmd: 'built', ok: true });
  check(posted[posted.length - 1].cmd === 'load', 'webview: the build checks again');
  // A problem the last build added, that leaves no AVC, with the line that causes it.
  p = policy({ remove: ['staff_t|sshd_t|fd|use'], dontaudit: ['staff_t|sshd_t|fd|use'] });
  r = await S.analyze(rep, facts(), p.ask);
  const fd = r.problems.find(x => x.kind === 'session-fd');
  fd.isNew = true; fd.since = ['policy/modules/roles/ro.te'];
  fd.trace.hidden[0].origin = { path: '/t/userdomain.if', line: 41, via: 'userdom_restricted_user_template' };
  fd.causes = [{ rule: { rt: 'typeattribute' }, what: 'puts staff_t into x', origin: { path: '/t/ro.te', line: 11, via: 'ro_thing(staff_t)' } }];
  const ld = posted[posted.length - 1];
  send({ cmd: 'result', key: ld.key, result: { ...rep, problems: r.problems, sessions: r.sessions, notes: [], policies, policy: policies[0],
    runs: [{ user: 'staff_u', login: 'alice', restricted: true, reached: 4, checked: 6, more: false, items: [{ s: 'staff_t', e: 'wrap_exec_t', to: 'wrap_t', fails: [{ kind: 'terminal' }] }] }] } });
  page = byId.main.textContent;
  check(/new with this build/.test(page) && /no AVC: dontaudit/.test(page) && /Caused by ro\.te:12 ro_thing\(staff_t\) puts staff_t into x/.test(page) && /Hidden by userdomain\.if:42 \(userdom_restricted_user_template\)/.test(page) && /✗ tty \(no AVC\)/.test(page),
    'webview: new with this build, no AVC (and where the dontaudit comes from), the line that causes it', page.slice(0, 1500));
  check(/Programs the sessions run/.test(page) && /restricted: 4 domains reached/.test(page), 'webview: the programs the sessions run, per user', page.slice(-600));
  const newBadge = byId.main.all(e => e.attrs.class === 'badge new')[0];
  check(newBadge && /ro\.te/.test(newBadge.attrs.title), 'webview: the badge names the files changed since the previous build', newBadge && newBadge.attrs);

  console.log(failures ? `\n${failures} check(s) failed` : '\nall session start checks passed');
  process.exit(failures ? 1 : 0);
})();
