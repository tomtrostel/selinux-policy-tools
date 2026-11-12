'use strict';
/*
 * What runs unconfined on a host (pure). The services systemd starts and the
 * processes running now, each with the executable's label, the domain it
 * runs in here (ps) and the domain the chosen policy would start it in
 * (type_transition from init_t on the executable's type), sorted so the
 * programs with no domain of their own come first: each is a candidate for
 * the service editor. The host facts come as command output (parse*), the
 * policy's answers as plain data (assemble).
 */

/** Domains that confine nothing: the policy's unconfined_domain_type attribute, plus these when the policy has them. */
const UNCONFINED_NAMES = ['unconfined_service_t', 'unconfined_t', 'initrc_t', 'init_t', 'kernel_t'];
/** Per-user service instances (a login's own systemd and runtime directory): sessions, not services. */
const USER_UNITS = /^(user|user-runtime-dir)@/;
/** File types that label programs without a type of their own (no transition to a domain of their own). */
const GENERIC_EXEC = new Set(['bin_t', 'usr_t', 'lib_t', 'default_t', 'unlabeled_t', 'etc_t', 'var_t', 'var_lib_t', 'home_root_t', 'user_home_t', 'admin_home_t', 'root_t', 'tmp_t', 'var_tmp_t', 'shell_exec_t', 'file_t', 'opt_t']);

/** `ps -eo pid=,ppid=,user=,label=,comm=,args=` → [{ pid, ppid, user, ctx, type, comm, args, argv0 }]; kernel threads left out. */
function parsePs(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const m = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/.exec(line);
    if (!m) continue;
    const args = m[6].trim();
    if (!args || args.startsWith('[')) continue; // kernel threads
    const ctx = m[4] === '-' ? null : m[4];
    out.push({ pid: +m[1], ppid: +m[2], user: m[3], ctx, seuser: ctx ? ctx.split(':')[0] || null : null, type: ctx ? ctx.split(':')[2] || null : null, comm: m[5], args, argv0: args.split(/\s+/)[0] });
  }
  return out;
}

/**
 * `systemctl show -p Id,ExecStart,MainPID,ActiveState,SubState,FragmentPath,User,NoNewPrivileges '*.service'`
 * → [{ id, exec: [paths], mainPid, active, sub, fragment, user, nnp }] (blank-line separated blocks).
 */
function parseUnits(text) {
  const out = [];
  for (const block of String(text || '').split(/\n\s*\n/)) {
    const kv = {};
    for (const line of block.split('\n')) { const i = line.indexOf('='); if (i > 0) kv[line.slice(0, i)] = (kv[line.slice(0, i)] ? `${kv[line.slice(0, i)]} ; ` : '') + line.slice(i + 1); }
    if (!kv.Id) continue;
    const exec = [];
    for (const m of (kv.ExecStart || '').matchAll(/\bpath=(\S+)\s*;/g)) if (!exec.includes(m[1])) exec.push(m[1]);
    out.push({ id: kv.Id, exec, mainPid: +(kv.MainPID || 0) || 0, active: kv.ActiveState || null, sub: kv.SubState || null, fragment: kv.FragmentPath || null, user: kv.User || '', nnp: kv.NoNewPrivileges === 'yes' });
  }
  return out;
}

/** `ss -lntuHp` → [{ proto, addr, port, pids }] (pids only for processes ss may inspect: root, or one's own). */
function parseSs(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const f = line.trim().split(/\s+/);
    if (f.length < 5 || !/^(tcp|udp)$/.test(f[0])) continue;
    const local = f[4];
    const m = /^(.*):(\d+|\*)$/.exec(local);
    if (!m) continue;
    const pids = [...line.matchAll(/pid=(\d+)/g)].map(x => +x[1]);
    out.push({ proto: f[0], addr: m[1].replace(/^\[|\]$/g, ''), port: m[2] === '*' ? null : +m[2], pids: [...new Set(pids)] });
  }
  return out;
}

/**
 * The rows. facts: { processes, units, sockets, labelOf(path) → type | null, startsAs(type) →
 * { domain, how: 'auto' | 'stays' | 'manual' | 'none' } (what init_t gets when it runs a file of that
 * type), unconfined: Set of domains, exists(path) → bool, realpath(path) → path, pkgOf(path) → name | null }.
 * → { rows, summary: { unconfined, confined, notRunning, noStart, rows }, unconfined: [...] }
 * Row: { exe, real, type, generic, pkg, units: [{ id, active, sub, user, nnp }], pids, users, hostDomains,
 *   policyDomain, how, verdict: 'unconfined' | 'confined' | 'nostart' | 'unknown', running, listens: [{ proto, port }] }
 */
function assemble(facts) {
  const { processes = [], units = [], sockets = [], labelOf, startsAs, unconfined = new Set(), exists = () => true, realpath = (p) => p, pkgOf = () => null, which = () => null } = facts;
  // ExecStart= may name a bare program (systemd ≥ 245 searches its PATH): resolved the same way, or left out.
  const execPath = (p) => (p.startsWith('/') ? p : which(p));
  const rows = new Map();
  const rowFor = (exe) => {
    const real = realpath(exe) || exe;
    const key = real;
    if (!rows.has(key)) rows.set(key, { exe: real !== exe ? exe : real, real, type: null, generic: false, pkg: null, units: [], pids: [], users: [], hostDomains: [], policyDomain: null, how: null, verdict: null, running: false, listens: [], exists: exists(real) });
    return rows.get(key);
  };
  const byPid = new Map(processes.map(p => [p.pid, p]));
  // Executables: each system service's ExecStart (and its main process, when known), then the system's own
  // processes (SELinux user system_u, or no label) that systemd started directly or that run unconfined.
  // Users' sessions (unconfined_u, staff_u, …: desktops, shells, their systemd --user) are not services.
  for (const u of units.filter(u => !USER_UNITS.test(u.id))) {
    const main = byPid.get(u.mainPid) || null;
    const paths = (u.exec.length ? u.exec.map(execPath) : main && main.argv0.startsWith('/') ? [main.argv0] : []).filter(Boolean);
    for (const p of paths) {
      const r = rowFor(p);
      r.units.push({ id: u.id, active: u.active, sub: u.sub, user: u.user, nnp: u.nnp });
      if (main && !r.pids.includes(main.pid)) { r.pids.push(main.pid); if (main.type && !r.hostDomains.includes(main.type)) r.hostDomains.push(main.type); if (!r.users.includes(main.user)) r.users.push(main.user); }
    }
  }
  const covered = new Set([...rows.values()].flatMap(r => r.pids));
  for (const p of processes) {
    if (covered.has(p.pid) || p.pid === 1) continue;
    if (p.seuser && p.seuser !== 'system_u') continue;
    if (!(p.ppid === 1 || (p.type && unconfined.has(p.type)))) continue;
    if (!p.argv0.startsWith('/')) continue; // no path to look up (a kernel helper, a rewritten argv)
    const r = rowFor(p.argv0);
    r.pids.push(p.pid);
    if (p.type && !r.hostDomains.includes(p.type)) r.hostDomains.push(p.type);
    if (!r.users.includes(p.user)) r.users.push(p.user);
  }
  // Ports: by the processes' pids.
  for (const s of sockets) {
    for (const pid of s.pids) {
      const r = [...rows.values()].find(x => x.pids.includes(pid));
      if (r && !r.listens.some(l => l.proto === s.proto && l.port === s.port)) r.listens.push({ proto: s.proto, port: s.port });
    }
  }
  for (const r of rows.values()) {
    r.running = r.pids.length > 0;
    r.type = labelOf ? labelOf(r.real) : null;
    r.generic = !!r.type && GENERIC_EXEC.has(r.type);
    r.pkg = pkgOf(r.real);
    const st = r.type && startsAs ? startsAs(r.type) : null;
    r.policyDomain = st ? st.domain : null;
    r.how = st ? st.how : null;
    r.listens.sort((a, b) => a.proto.localeCompare(b.proto) || (a.port || 0) - (b.port || 0));
    // The domain that counts: what runs here now, else what the policy would start.
    const dom = r.hostDomains[0] || r.policyDomain;
    if (!r.type && !r.running) r.verdict = 'unknown';
    else if (!dom) r.verdict = st && st.how === 'none' ? 'nostart' : 'unknown';
    else r.verdict = unconfined.has(dom) ? 'unconfined' : 'confined';
    // The policy says something else than this host shows: both are shown. For a service systemd starts
    // (a unit) the policy's answer is what a host running it would get, so the verdict follows it; a
    // process found on its own keeps the host's domain (something other than init_t may have started it).
    const service = r.units.length > 0;
    if (r.hostDomains.length && r.type && (r.policyDomain || r.how === 'none') && r.policyDomain !== r.hostDomains[0]) {
      r.differs = true;
      if (service) r.verdict = !r.policyDomain ? 'nostart' : unconfined.has(r.policyDomain) ? 'unconfined' : 'confined';
    }
  }
  const order = { unconfined: 0, nostart: 1, confined: 2, unknown: 3 };
  const list = [...rows.values()].sort((a, b) => order[a.verdict] - order[b.verdict] || (b.running - a.running) || (b.listens.length - a.listens.length) || a.real.localeCompare(b.real));
  const summary = { rows: list.length, unconfined: list.filter(r => r.verdict === 'unconfined').length, confined: list.filter(r => r.verdict === 'confined').length,
    nostart: list.filter(r => r.verdict === 'nostart').length, notRunning: list.filter(r => !r.running).length, listening: list.filter(r => r.verdict === 'unconfined' && r.listens.length).length };
  return { rows: list, summary, unconfined: [...unconfined].sort() };
}

/**
 * What init_t gets when it runs a file of type T, from policy_query's transitions out of init_t
 * (entries { target, entrypoints, auto }) and its execute / execute_no_trans answers for T:
 * → { domain, how } (auto: a type_transition; manual: an entrypoint that needs setexec; stays: no
 * transition but execute_no_trans; none: init_t can't run it at all).
 */
function startsAsFrom(transitions, canExec) {
  const auto = new Map(), manual = new Map();
  for (const tr of transitions || []) {
    for (const e of tr.auto || []) if (!auto.has(e)) auto.set(e, tr.target);
    for (const e of tr.entrypoints || []) if (!manual.has(e)) manual.set(e, tr.target);
  }
  return (T) => {
    if (auto.has(T)) return { domain: auto.get(T), how: 'auto' };
    const x = canExec ? canExec(T) : null; // { execute, noTrans }
    if (x && x.noTrans) return { domain: 'init_t', how: 'stays' };
    if (manual.has(T)) return { domain: null, how: 'manual', manual: manual.get(T) };
    return { domain: null, how: 'none' };
  };
}

module.exports = { parsePs, parseUnits, parseSs, assemble, startsAsFrom, UNCONFINED_NAMES, GENERIC_EXEC };
