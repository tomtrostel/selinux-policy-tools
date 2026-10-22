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
  const ask = async (items) => {
    asked.push(...items);
    const out = {};
    for (const it of items) {
      let a;
      if (it.kind === 'avc') {
        const perms = {};
        for (const p of it.perms) perms[p] = { status: allow.has(`${it.s}|${it.t}|${it.c}|${p}`) ? 'allowed' : (over.bool && over.bool[`${it.s}|${it.t}|${it.c}|${p}`]) ? 'boolean' : 'missing', options: over.bool ? [over.bool[`${it.s}|${it.t}|${it.c}|${p}`]].filter(Boolean) : undefined };
        a = { perms };
      } else if (it.kind === 'computed') a = { type: computed[`${it.rt}|${it.s}|${it.t}|${it.c}`] || null };
      else if (it.kind === 'nnp') {
        const n = nnp[`${it.from}>${it.to}`] || {};
        a = { process2: true, cap: true, bounded: !!n.bounded, nnp_transition: { status: n.nnp ? 'allowed' : 'missing' }, nosuid_transition: { status: n.nosuid ? 'allowed' : 'missing' }, nnpTo: n.nnpTo || [], attrs: n.attrs || [] };
      } else if (it.kind === 'autoinvalid') a = { items: (over.invalid || {})[it.user] || [], more: false };
      else if (it.kind === 'bounds') a = { bounds: over.bounds || [] };
      out[it.id] = a;
    }
    return out;
  };
  return { ask, asked };
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

  console.log(failures ? `\n${failures} check(s) failed` : '\nall session start checks passed');
  process.exit(failures ? 1 : 0);
})();
