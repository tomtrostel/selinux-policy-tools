// Login contexts: libselinux 3.x / 2.x context selection over seusers and the
// contexts files, against a small fake policy (server/loginctx.js). Any OS.
const L = require('../server/loginctx');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

// The fake policy: users with roles and range, roles with types, which transitions are allowed.
const USERS = {
  system_u: { roles: ['system_r'], range: 's0-s0:c0.c1023', level: 's0' },
  staff_u: { roles: ['staff_r', 'sysadm_r'], range: 's0-s0:c0.c1023', level: 's0' },
  user_u: { roles: ['user_r'], range: 's0', level: 's0' },
  ro_u: { roles: ['ro_r'], range: 's0', level: 's0' },
  nl_u: { roles: ['nl_r'], range: 's0', level: 's0' },
  fs_u: { roles: ['unconfined_r'], range: 's0-s0:c0.c1023', level: 's0' },
};
const ROLES = { system_r: ['sshd_t', 'local_login_t', 'crond_t'], staff_r: ['staff_t'], sysadm_r: ['sysadm_t'], user_r: ['user_t'], ro_r: ['ro_t'], nl_r: ['nl_t'], unconfined_r: ['unconfined_t'] };
const TRANS = new Set(['sshd_t>staff_t', 'sshd_t>sysadm_t', 'sshd_t>user_t', 'sshd_t>ro_t', 'sshd_t>unconfined_t', 'local_login_t>staff_t', 'local_login_t>user_t']);
const covers = (outer, inner) => outer === inner || (outer === 's0-s0:c0.c1023') || inner === 's0';
const asked = [];
async function ask(items) {
  asked.push(items.length);
  const out = {};
  for (const it of items) {
    let a;
    if (it.kind === 'info') a = { mls: true, users: USERS };
    else if (it.kind === 'resolve') a = it.range === 'bogus' ? { error: 'bogus isn\'t a valid range for this policy' } : { range: it.range.replace('mcs_systemhigh', 's0:c0.c1023').replace(/\s/g, '') };
    else if (it.kind === 'userrange') a = { range: USERS[it.user].range === 's0' ? 's0' : it.from };
    else if (it.kind === 'valid') {
      const [u, r, t, ...lv] = it.ctx.split(':');
      const reasons = [];
      if (!USERS[u]) reasons.push({ kind: 'user', text: `there is no SELinux user ${u}` });
      else if (!USERS[u].roles.includes(r)) reasons.push({ kind: 'userrole', text: `${u} doesn't have role ${r}` });
      if (!ROLES[r] || !ROLES[r].includes(t)) reasons.push({ kind: 'roletype', text: `role ${r} isn't authorized for ${t}` });
      if (USERS[u] && !covers(USERS[u].range, lv.join(':'))) reasons.push({ kind: 'userrange', text: `${lv.join(':')} is outside ${u}'s range ${USERS[u].range}` });
      a = { ok: !reasons.length, reasons };
    } else if (it.kind === 'transition') {
      const S = it.from.split(':')[2], T = it.to.split(':')[2];
      a = TRANS.has(`${S}>${T}`) ? { ok: true, te: 'allowed', constraints: [] } : { ok: false, te: 'missing', constraints: [] };
    }
    out[it.id] = a;
  }
  return out;
}
const files = (seusers, defaults, own = {}, failsafe = 'unconfined_r:unconfined_t:s0') => ({
  seusers: { path: '/c/seusers', text: seusers },
  defaults: { path: '/c/default_contexts', text: defaults },
  userFile: (u) => (own[u] != null ? { path: `/c/users/${u}`, text: own[u] } : null),
  failsafe: failsafe == null ? null : { path: '/c/failsafe_context', text: failsafe },
});
const DEFAULTS = [
  'system_r:sshd_t:s0\tuser_r:user_t:s0 staff_r:staff_t:s0',
  'system_r:local_login_t:s0\tuser_r:user_t:s0 staff_r:staff_t:s0',
  'system_r:crond_t:s0\tsystem_r:crond_t:s0',
].join('\n');
const kinds = (r) => r.problems.map(p => `${p.kind}:${p.login}${p.source ? `@${p.source}` : ''}`).sort();

(async () => {
  // A healthy configuration.
  let r = await L.analyze(files('root:staff_u:s0-mcs_systemhigh\n__default__:user_u:s0\n', DEFAULTS), ask);
  check(r.mls && r.problems.length === 0, 'healthy: no problems', r.problems);
  const root = r.mappings.find(m => m.login === 'root');
  const ssh = root.ways.find(w => w.source === 'sshd_t');
  check(root.level === 's0-s0:c0.c1023' && ssh.v3.ctx === 'staff_u:staff_r:staff_t:s0-s0:c0.c1023' && ssh.works3 && ssh.works2, 'root over ssh: staff_r:staff_t at its resolved seusers range, on RHEL 8 and 9', ssh);
  check(root.ways.map(w => w.source).join() === 'sshd_t,local_login_t', 'ways in: only those whose line lists one of the user\'s roles (not crond_t\'s system_r line)', root.ways.map(w => w.source));
  check(asked.length <= 4, `questions batched: ${asked.length} round trips`, asked);

  // Every way of breaking a login.
  r = await L.analyze(files([
    'root:staff_u:s0-mcs_systemhigh',
    'ghost:nosuch_u:s0',
    'alice:ro_u:s0',
    'bob:user_u:s0-s0:c0.c1023',
    'carol:nl_u:s0',
    'dave:fs_u:s0',
    'erin:staff_u:s0',
    'root:user_u:s0',
    'frank:staff_u:bogus',
  ].join('\n'), DEFAULTS, {
    ro_u: 'system_r:sshd_t:s0\tstaff_r:staff_t:s0',
    nl_u: 'system_r:sshd_t:s0\tnl_r:nl_t:s0',
    fs_u: 'system_r:sshd_t:s0\tstaff_r:staff_t:s0',
    staff_u: 'system_r:sshd_t:s0\tsysadm_r:nosuch_t:s0 staff_r:staff_t:s0',
  }), ask);
  const P = (kind, login) => r.problems.find(p => p.kind === kind && p.login === login);
  check(P('nodefault', '__default__') && P('nodefault', '__default__').l === 0, 'no __default__ line: an error on the file');
  check(/mapped to nosuch_u, which this policy doesn't have/.test((P('nouser', 'ghost') || {}).text) && P('nouser', 'ghost').l === 1, 'a login mapped to a user the policy lacks', P('nouser', 'ghost'));
  const a = P('nocontext', 'alice');
  check(a && a.source === 'sshd_t' && /can't log in by ssh: unable to get a valid context from sshd_t/.test(a.text) && /list only roles ro_u doesn't have \(staff_r user_r; it has ro_r\)/.test(a.text) && /failsafe ro_u:unconfined_r:unconfined_t:s0 isn't valid either/.test(a.text),
    'a user file listing only roles the user lacks: unable to get a valid context, failsafe invalid too', a);
  check(a.related.some(x => x.file === '/c/users/ro_u' && x.l === 0), 'related: the contexts file line');
  const b = P('nocontext3', 'bob');
  check(b && /on RHEL 9 and later/.test(b.text) && /outside user_u's range s0/.test(b.text) && /On RHEL 8 it gets user_u:user_r:user_t:s0/.test(b.text),
    'a seusers range beyond the user\'s: fails on RHEL 9 (libselinux uses the login\'s range), works on RHEL 8 (the kernel clips it)', b);
  const c = P('nocontext', 'carol');
  check(c && /no rule lets sshd_t transition to nl_t/.test(c.text), 'a valid context the caller may not transition to: the session can\'t start on either', c);
  const d = r.problems.find(p => p.kind === 'failsafe' && p.login === 'dave');
  check(d && d.severity === 'warning' && /only through the failsafe context fs_u:unconfined_r:unconfined_t:s0/.test(d.text), 'only the failsafe works: a warning', d);
  const e = P('skipped', 'erin');
  check(e && e.severity === 'info' && e.file === '/c/users/staff_u' && /lands in staff_u:staff_r:staff_t:s0, not staff_u:sysadm_r:nosuch_t:s0 listed before it: role sysadm_r isn't authorized for nosuch_t/.test(e.text), 'its own entry passed over for a later one: info on the contexts line', e);
  check(P('duplicate', 'root') && P('duplicate', 'root').l === 7, 'a second line for a login: only the first counts');
  check(/frank's range bogus: bogus isn't a valid range/.test((P('range', 'frank') || {}).text), 'an invalid range');
  check(r.problems[0].severity === 'error' && r.problems[r.problems.length - 1].severity === 'info', 'errors first', r.problems.map(p => p.severity));
  check(r.problems.filter(p => p.login === 'root').map(p => p.kind).sort().join() === 'duplicate,skipped' && r.problems.filter(p => p.login === 'erin').map(p => p.kind).join() === 'skipped', 'the working logins: only the duplicate line and the passed-over entry of staff_u\'s file', kinds(r));

  // A user no seusers line maps but with a contexts file of its own (logins added with semanage on the hosts).
  r = await L.analyze(files('root:staff_u:s0\n__default__:user_u:s0\n', DEFAULTS, { nl_u: 'system_r:sshd_t:s0\tnl_r:nl_t:s0' }), ask);
  const h = r.problems.find(p => p.login === 'a login mapped to nl_u');
  check(h && h.kind === 'unmapped' && h.severity === 'info' && h.file === '/c/users/nl_u' && h.l === 0 && /^No seusers line maps a login to nl_u .*If one is mapped, it can't log in by ssh: unable to get a valid context from sshd_t/.test(h.text)
    && r.mappings.some(m => m.hypothetical && m.user === 'nl_u') && r.problems.filter(p => p.login === 'a login mapped to nl_u').length === 1,
    'an unmapped user with its own contexts file: checked as a login mapped to it, one info on its file', r.problems);
  check(!r.mappings.some(m => m.hypothetical && m.user !== 'nl_u'), 'users without a file of their own (and system_u) aren\'t');

  // No failsafe file, no seusers at all.
  r = await L.analyze(files('__default__:ro_u:s0\n', DEFAULTS, { ro_u: 'system_r:sshd_t:s0\tstaff_r:staff_t:s0' }, null), ask);
  check(/There is no failsafe_context to fall back to/.test((r.problems.find(p => p.kind === 'nocontext') || {}).text), 'no failsafe_context: said so', r.problems);
  r = await L.analyze(files('__default__:ro_u:s0\n', DEFAULTS), ask);
  const nw = r.problems.find(p => p.kind === 'noway');
  check(nw && nw.severity === 'warning' && /No contexts file offers ro_u \(roles ro_r\) a context for any login program \(sshd_t, local_login_t, crond_t\)/.test(nw.text), 'a user no contexts file offers a way in: a warning', r.problems);
  r = await L.analyze(files(null, DEFAULTS), ask);
  check(r.problems.length === 0 && /No seusers file/.test(r.notes.join(' ')), 'no seusers file: a note');

  // A transition answer worded: rule, boolean, constraint.
  const t = L.transitionOf({ ok: false, te: 'allowed', constraints: [{ kind: 'mlsconstrain', text: 'h1 dom h2', leaves: [{ text: 'h1 dom h2', ok: false, a: 's0', b: 's0:c1' }] }] }, 'sshd_t', 'staff_t');
  check(/a mlsconstrain on process transition fails \(h1 dom h2 \(s0 vs s0:c1\)\)/.test(t.text), 'a failing constraint with its values', t);
  check(/only with ssh_sysadm_login on/.test(L.transitionOf({ ok: false, te: 'boolean', options: [{ ssh_sysadm_login: true }] }, 'sshd_t', 'sysadm_t').text), 'a transition behind a boolean');

  /* ---------- webview ---------- */
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
  check(posted[0] && posted[0].cmd === 'load' && /Checking/.test(byId.status.textContent), 'webview: asks for the report at once');
  const bad = await L.analyze(files('alice:ro_u:s0\n__default__:user_u:s0\n', DEFAULTS, { ro_u: 'system_r:sshd_t:s0\tstaff_r:staff_t:s0' }), ask);
  const policies = [{ id: 'build', label: 'Last build of tree', build: true }, { id: 'installed:targeted', label: 'Installed targeted policy', active: true }];
  send({ cmd: 'result', key: posted[0].key, result: { ...bad, policies, policy: policies[0] } });
  const page = byId.main.textContent;
  check(/1 error, 0 warnings/.test(page) && /alice \(ro_u\) can't log in by ssh/.test(page) && byId.against.children.length === 2, 'webview: the verdict, the problem, the policy picker', page.slice(0, 400));
  check(/RHEL 9 and later/.test(page) && /RHEL 8/.test(page) && /✗ no session/.test(page) && /ro_u doesn't have role staff_r/.test(page), 'webview: each way with both versions\' result and each listed context\'s reason');
  const openLink = byId.main.all(e => e.tag === 'button' && e.textContent === 'seusers:1')[0];
  openLink.fire('click');
  check(posted[posted.length - 1].cmd === 'open' && posted[posted.length - 1].loc.p === '/c/seusers' && posted[posted.length - 1].loc.l === 0, 'webview: a line link opens the file there');
  const ok = await L.analyze(files('__default__:user_u:s0\n', DEFAULTS), ask);
  send({ cmd: 'built', ok: true });
  const k = posted[posted.length - 1];
  check(k.cmd === 'load', 'webview: a build of the shown tree checks again');
  send({ cmd: 'result', key: k.key, result: { ...ok, policies, policy: policies[0] } });
  check(/Every login gets a valid context/.test(byId.main.textContent), 'webview: a clean report says so');
  byId.against.value = 'installed:targeted';
  byId.against.fire('change');
  check(posted[posted.length - 1].cmd === 'load' && posted[posted.length - 1].against === 'installed:targeted', 'webview: picking another policy checks that one');

  console.log(failures ? `\n${failures} check(s) failed` : '\nall login context checks passed');
  process.exit(failures ? 1 : 0);
})();
