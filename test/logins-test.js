// Logins view: parsing (server/logins.js) and the webview against a fake DOM. Any OS.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const L = require('../server/logins');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2000).replace(/\n/g, '\n     ')); }
};

/* ---------- configuration files ---------- */

const se = L.parseSeusers('# comment\nroot:unconfined_u:s0-s0:c0.c1023\n%wheel:staff_u:s0\n\n__default__:user_u:s0  # trailing\nbroken line\n');
check(se.length === 3 && se[0].login === 'root' && se[0].range === 's0-s0:c0.c1023' && se[1].group && se[1].login === 'wheel' && se[2].user === 'user_u' && se[2].l === 4,
  'seusers: logins, %groups, ranges, line numbers', se);
const defaults = { path: '/c/default_contexts', list: L.parseContexts(`system_r:sshd_t:s0\t\tuser_r:user_t:s0 staff_r:staff_t:s0 sysadm_r:sysadm_t:s0
system_r:crond_t:s0  user_r:cronjob_t:s0 staff_r:cronjob_t:s0
system_r:local_login_t:s0 staff_r:staff_t:s0
staff_r:staff_sudo_t:s0 sysadm_r:sysadm_t:s0
`) };
check(defaults.list.length === 4 && defaults.list[0].to.length === 3 && defaults.list[0].to[2].level === 's0', 'default_contexts parsed', defaults.list);
const own = { path: '/c/users/staff_u', list: L.parseContexts('system_r:sshd_t:s0 staff_r:staff_t:s0 sysadm_r:sysadm_t:s0\n') };
const types = { user_r: new Set(['user_t', 'cronjob_t']), staff_r: new Set(['staff_t', 'cronjob_t']), sysadm_r: new Set(['sysadm_t']) };
const rt = (r) => types[r] || new Set();
let ent = L.entries(['staff_r', 'sysadm_r'], rt, own, defaults);
check(ent.map(e => e.source).join() === 'sshd_t,local_login_t,crond_t', 'ways in: system_r sources only, ssh first', ent.map(e => e.source));
check(ent[0].file === '/c/users/staff_u' && ent[0].contexts.map(c => c.type).join() === 'staff_t,sysadm_t', 'the user\'s own file wins for ssh', ent[0]);
check(ent[2].contexts.map(c => `${c.role}:${c.type}`).join() === 'staff_r:cronjob_t' && ent[2].label === L.ENTRY_LABELS.crond_t, 'cron: only contexts its roles may use');
ent = L.entries(['user_r'], rt, null, defaults);
check(ent.find(e => e.source === 'local_login_t').contexts.length === 0, 'a way in with no fitting context stays, empty');

/* ---------- accounts ---------- */

const pw = L.parsePasswd('root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync\npostgres:x:26:26::/var/lib/pgsql:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/zsh\nnobody:x:65534:65534::/:/sbin/nologin\n');
const groups = L.parseGroups('wheel:x:10:bob\nalice:x:1000:\nbob:x:1001:\n', pw);
check(groups.get('bob').includes('wheel') && groups.get('alice').includes('alice'), 'groups: members and primary groups');
check(L.mappingFor('root', se, groups).how === 'own' && L.mappingFor('bob', se, groups).user === 'staff_u' && L.mappingFor('bob', se, groups).how === 'group'
  && L.mappingFor('alice', se, groups).user === 'user_u' && L.mappingFor('alice', se, groups).how === 'default', 'mapping: own line, then %group, then __default__');
const svc = L.serviceAccounts(pw, se, groups, 1000);
const S = (n) => svc.find(x => x.name === n);
check(!svc.some(x => x.name === 'root' || x.name === 'alice') && S('nobody'), 'service accounts: system UIDs and nobody, not root or people');
check(S('bin').canLogin === false && S('postgres').canLogin === true && S('sync').canLogin === false && S('sync').special, 'login shells: nologin no, bash yes, sync a one-command shell');
check(S('postgres').mapping.user === 'user_u' && S('postgres').mapping.how === 'default', 'a service account that logs in gets __default__');

/* ---------- paths and notes ---------- */

const reach = { reached: { staff_t: 'staff_r:staff_t', newrole_t: 'staff_r:newrole_t', sysadm_t: 'sysadm_r:sysadm_t', mount_t: 'staff_r:mount_t' }, steps: {
  'staff_r:staff_t': { depth: 0, start: true, role: 'staff_r', type: 'staff_t' },
  'staff_r:newrole_t': { depth: 1, from: 'staff_r:staff_t', role: 'staff_r', type: 'newrole_t', entrypoints: ['newrole_exec_t'], conditional: [] },
  'sysadm_r:sysadm_t': { depth: 2, from: 'staff_r:newrole_t', role: 'sysadm_r', type: 'sysadm_t', roleChange: 'setexec', entrypoints: ['shell_exec_t'], conditional: [] },
  'staff_r:mount_t': { depth: 1, from: 'staff_r:staff_t', role: 'staff_r', type: 'mount_t', entrypoints: ['mount_exec_t'], conditional: ['allow_mount_anyfile:true'] },
} };
const p = L.pathTo(reach.steps, 'sysadm_r:sysadm_t');
check(p.length === 2 && p[0].from === 'staff_t' && p[1].to === 'sysadm_t' && p[1].roleChange === 'setexec', 'path from the start, in order', p);
check(/^newrole_t → sysadm_t \(runs shell_exec_t, role → sysadm_r/.test(L.stepText(p[1])), L.stepText(p[1]));
check(/only when allow_mount_anyfile/.test(L.stepText(L.pathTo(reach.steps, 'staff_r:mount_t')[0])), 'conditional step worded');
check(L.nearest(reach, ['sysadm_t', 'mount_t']).d === 'mount_t' && L.nearest(reach, ['staff_t', 'mount_t']).d === 'staff_t', 'nearest reached domain wins');
const staffU = { roles: ['staff_r', 'sysadm_r'] };
check(L.mappingNotes({ login: '__default__', user: 'staff_u' }, staffU, ['sysadm_r']).some(n => n.severity === 'high' && /admin role/.test(n.text)), '__default__ on a user with an admin role: high');
check(L.mappingNotes({ login: 'root', user: 'unconfined_u' }, { roles: ['unconfined_r'] }, []).some(n => /unconfined_u/.test(n.text)), 'unconfined_u noted');
check(L.mappingNotes({ login: 'x', user: 'gone_u' }, null, []).some(n => /not a user/.test(n.text)), 'a mapping to a missing user');
check(L.mappingNotes({ login: 'alice', user: 'user_u' }, { roles: ['user_r'] }, ['sysadm_r']).length === 0, 'an ordinary mapping: no notes');

/* ---------- webview ---------- */

class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this._text = ''; this.open = false; this.nodeType = 1; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set className(v) { this.attrs.class = v; } get className() { return this.attrs.class || ''; }
  append(...cs) { for (let c of cs) { if (typeof c === 'string') c = text(c); this.children.push(c); c.parent = this; } }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'open') this.open = true; if (k === 'value') this.value = String(v); }
  addEventListener(ev, f) { (this.listeners[ev] = this.listeners[ev] || []).push(f); }
  fire(ev, extra = {}) { for (const f of this.listeners[ev] || []) f({ target: this, currentTarget: this, preventDefault() {}, stopPropagation() {}, ...extra }); }
  all(pred, out = []) { for (const c of this.children) { if (c.tag && pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
}
const text = (s) => ({ nodeType: 3, textContent: s });
const byId = {};
for (const id of ['main', 'status', 'against', 'refresh', 'title']) byId[id] = new El(id);
const posted = [];
const winListeners = [];
const wctx = {
  setTimeout, clearTimeout,
  acquireVsCodeApi: () => ({ postMessage: (m) => posted.push(JSON.parse(JSON.stringify(m))), getState: () => null, setState: () => {} }),
  document: { getElementById: (id) => byId[id], createElement: (tag) => new El(tag), createTextNode: text },
  window: { addEventListener: (ev, f) => winListeners.push(f) },
};
vm.createContext(wctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/logins.js'), 'utf8'), wctx);
const send = (data) => winListeners.forEach(f => f({ data }));
const last = (cmd) => [...posted].reverse().find(m => m.cmd === cmd);
const find = (pred) => byId.main.all(pred);

check(posted[0] && posted[0].cmd === 'load' && posted[0].against === null, 'webview asks for the report when loaded');
const ssh = { source: 'sshd_t', label: 'ssh', contexts: [{ role: 'staff_r', type: 'staff_t' }, { role: 'sysadm_r', type: 'sysadm_t' }], file: '/etc/selinux/targeted/contexts/users/staff_u', l: 0 };
const report = {
  policy: { id: 'installed:targeted', label: 'Installed targeted policy (running here)', configDir: '/etc/selinux/targeted', host: true },
  policies: [{ id: 'installed:targeted', label: 'Installed targeted policy (running here)', active: true }, { id: 'build', label: 'Last build of clip', build: true }],
  mappings: [{ login: '__default__', group: false, user: 'staff_u', range: 's0', l: 1, file: '/etc/selinux/targeted/seusers', notes: [{ severity: 'high', text: 'Every login without its own line gets staff_u, which has an admin role (sysadm_r).' }] }],
  users: [
    { name: 'staff_u', roles: ['staff_r', 'sysadm_r'], range: 's0', loc: null, logins: [{ login: '__default__', group: false, user: 'staff_u', l: 1, file: '/etc/selinux/targeted/seusers' }],
      entries: [ssh, { source: 'local_login_t', label: 'console login', contexts: [], file: '/etc/selinux/targeted/contexts/default_contexts', l: 2 }], contextsFile: ssh.file, reached: 77, roleSet: ['staff_r', 'sysadm_r'],
      abilities: [{ id: 'loadPolicy', label: 'can load a new SELinux policy', severity: 'high', domain: 'load_policy_t', count: 2, rule: { rt: 'allow', s: 'load_policy_t', t: 'security_t', c: 'security', perms: ['load_policy'], cond: '' },
        path: [{ text: 'staff_t → newrole_t (runs newrole_exec_t)' }, { text: 'newrole_t → sysadm_t (…)' }, { text: 'sysadm_t → load_policy_t (runs load_policy_exec_t)' }] }] },
    { name: 'system_u', roles: ['system_r'], range: 's0', loc: null, logins: [], entries: [], reached: 0, abilities: [] },
  ],
  accounts: { uidMin: 1000, people: [{ name: 'root', uid: 0, shell: '/bin/bash', canLogin: true, mapping: { user: 'staff_u', how: 'default', login: '__default__' } }],
    services: [{ name: 'postgres', uid: 26, shell: '/bin/bash', canLogin: true, mapping: { user: 'staff_u', how: 'default' } }, { name: 'bin', uid: 1, shell: '/sbin/nologin', canLogin: false, mapping: { user: 'staff_u', how: 'default' } }] },
  notes: [],
};
send({ cmd: 'report', report });
check(byId.against.children.length === 2 && byId.against.value === 'installed:targeted', 'policy picker filled, reported policy selected');
const cards = find(e => (e.attrs.class || '').split(' ').includes('card'));
check(cards.length === 2 && /staff_u/.test(cards[0].textContent) && cards[0].attrs.class.includes('high'), 'user cards, users with logins first, staff_u marked high', cards.map(c => c.attrs.class));
check(cards[1].attrs.class.includes('idle') && /not logins/.test(cards[1].textContent), 'system_u: cannot log in, explained');
check(/admin role/.test(byId.main.textContent) && /People's accounts/.test(byId.main.textContent) && /Service accounts/.test(byId.main.textContent), 'mapping note, people and service accounts sections');
check(/Has a login shell and would get staff_u/.test(byId.main.textContent) && !/bin.*Has a login shell/.test(byId.main.textContent.replace(/\n/g, ' ').slice(byId.main.textContent.indexOf('(uid 1)'))), 'postgres (bash) flagged, bin (nologin) not');
check(/sysadm_r:sysadm_t/.test(cards[0].textContent) && /load_policy_t/.test(cards[0].textContent) && /newrole_t → sysadm_t/.test(cards[0].textContent), 'ways in (may also choose), ability with its path');
check(!/console login/.test(cards[0].textContent), 'a way in that fits none of its roles is left out');
const btn = (root, t) => root.all(e => e.tag === 'button' && e.textContent === t)[0];
btn(find(e => (e.attrs.class || '').includes('card'))[0], 'Show the 77 domains').fire('click');
check(last('reach') && last('reach').user === 'staff_u' && last('reach').starts.length === 2 && last('reach').against === 'installed:targeted', 'reach asked with the user\'s start contexts');
send({ cmd: 'reach', user: 'staff_u', result: { domains: [{ name: 'staff_t', depth: 0, role: 'staff_r', path: [] }, { name: 'newrole_t', depth: 1, role: 'staff_r', path: [{ text: 'staff_t → newrole_t (runs newrole_exec_t)' }] }] } });
check(/logs in here/.test(byId.main.textContent) && find(e => e.tag === 'summary' && /newrole_t/.test(e.textContent)).length === 1, 'reached domains listed, with paths');
const card0 = find(e => (e.attrs.class || '').includes('card'))[0];
const inputs = card0.all(e => e.tag === 'input');
inputs[1].value = '/etc/shadow'; inputs[1].fire('input');
btn(card0, 'Ask').fire('click');
check(last('can') && last('can').path === '/etc/shadow' && last('can').tclass === 'file' && last('can').perms.join() === 'read', 'Ask sends path, class and perms', last('can'));
send({ cmd: 'can', user: 'staff_u', result: { target: 'shadow_t', resolved: { path: '/etc/shadow', type: 'shadow_t' }, can: true, domain: 'sysadm_t', count: 3, rule: { rt: 'allow', s: 'sysadm_t', t: 'shadow_t', c: 'file', perms: ['read'], cond: '' }, path: [{ text: 'staff_t → newrole_t' }] } });
check(/Yes: as sysadm_t \(\/etc\/shadow is shadow_t\), and 2 more domains/.test(byId.main.textContent), 'answer: yes, the domain and path');
send({ cmd: 'can', user: 'staff_u', result: { target: 'security_t', can: false, reached: 77 } });
check(/No: none of the 77 domains/.test(byId.main.textContent), 'answer: no');
byId.against.value = 'build'; byId.against.fire('change');
check(last('load').against === 'build', 'switching the policy reloads');
posted.length = 0;
send({ cmd: 'built', ok: true });
check(last('load') && last('load').against === 'build', 'a finished build reloads the build report');

console.log(failures ? `${failures} FAILED` : 'all passed');
process.exit(failures ? 1 : 0);
