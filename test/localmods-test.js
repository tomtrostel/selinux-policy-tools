'use strict';
// A host's local changes (server/localmods.js): parsing semanage export and
// semodule --list-modules=full, comparing with a policy, writing changes into
// policy source; and the Host Changes webview with a fake DOM. Any OS.
//   node test/localmods-test.js
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const M = require('../server/localmods');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/* ---------- parsing ---------- */
check(same(M.words(`fcontext -a -f a -t httpd_sys_content_t -r 's0' '/srv/my www(/.*)?'`), ['fcontext', '-a', '-f', 'a', '-t', 'httpd_sys_content_t', '-r', 's0', '-f', 'a'].slice(0, 0).concat(['fcontext', '-a', '-f', 'a', '-t', 'httpd_sys_content_t', '-r', 's0', '/srv/my www(/.*)?'])), 'words: quotes group and are removed');
// As semanage export writes it (seobject.py customized()), with Windows line ends.
const EXPORT = [
  'boolean -D', 'login -D', 'interface -D', 'user -D', 'port -D', 'node -D', 'fcontext -D', 'module -D', 'ibendport -D', 'ibpkey -D', 'permissive -D',
  'boolean -m -1 httpd_can_network_connect',
  'boolean -m -0 deny_ptrace',
  "login -a -s staff_u -r 's0-s0:c0.c1023' alice",
  'login -a -s user_u %developers',
  "user -a -L s0 -r s0-s0:c0.c1023 -R 'staff_r sysadm_r' ops_u",
  "port -a -t http_port_t -r 's0' -p tcp 8080",
  'port -a -t http_port_t -p tcp 9000-9010',
  "interface -a -t netif_t -r 's0' eth1",
  "node -a -M 255.255.255.0 -p ipv4 -t node_t -r 's0' 10.0.0.0",
  "fcontext -a -f a -t httpd_sys_content_t -r 's0' '/srv/www(/.*)?'",
  "fcontext -a -f f -t bin_t '/opt/tool/run'",
  'fcontext -a -e / /var/chroot',
  'module -d sandbox',
  'permissive -a httpd_t',
  "ibpkey -a -t ibpkey_t -r 's0' -x fe80:: 0x8001",
  'ibendport -a -t ibendport_t -z mlx4_0 1',
  'something odd here',
  '#### modules',
  '100 abrt pp',
  '100 sandbox pp disabled',
  '200 container cil',
  '400 mymod pp',
  '400 permissive_httpd_t cil',
  '',
].join('\r\n');
const p = M.parseExport(EXPORT);
const k = (kind) => p.items.filter(x => x.kind === kind);
check(p.items.length === 16, `16 changes (the -D reset lines carry nothing) (${p.items.length})`, p.items.map(x => x.kind));
check(same(k('boolean').map(x => [x.name, x.value]), [['httpd_can_network_connect', true], ['deny_ptrace', false]]), 'booleans: -1 on, -0 off');
check(k('login')[0].user === 'staff_u' && k('login')[0].range === 's0-s0:c0.c1023' && k('login')[1].name === '%developers' && k('login')[1].range === '', 'logins: user, quoted range, %group');
check(same(k('user')[0].roles, ['staff_r', 'sysadm_r']) && k('user')[0].level === 's0' && k('user')[0].range === 's0-s0:c0.c1023', 'users: roles, level, range');
check(k('port')[0].low === 8080 && k('port')[0].high === 8080 && k('port')[1].low === 9000 && k('port')[1].high === 9010 && k('port')[1].proto === 'tcp', 'ports: a number and a range');
check(k('interface')[0].name === 'eth1' && k('node')[0].addr === '10.0.0.0' && k('node')[0].mask === '255.255.255.0', 'interface and node');
check(k('fcontext')[0].spec === '/srv/www(/.*)?' && k('fcontext')[0].ftype === 'a' && k('fcontext')[1].ftype === 'f', 'file contexts: quoted spec, file kind');
check(k('equivalence')[0].source === '/' && k('equivalence')[0].target === '/var/chroot', 'equivalence: target labeled like source');
check(k('module-disabled')[0].name === 'sandbox' && k('permissive')[0].type === 'httpd_t', 'module -d and permissive');
check(k('ibpkey')[0].pkey === '0x8001' && k('ibendport')[0].device === 'mlx4_0', 'InfiniBand pkey and end port');
check(p.unknown.length === 1 && p.unknown[0].text === 'something odd here', 'unknown lines are kept, not dropped silently');
check(p.modules.length === 5 && p.modules[1].disabled && p.modules[2].priority === 200, 'the module list after "#### modules"');
const lm = M.localModules(p.modules);
check(same(lm.map(x => [x.name, x.priority]), [['container', 200], ['mymod', 400]]), 'local modules: not priority 100, not permissive_* (permissive is its own kind)', lm);
check(M.parseExport('').items.length === 0 && M.parseExport('boolean -D\nlogin -D\n').items.length === 0, 'an empty export: nothing changed');

/* ---------- comparing with a policy ---------- */
const facts = {
  types: new Set(['http_port_t', 'http_cache_port_t', 'httpd_sys_content_t', 'bin_t', 'netif_t', 'node_t', 'httpd_t', 'usr_t']),
  users: { staff_u: { roles: ['staff_r', 'sysadm_r'], range: 's0-s0:c0.c1023' }, user_u: { roles: ['user_r'], range: 's0' }, ops_u: { roles: ['staff_r'], range: 's0' } },
  roles: new Set(['staff_r', 'sysadm_r', 'user_r']),
  bools: { httpd_can_network_connect: false, deny_ptrace: false },
  ports: [{ proto: 'tcp', low: 8080, high: 8080, type: 'http_cache_port_t' }, { proto: 'tcp', low: 9005, high: 9005, type: 'http_port_t' }],
  netifs: { eth1: 'netif_t' }, nodes: [],
  fc: (spec, flag) => (spec === '/opt/tool/run' && flag === '--' ? 'usr_t' : null),
  subs: {}, seusers: [{ login: 'alice', user: 'user_u', range: '' }, { login: '__default__', user: 'user_u', range: '' }],
  modules: new Map([['sandbox', 'module'], ['abrt', 'module'], ['kernel', 'base']]), builtModules: new Set(['sandbox', 'abrt']),
};
const c = M.compare([...p.items, ...lm], facts);
const st = (pred) => (c.find(pred) || {});
check(st(x => x.name === 'httpd_can_network_connect').state === 'override' && /defaults to off; the host turns it on/.test(st(x => x.name === 'httpd_can_network_connect').note), 'boolean turned on: override');
check(st(x => x.name === 'deny_ptrace').state === 'redundant', 'boolean set to its default: redundant');
check(st(x => x.kind === 'port' && x.low === 8080).state === 'override' && /gives tcp 8080 to http_cache_port_t/.test(st(x => x.kind === 'port' && x.low === 8080).note), 'port the policy gives another type: override');
check(st(x => x.kind === 'port' && x.low === 9000).state === 'local' && /Overlaps tcp 9005 \(http_port_t\)/.test(st(x => x.kind === 'port' && x.low === 9000).note), 'port range: local, overlaps noted');
check(st(x => x.kind === 'fcontext' && x.ftype === 'a').state === 'local' && st(x => x.kind === 'fcontext' && x.ftype === 'f').state === 'override' && /labels \/opt\/tool\/run usr_t/.test(st(x => x.kind === 'fcontext' && x.ftype === 'f').note), 'file contexts: new line local, a path the policy labels otherwise: override');
check(st(x => x.kind === 'login' && x.name === 'alice').state === 'override' && st(x => x.name === '%developers').state === 'local', 'logins: changed mapping override, new group local');
check(st(x => x.kind === 'user').state === 'override' && /the host adds sysadm_r/.test(st(x => x.kind === 'user').note) && st(x => x.kind === 'user').severity === 'warn', 'user with an admin role added: override, flagged');
check(st(x => x.kind === 'interface').state === 'present', 'interface the policy has: present');
check(st(x => x.kind === 'node').state === 'local' && st(x => x.kind === 'equivalence').state === 'local', 'node and equivalence: local');
check(st(x => x.kind === 'module-disabled').state === 'override' && /ships this module; the host turns it off/.test(st(x => x.kind === 'module-disabled').note), 'disabling a module the policy ships: override');
check(st(x => x.kind === 'permissive').state === 'local' && st(x => x.kind === 'permissive').severity === 'warn', 'permissive domain: flagged');
check(st(x => x.kind === 'ibpkey').state === 'broken', 'a type the policy lacks: broken');
check(st(x => x.name === 'container').state === 'local' && /from a package \(priority 200\)/.test(st(x => x.name === 'container').note) && st(x => x.name === 'mymod').severity === 'warn', 'added modules: a package\'s (200), one installed by hand (400, flagged)');
check(c.every(x => x.text && x.note), 'every change gets a one-line description and a note');
const c2 = M.compare([
  { kind: 'boolean', name: 'nosuch_bool', value: true }, { kind: 'login', name: 'bob', user: 'nosuch_u', range: '' }, { kind: 'login', name: 'eve', user: 'unconfined_u', range: '' },
  { kind: 'user', name: 'x_u', roles: ['nosuch_r'] }, { kind: 'fcontext', spec: '/a', ftype: 'a', type: 'nosuch_t' }, { kind: 'module-disabled', name: 'kernel' },
  { kind: 'module-disabled', name: 'gone' }, { kind: 'port', type: 'http_cache_port_t', proto: 'tcp', low: 8080, high: 8080 },
], { ...facts, users: { ...facts.users, unconfined_u: { roles: ['unconfined_r'] } }, builtModules: new Set(['sandbox', 'abrt']) });
check(c2[0].state === 'broken' && c2[1].state === 'broken' && c2[3].state === 'broken' && c2[4].state === 'broken', 'missing boolean, user, role, type: broken');
check(c2[2].severity === 'warn' && /unconfined_u is not confined/.test(c2[2].note), 'a login mapped to unconfined_u: flagged');
check(c2[5].state === 'info' && /base module/.test(c2[5].note) && c2[6].state === 'present', 'disabling a base module: info; a module the policy doesn\'t ship: present');
check(c2[7].state === 'present', 'a port the policy has with the same type: present');

/* ---------- into the policy source ---------- */
const fcIt = k('fcontext')[0];
check(M.fcLine(fcIt) === '/srv/www(/.*)?\t\tgen_context(system_u:object_r:httpd_sys_content_t,s0)' && M.fcLine(k('fcontext')[1]) === '/opt/tool/run\t--\tgen_context(system_u:object_r:bin_t,s0)', 'fcLine: refpolicy form with the file kind flag');
let r = M.fcontextFix('/srv/x\t\tgen_context(system_u:object_r:a_t,s0)\n\n', fcIt);
check(r && r.line === 1 && r.text === '/srv/x\t\tgen_context(system_u:object_r:a_t,s0)\n/srv/www(/.*)?\t\tgen_context(system_u:object_r:httpd_sys_content_t,s0)\n\n', 'fcontextFix: appended after the last line, blank lines kept', r);
check(M.fcontextFix(r.text, fcIt) === null, 'fcontextFix: already there → null');
check(/\r\n/.test(M.fcontextFix('a\r\nb\r\n', fcIt).text) && !/[^\r]\n/.test(M.fcontextFix('a\r\nb\r\n', fcIt).text), 'CRLF files stay CRLF');
r = M.subsFix('/run /var/run\n', k('equivalence')[0]);
check(r.text === '/run /var/run\n/var/chroot /\n' && M.subsFix(r.text, k('equivalence')[0]) === null, 'subsFix: "TARGET SOURCE" appended once');
r = M.booleanFix('a = false\nhttpd_can_network_connect = false\n', k('boolean')[0]);
check(r.text === 'a = false\nhttpd_can_network_connect = true\n' && r.line === 1, 'booleanFix: its line rewritten');
check(M.booleanFix('a = false\n', k('boolean')[0]).text === 'a = false\nhttpd_can_network_connect = true\n' && M.booleanFix('httpd_can_network_connect = true\n', k('boolean')[0]) === null, 'booleanFix: appended when missing; null when already so');
r = M.loginFix('root:unconfined_u:s0-s0:c0.c1023\n__default__:user_u:s0\n', k('login')[0]);
check(r.text === 'root:unconfined_u:s0-s0:c0.c1023\nalice:staff_u:s0-s0:c0.c1023\n__default__:user_u:s0\n' && r.line === 1, 'loginFix: a new login goes before __default__');
check(M.loginFix('alice:user_u\n__default__:user_u\n', k('login')[0]).text === 'alice:staff_u:s0-s0:c0.c1023\n__default__:user_u\n' && M.loginFix('%developers:user_u\n', k('login')[1]) === null, 'loginFix: an existing login rewritten; the same line: null');
const CN = 'network_port(ssh, tcp,22,s0)\nnetwork_port(http, tcp,80,s0, tcp,443,s0) # web\nnetwork_port(http_cache, tcp,8080,s0)\n';
r = M.portFix(CN, k('port')[0]);
check(r && r.line === 1 && r.text.split('\n')[1] === 'network_port(http, tcp,80,s0, tcp,443,s0, tcp,8080,s0) # web', 'portFix: the number added to the type\'s network_port line, comment kept', r && r.text);
check(M.portFix(CN, k('port')[1]).text.split('\n')[1] === 'network_port(http, tcp,80,s0, tcp,443,s0, tcp,9000-9010,s0) # web', 'portFix: a range');
check(M.portFix(r.text, k('port')[0]) === null && M.portFix(CN, { ...k('port')[0], type: 'unknown_port_t' }) === null && M.portFix(CN, { ...k('port')[0], type: 'not_a_port' }) === null, 'portFix: already there, no line for the type, not a port type → null');
const ov = c.find(x => x.kind === 'port' && x.low === 8080);
check(ov.was === 'http_cache_port_t', 'an override records what the policy has (was)');
r = M.portFix(CN, ov);
check(r && r.text.split('\n')[1] === 'network_port(http, tcp,80,s0, tcp,443,s0, tcp,8080,s0) # web' && r.text.split('\n')[2] === 'network_port(http_cache)' && r.removedFrom.line === 2,
  'portFix for an override: the number moves from the other type\'s line (no duplicate portcon)', r && r.text);
check(M.portFix('network_port(http, tcp,80,s0)\nnetwork_port(reserved, tcp,1-511,s0)\n', { ...ov, low: 100, high: 100, was: 'reserved_port_t' }) === null, 'portFix: an override whose number the other line doesn\'t list as such → not fixable');
const fov = c.find(x => x.kind === 'fcontext' && x.ftype === 'f');
check(fov.was === 'usr_t', 'file context override: was');
const RPMFC = '/usr/bin/rpm\t--\tgen_context(system_u:object_r:usr_t,s0)\n/usr/bin/other\t--\tgen_context(system_u:object_r:usr_t,s0)\n';
r = M.fcontextReplace(RPMFC, { ...fov, spec: '/usr/bin/rpm' }, 0);
check(r && r.text === '/usr/bin/rpm\t--\tgen_context(system_u:object_r:bin_t,s0)\n/usr/bin/other\t--\tgen_context(system_u:object_r:usr_t,s0)\n' && r.line === 0, 'fcontextReplace: the type on the policy\'s own line changes, nothing added', r);
check(M.fcontextReplace(RPMFC, fov, 5) === null && M.fcontextReplace(r.text, fov, 0) === null && M.fcontextReplace(RPMFC, { ...fov, was: null }, 0) === null, 'fcontextReplace: wrong line, already changed, no was → null');
check(M.moduleOffFix('kernel = base\nsandbox = module\n', 'sandbox').text === 'kernel = base\nsandbox = off\n' && M.moduleOffFix('kernel = base\n', 'kernel') === null && M.moduleOffFix('a = module\n', 'b') === null && M.moduleOffFix('a = off\n', 'a') === null,
  'moduleOffFix: module → off; base, absent or already off → null');
check(/^gen_user\(ops_u,, staff_r sysadm_r, s0, s0-s0:c0\.c1023\)/.test(M.snippet(k('user')[0])) && /^permissive httpd_t;/.test(M.snippet(k('permissive')[0])) && M.snippet({ kind: 'local-module' }) === null, 'snippets for the changes without a file to edit');

/* ---------- webview ---------- */
class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this._text = ''; this.open = false; this.nodeType = 1; this.checked = false; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set className(v) { this.attrs.class = v; } get className() { return this.attrs.class || ''; }
  append(...cs) { for (let c of cs) { if (typeof c === 'string') c = textNode(c); this.children.push(c); c.parent = this; } }
  setAttribute(k2, v) { this.attrs[k2] = String(v); if (k2 === 'checked') this.checked = true; }
  addEventListener(ev, f) { (this.listeners[ev] = this.listeners[ev] || []).push(f); }
  fire(ev) { for (const f of this.listeners[ev] || []) f({ target: this, currentTarget: this, preventDefault() {} }); }
  all(pred, out = []) { for (const ch of this.children) { if (ch.tag && pred(ch)) out.push(ch); if (ch.all) ch.all(pred, out); } return out; }
}
const textNode = (s) => ({ nodeType: 3, textContent: s });
const byId = {};
for (const id of ['main', 'status', 'against']) byId[id] = new El(id);
const posted = [];
const winListeners = [];
const wctx = {
  acquireVsCodeApi: () => ({ postMessage: (m) => posted.push(JSON.parse(JSON.stringify(m))) }),
  document: { getElementById: (id) => byId[id] || byId.main.all(e => e.attrs.id === id)[0], createElement: (tag) => new El(tag), createTextNode: textNode },
  window: { addEventListener: (ev, f) => winListeners.push(f) }, setTimeout: (f) => f(),
};
vm.createContext(wctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/hostmods.js'), 'utf8'), wctx);
const send = (data) => winListeners.forEach(f => f({ data }));
const last = (cmd) => [...posted].reverse().find(m => m.cmd === cmd);
const all = (pred) => byId.main.all(pred);
const button = (t) => all(e => e.tag === 'button').find(e => e.textContent === t);
check(last('ready'), 'ready posted');
const policies = [{ id: 'installed:targeted', label: 'Installed targeted policy (running here)', active: true }, { id: 'build', label: 'Last build of clip', build: true }];
send({ cmd: 'policies', policies });
check(byId.against.children.length === 2 && byId.against.children[1].attrs.selected !== undefined, 'compare with: the build preselected');
button('Read this host (sudo)').fire('click');
check(last('sudo') && /Waiting for the terminal/.test(byId.main.textContent), 'Read this host asks the extension to run sudo in a terminal');
button('Read without sudo').fire('click');
check(last('local'), 'Read without sudo');
button('Open file…').fire('click');
check(last('openFile'), 'Open file…');
send({ cmd: 'export', text: EXPORT });
check(last('compare') && last('compare').against === 'build' && last('compare').text === EXPORT, 'an export arrives: compared with the build');
send({ cmd: 'result', result: { policies, policy: policies[1], modulesListed: true, unknown: p.unknown, containsLocal: false, items: c.map(x => ({ ...x, fixable: ['fcontext', 'port', 'boolean'].includes(x.kind), snippet: M.snippet(x) })) } });
let t = byId.main.textContent;
check(/18 local changes: /.test(t) && /2 not in your policy/.test(t) && /overrides your policy/.test(t), 'summary with counts per verdict', t.slice(t.indexOf('local changes') - 10, t.indexOf('local changes') + 200));
check(['File contexts', 'Ports', 'Booleans', 'Logins', 'SELinux users', 'Modules turned off', 'Modules added', 'Permissive domains', 'InfiniBand pkeys'].every(g => t.includes(g)), 'grouped by kind');
check(/Lines not understood 1/.test(t) && /something odd here/.test(t), 'lines not understood are listed');
const copy = all(e => e.tag === 'button' && e.textContent === 'copy line')[0];
copy.fire('click');
check(last('copy') && /^\/opt\/tool\/run\t--\tgen_context\(system_u:object_r:bin_t,s0\)$/.test(last('copy').text), 'copy line: the source line for the change (overrides sort first)', last('copy'));
const w = all(e => e.tag === 'button' && e.textContent === 'write into the policy')[0];
w.fire('click');
const pl = last('plan');
check(pl && pl.item.kind === 'fcontext' && pl.against === 'build', 'write into the policy: asks for the edit first', pl && pl.item.kind);
send({ cmd: 'plan', key: pl.key, plan: { path: '/t/policy/modules/contrib/apache.fc', text: 'x', line: 3, inserted: [M.fcLine(fcIt)] } });
check(/Adds to \/t\/policy\/modules\/contrib\/apache\.fc:/.test(byId.main.textContent), 'the edit is shown before writing');
button('Write it').fire('click');
check(last('apply') && last('apply').plan.path === '/t/policy/modules/contrib/apache.fc', 'Write it applies the edit');
send({ cmd: 'applied', key: pl.key, path: '/t/policy/modules/contrib/apache.fc' });
check(/Written to apache\.fc \(saved; the build checks it\)/.test(byId.main.textContent), 'written; the build checks it');
const n0 = posted.filter(m => m.cmd === 'compare').length;
send({ cmd: 'built', ok: true });
check(posted.filter(m => m.cmd === 'compare').length === n0 + 1, 'after a build of the compared policy: compared again');
send({ cmd: 'result', result: { policies, policy: policies[1], modulesListed: true, unknown: [], items: c.map(x => ({ ...x, fixable: ['fcontext', 'port', 'boolean'].includes(x.kind), snippet: M.snippet(x) })) } });
all(e => e.tag === 'button' && e.textContent === 'write into the policy')[1].fire('click');
send({ cmd: 'plan', key: last('plan').key, plan: { already: true, path: '/t/policy/booleans.conf' } });
check(/booleans\.conf has it already/.test(byId.main.textContent), 'a file that has it already says so');
send({ cmd: 'result', result: { policies, policy: policies[0], items: c.slice(0, 2), unknown: [], modulesListed: false, containsLocal: true } });
t = byId.main.textContent;
check(/comparing with an installed policy/.test(t) && /Modules added on the host aren't listed/.test(t), 'notes: installed policy contains its own local changes; modules not listed');
send({ cmd: 'export', text: '# Read without root from this host\nboolean -m -1 x\n' });
send({ cmd: 'result', result: { policies, policy: policies[1], items: c.slice(0, 1), unknown: [], modulesListed: false } });
check(/Read without root: only file contexts/.test(byId.main.textContent), 'the no-root read says what it covers');
send({ cmd: 'result', result: { policies, policy: policies[1], items: [], unknown: [], note: 'No local changes in this export: the host runs the policy as installed.' } });
check(/No local changes in this export/.test(byId.main.textContent), 'no local changes: said so');

console.log(failures ? `\n${failures} check(s) failed` : '\nall local changes checks passed');
process.exit(failures ? 1 : 0);
