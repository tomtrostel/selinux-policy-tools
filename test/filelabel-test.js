// File label lookup: file-context parsing, fc_sort.py's order, libselinux's
// lookup order and substitutions, home templates, and the File Labels webview
// with a fake DOM. Any OS.
//   node test/filelabel-test.js
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const F = require('../server/filelabel');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2000).replace(/\n/g, '\n     ')); }
};

/* ---------- parsing ---------- */

const FC = [
  '/usr/bin(/.*)?\t\t\tsystem_u:object_r:bin_t:s0',
  '/usr/bin/rpm\t--\tsystem_u:object_r:rpm_exec_t:s0',
  '',
  '# a comment',
  '/usr/.*\t\t\tsystem_u:object_r:usr_t:s0',
  '/usr/bin/dnf-[0-9]+\t\t--\tsystem_u:object_r:rpm_exec_t:s0',
  '/var/run/.*\\.pid\t--\tsystem_u:object_r:var_run_t:s0',
  '/usr/lib/debug(/.*)?\t\t<<none>>',
  '/dev/tty[[:digit:]]+\t-c\tsystem_u:object_r:tty_device_t:s0',
  '/usr/bin\t-d\tsystem_u:object_r:bin_t:s0',
].join('\n');
const specs = F.parseSpecs(FC, '/x/file_contexts', 'mod');
check(specs.length === 8 && specs[1].flag === '--' && specs[1].mode === 'file' && specs[1].type === 'rpm_exec_t' && specs[1].l === 1 && specs[1].module === 'mod', 'lines, flags, types, 0-based line numbers', specs[1]);
check(specs[5].context === '<<none>>' && specs[5].type === null, '<<none>> has no type');

/* ---------- fc_sort.py's order ---------- */

check(JSON.stringify(F.specificity('/usr/bin(/.*)?')) === JSON.stringify({ meta: true, stem: 8, len: 14 }), 'specificity: stem stops at the first regex character');
check(JSON.stringify(F.specificity('/a\\.b')) === JSON.stringify({ meta: false, stem: 4, len: 4 }), 'specificity: an escaped character counts once and is not a regex character', F.specificity('/a\\.b'));
const sorted = F.sortSpecs(specs).map(s => s.spec);
check(sorted.indexOf('/usr/.*') < sorted.indexOf('/usr/bin(/.*)?') && sorted.indexOf('/usr/bin(/.*)?') < sorted.indexOf('/usr/bin/dnf-[0-9]+') && sorted.slice(-2).join() === '/usr/bin,/usr/bin/rpm',
  'sorted from general to specific: /usr/.* before /usr/bin(/.*)?, exact paths last', sorted);
const same = F.parseSpecs('/a(/.*)?\tsystem_u:object_r:x_t:s0\n/a(/.*)?\t--\tsystem_u:object_r:y_t:s0\n/a(/.*)?\tsystem_u:object_r:z_t:s0\n');
check(F.sortSpecs(same).map(s => s.type).join() === 'x_t,z_t,y_t', 'equally specific lines keep their order; one with a file kind sorts after');
check(F.sortSpecs(same, true).map(s => s.type).join() === 'y_t,x_t,z_t', 'libsemanage 2.9 (RHEL 8): one with a file kind sorts first');
check(F.typedFirstIn(F.sortSpecs(specs.concat(same))) === false && F.typedFirstIn(F.sortSpecs(specs.concat(same), true)) === true && F.typedFirstIn(specs.slice(0, 1)) === null,
  'which way a file_contexts sorts equally specific lines: last, first, can\'t tell');

/* ---------- lookup ---------- */

// Unsorted (as tmp/all_mods.fc): /usr/.* comes later and wins for rpmbuild. Sorted: bin_t.
const asWritten = F.lookupOrder(specs);
check(F.matches(asWritten, '/usr/bin/rpmbuild', 'file')[0].type === 'usr_t', 'unsorted file contexts: the later general line wins (the old bug)');
const order = F.lookupOrder(F.sortSpecs(specs));
const win = (p, mode = 'file') => { const m = F.matches(order, p, mode); return m.length ? m[0].type || m[0].context : null; };
check(win('/usr/bin/rpmbuild') === 'bin_t' && win('/usr/bin/rpm') === 'rpm_exec_t' && win('/usr/bin/dnf-3') === 'rpm_exec_t', 'sorted: rpmbuild bin_t, rpm and dnf-3 rpm_exec_t');
check(win('/usr/bin/rpm', 'lnk_file') === 'bin_t', 'a -- line applies to regular files only: a link /usr/bin/rpm gets bin_t');
check(win('/usr/bin', 'dir') === 'bin_t' && win('/usr/share/x') === 'usr_t' && win('/opt/x') === null, 'directory line; general line; nothing matches');
check(win('/usr/lib/debug/x') === '<<none>>', '<<none>> line');
check(win('/dev/tty12', 'chr_file') === 'tty_device_t' && win('/dev/tty12', 'file') === null, 'POSIX class [[:digit:]] translated; -c only for character devices');
check(win('/var/run/x.pid') === 'var_run_t' && win('/var/run/xpid') === null, 'escaped dot is literal');
const ms = F.matches(order, '/usr/bin/rpm', 'file');
check(ms.map(s => s.type).join() === 'rpm_exec_t,bin_t,usr_t', 'every matching line, the winner first', ms.map(s => s.spec));
// libselinux: file_contexts, .homedirs, .local concatenated; exact specs after patterns (local patterns win over main patterns).
const local = F.parseSpecs('/usr/bin(/.*)?\tsystem_u:object_r:local_t:s0\n');
const main = F.parseSpecs('/usr/bin(/.*)?\tsystem_u:object_r:bin_t:s0\n/usr/bin/rpm\t--\tsystem_u:object_r:rpm_exec_t:s0\n');
const lo = F.lookupOrder(main, [], local);
check(F.matches(lo, '/usr/bin/x', 'file')[0].type === 'local_t' && F.matches(lo, '/usr/bin/rpm', 'file')[0].type === 'rpm_exec_t', 'local patterns win over the main file; exact paths win over both');

/* ---------- substitutions ---------- */

const dist = F.parseSubs('/lib64 /usr/lib\n/usr/lib64 /usr/lib\n# c\n/bin   /usr/bin\n');
check(F.applySubs('/usr/lib64/libc.so', [], dist) === '/usr/lib/libc.so' && F.applySubs('/usr/lib64', [], dist) === '/usr/lib', 'dist subs at a component boundary');
check(F.applySubs('/usr/lib64x/a', [], dist) === '/usr/lib64x/a', 'not in the middle of a name');
check(F.applySubs('/srv/web/a', F.parseSubs('/srv/web /var/www'), dist) === '/var/www/a', 'local subs');
check(F.applySubs('/data/lib64/a', F.parseSubs('/data /usr'), dist) === '/usr/lib/a', 'local subs, then dist subs on the result');
const rootSubs = F.parseSubs('/var/chroot/ro /\n');
check(F.applySubs('/var/chroot/ro/etc/passwd', rootSubs, []) === '/etc/passwd' && F.applySubs('/var/chroot/ro', rootSubs, []) === '/', 'a directory labeled like / (a chroot): its paths as at the root');
const runSubs = F.parseSubs('/run /var/run\n/run/systemd/generator /usr/lib/systemd/system\n');
check(F.applySubs('/run/systemd/generator/home.mount', [], runSubs) === '/usr/lib/systemd/system/home.mount' && F.applySubs('/run/x.pid', [], runSubs) === '/var/run/x.pid',
  'later lines are tried first (libselinux prepends them): /run/systemd/generator before /run');

/* ---------- home directory templates ---------- */

const tplIn = F.parseSpecs('HOME_DIR/\\.ssh(/.*)?\tsystem_u:object_r:ssh_home_t:s0\nHOME_ROOT\t-d\tsystem_u:object_r:home_root_t:s0\n/run/user/%{USERID}\t-d\tsystem_u:object_r:user_tmp_t:s0\n/etc(/.*)?\tsystem_u:object_r:etc_t:s0\n');
const [tpl, rest] = F.splitHomeTemplates(tplIn);
check(tpl.length === 3 && rest.length === 1 && tpl[0].template === 'HOME_DIR/\\.ssh(/.*)?', 'template lines split off, original kept');
const ho = F.lookupOrder(F.sortSpecs(rest), F.sortSpecs(tpl));
check(F.matches(ho, '/home/alice/.ssh/id_rsa', 'file')[0].type === 'ssh_home_t' && F.matches(ho, '/home', 'dir')[0].type === 'home_root_t' && F.matches(ho, '/run/user/1000', 'dir')[0].type === 'user_tmp_t', 'HOME_DIR, HOME_ROOT, %{USERID} expanded');

/* ---------- rendering, permission levels ---------- */

const text = F.renderSpecs(F.sortSpecs(specs));
check(F.parseSpecs(text).map(s => `${s.spec}|${s.flag}|${s.context}`).join('\n') === F.sortSpecs(specs).map(s => `${s.spec}|${s.flag}|${s.context}`).join('\n'), 'rendered file reads back the same');
check(F.permLevels(['read', 'open', 'getattr']).join() === 'read' && F.permLevels(['create', 'unlink', 'write', 'read']).join() === 'read,manage'
  && F.permLevels(['execute', 'read']).join() === 'read,execute' && F.permLevels(['entrypoint']).join() === 'enter' && F.permLevels(['relabelto']).join() === 'relabel', 'permission levels');

/* ---------- webview ---------- */

class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this._text = ''; this.open = false; this.nodeType = 1; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set className(v) { this.attrs.class = v; } get className() { return this.attrs.class || ''; }
  append(...cs) { for (let c of cs) { if (typeof c === 'string') c = textNode(c); this.children.push(c); c.parent = this; } }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'open') this.open = true; if (k === 'value') this.value = String(v); }
  addEventListener(ev, f) { (this.listeners[ev] = this.listeners[ev] || []).push(f); }
  fire(ev, extra = {}) { for (const f of this.listeners[ev] || []) f({ target: this, currentTarget: this, key: extra.key, preventDefault() {}, stopPropagation() {} }); }
  all(pred, out = []) { for (const c of this.children) { if (c.tag && pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
}
const textNode = (s) => ({ nodeType: 3, textContent: s });
const byId = {};
for (const id of ['main', 'status', 'against', 'path', 'mode', 'go', 'browse', 'title']) byId[id] = new El(id);
const posted = [];
const winListeners = [];
const wctx = {
  setTimeout, clearTimeout,
  acquireVsCodeApi: () => ({ postMessage: (m) => posted.push(JSON.parse(JSON.stringify(m))), getState: () => null, setState: () => {} }),
  document: { getElementById: (id) => byId[id], createElement: (tag) => new El(tag), createTextNode: textNode },
  window: { addEventListener: (ev, f) => winListeners.push(f) },
};
vm.createContext(wctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/filelabel.js'), 'utf8'), wctx);
const send = (data) => winListeners.forEach(f => f({ data }));
const last = (cmd) => [...posted].reverse().find(m => m.cmd === cmd);
const find = (pred) => byId.main.all(pred);
const btn = (t) => find(e => e.tag === 'button' && e.textContent === t)[0];

check(last('ready') && byId.mode.children.length === 8 && /\/usr\/bin\/rpm/.test(byId.main.textContent), 'ready posted; kinds offered; intro shown');
send({ cmd: 'lookup', path: '/usr/bin/rpm' });
const req = last('label');
check(req && req.path === '/usr/bin/rpm' && req.mode === '' && byId.path.value === '/usr/bin/rpm', 'a lookup asks for the label', req);
const winner = { spec: '/usr/bin/rpm', flag: '--', mode: 'file', context: 'system_u:object_r:rpm_exec_t:s0', type: 'rpm_exec_t', module: 'rpm', local: false, template: false, file: null, src: { p: '/t/policy/modules/admin/rpm.fc', l: 15, c: 20, m: 'rpm' } };
const result = {
  path: '/usr/bin/rpm', lookedUp: '/usr/bin/rpm', exists: true, mode: 'file', executable: true, current: 'system_u:object_r:bin_t:s0', linkTarget: null, pkg: 'rpm-4.16.1.3-40.el9.x86_64',
  policies: [
    { id: 'installed:targeted', label: 'Installed targeted policy (running here)', build: false, active: true, key: null, context: 'system_u:object_r:rpm_exec_t:s0', type: 'rpm_exec_t',
      winner: { ...winner, module: null, src: null, file: { p: '/etc/selinux/targeted/contexts/files/file_contexts', l: 99 } }, others: [] },
    { id: 'build', label: 'Last build of clip', build: true, active: false, key: null, context: winner.context, type: 'rpm_exec_t', winner,
      others: [{ ...winner, spec: '/usr/bin(/.*)?', flag: null, type: 'bin_t', context: 'system_u:object_r:bin_t:s0', src: { p: '/t/policy/modules/kernel/corecommands.fc', l: 140, c: 0, m: 'corecommands' } }] },
  ],
};
send({ cmd: 'label', key: req.key, result });
check(byId.against.children.length === 2 && byId.against.value === 'build', 'policy picker filled; the build is preferred for rules');
const info = last('info');
check(info && info.against === 'build' && info.type === 'rpm_exec_t', 'asks what the build lets happen to rpm_exec_t', info);
let t = byId.main.textContent;
check(/rpm-4\.16/.test(t) && /restorecon would relabel it to rpm_exec_t/.test(t) && /admin\/rpm\.fc:16/.test(t) && /1 other line also matches, but loses/.test(t), 'package, restorecon warning (labeled bin_t now), source line, losing line', t.slice(0, 600));
check(find(e => (e.attrs.class || '').includes('card') && (e.attrs.class || '').includes('warn')).length === 1, 'card marked: the current label differs');
const srcBtn = find(e => e.tag === 'button' && e.textContent === 'admin/rpm.fc:16')[0];
srcBtn.fire('click');
check(last('open') && last('open').loc.p === '/t/policy/modules/admin/rpm.fc' && last('open').loc.l === 15, 'source line opens');
send({ cmd: 'info', key: info.key, result: {
  type: 'rpm_exec_t', alias: null, attrs: ['exec_type', 'file_type'], permissive: false, isDomain: false, traceable: true,
  locs: { rpm_exec_t: { p: '/t/policy/modules/admin/rpm.te', l: 10, c: 5, m: 'rpm' }, rpm_t: { p: '/t/policy/modules/admin/rpm.te', l: 9, c: 5, m: 'rpm' } },
  entrypointOf: [{ domain: 'rpm_t', via: ['rpm_t'], permissive: false, from: [{ source: 'sysadm_t', auto: true, setexec: false, conditional: [] }, { source: 'unconfined_t', auto: true, setexec: true, conditional: [] }], fromCount: 2 }],
  entryViaAttr: 0,
  access: [
    { s: 'rpm_t', t: 'rpm_exec_t', cond: '', attr: false, size: 1, domains: 1, classes: { file: ['entrypoint', 'execute', 'getattr', 'map', 'open', 'read'] } },
    { s: 'domain', t: 'exec_type', cond: '', attr: true, size: 900, domains: 400, classes: { file: ['getattr'] } },
    { s: 'rpm_t', t: 'rpm_exec_t', cond: 'secure_mode:false', attr: false, size: 1, domains: 1, classes: { file: ['relabelto'] } },
  ], accessCount: 3, created: [], createdCount: 0, inside: [], insideCount: 0, policy: { id: 'build', label: 'Last build of clip', build: true } } });
t = byId.main.textContent;
check(/Running it starts/.test(t) && /sysadm_t \(automatically\)/.test(t) && /rpm_t/.test(t), 'domains it starts and from where');
check(/attribute: 900 types, 400 domains/.test(t) && /via its attribute exec_type/.test(t) && /when not \(secure_mode\)/.test(t), 'access rows: attribute sizes, via an attribute, conditions', t.slice(t.indexOf('Who may'), t.indexOf('Who may') + 600));
const rows = find(e => e.tag === 'tr' && /relabel|enter|read/.test(e.textContent) && e.children.length === 4);
check(rows.length >= 3 && /relabel/.test(rows[0].textContent) && /enter/.test(rows[1].textContent) && /domain/.test(rows[2].textContent), 'rows ordered by the strongest access (relabel before read)', rows.map(r => r.textContent.slice(0, 40)));
btn('where from').fire('click');
const o = last('origins');
check(o && o.s === 'rpm_t' && o.classes.join() === 'file', 'where from asks for the rule\'s source statements', o);
send({ cmd: 'origins', key: o.key, result: { origins: [{ path: '/t/policy/modules/admin/rpm.te', line: 40, text: 'can_exec(rpm_t, rpm_exec_t)', via: 'can_exec' }], more: 0 } });
check(/admin\/rpm\.te:41/.test(byId.main.textContent) && /via can_exec/.test(byId.main.textContent), 'source statement shown');
byId.against.value = 'installed:targeted';
byId.against.fire('change');
check(last('info').against === 'installed:targeted', 'another policy: its rules are asked for');

// A program with no domain of its own: offer to confine it.
send({ cmd: 'lookup', path: '/usr/local/bin/tool' });
const r2 = last('label');
send({ cmd: 'label', key: r2.key, result: { ...result, path: '/usr/local/bin/tool', lookedUp: '/usr/local/bin/tool', current: 'system_u:object_r:bin_t:s0', pkg: null,
  policies: [{ ...result.policies[0], context: 'system_u:object_r:bin_t:s0', type: 'bin_t' }] } });
const i2 = last('info');
send({ cmd: 'info', key: i2.key, result: { type: 'bin_t', alias: null, attrs: ['file_type'], permissive: false, isDomain: false, traceable: false, locs: {}, entrypointOf: [], entryViaAttr: 3, access: [], accessCount: 0, created: [], createdCount: 0, inside: [], insideCount: 0 } });
t = byId.main.textContent;
check(/starts no domain of its own/.test(t) && /no package owns it/.test(t) && !!btn('Confine it: New Service…'), 'no domain of its own: explained, New Service offered');
btn('Confine it: New Service…').fire('click');
check(last('newService') && last('newService').exec === '/usr/local/bin/tool', 'New Service gets the program path');
send({ cmd: 'built', ok: true });
check(posted.filter(m => m.cmd === 'label').length >= 4, 'after a build the paths are looked up again');

console.log(failures ? `\n${failures} check(s) failed` : '\nall file label checks passed');
process.exit(failures ? 1 : 0);
