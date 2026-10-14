'use strict';
// Levels and Categories: the `may ignore levels` checks syntax and the
// webview with a fake DOM. Any OS.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { parseChecks } = require('../server/checks');

let failures = 0;
const check = (ok, what, extra) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`); if (!ok) { failures++; if (extra !== undefined) console.log('     ', JSON.stringify(extra, null, 1).slice(0, 2000)); } };

/* ---------- checks syntax ---------- */

const p = parseChecks([
  'never container_t, svirt_t may ignore levels',
  'only init_t kernel_t may ignore levels on { file dir }',
  'never init_t may ignore levels on process',
  'require init_t may ignore levels',
  'never init_t may ignore',
  'never init_t may ignore levels on',
  'never init_t may ignore levels file',
].join('\n'));
check(p.checks.length === 3 && p.checks[0].kind === 'never-levels' && p.checks[0].sources.join() === 'container_t,svirt_t' && !p.checks[0].classes.length,
  'never … may ignore levels', p.checks[0]);
check(p.checks[1].kind === 'only-levels' && p.checks[1].classes.join() === 'file,dir' && p.checks[2].classes.join() === 'process', 'only … on { classes } / on class', p.checks.slice(1));
const err = (l) => (p.errors.find(e => e.l === l) || {}).msg || '';
check(/works with 'only' and 'never'/.test(err(3)) && /Expected 'levels'/.test(err(4)) && /after 'on'/.test(err(5)) && /Unexpected 'file'/.test(err(6)), 'errors: require, missing levels, missing class, extra word', p.errors);

/* ---------- levels.js: canonical form, setrans names, descriptions ---------- */

const LV = require('../server/levels');
check(LV.canon('s0:c1,c2') === 's0:c1.c2' && LV.canon('s0 - s0:c0.c1023') === 's0-s0:c0.c1023' && LV.canon('s0:c5,c1,c2,c3') === 's0:c1.c3,c5' && LV.canon('s0:c1,c3') === 's0:c1,c3',
  'canonical levels: sorted, runs of two or more as cA.cB', [LV.canon('s0:c1,c2'), LV.canon('s0:c5,c1,c2,c3')]);
check(LV.canon('x0') === null && LV.canon('s0:c1-c2') === null && LV.canon('s0-s1-s2') === null && LV.canon('s0:c3.c1') === null, 'not levels: null');
const ST = LV.parseSetrans('# names\ns0=SystemLow\ns0-s0:c0.c1023=SystemLow-SystemHigh\ns0:c0.c1023=SystemHigh\ns2:c0,c1=Secret:AB\nBase=Sensitivity\n\n');
check(ST.entries.length === 4 && ST.skipped.length === 1 && ST.byRaw.get('s2:c0.c1').name === 'Secret:AB', 'setrans.conf: simple lines read, advanced ones counted', ST.entries);
check(LV.translate('s0', ST) === 'SystemLow' && LV.translate('s0 - s0:c0,c1,c2.c1023', ST) === 'SystemLow-SystemHigh' && LV.translate('s0-s2:c0,c1', ST) === 'SystemLow-Secret:AB' && LV.translate('s0:c7', ST) === null && LV.translate('s0', null) === null,
  'translate: whole range, else each end, else none');
check(LV.describe('s0:c1,c5') === 's0 with 2 categories (c1,c5)' && LV.describe('s0-s0:c0.c1023', { cats: 1024 }) === 'from s0 with no categories up to s0 with all 1024 categories' && LV.describe('s0:c3') === 's0 with category c3',
  'describe in plain words', [LV.describe('s0:c1,c5'), LV.describe('s0-s0:c0.c1023', { cats: 1024 })]);
check(LV.problems('s3', { sens: 1, cats: 1024 })[0] === 's3 doesn\'t exist: this policy has only s0' && /c2000 is out of range/.test(LV.problems('s0:c2000', { sens: 1, cats: 1024 })[0])
  && /doesn't cover the low level/.test(LV.problems('s0:c1-s0:c2', {})[0]) && !LV.problems('s0-s0:c0.c1023', { sens: 1, cats: 1024 }).length, 'problems: sensitivity, category, high below low');
check(LV.covers('s0:c0.c1023', 's0:c5') && !LV.covers('s0:c1,c2', 's0:c1,c3') && LV.covers('s2', 's1') && !LV.covers('s0', 's0:c1'), 'covers (dominance)');

/* ---------- webview ---------- */

class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this._text = ''; this.open = false; this.nodeType = 1; this.checked = false; this.disabled = false; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set className(v) { this.attrs.class = v; } get className() { return this.attrs.class || ''; }
  append(...cs) { for (let c of cs) { if (typeof c === 'string') c = textNode(c); this.children.push(c); c.parent = this; } }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'open') this.open = true; if (k === 'value') this.value = String(v); if (k === 'checked') this.checked = true; if (k === 'disabled') this.disabled = true; }
  addEventListener(ev, f) { (this.listeners[ev] = this.listeners[ev] || []).push(f); }
  fire(ev, extra = {}) { for (const f of this.listeners[ev] || []) f({ target: this, currentTarget: this, key: extra.key, preventDefault() {}, stopPropagation() {} }); }
  all(pred, out = []) { for (const c of this.children) { if (c.tag && pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
  focus() { focused = this; }
}
let focused = null;
const textNode = (s) => ({ nodeType: 3, textContent: s });
const byId = {};
for (const id of ['main', 'status', 'against']) byId[id] = new El(id);
const find = (id) => byId[id] || byId.main.all(e => e.attrs.id === id)[0] || null;
const posted = [];
const winListeners = [];
const wctx = {
  acquireVsCodeApi: () => ({ postMessage: (m) => posted.push(JSON.parse(JSON.stringify(m))), getState: () => null, setState: () => {} }),
  document: { getElementById: find, createElement: (tag) => new El(tag), createTextNode: textNode },
  window: { addEventListener: (ev, f) => winListeners.push(f) },
};
vm.createContext(wctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/levels.js'), 'utf8'), wctx);
const send = (data) => winListeners.forEach(f => f({ data }));
const last = (cmd) => [...posted].reverse().find(m => m.cmd === cmd);
const all = (pred) => byId.main.all(pred);
const button = (t) => all(e => e.tag === 'button').find(e => e.textContent === t);
const input = (ph) => all(e => e.tag === 'input' && (e.attrs.placeholder || '').startsWith(ph))[0];

check(last('ready') && last('levels'), 'ready, then asks for the levels report');
const policies = [{ id: 'installed:targeted', label: 'Installed targeted policy (running here)', active: true }, { id: 'build', label: 'Last build of clip', build: true }];
send({ cmd: 'levels', key: last('levels').key, result: {
  mls: true, kind: 'mcs', sensitivities: 1, categories: 1024, domains: 5, policies, policy: policies[0],
  constraints: Array.from({ length: 10 }, (_, i) => ({ cls: i ? 'dir' : 'file', perms: ['read'], text: 'h1 dom h2 or ( t1 != mcs_constrained_type )' })),
  groups: [
    { constraints: [0, 1, 2], via: ['not in mcs_constrained_type'], domains: ['init_t', 'sshd_t', 'syslogd_t'], classes: { file: ['read', 'write'], dir: ['search'] } },
    { constraints: [], via: [], domains: ['container_t', 'svirt_t'], classes: {} },
  ],
  targetTerms: [{ term: 'not in mcs_constrained_type', constraints: 2, types: 21 }],
  locs: { mcs_constrained_type: { p: '/t/policy/modules/kernel/mcs.te', l: 12 }, container_t: { p: '/t/container.te', l: 3 } },
} });
let t = byId.main.textContent;
check(/MCS policy: one sensitivity \(s0\) and 1024 categories; 10 level constraints/.test(t) && /2 domains are held to all of them/.test(t) && /3 pass some or all/.test(t), 'summary: kind, counts', t.slice(0, 400));
check(/3 domains pass 3 of 10 constraints whatever the levels/.test(t) && /because: not in mcs_constrained_type/.test(t) && /2 domains held to every level constraint/.test(t), 'groups with their reason', t);
check(byId.against.children.length === 2 && byId.against.children[0].attrs.selected !== undefined, 'policy picker filled, the running policy selected');
const mcsLink = all(e => e.tag === 'button' && e.textContent === 'mcs_constrained_type')[0];
mcsLink.fire('click');
check(last('open') && last('open').loc.l === 12, 'the deciding attribute opens where it is declared');
button('Add check').fire('click');
check(last('addCheck') && last('addCheck').text === 'never container_t svirt_t may ignore levels', 'Add check writes `never <held domains> may ignore levels`', last('addCheck'));
send({ cmd: 'checkAdded', text: 'Added to selinux.checks' });
check(byId.status.textContent === 'Added to selinux.checks', 'status shows the result');
const f = input('find a domain');
f.value = 'ssh'; f.fire('input');
t = find('levelsBox').textContent;
check(/sshd_t/.test(t) && !/syslogd_t/.test(t) && !/container_t/.test(t) && focused && focused.attrs.id === 'lvfilter', 'filter narrows the domains and keeps the focus', t.slice(-500));
f.value = ''; input('find a domain').value = ''; input('find a domain').fire('input');

// Can it access?
button('Two containers').fire('click');
const q = last('check');
check(q && q.source === 'system_u:system_r:container_t:s0:c1,c2' && q.target.endsWith(':s0:c1,c3') && q.tclass === 'file' && q.perms === 'read open' && q.against === 'installed:targeted', 'example fills the form and checks', q);
send({ cmd: 'check', key: q.key, result: {
  problems: [], mls: true, permissiveDomain: false, booleans: 'running',
  te: { read: { status: 'allowed', rules: [{ rt: 'allow', s: 'svirt_sandbox_domain', t: 'container_file_t', c: 'file', perms: ['open', 'read'], cond: '', origin: { path: '/t/container.te', line: 40, via: 'x' } }] }, open: { status: 'allowed', rules: [{ rt: 'allow', s: 'svirt_sandbox_domain', t: 'container_file_t', c: 'file', perms: ['open', 'read'], cond: '' }] } },
  constraints: [
    { kind: 'mlsconstrain', perms: ['read'], text: 'h1 dom h2 or ( t1 != mcs_constrained_type )', ok: false, leaves: [{ text: 'h1 dom h2', ok: false, a: 's0:c1.c2', b: 's0:c1,c3' }, { text: 't1 != { mcs_constrained_type }', ok: false, a: 'container_t' }] },
    { kind: 'constrain', perms: ['read'], text: 'u1 == u2 or ( t1 == unconfined_domain )', ok: true, leaves: [{ text: 'u1 == u2', ok: true, a: 'system_u', b: 'system_u' }] },
  ],
  levels: { source: { low: 's0:c1.c2', high: 's0:c1.c2' }, target: { low: 's0:c1,c3', high: 's0:c1,c3' }, user: 's0 - s0:c0.c1023' },
} });
t = byId.main.textContent;
check(/Denied by a constraint \(the type rules allow it\)/.test(t), 'verdict: denied by a constraint', t.slice(t.indexOf('Denied') - 10, t.indexOf('Denied') + 80));
check(/the process's clearance \(high level\) \(s0:c1\.c2\) covers the object's high level \(s0:c1,c3\)/.test(t) && /the process's type \(container_t\) is not in \{ mcs_constrained_type \}/.test(t), 'comparisons in plain words', t);
check(/its user may have s0-s0:c0\.c1023/.test(t) && /1 constraint hold/.test(t) && /container\.te:41/.test(t), 'levels, held constraints folded, rule source linked');
send({ cmd: 'label', key: 9, result: { policies: [{ id: 'installed:targeted', context: 'system_u:object_r:etc_t:s0' }] } });
check(input('system_u:object_r:container_file_t').value === 'system_u:object_r:etc_t:s0', 'a file\'s label fills the object context');
// Kept apart by levels?
const isoBtn = all(e => e.tag === 'button' && e.textContent === 'Check')[1];
isoBtn.fire('click');
const iq = last('isolation');
check(iq && iq.domains === 'container_t svirt_t' && iq.weight === 10 && iq.scope === 'own', 'isolation: the held domains suggested, checked for shared objects', iq);
send({ cmd: 'isolation', key: iq.key, result: { locs: {}, results: [
  { domain: 'container_t', binds: 72, constraints: 72, count: 2, open: 1, scope: 'own', unchecked: [
    { target: 'container_t', class: 'unix_stream_socket', perms: ['connectto'], dirs: ['write'], rules: [{ s: 'container_t', t: 'container_t', c: 'unix_stream_socket' }], conditional: [], fdOnly: false, origin: { path: '/t/container.te', line: 9 } },
    { target: 'container_file_t', class: 'fifo_file', perms: ['read', 'write'], dirs: ['read/write'], rules: [{ s: 'svirt_sandbox_domain', t: 'container_file_t', c: 'fifo_file' }], conditional: [], fdOnly: true }] },
  { domain: 'svirt_t', binds: 72, constraints: 72, count: 0, open: 0, scope: 'own', unchecked: [] }] } });
t = byId.main.textContent;
check(/container_t: 2 accesses levels don't check \(1 only through a descriptor it is given\)/.test(t) && /container_t:unix_stream_socket\{ connectto \}/.test(t) && /opening is checked/.test(t) && /container\.te:10/.test(t),
  'isolation result: unchecked accesses, descriptor-only ones marked, source linked', t.slice(t.indexOf('container_t: 2'), t.indexOf('container_t: 2') + 300));
check(/svirt_t: every such access is level-checked/.test(t), 'a domain with none says so');
all(e => e.tag === 'button' && e.textContent === 'Add check').find(b => /isolated/.test(b.parent.textContent)).fire('click');
check(last('addCheck').text === 'require container_t isolated by levels', 'Add check: require … isolated by levels', last('addCheck'));
send({ cmd: 'prefill', state: { source: 'a:b:c_t:s0', target: 'd:e:f_t:s0', tclass: 'dir', perms: 'search' } });
check(last('check').source === 'a:b:c_t:s0' && last('check').tclass === 'dir', 'prefill (from the denial assistant) checks at once');
send({ cmd: 'check', key: last('check').key, result: { error: 'c_t (the source type) is not a type in this policy.' } });
check(/c_t \(the source type\) is not a type/.test(byId.main.textContent), 'errors shown');
send({ cmd: 'levels', key: last('levels').key, result: { mls: true, kind: 'mcs', sensitivities: 1, categories: 1024, domains: 1, policies, policy: policies[0], constraints: [], targetTerms: [], locs: {},
  groups: [{ constraints: [], via: [], domains: ['container_t'], classes: {} }], setrans: { path: '/etc/selinux/targeted/setrans.conf', entries: [{ raw: 's0', name: 'SystemLow', l: 3 }, { raw: 's0-s0:c0.c1023', name: 'SystemLow-SystemHigh', l: 4 }], skipped: 1 } } });
t = byId.main.textContent;
check(/Level names: 2 in setrans\.conf \(1 line in mcstrans' advanced format not read\)/.test(t) && /s0SystemLow/.test(t), 'level names listed from setrans.conf', t.slice(t.indexOf('Level names'), t.indexOf('Level names') + 120));
send({ cmd: 'check', key: last('check').key, result: { problems: [], mls: true, te: {}, constraints: [], levels: { source: { low: 's0', high: 's0:c0.c1023', name: 'SystemLow-SystemHigh' }, target: { low: 's0', high: 's0', name: 'SystemLow' }, user: 's0 - s0:c0.c1023', userName: 'SystemLow-SystemHigh', setrans: '/etc/selinux/targeted/setrans.conf' } } });
t = byId.main.textContent;
check(/s0 – s0:c0\.c1023 SystemLow-SystemHigh/.test(t) && /Object.*s0 SystemLow/.test(t) && /Names from \/etc\/selinux\/targeted\/setrans\.conf/.test(t), 'check result shows level names', t.slice(t.indexOf('Levels'), t.indexOf('Levels') + 220));
send({ cmd: 'levels', key: last('levels').key, result: { mls: false, policies, policy: policies[1] } });
check(/no levels: it was built without MLS or MCS/.test(byId.main.textContent), 'a policy without levels says so');

console.log(failures ? `\n${failures} check(s) failed` : '\nall levels checks passed');
process.exit(failures ? 1 : 0);
