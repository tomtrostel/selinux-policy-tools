// Runs media/transitions.js (the transition graph webview) against a tiny fake
// DOM and plays a session: init, expand, filter, open, re-root. No VS Code or
// policy needed; runs anywhere (`node test/webview-transitions-test.js`).
const fs = require('fs');
const path = require('path');
const vm = require('vm');

class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this.textContent = ''; this.checked = false; }
  set innerHTML(v) { if (v === '') this.children = []; }
  appendChild(c) { this.children.push(c); c.parent = this; return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(ev, f) { (this.listeners[ev] = this.listeners[ev] || []).push(f); }
  fire(ev, arg = {}) { for (const f of this.listeners[ev] || []) f(arg); }
  all(pred, out = []) { for (const c of this.children) { if (pred(c)) out.push(c); c.all(pred, out); } return out; }
}
const byId = {};
for (const id of ['graph', 'root', 'domains', 'title', 'status', 'filter']) byId[id] = new El(id === 'graph' ? 'svg' : 'input');
const radios = ['out', 'in'].map(v => Object.assign(new El('input'), { value: v, checked: v === 'out' }));
const posted = [];
const winListeners = [];
const ctx = {
  setTimeout, clearTimeout,
  acquireVsCodeApi: () => ({ postMessage: (m) => posted.push(m) }),
  document: {
    getElementById: (id) => byId[id],
    createElementNS: (ns, tag) => new El(tag),
    createElement: (tag) => new El(tag),
    querySelectorAll: () => radios,
  },
  window: { addEventListener: (ev, f) => winListeners.push(f) },
};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/transitions.js'), 'utf8'), ctx);
const send = (data) => winListeners.forEach(f => f({ data }));

let failures = 0;
const check = (cond, what, extra) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`); if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra)); } };
const svg = byId.graph;
const nodes = () => svg.all(e => e.tag === 'g' && /node/.test(e.attrs.class || ''));
const nodeNamed = (n) => nodes().find(g => g.children.some(c => c.tag === 'text' && c.textContent.startsWith(n)));
const edges = () => svg.all(e => e.tag === 'path' && /edge/.test(e.attrs.class || ''));
const last = (cmd) => [...posted].reverse().find(m => m.cmd === cmd);

const wait = (ms) => new Promise(r => setTimeout(r, ms));
(async () => {
check(posted[0] && posted[0].cmd === 'ready', 'webview asks for data when loaded');
send({ cmd: 'init', root: 'init_t', dir: 'out', domains: ['init_t', 'sshd_t', 'crond_t', 'getty_t'] });
check(last('rooted') && last('rooted').root === 'init_t' && last('expand') && last('expand').name === 'init_t', 'init: reports the root and asks to expand it');
check(byId.domains.children.length === 4 && byId.title.textContent === 'Transitions from init_t', 'root picker filled, title set');
const tr = (s, t, o = {}) => ({ source: s, target: t, entrypoints: [`${t.replace(/_t$/, '')}_exec_t`], auto: [`${t.replace(/_t$/, '')}_exec_t`], setexec: true, dynamic: false, conditional: [], ...o });
send({ cmd: 'transitions', name: 'init_t', dir: 'out', locs: { sshd_t: { p: '/x/ssh.te', l: 5, c: 5 } }, transitions: [
  tr('init_t', 'sshd_t'), tr('init_t', 'crond_t', { auto: [] }), tr('init_t', 'getty_t', { conditional: ['some_bool:true'] })] });
check(nodes().length === 4 && edges().length === 3, `init_t expanded: ${nodes().length} nodes, ${edges().length} arrows`);
const [eSsh, eCron, eGetty] = edges();
check(!eSsh.attrs['stroke-dasharray'] && eCron.attrs['stroke-dasharray'] === '6 4' && /cond/.test(eGetty.attrs.class),
  'arrow styles: automatic solid, explicit (setexec) dashed, boolean-controlled marked');
const tip = eCron.children.find(c => c.tag === 'title').textContent;
check(/entrypoints: crond_exec_t/.test(tip) && /explicit/.test(tip), 'arrow tooltip lists entrypoints and how the transition happens');
check(byId.status.textContent === '3 domains shown', `status: ${byId.status.textContent}`);

nodeNamed('sshd_t').fire('click', {});
await wait(300);
check(last('expand').name === 'sshd_t', 'click on a domain asks to expand it');
send({ cmd: 'transitions', name: 'sshd_t', dir: 'out', transitions: [tr('sshd_t', 'init_t', { auto: [], dynamic: true, entrypoints: [] }), tr('sshd_t', 'chkpwd_t')] });
check(nodes().length === 5 && edges().length === 5, `sshd_t expanded (incl. a back-edge to init_t): ${nodes().length} nodes, ${edges().length} arrows`);
const back = edges().find(e => e.children.some(c => c.tag === 'title' && /sshd_t → init_t/.test(c.textContent)));
check(back && back.attrs['stroke-dasharray'] === '2 3', 'dynamic transition drawn dotted');

byId.filter.value = 'cron'; byId.filter.fire('input');
check(nodes().length === 3 && byId.status.textContent.includes('filter: cron'), `filter "cron" keeps root + expanded + matches: ${nodes().length} nodes`);
byId.filter.value = ''; byId.filter.fire('input');

nodeNamed('sshd_t').fire('click', {}); nodeNamed('sshd_t').fire('dblclick');
await wait(300);
check(last('open') && last('open').name === 'sshd_t' && last('open').loc.p === '/x/ssh.te' && nodes().length === 5, 'double-click opens the source declaration without collapsing');
nodeNamed('sshd_t').fire('click', {});
await wait(300);
check(nodes().length === 4, 'click again collapses');
nodeNamed('crond_t').fire('click', { altKey: true });
check(last('rooted').root === 'crond_t' && byId.root.value === 'crond_t', 'alt-click makes a domain the root');
radios[1].checked = true; radios[1].fire('change');
check(last('rooted').dir === 'in' && byId.title.textContent === 'Who can enter crond_t' && last('expand').dir === 'in', 'switching to "who can enter" re-roots in reverse');
send({ cmd: 'transitions', name: 'crond_t', dir: 'in', transitions: [tr('init_t', 'crond_t')] });
const inEdge = edges()[0];
check(inEdge && inEdge.attrs['marker-start'] && !inEdge.attrs['marker-end'], 'reverse mode: arrows point from the entering domain to the root');

console.log(failures ? `\n${failures} check(s) failed` : '\nall transition graph webview checks passed');
process.exit(failures ? 1 : 0);
})();
