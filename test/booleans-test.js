// Booleans (server/booleans.js): booleans.conf parsing, the rows from the
// sources, booleans.conf, the compiled and running values, setting a value in
// booleans.conf, and the Booleans webview against a fake DOM. Any OS, in npm test.
const B = require('../server/booleans');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + (typeof extra === 'string' ? extra : JSON.stringify(extra, null, 1)).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

// 1. booleans.conf.
const CONF = '# defaults for the tree\nhttpd_enable_cgi = true\nssh_sysadm_login=false   # keep off\n\nodd_line\nmount_anyfile = 1\nkerberos_enabled = Off\n';
const conf = B.parseConf(CONF);
check(conf.size === 4 && conf.get('httpd_enable_cgi').value === true && conf.get('httpd_enable_cgi').line === 1 && conf.get('ssh_sysadm_login').value === false && conf.get('mount_anyfile').value === true && conf.get('kerberos_enabled').value === false,
  'parseConf: name = true|false|1|0|On|Off, comments and odd lines skipped, line numbers', [...conf]);
check(B.parseDefault('true') === true && B.parseDefault(' false ') === false && B.parseDefault('') === null && B.parseDefault('maybe') === null, 'parseDefault');
let s = B.setInConf(CONF, 'ssh_sysadm_login', true);
check(s && s.line === 2 && /^ssh_sysadm_login = true$/m.test(s.text) && !/keep off/.test(s.text) && s.text.split('\n').length === CONF.split('\n').length, 'setInConf: an existing line is rewritten in place');
s = B.setInConf(CONF, 'new_bool', false);
check(s && s.line === 7 && s.text.split('\n')[7] === 'new_bool = false' && s.text.endsWith('\n'), 'setInConf: a new line goes before the trailing blank line', s && s.text.split('\n'));
check(B.setInConf(CONF, 'httpd_enable_cgi', true) === null && /\r\n/.test(B.setInConf('a = true\r\nb = false\r\n', 'b', true).text), 'setInConf: already so → null; CRLF kept');

// 2. Rows.
const decls = new Map([
  ['httpd_enable_cgi', { path: '/t/apache.te', l: 20, c: 0, module: 'apache', desc: 'Allow httpd to run CGI scripts', tunable: true, default: 'false' }],
  ['ssh_sysadm_login', { path: '/t/ssh.te', l: 30, c: 0, module: 'ssh', desc: 'Allow sshd to log in as sysadm_r', tunable: true, default: 'false' }],
  ['secure_mode', { path: '/t/kernel.te', l: 5, c: 0, module: 'kernel', desc: 'secure mode', tunable: false, default: 'false' }],
  ['only_in_sources', { path: '/t/x.te', l: 1, c: 0, module: 'x', desc: '', tunable: true, default: 'true' }],
]);
const compiled = { httpd_enable_cgi: true, ssh_sysadm_login: false, secure_mode: false, legacy_bool: true };
const running = { httpd_enable_cgi: true, ssh_sysadm_login: true, secure_mode: false, legacy_bool: true };
const effects = { httpd_enable_cgi: { on: { count: 5, domains: ['httpd_t'], rules: [{ rt: 'allow', s: 'httpd_t', t: 'bin_t', c: 'file', perms: ['execute'] }] }, off: { count: 0, domains: [], rules: [] }, mixed: 1, exprs: ['httpd_enable_cgi', 'httpd_enable_cgi && httpd_builtin_scripting'] },
  ssh_sysadm_login: { on: { count: 2, domains: ['sshd_t'], rules: [] }, off: { count: 0, domains: [], rules: [] }, mixed: 0, exprs: ['ssh_sysadm_login'] } };
const r = B.assemble({ decls, conf, compiled, running, effects });
const by = Object.fromEntries(r.rows.map(x => [x.name, x]));
check(r.rows.map(x => x.name).join() === 'httpd_enable_cgi,kerberos_enabled,legacy_bool,mount_anyfile,only_in_sources,secure_mode,ssh_sysadm_login', 'rows: the union of policy, sources and booleans.conf, sorted', r.rows.map(x => x.name));
check(by.httpd_enable_cgi.source === false && by.httpd_enable_cgi.conf === true && by.httpd_enable_cgi.compiled === true && by.httpd_enable_cgi.running === true && by.httpd_enable_cgi.effective === true && by.httpd_enable_cgi.changed && by.httpd_enable_cgi.on.count === 5 && by.httpd_enable_cgi.module === 'apache' && by.httpd_enable_cgi.loc.l === 20,
  'httpd_enable_cgi: declared off, booleans.conf on → changed; compiled and running on; what it switches', by.httpd_enable_cgi);
check(by.ssh_sysadm_login.source === false && by.ssh_sysadm_login.conf === false && by.ssh_sysadm_login.compiled === false && by.ssh_sysadm_login.running === true && by.ssh_sysadm_login.effective === true && by.ssh_sysadm_login.changed, 'ssh_sysadm_login: switched on at run time → changed, effective on', by.ssh_sysadm_login);
check(by.secure_mode.tunable === false && !by.secure_mode.changed && by.secure_mode.effective === false && by.secure_mode.on === null, 'secure_mode: a gen_bool, unchanged, nothing known about its rules');
check(by.legacy_bool.declared === false && by.legacy_bool.inPolicy && by.legacy_bool.effective === true && by.only_in_sources.inPolicy === false && by.only_in_sources.effective === true && by.kerberos_enabled.inPolicy === false && by.kerberos_enabled.effective === false,
  'a compiled boolean the sources lack; one only in the sources; one only in booleans.conf');
check(r.summary.total === 7 && r.summary.on === 5 && r.summary.off === 2 && r.summary.changed === 2 && r.summary.confOnly === 2 && r.summary.undeclared === 1, 'summary', r.summary);
const inst = B.assemble({ compiled, running, effects });
check(inst.rows.length === 4 && inst.rows.every(x => !x.declared && x.loc === null) && inst.summary.undeclared === 0 && inst.rows.find(x => x.name === 'ssh_sysadm_login').changed, 'an installed policy: no sources, running vs compiled still counts as changed');

// 3. The webview.
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
  addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
  fire(ev) { for (const fn of this.listeners[ev] || []) fn({ target: this }); }
  all(pred, out = []) { for (const c of this.children) { if (c.tag && pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; }
}
const byId = {};
for (const id of ['main', 'status', 'against', 'refresh']) byId[id] = new El(id);
const posted = [], winListeners = [];
const wctx = {
  acquireVsCodeApi: () => ({ postMessage: (msg) => posted.push(JSON.parse(JSON.stringify(msg))) }),
  document: { getElementById: (id) => byId[id], createElement: (tag) => new El(tag), createTextNode: (s) => ({ nodeType: 3, textContent: s }) },
  window: { addEventListener: (ev, fn) => winListeners.push(fn) },
};
vm.createContext(wctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../media/booleans.js'), 'utf8'), wctx);
const send = (data) => winListeners.forEach(fn => fn({ data }));
check(posted[0] && posted[0].cmd === 'load' && /Reading the booleans/.test(byId.status.textContent), 'webview: asks at once');
const policies = [{ id: 'build', label: 'Last build of clip', build: true }, { id: 'installed:targeted', label: 'Installed targeted policy (running here)', active: true }];
send({ cmd: 'result', key: posted[0].key, result: { ...r, policies, policy: policies[0], conf: { path: '/t/policy/booleans.conf', exists: true, editable: true } } });
let page = byId.main.textContent;
check(/7 booleans: 5 on, 2 off · 2 changed from the declared default · 1 not declared in this tree's sources · 2 in booleans.conf but not in the policy/.test(page) && /booleans\.conf: booleans\.conf/.test(page), 'webview: the summary line', page.slice(0, 700));
check(/httpd_enable_cgiAllow httpd to run CGI scripts/.test(page) && /on changeddeclared off, booleans\.conf on, compiled on, running on/.test(page) && /on: 5 rules for httpd_t/.test(page) && /1 with other booleans/.test(page) && /secure_mode \(bool\)/.test(page), 'webview: a row with its sources, effects and the gen_bool mark', page.slice(700, 2000));
const setBtn = byId.main.all(e => e.tag === 'button' && /^Set off in booleans\.conf$/.test(e.textContent));
check(setBtn.length === 5 && byId.main.all(e => e.tag === 'button' && /^Set on in booleans\.conf$/.test(e.textContent)).length === 2, 'webview: a Set button per row, towards the other value (tree build)');
byId.main.all(e => e.tag === 'button' && e.textContent === 'show the rules')[0].fire('click');
check(/When on \(5 rules, the first 1\):allow httpd_t bin_t:file \{ execute \}/.test(byId.main.textContent) && /Conditions: httpd_enable_cgi; httpd_enable_cgi && httpd_builtin_scripting/.test(byId.main.textContent), 'webview: show the rules opens the rule list and the conditions', byId.main.textContent.slice(700, 1600));
byId.main.all(e => e.tag === 'button' && e.textContent === 'httpd_enable_cgi')[0].fire('click');
check(posted[posted.length - 1].cmd === 'open' && posted[posted.length - 1].loc.p === '/t/apache.te' && posted[posted.length - 1].loc.l === 20, 'webview: the name opens the declaration');
setBtn[0].fire('click');
const sm = posted[posted.length - 1];
check(sm.cmd === 'set' && sm.name === 'httpd_enable_cgi' && sm.value === false && /planning…/.test(byId.main.textContent), 'webview: Set asks the client to write booleans.conf', sm);
send({ cmd: 'setPlan', name: 'httpd_enable_cgi', plan: { error: 'This tree\'s booleans.conf is generated from several sources' } });
check(/generated from several sources/.test(byId.main.textContent), 'webview: a refusal is shown in the row');
send({ cmd: 'applied', name: 'ssh_sysadm_login' });
check(/✓ written; building…/.test(byId.main.textContent), 'webview: an applied change says so until the build');
const inp = byId.main.all(e => e.tag === 'input')[0];
inp.value = 'ssh'; inp.fire('input');
check(/1 of 7 shown/.test(byId.main.textContent) && /ssh_sysadm_login/.test(byId.main.textContent) && !/httpd_enable_cgi/.test(byId.main.textContent), 'webview: the filter narrows the table');
const selOnly = byId.main.all(e => e.tag === 'select')[0];
inp.value = ''; inp.fire('input');
selOnly.value = 'changed'; selOnly.fire('change');
check(/2 of 7 shown/.test(byId.main.textContent), 'webview: "changed from the default" shows the 2 changed ones');
selOnly.value = 'all'; selOnly.fire('change');
send({ cmd: 'built', ok: true });
check(posted[posted.length - 1].cmd === 'load', 'webview: a build of the shown tree reloads');
send({ cmd: 'result', key: posted[posted.length - 1].key, result: { ...inst, policies, policy: policies[1], conf: { path: null, exists: false, editable: false } } });
check(byId.main.all(e => e.tag === 'button' && /^setsebool -P (on|off)$/.test(e.textContent)).length === 4 && !byId.main.all(e => e.tag === 'button' && /booleans\.conf/.test(e.textContent)).length, 'webview: the running policy offers setsebool -P instead');
byId.main.all(e => e.tag === 'button' && /^setsebool -P on$/.test(e.textContent))[0].fire('click');
check(posted[posted.length - 1].cmd === 'setsebool' && posted[posted.length - 1].value === true, 'webview: setsebool goes to the client (a terminal)');

// 4. Booleans a template declares keep their default, kind and description in the index
//    (gen_tunable(`$1_manage_all_user_content', false) in userdomain.if, called for cron).
{
  const { PolicyIndex } = require('../server/indexer');
  const path = require('path');
  const P = (rel) => path.resolve('/t', rel);
  const idx = new PolicyIndex();
  idx.setFile(P('policy/modules/system/userdomain.if'), [
    '## <summary>User domains</summary>',
    'template(`userdom_manage_home_template\',`',
    '\tgen_require(`', '\t\ttype $1_t;', '\t\')',
    '\t## <desc>', '\t## <p>Allow $1 to manage all user content.</p>', '\t## </desc>',
    '\tgen_tunable(`$1_manage_all_user_content\', false)',
    '\')',
  ].join('\n'), true);
  idx.setFile(P('policy/modules/services/cron.te'), 'policy_module(cron, 1.0)\ntype cron_t;\nuserdom_manage_home_template(cron)\n', true);
  idx.rebuild();
  const d = (idx.decls.get('cron_manage_all_user_content') || []).find(x => x.kind === 'bool');
  check(d && d.generated && d.tunable === true && B.parseDefault(d.default) === false && d.doc && /Allow cron to manage/.test(d.doc.desc || '') && /cron\.te$/.test(d.path),
    'index: a template-generated boolean carries its default, tunable kind and description', d);
}

console.log(failures ? `\n${failures} booleans checks FAILED` : '\nall booleans checks passed');
process.exit(failures ? 1 : 0);
