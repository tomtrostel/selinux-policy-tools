// Denial assistant over LSP on a Linux host with an installed policy: audit
// records for real types get the right verdicts against the installed policy
// (wrong label, boolean, already allowed, generic label, missing rule, other
// policy, error), and against the workspace build (a standalone module linked
// with the installed policy) the module's own types are known; against a tree
// build (default: the CLIP clone on melody) its own file contexts decide labels.
//   node test/denials-e2e.js [tree-dir]
// Needs Linux with an installed targeted policy, python3-setools, matchpathcon;
// the build part also make, m4, checkpolicy, selinux-policy-devel. Skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain, installedPolicies } = require('../server/build');

const installed = installedPolicies().find(p => p.active);
if (process.platform !== 'linux' || !installed || installed.name !== 'targeted') { console.log('SKIP: needs Linux running the targeted policy'); process.exit(0); }
const bool = (b) => { try { return fs.readFileSync(`/sys/fs/selinux/booleans/${b}`, 'utf8').trim().split(/\s+/)[0] === '1'; } catch { return null; } };
if (bool('httpd_can_network_relay') !== false || bool('httpd_read_user_content') !== false) { console.log('SKIP: expects httpd_can_network_relay and httpd_read_user_content off'); process.exit(0); }
const tc = detectToolchain('/usr/share/selinux/devel/Makefile');

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-denials-e2e-'));
const te = path.join(ws, 'demo.te');
fs.writeFileSync(te, `policy_module(demo, 1.0.0)

type demo_t;
type demo_exec_t;
init_daemon_domain(demo_t, demo_exec_t)

type demo_data_t;
files_type(demo_data_t)

allow demo_t demo_data_t:file read_file_perms;
`);
fs.writeFileSync(path.join(ws, 'demo.if'), '## <summary>demo</summary>\n');
fs.writeFileSync(path.join(ws, 'demo.fc'), '/usr/bin/demo\t--\tgen_context(system_u:object_r:demo_exec_t,s0)\n');

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
let doneIndex;
const indexed = new Promise(r => (doneIndex = r));
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
for (const n of ['textDocument/publishDiagnostics', 'selinux/checks', 'selinux/build', 'window/logMessage', 'selinux/inactiveRanges']) conn.onNotification(n, () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 3000).replace(/\n/g, '\n     ')); }
};

const top = (g) => (g && g.suggest && g.suggest.list && g.suggest.list[0] ? g.suggest.list[0].name : null);
let ev = 100;
const avc = (perms, s, t, cls, extra = '') => `type=AVC msg=audit(1728650000.${ev}:${ev++}): avc:  denied  { ${perms} } for  pid=1234 comm="x" ${extra} scontext=system_u:system_r:${s}:s0 tcontext=system_u:object_r:${t}:s0 tclass=${cls} permissive=0`;
const LOG = [
  avc('read', 'httpd_t', 'user_home_t', 'file', 'path="/var/www/html/index.html"'),     // label: policy says httpd_sys_content_t
  avc('name_connect', 'httpd_t', 'http_cache_port_t', 'tcp_socket', 'dest=8080'),        // boolean: httpd_can_network_relay
  avc('read', 'httpd_t', 'user_home_t', 'file', 'name="notes.txt"'),                     // no path → boolean httpd_read_user_content
  avc('read open', 'httpd_t', 'httpd_sys_content_t', 'file', 'path="/var/www/html/a.html"'), // already allowed
  avc('getattr', 'chronyd_t', 'default_t', 'file', 'path="/myapp/data"'),                // generic label
  avc('write', 'chronyd_t', 'etc_t', 'file', 'path="/etc/chrony.conf"'),                 // missing rule
  avc('read', 'nope_t', 'etc_t', 'file'),                                                 // not in this policy
  avc('read', 'demo_t', 'demo_data_t', 'file'),                                           // the module's own types
  `type=SELINUX_ERR msg=audit(1728650001.000:900): op=security_compute_sid invalid_context="system_u:system_r:demo_t:s0" scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:demo_exec_t:s0 tclass=process`,
].join('\n') + '\n';

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {}, initializationOptions: { trusted: true } });
  conn.sendNotification('initialized', {});
  await indexed;

  const pol = await conn.sendRequest('selinux/denialPolicies');
  check(pol.policies.some(p => p.id === 'installed:targeted' && p.active) && !pol.policies.some(p => p.build), 'policies: the running targeted policy; no build yet', pol);

  const t0 = Date.now();
  let r = await conn.sendRequest('selinux/analyzeDenials', { text: LOG });
  console.log(`     analyzed in ${Date.now() - t0} ms`);
  const by = (s, t, c) => r.groups.find(g => g.source === s && g.target === t && (!c || g.tclass === c));
  check(r.policy && r.policy.id === 'installed:targeted' && r.count === 9 && r.groups.length === 8, `9 records in 8 groups against ${r.policy && r.policy.label}`, r.notes);
  const home = by('httpd_t', 'user_home_t');
  check(home.v.verdict === 'label' && home.labels.some(l => l.path === '/var/www/html/index.html' && l.expected === 'httpd_sys_content_t') && /restorecon -v \/var\/www\/html\/index\.html/.test(home.v.fixes[0] ? home.v.fixes[0].command : ''),
    `httpd_t → user_home_t with a path under /var/www: ${home.v.title}`, home);
  const port = by('httpd_t', 'http_cache_port_t');
  check(port.v.verdict === 'boolean' && port.v.fixes[0].command === 'setsebool -P httpd_can_network_relay on', `http_cache_port_t: ${port.v.fixes[0] && port.v.fixes[0].command}`, port.v);
  const ok = by('httpd_t', 'httpd_sys_content_t');
  check(ok.v.verdict === 'allowed' && ok.v.rules.length > 0, `httpd_sys_content_t read: ${ok.v.title}`, ok.v);
  const gen = by('chronyd_t', 'default_t');
  check(gen.v.verdict === 'generic', `default_t: ${gen.v.title}`, gen);
  const miss = by('chronyd_t', 'etc_t');
  check(miss.v.verdict === 'missing' && miss.v.needed === 'allow chronyd_t etc_t:file { write };', `chronyd_t write etc_t: ${miss.v.title}`, miss);
  // Suggestions with the devel headers (no module built yet: a scratch dir of its own).
  check(top(miss) === 'files_rw_etc_files' && miss.suggest.list[0].covers && miss.suggest.list[0].owner && miss.suggest.list.some(x => x.name === 'files_manage_etc_files'),
    `chronyd_t write etc_t: suggested ${miss.suggest && miss.suggest.list ? miss.suggest.list.map(x => `${x.name} (${x.extra})`).join(', ') : JSON.stringify(miss.suggest)}`, r.notes);
  check(!by('httpd_t', 'httpd_sys_content_t').suggest, 'no suggestions for an allowed access');
  check(by('nope_t', 'etc_t').v.verdict === 'unknown', 'nope_t: not in this policy');
  check(by('demo_t', 'demo_data_t').v.verdict === 'unknown', 'the module\'s types are unknown to the installed policy');
  check(r.groups.find(g => g.kind === 'error').v.verdict === 'error', 'SELINUX_ERR: error verdict');

  // The same user_home_t read without a path is a boolean (httpd_read_user_content).
  r = await conn.sendRequest('selinux/analyzeDenials', { text: LOG.split('\n')[2] + '\n' });
  check(r.groups[0].v.verdict === 'boolean' && /httpd_read_user_content on/.test(r.groups[0].v.fixes[0].command), `user_home_t read without a path: ${r.groups[0].v.fixes[0] && r.groups[0].v.fixes[0].command}`, r.groups[0].v);

  // Against the workspace build: the module linked with the installed policy knows demo_t.
  if (tc.ok) {
    conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(te), languageId: 'selinux', version: 1, text: fs.readFileSync(te, 'utf8') } });
    const b = await conn.sendRequest('selinux/build', { uri: uri(te) });
    check(b.ok, `module builds (${b.ms} ms)`, b);
    const pol2 = await conn.sendRequest('selinux/denialPolicies');
    check(pol2.policies.some(p => p.id === 'build'), 'after a build: the workspace build is offered', pol2);
    r = await conn.sendRequest('selinux/analyzeDenials', { text: LOG, against: 'build' });
    const own = by('demo_t', 'demo_data_t');
    check(r.policy.id === 'build' && own.v.verdict === 'allowed', `against the build: demo_t reads demo_data_t: ${own.v.title}`, { policy: r.policy, v: own.v, notes: r.notes });
    check(by('chronyd_t', 'etc_t').v.verdict === 'missing', 'against the build: the installed policy\'s types are there too');
    // The module's build dir for the probe; a template-generated interface; own types get a plain rule.
    r = await conn.sendRequest('selinux/analyzeDenials', { text: [avc('name_connect', 'demo_t', 'http_port_t', 'tcp_socket'), avc('write', 'demo_t', 'demo_data_t', 'file'), avc('read', 'demo_t', 'shadow_t', 'file')].join('\n'), against: 'build' });
    check(top(by('demo_t', 'http_port_t')) === 'corenet_tcp_connect_http_port', `demo_t connect http_port_t: ${top(by('demo_t', 'http_port_t'))}`, by('demo_t', 'http_port_t').suggest);
    const ownS = by('demo_t', 'demo_data_t').suggest;
    check(ownS && ownS.own && ownS.module === 'demo' && ownS.rule === 'allow demo_t demo_data_t:file { write };', 'own types: a plain rule in the module', ownS);
    check(top(by('demo_t', 'shadow_t')) === 'auth_read_shadow' && by('demo_t', 'shadow_t').suggest.list[0].attrs.includes('can_read_shadow_passwords'), `demo_t read shadow_t: ${top(by('demo_t', 'shadow_t'))} (adds can_read_shadow_passwords)`, by('demo_t', 'shadow_t').suggest);
  } else console.log(`SKIP build part: ${tc.reason}`);
  proc.kill();

  // A tree build: checked against its own policy.bin and file contexts.
  const tree = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');
  if (detectToolchain(null).ok && fs.existsSync(path.join(tree, 'Rules.modular'))) {
    const CLIP_SEPARATE = 'ssh rhsmcertd oddjob rtkit aide postfix usbguard fapolicyd rngd logadm auditadm secadm sasl rpcbind rpc gssproxy kerberos certmonger pcscd apcupsd nut postgresql mysql apache bind openvpn samba ntp xserver accountsd colord geoclue gnome wm telepathy bluetooth devicekit';
    const makeArgs = ['NAME=mcs', 'TYPE=mcs', 'DISTRO=redhat', 'UBAC=y', 'DIRECT_INITRC=n', 'MONOLITHIC=n', 'POLY=y', 'UNK_PERMS=deny',
      'MLS_CATS=1024', 'MCS_CATS=1024', 'SEMOD_EXP=/usr/bin/semodule_expand', `APPS_MODS=${CLIP_SEPARATE}`];
    const p2 = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
    const c2 = rpc.createMessageConnection(new rpc.StreamMessageReader(p2.stdout), new rpc.StreamMessageWriter(p2.stdin));
    let done2;
    const idx2 = new Promise(res => (done2 = res));
    c2.onNotification('selinux/indexing', p => { if (p.state === 'done') done2(); });
    for (const n of ['textDocument/publishDiagnostics', 'selinux/checks', 'selinux/build', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/trees']) c2.onNotification(n, () => {});
    c2.listen();
    await c2.sendRequest('initialize', { processId: null, rootUri: uri(tree), capabilities: {}, initializationOptions: { trusted: true, build: { tree: { makeArgs } } } });
    c2.sendNotification('initialized', {});
    await idx2;
    const logging = path.join(tree, 'policy/modules/system/logging.te');
    c2.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(logging), languageId: 'selinux', version: 1, text: fs.readFileSync(logging, 'utf8') } });
    const tb = await c2.sendRequest('selinux/build', { uri: uri(logging) });
    check(tb.ok, `tree builds (${tb.ms} ms)`, tb.ok ? undefined : tb);
    r = await c2.sendRequest('selinux/analyzeDenials', { text: LOG, against: 'build' });
    check(r.policy && r.policy.id === 'build' && /Last build of/.test(r.policy.label) && /\/(file_contexts|all_mods\.fc)$/.test(r.policy.fileContexts) && r.policy.fileContexts.startsWith(os.tmpdir()), `against ${r.policy && r.policy.label}, labels from ${r.policy && r.policy.fileContexts}`, r.notes);
    const h2 = by('httpd_t', 'user_home_t');
    check(h2 && h2.v.verdict === 'label' && h2.labels.some(l => l.expected === 'httpd_sys_content_t'), `tree build: /var/www/html labeled by the tree's file contexts: ${h2 && h2.v.title}`, h2 && h2.labels);
    check(by('demo_t', 'demo_data_t').v.verdict === 'unknown', 'tree build: the standalone module\'s types are not in it');
    // Suggestions from the tree's own m4 output and interfaces.
    r = await c2.sendRequest('selinux/analyzeDenials', { text: avc('write', 'httpd_t', 'etc_t', 'file'), against: 'build' });
    const hw = by('httpd_t', 'etc_t');
    check(hw && hw.v.verdict === 'missing' && top(hw) === 'files_rw_etc_files' && hw.suggest.list[0].loc.p.startsWith(tree), `tree build: httpd_t write etc_t: ${top(hw)} from ${hw && hw.suggest && hw.suggest.list && hw.suggest.list[0] ? path.relative(tree, hw.suggest.list[0].loc.p) : '?'}`, hw && { v: hw.v, s: hw.suggest, notes: r.notes });
    p2.kill();
  } else console.log('SKIP tree part: no refpolicy tree or toolchain');

  console.log(failures ? `\n${failures} check(s) failed` : '\nall denial e2e checks passed');
  fs.rmSync(ws, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); fs.rmSync(ws, { recursive: true, force: true }); process.exit(1); });
