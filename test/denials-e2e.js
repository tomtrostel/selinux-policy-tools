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
// A second module next to it whose type no interface mentions (for "a new interface in the owner module").
fs.writeFileSync(path.join(ws, 'other.te'), 'policy_module(other, 1.0.0)\n\ntype other_data_t;\nfiles_type(other_data_t)\n');
fs.writeFileSync(path.join(ws, 'other.if'), '## <summary>other</summary>\n');
fs.writeFileSync(path.join(ws, 'other.fc'), '');

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

/** What the client does with a fix plan: write the file (also as the open editor's text) and build it. */
async function applyPlan(c, plan, versions) {
  fs.mkdirSync(path.dirname(plan.path), { recursive: true });
  fs.writeFileSync(plan.path, plan.text);
  const u = URI.file(plan.path).toString();
  if (versions[plan.path]) c.sendNotification('textDocument/didChange', { textDocument: { uri: u, version: ++versions[plan.path] }, contentChanges: [{ text: plan.text }] });
  else { versions[plan.path] = 1; c.sendNotification('textDocument/didOpen', { textDocument: { uri: u, languageId: 'selinux', version: 1, text: plan.text } }); }
  await new Promise(r => setTimeout(r, 600)); // reindex debounce
  return c.sendRequest('selinux/build', { uri: u });
}
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
    // Phase 3: write the fix, build, and the denial is allowed by the build.
    const versions = { [te]: 1 };
    const LOG3 = [avc('write', 'demo_t', 'etc_t', 'file'), avc('read', 'demo_t', 'httpd_sys_content_t', 'file'), avc('write', 'httpd_t', 'etc_t', 'file')].join('\n');
    r = await conn.sendRequest('selinux/analyzeDenials', { text: LOG3, against: 'build' });
    const call1 = `${top(by('demo_t', 'etc_t'))}(demo_t)`;
    let plan = await conn.sendRequest('selinux/denialFix', { domain: 'demo_t', call: call1 });
    check(plan.path === te && !plan.optional && plan.inserted.join() === call1 && plan.diff.some(x => x.t === '+' || x.add || x.kind === 'add' || /\+/.test(JSON.stringify(x))), `fix plan: ${call1} into demo.te at line ${plan.line + 1}, not optional (files is a base module)`, plan);
    let b3 = await applyPlan(conn, plan, versions);
    check(b3.ok, 'demo.te with the call builds', b3.ok ? undefined : b3.log);
    const call2 = `${top(by('demo_t', 'httpd_sys_content_t'))}(demo_t)`;
    plan = await conn.sendRequest('selinux/denialFix', { domain: 'demo_t', call: call2 });
    check(plan.optional && /optional_policy\(`\n\t/.test(plan.text) && plan.inserted[0] === 'optional_policy(`', `${call2} goes in optional_policy (apache can be off)`, plan);
    b3 = await applyPlan(conn, plan, versions);
    check(b3.ok, 'demo.te with the optional call builds', b3.ok ? undefined : b3.log);
    r = await conn.sendRequest('selinux/analyzeDenials', { text: LOG3, against: 'build' });
    check(by('demo_t', 'etc_t').v.verdict === 'allowed' && by('demo_t', 'httpd_sys_content_t').v.verdict === 'allowed', `after the fixes the build allows both: ${by('demo_t', 'etc_t').v.verdict}, ${by('demo_t', 'httpd_sys_content_t').v.verdict}`, r.notes);
    plan = await conn.sendRequest('selinux/denialFix', { domain: 'demo_t', call: call1 });
    check(plan.already, 'asking again: already there');
    // A domain of the installed policy: a local module of its own.
    const call3 = `${top(by('httpd_t', 'etc_t'))}(httpd_t)`;
    plan = await conn.sendRequest('selinux/denialFix', { domain: 'httpd_t', call: call3 });
    check(!plan.exists && plan.path === path.join(ws, 'local_httpd', 'local_httpd.te') && /gen_require\(`\n\ttype httpd_t;/.test(plan.text) && plan.note, `httpd_t (installed policy): new module ${plan.path && path.relative(ws, plan.path)}`, plan);
    b3 = await applyPlan(conn, plan, versions);
    check(b3.ok, 'the local module builds', b3.ok ? undefined : b3.log);
    r = await conn.sendRequest('selinux/analyzeDenials', { text: LOG3, against: 'build' });
    check(by('httpd_t', 'etc_t').v.verdict === 'allowed' && /local_httpd/.test(r.policy.label), `the installed policy + local_httpd allows it: ${by('httpd_t', 'etc_t').v.verdict} (${r.policy.label})`, r.notes);
    // Phase 4: the fix with a new interface in another module next to it (the linked policy holds only
    // demo, so other_data_t isn't analyzed here; the tree part checks the whole flow).
    plan = await conn.sendRequest('selinux/denialFix', { domain: 'demo_t', newInterface: { target: 'other_data_t', tclass: 'file', perms: ['read', 'open'] } });
    const ifPlan = (plan.also || [])[0];
    check(ifPlan && ifPlan.path === path.join(ws, 'other.if') && /interface\(`other_read_data_files'/.test(ifPlan.text) && plan.path === te && plan.inserted.includes('\tother_read_data_files(demo_t)'),
      `fix: the interface into other.if and the call into demo.te (${plan.optional ? 'optional' : 'not optional'})`, plan);
    fs.writeFileSync(ifPlan.path, ifPlan.text);
    conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(ifPlan.path), languageId: 'selinux', version: 1, text: ifPlan.text } });
    b3 = await applyPlan(conn, plan, versions);
    check(b3.ok, 'demo.te calling the new interface builds', b3.ok ? undefined : b3.log);
    // The service editor opened from "No policy for this program": its path and a name filled in.
    const pre = await conn.sendRequest('selinux/serviceInfo', { prefill: { exec: '/opt/acme/bin/acme-agent' } });
    check(pre.isNew && pre.model.exec.join() === '/opt/acme/bin/acme-agent' && pre.model.name === 'acme_agent', `New Service from the denial assistant: ${pre.model && pre.model.name} for ${pre.model && pre.model.exec}`);
  } else console.log(`SKIP build part: ${tc.reason}`);

  // Phase 4 against the running policy: constraints and programs outside their domain.
  const sys = (ev2, exe) => `type=SYSCALL msg=audit(1728650100.${ev2}:${ev2}): arch=c000003e syscall=257 success=no exit=-13 items=1 ppid=1 pid=77 comm="x" exe="${exe}" subj=system_u:system_r:unconfined_service_t:s0 key=(null)`;
  const P4 = [
    'type=AVC msg=audit(1728650100.901:901): avc:  denied  { read } for  pid=7 comm="qemu-kvm" path="/var/lib/libvirt/images/a.img" scontext=system_u:system_r:svirt_t:s0:c1,c2 tcontext=system_u:object_r:svirt_image_t:s0:c3,c4 tclass=file permissive=0',
    'type=AVC msg=audit(1728650100.902:902): avc:  denied  { write } for  pid=77 comm="chronyd" name="x" scontext=system_u:system_r:unconfined_service_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0', sys(902, '/usr/sbin/chronyd'),
    'type=AVC msg=audit(1728650100.903:903): avc:  denied  { write } for  pid=78 comm="true" name="y" scontext=system_u:system_r:unconfined_service_t:s0 tcontext=system_u:object_r:etc_runtime_t:s0 tclass=file permissive=0', sys(903, '/usr/bin/true'),
  ].join('\n');
  const c4 = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const k4 = rpc.createMessageConnection(new rpc.StreamMessageReader(c4.stdout), new rpc.StreamMessageWriter(c4.stdin));
  let d4; const i4 = new Promise(res => (d4 = res));
  k4.onNotification('selinux/indexing', p => { if (p.state === 'done') d4(); });
  for (const n of ['textDocument/publishDiagnostics', 'selinux/checks', 'selinux/build', 'window/logMessage', 'selinux/inactiveRanges']) k4.onNotification(n, () => {});
  k4.listen();
  const ws4 = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-denials-p4-'));
  await k4.sendRequest('initialize', { processId: null, rootUri: uri(ws4), capabilities: {}, initializationOptions: { trusted: true } });
  k4.sendNotification('initialized', {});
  await i4;
  r = await k4.sendRequest('selinux/analyzeDenials', { text: P4 });
  const sv = by('svirt_t', 'svirt_image_t');
  check(sv && sv.v.verdict === 'constraint' && /MCS/.test(sv.v.title) && /h1 dom h2/.test(sv.v.detail) && /chcon -l s0:c1,c2/.test((sv.v.fixes[0] || {}).command || ''), `svirt_t with other categories: ${sv && sv.v.title}`, sv && sv.v);
  const ch = by('unconfined_service_t', 'etc_t');
  check(ch && ch.v.verdict === 'transition' && ch.v.title === 'Not running in chronyd_t', `chronyd as unconfined_service_t: ${ch && ch.v.title}`, ch && ch.v);
  const tru = by('unconfined_service_t', 'etc_runtime_t');
  check(tru && tru.v.verdict === 'transition' && tru.v.title === 'No policy for this program' && tru.v.fixes[0].action.exec === '/usr/bin/true', `/usr/bin/true as unconfined_service_t: ${tru && tru.v.title}`, tru && tru.v);
  c4.kill();
  fs.rmSync(ws4, { recursive: true, force: true });
  proc.kill();

  // A tree build: checked against its own policy.bin and file contexts.
  const treeSrc = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');
  if (detectToolchain(null).ok && fs.existsSync(path.join(treeSrc, 'Rules.modular'))) {
    const tree = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-denials-tree-'));
    cp.execFileSync('cp', ['-a', treeSrc + '/.', tree]);
    fs.rmSync(path.join(tree, 'tmp'), { recursive: true, force: true });
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
    // Write the suggested call into apache.te and build: the build allows it.
    const tv = {};
    let tplan = await c2.sendRequest('selinux/denialFix', { domain: 'httpd_t', call: `${top(hw)}(httpd_t)` });
    check(tplan.path === path.join(tree, 'policy/modules/contrib/apache.te') || /\/apache\.te$/.test(tplan.path || ''), `tree fix plan: ${tplan.path && path.relative(tree, tplan.path)} line ${tplan.line + 1}`, tplan);
    const tb2 = await applyPlan(c2, tplan, tv);
    check(tb2.ok, `tree with the fix builds (${tb2.ms} ms)`, tb2.ok ? undefined : tb2.log && tb2.log.slice(-2000));
    r = await c2.sendRequest('selinux/analyzeDenials', { text: avc('write', 'httpd_t', 'etc_t', 'file'), against: 'build' });
    check(by('httpd_t', 'etc_t').v.verdict === 'allowed', `tree build after the fix: ${by('httpd_t', 'etc_t').v.title}`, r.notes);
    // No interface mentions a type: a new interface in its module (ntp), called from apache.te.
    const ntpTe = path.join(tree, 'policy/modules/services/ntp.te');
    const ntpText = fs.readFileSync(ntpTe, 'utf8').replace(/(\ntype ntpd_t;)/, '$1\ntype ntpd_extra_t;\nfiles_type(ntpd_extra_t)');
    await applyPlan(c2, { path: ntpTe, text: ntpText }, tv);
    r = await c2.sendRequest('selinux/analyzeDenials', { text: avc('read open', 'httpd_t', 'ntpd_extra_t', 'file'), against: 'build' });
    const nx = by('httpd_t', 'ntpd_extra_t');
    const nis = nx && nx.suggest && nx.suggest.newIface;
    check(nx && nx.v.verdict === 'missing' && nis && nis.module === 'ntp' && nis.name === 'ntp_read_ntpd_extra_files', `no interface mentions ntpd_extra_t: propose ${nis && nis.name} in ntp`, nx && { v: nx.v, s: nx.suggest, notes: r.notes });
    tplan = await c2.sendRequest('selinux/denialFix', { domain: 'httpd_t', newInterface: { target: 'ntpd_extra_t', tclass: 'file', perms: ['read', 'open'] } });
    const tif = (tplan.also || [])[0];
    check(tif && /\/ntp\.if$/.test(tif.path) && /interface\(`ntp_read_ntpd_extra_files'/.test(tif.text) && /\/apache\.te$/.test(tplan.path) && tplan.optional, `fix: the interface into ntp.if, the call into apache.te in optional_policy`, tplan);
    await applyPlan(c2, tif, tv);
    const tb3 = await applyPlan(c2, tplan, tv);
    check(tb3.ok, `tree with the new interface builds (${tb3.ms} ms)`, tb3.ok ? undefined : tb3.log && tb3.log.slice(-2000));
    r = await c2.sendRequest('selinux/analyzeDenials', { text: avc('read open', 'httpd_t', 'ntpd_extra_t', 'file'), against: 'build' });
    check(by('httpd_t', 'ntpd_extra_t').v.verdict === 'allowed', `after the new interface: ${by('httpd_t', 'ntpd_extra_t').v.title}`, r.notes);
    p2.kill();
    fs.rmSync(tree, { recursive: true, force: true });
  } else console.log('SKIP tree part: no refpolicy tree or toolchain');

  console.log(failures ? `\n${failures} check(s) failed` : '\nall denial e2e checks passed');
  fs.rmSync(ws, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); fs.rmSync(ws, { recursive: true, force: true }); process.exit(1); });
