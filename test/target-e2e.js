// Target hosts over LSP on a Linux host: connect to a target with a password
// (through the askpass helper, checked by a wrapper around ssh), read its facts,
// mirror its policy and analyze against it (denials, booleans, login contexts,
// context files give the same answers as for the installed policy when the
// target is this host), run a command, refresh, disconnect; a key-only target
// as a plain user; a wrong password.
//   TARGET=root@localhost TARGET_PASS_FILE=/path/0600file [KEY_TARGET=user@host] node test/target-e2e.js
// The password file is read by the test only to hand the password to the
// server; nothing prints it. Without TARGET_PASS_FILE the password part is skipped.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { tempDir } = require('./tmpdirs');
const { installedPolicies } = require('../server/build');

const installed = installedPolicies().find(p => p.active);
if (process.platform !== 'linux' || !installed) { console.log('SKIP: needs Linux running an SELinux policy'); process.exit(0); }
const TARGET = process.env.TARGET || 'root@localhost';
const PASS_FILE = process.env.TARGET_PASS_FILE || null;
const KEY_TARGET = process.env.KEY_TARGET || 'ricardo';

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
const finish = () => { console.log(failures ? `\n${failures} target e2e checks FAILED` : '\nall target e2e checks passed'); process.exit(failures ? 1 : 0); };

// A wrapper around ssh on the server's PATH: proves the askpass helper answers a
// password prompt (and nothing else) before handing over to the real ssh.
const fake = tempDir('selinux-target-fake-');
const logFile = path.join(fake, 'log');
fs.writeFileSync(path.join(fake, 'ssh'), `#!/bin/sh
if [ -n "$SSH_ASKPASS" ]; then
  pw=$("$SSH_ASKPASS" "root@host's password:")
  [ -n "$pw" ] && [ "$SSH_ASKPASS_REQUIRE" = force ] && echo "askpass ok" >> ${logFile}
  [ "$("$SSH_ASKPASS" "Are you sure you want to continue connecting (yes/no)?")" = no ] && echo "noanswer ok" >> ${logFile}
  [ -f "$SELINUX_TARGET_PW_FILE" ] && echo "pwfile exists during connect" >> ${logFile}
fi
echo "args: $*" >> ${logFile}
exec /usr/bin/ssh "$@"
`, { mode: 0o755 });

function start(ws) {
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio'], { env: { ...process.env, PATH: `${fake}:${process.env.PATH}` } });
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let doneIndex;
  const indexed = new Promise(r => (doneIndex = r));
  const changes = [];
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
  conn.onNotification('selinux/targetsChanged', p => changes.push(p));
  for (const n of ['textDocument/publishDiagnostics', 'selinux/build', 'selinux/checks', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged', 'selinux/loginsChanged']) conn.onNotification(n, () => {});
  conn.listen();
  return { proc, conn, changes, init: async () => { await conn.sendRequest('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: {} }); conn.sendNotification('initialized', {}); await indexed; } };
}

(async () => {
  const ws = tempDir('selinux-target-e2e-');
  fs.writeFileSync(path.join(ws, 'readme.txt'), 'empty workspace\n');
  const a = start(ws);
  await a.init();
  const req = (m, p) => a.conn.sendRequest(m, p || {});

  let r = await req('selinux/targets');
  check(r.linux && Array.isArray(r.targets) && !r.targets.length, 'no targets at first');
  check((await req('selinux/targetConnect', { spec: '-oProxyCommand=x' })).error && (await req('selinux/targetConnect', { spec: '' })).error, 'a spec that is not a host is refused');

  // 1. Password login through the askpass helper.
  if (!PASS_FILE) console.log('SKIP password part: no TARGET_PASS_FILE');
  else {
    const password = fs.readFileSync(PASS_FILE, 'utf8').replace(/\r?\n$/, '');
    let t0 = Date.now();
    const bad = await req('selinux/targetConnect', { spec: TARGET, password: `${password}x` });
    check(bad.error && /denied|Could not connect/.test(bad.error) && !bad.error.includes(password), `a wrong password: ${bad.error} (${Date.now() - t0} ms)`);
    r = await req('selinux/targets');
    check(r.targets.length === 1 && r.targets[0].state === 'error', 'the failed target is listed as an error', r.targets);
    t0 = Date.now();
    const c = await req('selinux/targetConnect', { spec: TARGET, password });
    check(!c.error && c.state === 'connected' && c.facts && c.facts.root && c.mirror && c.mirror.name === installed.name, `connected to ${TARGET} as root (${Date.now() - t0} ms): ${c.label}`, c.error || c);
    const f = c.facts || {};
    check(f.policy && f.policy.name === installed.name && f.policy.file === installed.policy && f.mode && f.os && f.os.id && f.policyRpm, `facts: ${f.os && f.os.pretty}, ${f.policyRpm}, ${f.mode}`, f);
    check(Array.isArray(f.modules) && f.modules.length > 100 && f.modules.every(m => m.priority && m.name && m.lang) && Array.isArray(f.permissive) && f.booleans && typeof f.booleans.ssh_sysadm_login === 'boolean' && !c.notes.length,
      `root sees ${f.modules && f.modules.length} modules, ${f.permissive && f.permissive.length} permissive domains, ${f.booleans && Object.keys(f.booleans).length} booleans; no notes`, c.notes);
    const log = fs.readFileSync(logFile, 'utf8');
    check(/askpass ok/.test(log) && /noanswer ok/.test(log) && /pwfile exists during connect/.test(log) && /ControlMaster=yes/.test(log), 'the askpass helper answered the password prompt (and "no" to anything else) for the master connection', log);
    const dir = path.dirname(path.dirname(path.dirname(c.mirror.root)));
    check(!fs.existsSync(path.join(dir, 'pw')) && (fs.statSync(dir).mode & 0o077) === 0 && fs.existsSync(c.mirror.policy) && fs.existsSync(path.join(c.mirror.root, installed.name, 'contexts', 'files', 'file_contexts')) && fs.existsSync(path.join(c.mirror.root, installed.name, 'seusers')),
      'the password file is gone after the connect; the private directory holds the mirrored policy, file_contexts and seusers', { dir, mode: (fs.statSync(dir).mode & 0o777).toString(8) });
    check(a.changes.length >= 2 && a.changes[a.changes.length - 1].targets[0].state === 'connected', 'selinux/targetsChanged notified', a.changes.map(x => x.targets.map(t => t.state)));
    const id = `target:${c.id}`;
    const pols = (await req('selinux/denialPolicies')).policies;
    const tp = pols.find(p => p.id === id);
    check(tp && /^Running on root@/.test(tp.label) && tp.label.includes(installed.name) && !tp.active && !tp.build, `the target's policy is listed: ${tp && tp.label}`, pols);

    // Same host, same policy: the answers must match the installed policy's.
    const LOG = [
      'type=AVC msg=audit(1700000000.001:1): avc:  denied  { read } for  pid=1 comm="sshd" name="passwd" dev="dm-0" ino=1 scontext=system_u:system_r:sshd_t:s0-s0:c0.c1023 tcontext=system_u:object_r:passwd_file_t:s0 tclass=file permissive=0',
      'type=AVC msg=audit(1700000000.002:2): avc:  denied  { write } for  pid=2 comm="httpd" name="shadow" dev="dm-0" ino=2 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0',
      'type=AVC msg=audit(1700000000.003:3): avc:  denied  { write } for  pid=3 comm="httpd" path="/etc/hosts" dev="dm-0" ino=3 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:tmp_t:s0 tclass=file permissive=0',
    ].join('\n');
    const d1 = await req('selinux/analyzeDenials', { text: LOG, against: id });
    const d0 = await req('selinux/analyzeDenials', { text: LOG, against: `installed:${installed.name}` });
    const v = (d) => (d.groups || []).map(g => `${g.source}>${g.target}:${g.v && g.v.verdict}${g.labels && g.labels.length ? `/${g.labels.map(x => `${x.path}=${x.expected}|${x.current}`).join(',')}` : ''}`);
    check(!d1.error && d1.policy && d1.policy.id === id && v(d1).length === 3 && JSON.stringify(v(d1)) === JSON.stringify(v(d0)) && v(d1).some(x => /^sshd_t>passwd_file_t:allowed/.test(x)) && v(d1).some(x => /tmp_t:label/.test(x)),
      `denials against the target's policy: the same verdicts as against the installed one (${v(d1).join(', ')})`, { target: v(d1), installed: v(d0), error: d1.error });
    const b1 = await req('selinux/booleans', { against: id });
    const b0 = await req('selinux/booleans', { against: `installed:${installed.name}` });
    const diff = (b1.rows || []).filter(x => { const y = (b0.rows || []).find(z => z.name === x.name); return !y || y.running !== x.running || y.compiled !== x.compiled; });
    check(!b1.error && b1.rows && b1.rows.length === b0.rows.length && !diff.length && b1.rows.some(x => x.running != null), `booleans against the target: ${b1.rows && b1.rows.length} rows, running values from getsebool on the target, same as here`, diff.slice(0, 3));
    const l1 = await req('selinux/loginContexts', { against: id });
    const l0 = await req('selinux/loginContexts', { against: `installed:${installed.name}` });
    const probs = (x) => (x.problems || []).map(p => `${p.kind}:${p.login || ''}:${p.source || ''}`).sort();
    check(!l1.error && l1.mappings && l1.mappings.length === l0.mappings.length && JSON.stringify(probs(l1)) === JSON.stringify(probs(l0)) && l1.policy && l1.policy.configDir && l1.policy.configDir.startsWith(c.mirror.root),
      `login contexts against the target: ${l1.mappings && l1.mappings.length} logins from the mirrored seusers, ${probs(l1).length} problems as for the installed policy`, { t: probs(l1).slice(0, 5), i: probs(l0).slice(0, 5), error: l1.error, dir: l1.policy && l1.policy.configDir });
    const x1 = await req('selinux/contextFiles', { against: id });
    const x0 = await req('selinux/contextFiles', { against: `installed:${installed.name}` });
    const xp = (x) => (x.problems || []).map(p => `${p.kind}:${path.basename(p.file || '')}:${p.l || ''}`).sort();
    check(!x1.error && x1.files && x1.files.length === x0.files.length && JSON.stringify(xp(x1)) === JSON.stringify(xp(x0)) && (x1.notes || []).some(n => /copied at the last refresh/.test(n)),
      `context files against the target: ${x1.files && x1.files.length} files, ${xp(x1).length} problems as for the installed policy`, { t: xp(x1).slice(0, 5), i: xp(x0).slice(0, 5), notes: x1.notes, error: x1.error });
    const run = await req('selinux/targetRun', { id: c.id, command: 'id -u; hostname' });
    check(run.code === 0 && run.stdout.split('\n')[0] === '0' && run.stdout.split('\n')[1] === os.hostname(), 'a command runs on the target over the open connection', run);
    const runIn = await req('selinux/targetRun', { id: c.id, command: 'sh -s', input: 'echo got $(cat | wc -l) lines\n' });
    check(runIn.code === 0 && /got 0 lines/.test(runIn.stdout), 'with stdin', runIn);
    t0 = Date.now();
    const rf = await req('selinux/targetRefresh', { id: c.id });
    check(!rf.error && rf.state === 'connected' && rf.facts.modules.length === f.modules.length && fs.existsSync(rf.mirror.policy), `refresh (${Date.now() - t0} ms)`, rf.error);
    const dc = await req('selinux/targetDisconnect', { id: c.id });
    r = await req('selinux/targets');
    check(dc.ok && !r.targets.length && !fs.existsSync(dir) && !(await req('selinux/denialPolicies')).policies.some(p => p.id === id) && (await req('selinux/targetRun', { id: c.id, command: 'true' })).lost,
      'disconnected: forgotten, its directory removed, its policy gone from the list, commands refused');
  }

  // 2. A key-only target as a plain user (host key and key auth from the server's ssh setup).
  const probe = cp.spawnSync('ssh', ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', KEY_TARGET, 'true'], { stdio: 'ignore' });
  if (probe.status !== 0) console.log(`SKIP key part: ${KEY_TARGET} not reachable with a key from here`);
  else {
    const t0 = Date.now();
    const c = await req('selinux/targetConnect', { spec: KEY_TARGET, keyOnly: true });
    const f = c.facts || {};
    check(!c.error && c.state === 'connected' && c.id === KEY_TARGET && f.policy && c.mirror && fs.existsSync(c.mirror.policy), `connected to ${KEY_TARGET} with a key, as ssh's own user (${Date.now() - t0} ms): ${c.label}`, c.error || c);
    if (!f.root) check(f.modules === null && f.permissive === null && f.booleans && c.notes.length === 2 && c.notes.every(n => /not root on the target/.test(n)), 'not root there: the module list and permissive domains are missing and said so; booleans read', c.notes);
    else check(f.modules && f.modules.length > 50, 'root there: modules listed');
    const id = `target:${c.id}`;
    const b = await req('selinux/booleans', { against: id });
    check(!b.error && b.rows.length > 100 && b.rows.filter(x => x.running != null).length > 100 && b.policy.id === id, `booleans against ${KEY_TARGET}: ${b.rows && b.rows.length} rows with running values`, b.error || b.summary);
    const l = await req('selinux/loginContexts', { against: id });
    check(!l.error && l.mappings && l.mappings.length >= 1, `login contexts against ${KEY_TARGET}: ${l.mappings && l.mappings.length} logins`, l.error);
    const d = await req('selinux/analyzeDenials', { text: 'type=AVC msg=audit(1700000000.003:3): avc:  denied  { write } for  pid=3 comm="httpd" path="/etc/hosts" dev="dm-0" ino=3 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:tmp_t:s0 tclass=file permissive=0', against: id });
    const g = d.groups && d.groups[0];
    check(!d.error && g && g.v && g.v.verdict === 'label' && g.labels && g.labels.some(x => x.path === '/etc/hosts' && x.current === 'net_conf_t'), `a label verdict with the current label read on ${KEY_TARGET} (stat over ssh)`, d.error || g);
    await req('selinux/targetDisconnect', { id: c.id });
  }
  a.proc.kill();
  finish();
})().catch((e) => { console.error(e); process.exit(1); });
