// Restricted logins over LSP on a Linux host: a restricted user on a copy of a
// tree (default: CLIP for RHEL 9) whose login works, then edits that give it
// more domains. What the checks say after each build: which login a build
// breaks or fixes (compared with the build before), the source line that
// causes a problem, and what a host would log (an AVC, nothing because of a
// dontaudit rule, SELINUX_ERR, or only the login program's log).
//   node test/restricted-e2e.js [tree-dir]
// Needs Linux with python3-setools and the build toolchain. Skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const { tempDir } = require('./tmpdirs');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain } = require('../server/build');
const { clipArgs } = require('./clip-args');

const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
const sleep = ms => new Promise(r => setTimeout(r, ms));
const until = async (cond, ms = 30000) => { for (const end = Date.now() + ms; !cond() && Date.now() < end;) await sleep(200); return cond(); };

const tc = detectToolchain(null);
if (process.platform !== 'linux' || !tc.ok || !fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP: ${tc.reason || `needs Linux and a tree at ${src}`}`); process.exit(0); }

function start(ws, initOptions = {}) {
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let doneIndex;
  const indexed = new Promise(r => (doneIndex = r));
  const s = { proc, conn, diags: {}, changes: [] };
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
  conn.onNotification('textDocument/publishDiagnostics', p => { s.diags[p.uri] = p.diagnostics; });
  conn.onNotification('selinux/loginsChanged', p => s.changes.push(p));
  for (const n of ['selinux/build', 'selinux/checks', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged']) conn.onNotification(n, () => {});
  conn.listen();
  s.init = async () => {
    await conn.sendRequest('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: initOptions });
    conn.sendNotification('initialized', {});
    await indexed;
  };
  return s;
}

(async () => {
  const ws = tempDir('selinux-restricted-e2e-');
  cp.execFileSync('cp', ['-a', src + '/.', ws]);
  fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
  const args = clipArgs(src);
  const type = (args.find(x => /^TYPE=/.test(x)) || 'TYPE=mcs').slice(5);
  const app = path.join(ws, 'config', `appconfig-${type}`);

  // A restricted user rt_u (role rt_r, domain rt_t) and a login rtuser mapped to it, by ssh and console.
  const te = path.join(ws, 'policy/modules/roles/rt.te');
  const head = ['policy_module(rt, 1.0)', '', 'role rt_r;', 'userdom_restricted_user_template(rt)', '',
    '########################################', '#', '# rt local policy', '#', ''];
  fs.writeFileSync(te, head.join('\n'));
  fs.writeFileSync(te.replace(/\.te$/, '.if'), '## <summary>A restricted test user.</summary>\n');
  fs.writeFileSync(te.replace(/\.te$/, '.fc'), '');
  fs.appendFileSync(path.join(ws, 'policy/modules.conf'), '\n# Layer: roles\nrt = module\n');
  fs.appendFileSync(path.join(ws, 'policy/users'), '\ngen_user(rt_u, rt, rt_r, s0, s0)\n');
  const kte = path.join(ws, 'policy/modules/kernel/kernel.te');
  fs.writeFileSync(kte, fs.readFileSync(kte, 'utf8').replace(/^role user_r;$/m, 'role user_r;\nrole rt_r;'));
  const seusers = path.join(app, 'seusers');
  fs.appendFileSync(seusers, 'rtuser:rt_u:s0\n');
  const rtL = fs.readFileSync(seusers, 'utf8').replace(/\n$/, '').split('\n').length - 1;
  fs.writeFileSync(path.join(app, 'rt_u_default_contexts'), 'system_r:local_login_t:s0\trt_r:rt_t:s0\nsystem_r:sshd_t:s0\trt_r:rt_t:s0\n');
  const teUri = URI.file(te).toString(), seUri = URI.file(seusers).toString();

  const b = start(ws, { build: { tree: { makeArgs: args } } });
  await b.init();
  const buildIt = async (what) => {
    const t0 = Date.now();
    const n = b.changes.length;
    const res = await b.conn.sendRequest('selinux/build', { uri: URI.file(ws).toString() });
    check(res && res.ok, `build: ${what} (${((Date.now() - t0) / 1000).toFixed(0)} s)`, res && res.diagnostics && res.diagnostics.filter(d => d.severity === 'error').slice(0, 3));
    // The login check runs after the build: wait for it (a notification when something changed).
    await sleep(500);
    return n;
  };
  const report = () => b.conn.sendRequest('selinux/loginContexts', { against: 'build' });
  const mine = (rep) => (rep.problems || []).filter(p => p.login === 'rtuser' || p.user === 'rt_u');

  // 1. The restricted user logs in.
  await buildIt('a restricted user rt_u, login rtuser');
  let rep = await report();
  const m = (rep.mappings || []).find(x => x.login === 'rtuser');
  check(m && m.ways.length === 2 && m.ways.every(w => w.works3 && w.works2), `rtuser gets ${m && m.ways.map(w => `${w.source}=${w.v3 && w.v3.ctx}`).join(', ')}`, m);
  const ses = (rep.sessions || []).filter(s => s.login === 'rtuser');
  check(ses.length === 2 && ses.every(s => s.checks.every(c => c.ok !== false)), `and its sessions start (${ses.map(s => `${s.way}: ${s.checks.map(c => c.id).join(' ')}`).join('; ')})`, ses);
  check(!mine(rep).some(p => p.severity === 'error'), 'no login errors for rtuser', mine(rep));

  // 2. A new domain rt_t may run (a wrapper-like program), without authorizing the role for it:
  //    running it fails with SELINUX_ERR, no AVC; the type_transition's line is named as the cause.
  const added = ['type rtw_t;', 'type rtw_exec_t;', 'domain_type(rtw_t)', 'domain_entry_file(rtw_t, rtw_exec_t)', 'userdom_use_user_terminals(rtw_t)', '', '# rt_t runs the wrapper.', 'domtrans_pattern(rt_t, rtw_exec_t, rtw_t)', ''];
  fs.writeFileSync(te, head.concat(added).join('\n'));
  const dtL = head.length + added.indexOf('domtrans_pattern(rt_t, rtw_exec_t, rtw_t)');
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: teUri, type: 2 }] });
  await sleep(500);
  await buildIt('rt_t may run rtw_exec_t into rtw_t; rt_r not authorized for rtw_t');
  rep = await report();
  const inv = mine(rep).find(p => p.kind === 'session-invalid');
  check(inv && /rt_t running rtw_exec_t → rtw_t \(role rt_r isn't authorized for rtw_t\)/.test(inv.text), 'rt_u\'s sessions can\'t run rtw_exec_t: invalid computed context', inv || mine(rep));
  check(inv && inv.trace && inv.trace.record === 'selinux_err' && /ausearch -m SELINUX_ERR/.test(inv.trace.text), 'a host logs no AVC for it, only SELINUX_ERR', inv && inv.trace);
  const cause = inv && (inv.causes || [])[0];
  check(cause && cause.origin && cause.origin.path === te && cause.origin.line === dtL && /type_transition rt_t rtw_exec_t:process rtw_t/.test(cause.origin.text || ''), `caused by rt.te:${dtL + 1} (${cause && cause.origin && cause.origin.text})`, cause);
  await until(() => (b.diags[teUri] || []).some(d => d.code === 'session-invalid-cause'));
  const cd = (b.diags[teUri] || []).find(d => d.code === 'session-invalid-cause');
  check(cd && cd.range.start.line === dtL && /This line makes rt_t run rtw_exec_t in rtw_t, but role rt_r isn't authorized for rtw_t/.test(cd.message) && (cd.relatedInformation || []).some(r => r.location.uri === seUri),
    'a diagnostic on that line in rt.te, pointing at the login it affects', (b.diags[teUri] || []).map(d => ({ code: d.code, l: d.range.start.line, m: d.message.slice(0, 200), rel: d.relatedInformation })));
  // The fix from the tree: a role-authorizing call (or the role statement).
  const an = await b.conn.sendRequest('selinux/analyzeDenials', { against: 'build', text: 'type=SELINUX_ERR msg=audit(1729000001.100:901): op=security_compute_sid invalid_context="rt_u:rt_r:rtw_t:s0" scontext=rt_u:rt_r:rt_t:s0 tcontext=system_u:object_r:rtw_exec_t:s0 tclass=process' });
  const gi = (an.groups || []).find(g => g.v.verdict === 'invalid');
  check(gi && gi.v.needed === 'role rt_r types rtw_t;', 'the denial assistant reads the SELINUX_ERR: role rt_r types rtw_t; is needed', gi && gi.v);
  fs.writeFileSync(te, head.concat(added, ['role rt_r types rtw_t;', '']).join('\n'));
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: teUri, type: 2 }] });
  await sleep(500);
  await buildIt('with role rt_r types rtw_t');
  rep = await report();
  check(!mine(rep).some(p => p.kind === 'session-invalid'), 'authorized: the problem is gone', mine(rep).map(p => p.kind));
  await until(() => !(b.diags[teUri] || []).some(d => d.code === 'session-invalid-cause'));
  check(!(b.diags[teUri] || []).some(d => d.code === 'session-invalid-cause'), 'and so is the diagnostic on rt.te');

  // 3. A build that breaks the login: rt as a base user (no terminal or login rules) — a new error,
  //    with the files changed since the previous build, and a notification.
  const n0 = b.changes.length;
  fs.writeFileSync(te, head.map(l => l.replace('userdom_restricted_user_template(rt)', 'userdom_base_user_template(rt)')).concat(added, ['role rt_r types rtw_t;', '']).join('\n'));
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: teUri, type: 2 }] });
  await sleep(500);
  await buildIt('rt as a base user template');
  await until(() => b.changes.length > n0);
  const ch = b.changes[b.changes.length - 1] || {};
  const broke = (ch.broken || []).filter(x => x.login === 'rtuser' && x.severity === 'error');
  check(broke.length && (ch.changed || []).includes('policy/modules/roles/rt.te'), `notification: this build breaks ${broke.map(x => `${x.login} by ${x.way} (${x.kind})`).join(', ')}; changed: ${(ch.changed || []).join(', ')}`, ch);
  rep = await report();
  const errs = mine(rep).filter(p => p.severity === 'error');
  for (const p of errs) console.log(`     ${p.kind}${p.isNew ? ' (new)' : ''} [${p.trace ? p.trace.record : '-'}] ${p.text.slice(0, 220)}`);
  check(errs.length && errs.every(p => p.isNew && (p.since || []).includes('policy/modules/roles/rt.te')), 'the errors are marked new with this build, with rt.te as the change', errs.map(p => ({ k: p.kind, isNew: p.isNew, since: p.since })));
  check(errs.every(p => p.trace && ['avc', 'none', 'log', 'selinux_err'].includes(p.trace.record)), `each says what a host logs: ${[...new Set(errs.map(p => p.trace && p.trace.record))].join(', ')}`, errs.map(p => p.trace));
  const quiet = errs.filter(p => p.trace && p.trace.record === 'none');
  check(quiet.every(p => (p.trace.hidden || []).length && p.trace.hidden.every(r => r.rt === 'dontaudit')), `refusals no AVC shows name their dontaudit rules (${quiet.length}${quiet.length ? `: ${quiet[0].trace.hidden.map(r => `${r.s} ${r.t}:${r.c}`).join(', ')}` : ''})`, quiet.map(p => p.trace));
  await until(() => (b.diags[seUri] || []).some(d => d.range.start.line === rtL && d.severity === 1 && /^New with this build/.test(d.message)));
  check((b.diags[seUri] || []).some(d => d.range.start.line === rtL && d.severity === 1 && /^New with this build \(changed: [^)]*rt\.te/.test(d.message)), 'the diagnostic on rtuser\'s seusers line says so', (b.diags[seUri] || []).map(d => d.message.slice(0, 120)));

  // 4. Back to the restricted template: the notification says the login works again.
  const n1 = b.changes.length;
  fs.writeFileSync(te, head.concat(added, ['role rt_r types rtw_t;', '']).join('\n'));
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: teUri, type: 2 }] });
  await sleep(500);
  await buildIt('back to the restricted template');
  await until(() => b.changes.length > n1);
  const ch2 = b.changes[b.changes.length - 1] || {};
  check((ch2.fixed || []).some(x => x.login === 'rtuser' && x.severity === 'error') && !(ch2.broken || []).some(x => x.login === 'rtuser' && x.severity === 'error'), `notification: fixed ${(ch2.fixed || []).length} rtuser problem(s)`, ch2);

  // 5. What the restricted user runs: rtw_t (now authorized) has no rules for the terminal it inherits,
  //    so running it over ssh gives it /dev/null instead — a warning for a restricted user, fixed from the tree.
  rep = await report();
  const runRt = (rep.runs || []).find(x => x.user === 'rt_u');
  check(runRt && runRt.restricted && runRt.checked > 0, `rt_u counts as restricted (${runRt && runRt.reached} domains reached, ${runRt && runRt.checked} programs checked)`, runRt);
  const lost = mine(rep).find(p => p.kind === 'run-terminal' && p.domain === 'rtw_t' && p.need && p.need.tclass === 'fd' && p.need.target === 'sshd_t');
  check(lost && lost.severity === 'warning' && /rtw_t, which rt_t runs through rtw_exec_t, may not use sshd_t's descriptors/.test(lost.text) && lost.trace && lost.need.source === 'rtw_t',
    `a wrapper without the terminal: ${lost && lost.text.slice(0, 160)} [${lost && lost.trace.record}]`, mine(rep).map(p => `${p.kind}: ${p.text.slice(0, 120)}`));
  const fxl = lost ? await b.conn.sendRequest('selinux/sessionFix', { against: 'build', need: lost.need, attrs: [] }) : {};
  const best = ((fxl.suggest && fxl.suggest.list) || []).find(x => x.covers);
  check(best && /\(rtw_t\)$/.test(best.call), `fix from the tree: ${best && best.call}`, fxl);
  if (best) {
    const plan = await b.conn.sendRequest('selinux/denialFix', { domain: 'rtw_t', call: best.call });
    check(plan && plan.path === te, `planned into rt.te: ${plan && (plan.inserted || []).join(' ')}`, plan);
    if (plan && plan.text) fs.writeFileSync(te, plan.text);
    b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: teUri, type: 2 }] });
    await sleep(500);
    await buildIt(`with ${best.call}`);
    rep = await report();
    check(!mine(rep).some(p => p.kind === 'run-terminal' && p.domain === 'rtw_t' && p.need && p.need.target === 'sshd_t' && p.need.tclass === 'fd'), 'rtw_t keeps the terminal now', mine(rep).map(p => p.kind));
  }

  // 6. A forced command (selinux.logins.sessions): the session is /usr/bin/rtw, labeled rtw_exec_t. Without
  //    the role for rtw_t the computed context is invalid, so every ssh login of rtuser ends at once.
  fs.writeFileSync(te.replace(/\.te$/, '.fc'), '/usr/bin/rtw\t--\tgen_context(system_u:object_r:rtw_exec_t,s0)\n');
  fs.writeFileSync(te, fs.readFileSync(te, 'utf8').replace(/^role rt_r types rtw_t;\n/m, ''));
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: teUri, type: 2 }, { uri: URI.file(te.replace(/\.te$/, '.fc')).toString(), type: 2 }] });
  b.conn.sendNotification('workspace/didChangeConfiguration', { settings: { selinux: { logins: { sessions: { rtuser: { command: '/usr/bin/rtw' } } } } } });
  await sleep(800);
  await buildIt('rtuser forced to run /usr/bin/rtw; role rt_r types rtw_t removed');
  rep = await report();
  const cmd = mine(rep).find(p => p.kind === 'session-command' && p.source === 'sshd_t');
  check(cmd && cmd.severity === 'error' && /rtuser \(rt_u\) can't use ssh: the session runs \/usr\/bin\/rtw \(rtw_exec_t\) and that program would run in rtw_t, but the computed context rt_u:rt_r:rtw_t is invalid: role rt_r isn't authorized for rtw_t/.test(cmd.text)
    && cmd.trace.record === 'selinux_err' && cmd.roleFix && cmd.roleFix.role === 'rt_r' && cmd.roleFix.type === 'rtw_t',
  'the forced command can\'t start: error on rtuser, SELINUX_ERR only, the role to authorize', cmd || mine(rep).map(p => `${p.kind}: ${p.text.slice(0, 160)}`));
  const sesCmd = (rep.sessions || []).find(s => s.login === 'rtuser' && s.source === 'sshd_t');
  check(sesCmd && sesCmd.checks.some(c => c.id === 'command' && c.ok === false), 'the ssh session lists the command check as failing', sesCmd && sesCmd.checks);
  check(!mine(rep).some(p => p.kind === 'session-command' && p.source === 'local_login_t'), 'console logins don\'t run the forced command (sshd only)');
  const fr = cmd ? await b.conn.sendRequest('selinux/sessionFix', { against: 'build', need: null, role: cmd.roleFix }) : {};
  check(fr.rule === 'role rt_r types rtw_t;' && fr.suggest && fr.suggest.roleCalls, `role fix: ${fr.rule}${fr.suggest && fr.suggest.list.length ? ` or ${fr.suggest.list.map(x => x.call).join(', ')}` : ''}`, fr);
  const rplan = await b.conn.sendRequest('selinux/denialFix', { domain: cmd ? cmd.roleFix.domain : 'rt_t', rule: fr.rule });
  check(rplan && rplan.path === te && (rplan.inserted || []).includes('role rt_r types rtw_t;'), 'Add… writes the role statement into rt.te', rplan);
  if (rplan && rplan.text) fs.writeFileSync(te, rplan.text);
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: teUri, type: 2 }] });
  await sleep(500);
  const n2 = b.changes.length;
  await buildIt('with the role authorized again');
  rep = await report();
  check(!mine(rep).some(p => p.kind === 'session-command'), 'the forced command starts: the error is gone', mine(rep).filter(p => /command/.test(p.kind)));
  await until(() => b.changes.length > n2);
  check(b.changes.slice(n2).some(c => (c.fixed || []).some(x => x.kind === 'session-command')), 'and the notification says the login works again');

  b.proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  console.log(failures ? `\n${failures} check(s) failed` : '\nall restricted login e2e checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.log(`FAIL ${e.stack}`); process.exit(1); });
