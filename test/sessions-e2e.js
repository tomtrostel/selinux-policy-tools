// Session starts over LSP on a Linux host: logins that get a valid context and
// then bounce. The running policy's sessions all start; then on a copy of a
// tree (default: CLIP for RHEL 9) a module gives staff_r a domain sshd may
// switch to but that lacks what a session needs (the shell as entrypoint, its
// libraries, sshd's descriptors, the pty): each is reported on the seusers
// line, the fix comes from the tree's own interfaces, applying it and
// rebuilding clears it.
//   node test/sessions-e2e.js [tree-dir]
// Needs Linux running the targeted policy with python3-setools; the tree part
// also the build toolchain. Skips otherwise.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { installedPolicies, detectToolchain } = require('../server/build');
const { clipArgs } = require('./clip-args');

const installed = installedPolicies().find(p => p.active);
if (process.platform !== 'linux' || !installed || installed.name !== 'targeted') { console.log('SKIP: needs Linux running the targeted policy'); process.exit(0); }
const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
const sleep = ms => new Promise(r => setTimeout(r, ms));
const until = async (cond, ms = 20000) => { for (const end = Date.now() + ms; !cond() && Date.now() < end;) await sleep(200); return cond(); };

function start(ws, initOptions = {}) {
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let doneIndex;
  const indexed = new Promise(r => (doneIndex = r));
  const diags = {};
  const s = { proc, conn, diags };
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
  conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
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
  // 1. The running targeted policy: every session that gets a context starts.
  const ws0 = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-sessions-e2e-'));
  fs.writeFileSync(path.join(ws0, 'readme.txt'), 'empty workspace\n');
  const a = start(ws0);
  await a.init();
  let t0 = Date.now();
  const run = await a.conn.sendRequest('selinux/loginContexts', {});
  const bad0 = (run.problems || []).filter(p => /^session-/.test(p.kind) && p.severity !== 'info');
  check(!run.error && (run.sessions || []).length > 5 && !bad0.length, `running ${installed.name}: ${(run.sessions || []).length} session starts checked, none fails (${Date.now() - t0} ms)`, run.error || bad0);
  const sshS = (run.sessions || []).find(s => s.source === 'sshd_t' && s.login === '__default__');
  check(sshS && sshS.programType === 'shell_exec_t' && sshS.checks.some(c => c.id === 'tty' && c.ok) && sshS.checks.some(c => c.id === 'libs' && c.ok && /lib/.test(c.text)), `__default__ over ssh: ${sshS && sshS.checks.map(c => c.id).join(', ')}`, sshS);
  a.proc.kill();

  // 2. A tree with a domain that can't hold a session.
  const tc = detectToolchain(null);
  if (!tc.ok || !fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP tree part: ${tc.reason || `no tree at ${src}`}`); return finish(); }
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-sessions-e2e-tree-'));
  cp.execFileSync('cp', ['-a', src + '/.', ws]);
  fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
  const args = clipArgs(src);
  const type = (args.find(x => /^TYPE=/.test(x)) || 'TYPE=mcs').slice(5);
  const app = path.join(ws, 'config', `appconfig-${type}`);
  const seusersPath = path.join(app, 'seusers');
  const seUri = URI.file(seusersPath).toString();
  // brk_t: staff_r may have it and sshd may switch to it, nothing else.
  const te = path.join(ws, 'policy/modules/roles/brk.te');
  fs.writeFileSync(te, [
    'policy_module(brk, 1.0)', '',
    'gen_require(`', '\ttype sshd_t;', '\trole staff_r;', "')", '',
    'type brk_t;', 'domain_type(brk_t)', 'domain_user_exemption_target(brk_t)', 'role staff_r types brk_t;', '',
    '########################################', '#', '# brk local policy', '#', '',
    'allow sshd_t brk_t:process transition;', '',
  ].join('\n'));
  fs.writeFileSync(te.replace(/\.te$/, '.if'), '## <summary>A domain that cannot hold a session (test).</summary>\n');
  fs.writeFileSync(te.replace(/\.te$/, '.fc'), '');
  const mc = path.join(ws, 'policy/modules.conf');
  fs.appendFileSync(mc, '\n# Layer: roles\nbrk = module\n');
  // A login mapped to staff_u whose ssh entry puts it in brk_t first.
  fs.appendFileSync(seusersPath, 'brk:staff_u:s0\n');
  const brkL = fs.readFileSync(seusersPath, 'utf8').replace(/\n$/, '').split('\n').length - 1;
  const own = path.join(app, 'staff_u_default_contexts');
  const ownOrig = fs.existsSync(own) ? fs.readFileSync(own, 'utf8') : '';
  fs.writeFileSync(own, `system_r:sshd_t:s0\tstaff_r:brk_t:s0 staff_r:staff_t:s0\n${ownOrig.split('\n').filter(l => !/^system_r:sshd_t:/.test(l)).join('\n')}`);

  const b = start(ws, { build: { tree: { makeArgs: args } } });
  await b.init();
  t0 = Date.now();
  let res = await b.conn.sendRequest('selinux/build', { uri: URI.file(ws).toString() });
  check(res && res.ok, `tree build with brk (${((Date.now() - t0) / 1000).toFixed(0)} s)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  let rep = await b.conn.sendRequest('selinux/loginContexts', { against: 'build' });
  const brk = (rep.mappings || []).find(m => m.login === 'brk');
  const way = brk && brk.ways.find(w => w.source === 'sshd_t');
  check(way && way.works3 && /:staff_r:brk_t:/.test(way.v3.ctx), `brk gets ${way && way.v3 && way.v3.ctx} over ssh: the context is valid and sshd may switch to it`, way);
  const mine = (rep.problems || []).filter(p => p.login === 'brk' && p.source === 'sshd_t');
  for (const p of mine) console.log(`     ${p.severity} ${p.kind}: ${p.text.slice(0, 220)}`);
  const kinds = new Set(mine.map(p => p.kind));
  check(['session-entry', 'session-fd', 'session-tty'].every(k => kinds.has(k)) && mine.every(p => p.severity === 'error' && p.file === seusersPath && p.l === brkL),
    `but the session can't start: ${[...kinds].join(', ')} — errors on brk's seusers line`, mine.map(p => p.kind));
  await until(() => (b.diags[seUri] || []).some(d => d.code === 'session-entry'));
  const d = (b.diags[seUri] || []).find(x => x.code === 'session-entry' && x.range.start.line === brkL);
  check(d && d.range.start.line === brkL && d.source === 'selinux-logins' && /brk_t may not be entered by running/.test(d.message) && (d.relatedInformation || []).some(r => /staff_u_default_contexts/.test(r.location.uri)),
    'as a diagnostic on that line, with the contexts line related', (b.diags[seUri] || []).map(x => ({ code: x.code, line: x.range.start.line, rel: (x.relatedInformation || []).map(r => r.location.uri.split('/').pop()) })));

  // 3. The fix from the tree's own interfaces: entrypoint on the shell.
  const entry = mine.find(p => p.kind === 'session-entry');
  t0 = Date.now();
  const fx = await b.conn.sendRequest('selinux/sessionFix', { against: 'build', need: entry.need, attrs: entry.attrs || [] });
  const list = (fx.suggest && fx.suggest.list) || [];
  console.log(`     suggestions for ${entry.need.target} entrypoint: ${list.map(x => x.call).join(', ')} (${Date.now() - t0} ms)`);
  check(!fx.error && list.length && list[0].covers && /\(brk_t\)$/.test(list[0].call) && fx.rule === `allow brk_t ${entry.need.target}:file { entrypoint };`,
    `the narrowest interface of the tree that grants it: ${list[0] && list[0].call}`, fx);
  const plan = await b.conn.sendRequest('selinux/denialFix', { domain: 'brk_t', call: list[0].call });
  check(plan && plan.path === te && plan.inserted.some(l => l.includes(list[0].call)), `planned into brk.te: ${plan && plan.inserted.join(' ')}`, plan);
  fs.writeFileSync(plan.path, plan.text);
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: URI.file(te).toString(), type: 2 }] });
  // The other needs the same way: the first full suggestion for each.
  const added = [list[0].call];
  for (const p of mine.filter(x => x.kind !== 'session-entry' && x.need)) {
    const f = await b.conn.sendRequest('selinux/sessionFix', { against: 'build', need: p.need, attrs: p.attrs || [] });
    const best = ((f.suggest && f.suggest.list) || []).find(x => x.covers);
    console.log(`     ${p.kind} ${p.need.target}:${p.need.tclass} { ${p.need.perms.join(' ')} } → ${best ? best.call : (f.suggest && f.suggest.own ? 'own rule' : 'none')}`);
    if (!best || added.includes(best.call) || !/\(brk_t\)$/.test(best.call)) continue;
    const pl = await b.conn.sendRequest('selinux/denialFix', { domain: 'brk_t', call: best.call });
    if (pl && pl.text) { fs.writeFileSync(pl.path, pl.text); added.push(best.call); }
  }
  b.conn.sendNotification('workspace/didChangeWatchedFiles', { changes: [{ uri: URI.file(te).toString(), type: 2 }] });
  await sleep(800);
  t0 = Date.now();
  res = await b.conn.sendRequest('selinux/build', { uri: URI.file(ws).toString() });
  check(res && res.ok, `rebuilt with ${added.join(', ')} (${((Date.now() - t0) / 1000).toFixed(0)} s)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  rep = await b.conn.sendRequest('selinux/loginContexts', { against: 'build' });
  const after = (rep.problems || []).filter(p => p.login === 'brk' && p.source === 'sshd_t');
  for (const p of after) console.log(`     still: ${p.kind}: ${p.text.slice(0, 200)}`);
  check(!after.some(p => p.kind === 'session-entry'), 'the shell now enters brk_t: that problem is gone after the build', after.map(p => p.kind));
  check(after.length < mine.length, `${mine.length - after.length} of ${mine.length} problems fixed with the tree's interfaces`, after.map(p => p.kind));
  await until(() => !(b.diags[seUri] || []).some(x => x.code === 'session-entry'));
  check(!(b.diags[seUri] || []).some(x => x.code === 'session-entry'), 'and its diagnostic is gone');

  // 4. The records a bounce leaves, in the denial assistant against the build.
  const log = [
    'type=AVC msg=audit(1729000000.100:900): avc:  denied  { nnp_transition } for  pid=4242 comm="sshd" scontext=system_u:system_r:sshd_t:s0-s0:c0.c1023 tcontext=staff_u:staff_r:brk_t:s0 tclass=process2 permissive=0',
    'type=SELINUX_ERR msg=audit(1729000000.100:900): op=security_bounded_transition seresult=denied oldcontext=system_u:system_r:sshd_t:s0-s0:c0.c1023 newcontext=staff_u:staff_r:brk_t:s0',
    'type=SYSCALL msg=audit(1729000000.100:900): arch=c000003e syscall=59 success=no exit=-1 pid=4242 comm="sshd" exe="/usr/sbin/sshd"',
    'type=SELINUX_ERR msg=audit(1729000001.100:901): op=security_compute_sid invalid_context="staff_u:staff_r:sysadm_t:s0" scontext=staff_u:staff_r:brk_t:s0 tcontext=system_u:object_r:shell_exec_t:s0 tclass=process',
  ].join('\n');
  const an = await b.conn.sendRequest('selinux/analyzeDenials', { text: log, against: 'build' });
  const gb = (an.groups || []).find(g => g.kind === 'error' && g.v.verdict === 'nnp');
  check(gb && gb.source === 'sshd_t' && gb.target === 'brk_t' && /NoNewPrivileges/.test(gb.v.detail) && gb.v.needed === 'allow sshd_t brk_t:process2 { nnp_transition nosuid_transition };',
    'denials: security_bounded_transition read as a NoNewPrivileges/nosuid refusal with the rule it needs', (an.groups || []).map(g => ({ k: g.kind, v: g.v.verdict, t: g.v.title })));
  check(gb && (gb.suggest || gb.joins), `  with suggestions from the tree: ${gb && gb.suggest ? ((gb.suggest.list || []).map(x => x.call).join(', ') || gb.suggest.note || (gb.suggest.newIface ? `new interface ${gb.suggest.newIface.call}` : 'none')) : 'none'}`, gb && gb.suggest);
  const gn = (an.groups || []).find(g => g.kind === 'deny' && g.tclass === 'process2');
  check(gn && gn.v.verdict === 'missing' && gn.v.notes.some(n => /NoNewPrivileges/.test(n)), 'the nnp_transition AVC of the same event: missing rule, explained', gn && gn.v);
  const gi = (an.groups || []).find(g => g.kind === 'error' && g.v.verdict === 'invalid');
  check(gi && /role staff_r isn't authorized for sysadm_t/.test(gi.v.detail) && gi.v.needed === 'role staff_r types sysadm_t;' && gi.suggest,
    `denials: an invalid computed context says which role to authorize; ${gi && gi.suggest ? ((gi.suggest.list || []).map(x => x.call).join(', ') || gi.suggest.note) : ''}`, gi && { v: gi.v, s: gi.suggest });
  b.proc.kill();
  finish();
})().catch((e) => { console.log(`FAIL ${e.stack}`); process.exit(1); });

function finish() {
  console.log(failures ? `\n${failures} check(s) failed` : '\nall session start e2e checks passed');
  process.exit(failures ? 1 : 0);
}
