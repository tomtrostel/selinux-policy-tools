// Levels and Categories over LSP on a Linux host: who ignores levels and the
// context check against this host's running targeted policy, then on a copy
// of a tree (default: CLIP for RHEL 9) after a build: the same requests, and
// `may ignore levels` / `reaches … except through` checks in selinux.checks.
//   node test/levels-e2e.js [tree-dir]
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

function start(ws, initOptions = {}) {
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let doneIndex;
  const indexed = new Promise(r => (doneIndex = r));
  const diags = {};
  const s = { proc, conn, diags, summary: null };
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
  conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
  conn.onNotification('selinux/checks', x => { s.summary = x; });
  for (const n of ['selinux/build', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged']) conn.onNotification(n, () => {});
  conn.listen();
  s.init = async () => {
    await conn.sendRequest('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: initOptions });
    conn.sendNotification('initialized', {});
    await indexed;
  };
  return s;
}

const C = {
  cross: { source: 'system_u:system_r:container_t:s0:c1,c2', target: 'system_u:object_r:container_file_t:s0:c1,c3', tclass: 'file', perms: 'read open' },
  same: { source: 'system_u:system_r:container_t:s0:c1,c2', target: 'system_u:object_r:container_file_t:s0:c1,c2', tclass: 'file', perms: ['read', 'open'] },
};

(async () => {
  // 1. The running targeted policy.
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-levels-e2e-'));
  fs.writeFileSync(path.join(ws, 'readme.txt'), 'empty workspace\n');
  const a = start(ws);
  await a.init();
  let t0 = Date.now();
  const L = await a.conn.sendRequest('selinux/levels', {});
  const held = (L.groups || []).filter(g => !g.constraints.length).flatMap(g => g.domains);
  const free = (L.groups || []).filter(g => g.constraints.length);
  console.log(`  levels in ${Date.now() - t0} ms: ${L.kind}, ${L.constraints && L.constraints.length} constraints, ${held.length} held, ${free.reduce((n, g) => n + g.domains.length, 0)} not`);
  check(!L.error && L.mls && L.kind === 'mcs' && L.sensitivities === 1 && L.categories === 1024 && L.policy && /targeted/.test(L.policy.label), 'running targeted: an MCS policy with 1024 categories', L.error || { kind: L.kind, policy: L.policy });
  const hasContainers = held.includes('container_t');
  check(held.includes('svirt_t') && (hasContainers || !L.locs) && held.length < 60, `domains held to every level constraint include svirt_t${hasContainers ? ' and container_t' : ''} (${held.length})`, held);
  const big = free[0];
  check(big && big.domains.includes('init_t') && big.via.some(v => /not in mcs_constrained_type/.test(v)) && big.classes.file && big.classes.file.includes('read'),
    `most domains pass them because they aren't in mcs_constrained_type (${big && big.domains.length}: ${big && big.via.join('; ')})`, big && { via: big.via, classes: big.classes });

  if (hasContainers) {
    const x = await a.conn.sendRequest('selinux/contextCheck', C.cross);
    const failing = (x.constraints || []).filter(c => !c.ok);
    check(!x.error && Object.values(x.te).every(p => p.status === 'allowed') && failing.length >= 1 && failing[0].leaves.some(l => l.text === 'h1 dom h2' && !l.ok && l.b === 's0:c1,c3'),
      `container c1,c2 → file c1,c3: type rules allow it, ${failing[0] && failing[0].text} fails`, x);
    const y = await a.conn.sendRequest('selinux/contextCheck', C.same);
    check(!y.error && !(y.constraints || []).some(c => !c.ok) && Object.values(y.te).every(p => p.status === 'allowed'), 'same categories: allowed', y);
    check(x.booleans === 'running', 'the running policy is checked with its current booleans');
  }
  const z = await a.conn.sendRequest('selinux/contextCheck', { source: 'user_u:user_r:user_t:s0', target: 'system_u:object_r:shadow_t:s0', tclass: 'file', perms: 'read' });
  check(!z.error && z.te.read.status === 'missing' && !(z.constraints || []).some(c => !c.ok), 'user_t → shadow_t: no rule allows it, no constraint fails', z);
  const r = await a.conn.sendRequest('selinux/contextCheck', { source: 'user_u:sysadm_r:user_t:s0:c5', target: 'system_u:object_r:etc_t', tclass: 'file', perms: 'read' });
  const kinds = (r.problems || []).map(p => p.kind);
  check(kinds.includes('role') && kinds.includes('range') && kinds.includes('level'), `invalid source context explained: ${(r.problems || []).map(p => p.text).join(' | ')}`, r);
  const e1 = await a.conn.sendRequest('selinux/contextCheck', { source: 'a:b', target: 'c:d:e', tclass: 'file', perms: 'read' });
  const e2 = await a.conn.sendRequest('selinux/contextCheck', { source: 'u:r:nosuch_t:s0', target: 'system_u:object_r:etc_t:s0', tclass: 'file', perms: 'fly' });
  const e3 = await a.conn.sendRequest('selinux/contextCheck', { source: 'user_u:user_r:user_t:s9', target: 'system_u:object_r:etc_t:s0', tclass: 'file', perms: 'read' });
  check(/user:role:type/.test(e1.error) && /fly is not a permission of file/.test(e2.error) && /Not a valid level/.test(e3.error), `errors: ${e1.error} | ${e2.error} | ${e3.error}`);
  a.proc.kill();

  // 2. A tree build.
  const tc = detectToolchain(null);
  if (!tc.ok || !fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP tree part: ${tc.ok ? `no tree at ${src}` : tc.reason}`); return finish(); }
  const tw = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-levels-tree-'));
  cp.execFileSync('cp', ['-a', src + '/.', tw]);
  fs.rmSync(path.join(tw, 'tmp'), { recursive: true, force: true });
  const CHECKS = path.join(tw, 'selinux.checks');
  fs.writeFileSync(CHECKS, '# levels\n');
  const b = start(tw, { build: { tree: { makeArgs: clipArgs(src) } } });
  await b.init();
  t0 = Date.now();
  const res = await b.conn.sendRequest('selinux/build', { uri: URI.file(tw).toString() });
  check(res && res.ok, `tree build (${Date.now() - t0} ms)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  const TL = await b.conn.sendRequest('selinux/levels', { against: 'build' });
  const theld = (TL.groups || []).filter(g => !g.constraints.length).flatMap(g => g.domains);
  const tfree = (TL.groups || []).filter(g => g.constraints.length);
  console.log(`  build: ${TL.kind}, ${TL.constraints && TL.constraints.length} constraints; held: ${theld.join(' ') || '(none)'}; groups ${tfree.map(g => `${g.domains.length} via ${g.via.join('; ')}`).join(' | ')}`);
  check(!TL.error && TL.policy && TL.policy.build && TL.kind === 'mcs' && tfree.length && tfree[0].domains.includes('init_t'), 'build: MCS, init_t passes level constraints whatever the levels', TL.error || TL.policy);
  // CLIP RHEL 9 (refpolicy 2.2024): t1 != mcs_constrained_type; CLIP RHEL 8: MLS-style exemption attributes (t1 == mlsfileread, …).
  const viaAttrs = tfree.flatMap(g => g.via.flatMap(v => (v.match(/[A-Za-z_]\w*/g) || []).filter(n => n !== 'in' && n !== 'not')));
  check(viaAttrs.length && viaAttrs.every(n => TL.locs && TL.locs[n] && /(mcs|mls)\.te$/.test(TL.locs[n].p)), `the deciding attributes are located in mcs.te / mls.te (${[...new Set(viaAttrs)].slice(0, 6).join(', ')})`, TL.locs);
  // Checks: a domain held to them (if the build has one), init_t (fails), an unknown class, only (fails), a syntax error, except through.
  const heldOne = theld[0];
  const reachText = 'never staff_t reaches sysadm_t';
  const lines = [
    '# levels',
    'never init_t may ignore levels',                                  // 1 fails
    'never init_t may ignore levels on nosuch_class',                 // 2 error
    'only init_t may ignore levels',                                   // 3 fails (every other domain not held to them)
    'require init_t may ignore levels',                                // 4 syntax error
    heldOne ? `never ${heldOne} may ignore levels` : '# no held domain',  // 5 holds
    reachText,                                                         // 6 either; gives the path for 7
  ];
  fs.writeFileSync(CHECKS, lines.join('\n') + '\n');
  const cu = URI.file(CHECKS).toString();
  b.conn.sendNotification('textDocument/didOpen', { textDocument: { uri: cu, languageId: 'selinux-checks', version: 1, text: lines.join('\n') + '\n' } });
  b.conn.sendNotification('textDocument/didSave', { textDocument: { uri: cu } });
  const wait = async (pred) => { for (let i = 0; i < 300 && !pred(); i++) await sleep(200); };
  await wait(() => b.summary && b.summary.total === (heldOne ? 5 : 4) && !b.summary.note);
  let lenses = await b.conn.sendRequest('textDocument/codeLens', { textDocument: { uri: cu } });
  const lens = (l) => (lenses.find(x => x.range.start.line === l) || { command: { title: '' } }).command.title;
  const D = (l) => (b.diags[cu] || []).find(d => d.range.start.line === l);
  check(lens(1) === '✗ 1 domain ignores levels' && D(1) && /^init_t passes level constraints whatever the levels \((not in mcs_constrained_type|in mls\w+(; in mls\w+)*)\), on file\b/.test(D(1).message) && (D(1).relatedInformation || []).some(x => /init\.te$/.test(URI.parse(x.location.uri).fsPath)),
    `never init_t may ignore levels: "${lens(1)}" — ${D(1) && D(1).message.slice(0, 140)}`, D(1));
  check(/no level constraint covers nosuch_class/.test(lens(2)), `unknown class: "${lens(2)}"`);
  check(/^✗ \d+ domains ignore levels$/.test(lens(3)) && D(3) && /other domains \(/.test(D(3).message), `only init_t: "${lens(3)}"`);
  check(D(4) && /'may ignore levels' works with 'only' and 'never'/.test(D(4).message), `require: ${D(4) && D(4).message}`);
  check(!heldOne || lens(5) === '✓ holds', `never ${heldOne || '(none)'} may ignore levels: "${lens(5)}"`);
  // except through: if staff_t reaches sysadm_t, the same check through the path's first step reroutes or holds.
  const d6 = D(6);
  if (d6) {
    const m = /: staff_t → (\w+)/.exec(d6.message);
    const via = m && m[1];
    const more = [...lines, `${reachText} except through ${via}`];
    b.conn.sendNotification('textDocument/didChange', { textDocument: { uri: cu, version: 2 }, contentChanges: [{ text: more.join('\n') + '\n' }] });
    await wait(() => b.summary && b.summary.total === (heldOne ? 6 : 5) && !b.summary.note);
    await sleep(500);
    lenses = await b.conn.sendRequest('textDocument/codeLens', { textDocument: { uri: cu } });
    const d7 = D(7);
    check(via && via !== 'sysadm_t' && (lens(7) === '✓ holds' || (d7 && /without going through/.test(d7.message) && !new RegExp(`staff_t → ${via}\\b`).test(d7.message))),
      `except through ${via}: "${lens(7)}"${d7 ? ` — ${d7.message}` : ''} (was: ${d6.message})`);
  } else console.log('  (staff_t can\'t reach sysadm_t here; except through not exercised)');
  const comp = await b.conn.sendRequest('textDocument/completion', { textDocument: { uri: cu }, position: { line: 1, character: 'never init_t may '.length } });
  check(comp.items.some(i => i.label === 'ignore levels'), 'completion offers "ignore levels" after may');
  // Context check against the build: the allowing rule traced to its source.
  const cc = await b.conn.sendRequest('selinux/contextCheck', { against: 'build', source: 'system_u:system_r:syslogd_t:s0', target: 'system_u:object_r:var_log_t:s0', tclass: 'file', perms: 'append' });
  const rule = cc.te && cc.te.append && cc.te.append.rules && cc.te.append.rules[0];
  check(!cc.error && cc.te.append.status === 'allowed' && rule && rule.origin && /\.te$/.test(rule.origin.path), `build: syslogd_t appends var_log_t, rule from ${rule && rule.origin && `${path.basename(rule.origin.path)}:${rule.origin.line + 1}`}`, cc);
  b.proc.kill();
  fs.rmSync(tw, { recursive: true, force: true });
  finish();
})().catch((e) => { console.error(e); process.exit(1); });

function finish() {
  console.log(failures ? `\n${failures} check(s) failed` : '\nall levels e2e checks passed');
  process.exit(failures ? 1 : 0);
}
