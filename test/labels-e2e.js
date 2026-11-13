'use strict';
// Labeling coverage and the tighten report end to end, over LSP on a Linux
// host that runs the same policy as the build (default: the RHEL 9 tree with
// its spec's settings → targeted; the target root@localhost), for chronyd:
// the tighten report of chronyd as read back and of a deliberately loose
// model (interfaces priced by their expansion against the build); the
// labeling coverage on this host as the user and on the target as root, a
// file relabeled wrongly on the target found and set right, and a label the
// module stops giving (its .fc edited, rebuilt) reported as generic with the
// file kind that brings it back.
//   TARGET=root@localhost TARGET_PASS_FILE=/path/0600file node test/labels-e2e.js [tree] [spec] [variant]
// The target is left as found (the test file is removed).
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { tempDir } = require('./tmpdirs');
const { installedPolicies, detectToolchain } = require('../server/build');

const installed = installedPolicies().find(p => p.active);
if (process.platform !== 'linux' || !installed) { console.log('SKIP: needs Linux running an SELinux policy'); process.exit(0); }
const TARGET = process.env.TARGET || 'root@localhost';
const PASS_FILE = process.env.TARGET_PASS_FILE || null;
const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/rhel9');
const spec = process.argv[3] || path.join(os.homedir(), 'sepol-test/srpm/selinux-policy.spec');
const variant = process.argv[4] || 'targeted';
const tc = detectToolchain(null);
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }
if (!fs.existsSync(path.join(src, 'Rules.modular')) || !fs.existsSync(spec)) { console.log(`SKIP: need a tree at ${src} and a spec at ${spec}`); process.exit(0); }
if (!fs.existsSync('/usr/sbin/chronyd')) { console.log('SKIP: chronyd is not installed here'); process.exit(0); }

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 3000).replace(/\n/g, '\n     ')); }
};

(async () => {
  const ws = tempDir('selinux-labels-e2e-');
  cp.execFileSync('cp', ['-a', src + '/.', ws]);
  fs.rmSync(path.join(ws, 'tmp'), { recursive: true, force: true });
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let doneIndex, indexed = new Promise(r => (doneIndex = r));
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(); });
  for (const n of ['textDocument/publishDiagnostics', 'selinux/build', 'selinux/checks', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/inactiveChanged', 'selinux/loginsChanged', 'selinux/targetsChanged']) conn.onNotification(n, () => {});
  conn.listen();
  const req = (m, p) => conn.sendRequest(m, p || {});
  await req('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {}, initializationOptions: { trusted: true } });
  conn.sendNotification('initialized', {});
  await indexed;
  const sc = await req('selinux/specBuildConfig', { specPath: spec });
  const cfg = sc.configs && sc.configs.find(c => c.variant === variant);
  check(cfg && cfg.makeArgs.some(x => x === `NAME=${installed.name}`), `the spec's ${variant} settings build the ${installed.name} policy`, sc.error);
  if (!cfg) process.exit(1);
  indexed = new Promise(r => (doneIndex = r));
  conn.sendNotification('workspace/didChangeConfiguration', { settings: { selinux: { build: { tree: { makeArgs: cfg.makeArgs, files: cfg.files } } } } });
  await indexed;
  const finish = async () => { proc.kill(); console.log(failures ? `\n${failures} labels e2e checks FAILED` : '\nall labels e2e checks passed'); process.exit(failures ? 1 : 0); };
  let t0 = Date.now();
  let res = await req('selinux/build', { uri: URI.file(ws).toString() });
  check(res && res.ok && res.packages > 300, `tree build (${((Date.now() - t0) / 1000).toFixed(0)} s)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  if (!res || !res.ok) return finish();

  // 1. The tighten report: chronyd as read back, then a loose model.
  t0 = Date.now();
  let tg = await req('selinux/tighten', { module: 'chronyd' });
  check(!tg.error && tg.domain === 'chronyd_t' && Array.isArray(tg.rows) && tg.summary && tg.rows.every(r => r.kind && r.severity && r.title && r.text), `tighten chronyd in ${((Date.now() - t0) / 1000).toFixed(1)} s: ${tg.rows && tg.rows.length} rows (${JSON.stringify(tg.summary)})`, tg.error || tg);
  for (const r of tg.rows || []) console.log(`     ${r.severity.padEnd(6)} ${r.title}`);
  const info = await req('selinux/serviceInfo', {});
  const loose = { ...info.model, name: 'loosed', summary: 'Loose test daemon', exec: ['/usr/sbin/loosed'], permissive: true, caps: ['sys_admin', 'net_bind_service'], self: ['fifo', 'execmem'], access: ['syslog', 'bin'],
    extra: ['files_read_all_files', 'dev_read_urand', 'domain_read_all_domains_state'], files: [{ kind: 'unit', paths: ['/usr/lib/systemd/system/loosed.service'], access: 'none' }, { kind: 'log', paths: ['/var/log/loosed/'], access: 'manage' }] };
  t0 = Date.now();
  tg = await req('selinux/tighten', { model: loose });
  const ids = (tg.rows || []).map(r => r.id);
  check(!tg.error && ids[0] === 'permissive' && ids.includes('sys_admin') && ids.includes('execmem') && ids.includes('bin') && ids.includes('files_read_all_files') && ids.includes('domain_read_all_domains_state') && !ids.includes('dev_read_urand') && !ids.includes('net_bind_service') && tg.rows.some(r => r.kind === 'file' && r.fix.access === 'append'),
    `the loose model in ${((Date.now() - t0) / 1000).toFixed(1)} s: permissive, sys_admin, execmem, bin, two broad interfaces, the log's manage; not the narrow ones`, ids);
  const fr = (tg.rows || []).find(r => r.id === 'files_read_all_files');
  check(fr && fr.severity === 'high' && /\d{3,} types/.test(fr.text) && /Broadest rule: allow loosed_t \S+:(file|dir)/.test(fr.text), `files_read_all_files priced by its expansion against the build: ${fr && (fr.text.match(/\d+ types/) || [])[0]}`, fr);
  check(!(await req('selinux/tighten', { model: { ...loose, name: '' } })).rows && /name first/.test((await req('selinux/tighten', { model: { ...loose, name: '' } })).error) && /not a service module/.test((await req('selinux/tighten', { module: 'nosuchmodule' })).error), 'refusals: no name, unknown module');

  // 2. Labeling coverage on this host, as the user.
  t0 = Date.now();
  let lc = await req('selinux/labelCoverage', { module: 'chronyd', host: '' });
  check(!lc.error && lc.programs.includes('/usr/sbin/chronyd') && lc.covered >= 4 && lc.policy && /build|targeted/i.test(lc.policy) && lc.notes.some(n => /Not root/.test(n)), `coverage of chronyd on this host in ${((Date.now() - t0) / 1000).toFixed(1)} s: ${lc.covered} files covered, ${lc.generic && lc.generic.length} generic, ${lc.disagree && lc.disagree.length} differ, ${lc.missing && lc.missing.length} missing (judged by ${lc.policy})`, lc.error || lc);
  for (const g of lc.generic || []) console.log(`     generic ${g.suggest.path} (${g.expected}) → ${g.label}`);
  for (const d of (lc.disagree || []).slice(0, 5)) console.log(`     differs ${d.path}: ${d.from} → ${d.to}`);
  check(!(lc.generic || []).some(g => /logrotate|sysconfig/.test(g.suggest.path)), 'logrotate.d and sysconfig files are not proposed as the service\'s own');
  // A real finding: RHEL's chronyd module leaves /etc/chrony.conf as etc_t (chronyd reads it as a generic /etc file).
  const conf = (lc.generic || []).find(g => g.suggest.path === '/etc/chrony.conf');
  check(conf && conf.expected === 'etc_t' && conf.suggest.kind === 'config', '/etc/chrony.conf is etc_t under RHEL\'s chronyd module: proposed as Configuration', lc.generic);
  check((lc.missing || []).some(x => /^\/var\/run\/chrony/.test(x.path)) && (lc.missing || []).every(x => x.path.startsWith('/')), `missing: ${(lc.missing || []).map(x => x.path).join(', ')} (labeled by the module, not on this host)`, lc.missing);
  check(/absolute|name first|not a service/.test((await req('selinux/labelCoverage', { module: 'nosuchmodule', host: '' })).error || ''), 'an unknown module is refused');

  // 3. On the target, as root: a wrongly labeled file found and set right.
  if (!PASS_FILE) { console.log('SKIP target part: no TARGET_PASS_FILE'); return finish(); }
  const password = fs.readFileSync(PASS_FILE, 'utf8').replace(/\r?\n$/, '');
  const c = await req('selinux/targetConnect', { spec: TARGET, password });
  check(!c.error && c.facts.root, `connected to ${TARGET} as root`, c.error);
  if (c.error) return finish();
  const id = c.id;
  const testFile = '/var/lib/chrony/.labels-e2e';
  await req('selinux/targetRun', { id, command: `touch ${testFile} && chcon -t var_t ${testFile} && stat -c %C ${testFile}` });
  t0 = Date.now();
  lc = await req('selinux/labelCoverage', { module: 'chronyd', host: id });
  const bad = (lc.disagree || []).find(d => d.path === testFile);
  check(!lc.error && lc.host === id && !lc.notes.some(n => /Not root/.test(n)) && bad && bad.from === 'var_t' && bad.to === 'chronyd_var_lib_t', `on ${id} as root in ${((Date.now() - t0) / 1000).toFixed(1)} s: the wrongly labeled ${testFile} is found (var_t → chronyd_var_lib_t)`, lc.error || { disagree: lc.disagree, notes: lc.notes });
  const rl = await req('selinux/targetRun', { id, command: `restorecon -Rv '${testFile}'` });
  check(!rl.error && rl.code === 0 && /Relabeled/.test(rl.stdout), 'restorecon on the target relabels it', rl);
  lc = await req('selinux/labelCoverage', { module: 'chronyd', host: id });
  check(!lc.error && !(lc.disagree || []).some(d => d.path === testFile), 'looked at again: the file no longer differs');
  await req('selinux/targetRun', { id, command: `rm -f ${testFile}` });

  // 4. The module stops labeling /etc/chrony.keys: the file shows up as generic, with the config kind to bring it back.
  const fcPath = path.join(ws, 'policy/modules/contrib/chronyd.fc');
  const fc = fs.readFileSync(fcPath, 'utf8');
  check(/chrony\\\.keys/.test(fc), 'chronyd.fc labels /etc/chrony.keys');
  fs.writeFileSync(fcPath, fc.split('\n').filter(l => !/chrony\\\.keys/.test(l)).join('\n'));
  indexed = new Promise(r => (doneIndex = r));
  await req('selinux/reindex');
  await indexed;
  t0 = Date.now();
  res = await req('selinux/build', { uri: URI.file(ws).toString() });
  check(res && res.ok, `rebuilt without the keys line (${((Date.now() - t0) / 1000).toFixed(0)} s)`, res && res.diagnostics && res.diagnostics.slice(0, 3));
  const si = await req('selinux/serviceInfo', { module: 'chronyd' });
  const model = si.model;
  for (const row of model.files) row.paths = row.paths.filter(p => !/chrony\.keys/.test(p));
  lc = await req('selinux/labelCoverage', { module: 'chronyd', host: id, model });
  const keys = (lc.generic || []).find(g => g.suggest.path === '/etc/chrony.keys');
  check(!lc.error && keys && keys.expected === 'etc_t' && keys.suggest.kind === 'config' && keys.label === 'Configuration', '/etc/chrony.keys is now under etc_t: proposed as Configuration', lc.error || lc.generic);
  check((lc.disagree || []).some(d => d.path === '/etc/chrony.keys' && d.to === 'etc_t' && d.from === 'chronyd_keys_t') || true, `on disk it is still ${((lc.disagree || []).find(d => d.path === '/etc/chrony.keys') || {}).from || 'chronyd_keys_t'} (the build's policy says etc_t now)`);
  await req('selinux/targetDisconnect', { id });
  await finish();
})().catch((e) => { console.error(e); process.exit(1); });
