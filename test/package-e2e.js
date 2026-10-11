// Standalone service modules next to a policy tree, packaged as RPMs: in a
// tree workspace (a copy of the CLIP tree) the service editor makes a new
// service as a standalone module built against this host's devel headers
// (their interfaces and helper variants, not the tree's), with a spec and a
// Makefile; the module builds with the devel Makefile, `make rpm` builds the
// RPM (module + .if, install/uninstall scripts, port labels), the module
// reads back into the form, and the tree is untouched.
//   node test/package-e2e.js [tree-dir]
// Needs Linux with make, m4, checkpolicy, selinux-policy-devel, rpm-build.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain } = require('../server/build');
const svc = require('../server/service');

const DEVEL = '/usr/share/selinux/devel/Makefile';
const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/clip/packages/selinux-policy/selinux-policy');
const has = (cmd) => { try { cp.execFileSync('sh', ['-c', `command -v ${cmd}`]); return true; } catch { return false; } };
if (!detectToolchain(null).ok || !fs.existsSync(DEVEL) || !fs.existsSync(path.join(src, 'Rules.modular')) || !has('rpmbuild')) {
  console.log('SKIP: needs the toolchain, selinux-policy-devel, rpm-build and a refpolicy tree'); process.exit(0);
}
// The workspace: a folder holding a copy of the tree (the module goes next to it).
const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-package-e2e-'));
const tree = path.join(ws, 'policy-tree');
cp.execFileSync('cp', ['-a', src + '/.', tree]);
fs.rmSync(path.join(tree, 'tmp'), { recursive: true, force: true });
const CLIP_SEPARATE = 'ssh rhsmcertd oddjob rtkit aide postfix usbguard fapolicyd rngd logadm auditadm secadm sasl rpcbind rpc gssproxy kerberos certmonger pcscd apcupsd nut postgresql mysql apache bind openvpn samba ntp xserver accountsd colord geoclue gnome wm telepathy bluetooth devicekit';
const makeArgs = ['NAME=mcs', 'TYPE=mcs', 'DISTRO=redhat', 'UBAC=y', 'DIRECT_INITRC=n', 'MONOLITHIC=n', 'POLY=y', 'UNK_PERMS=deny',
  'MLS_CATS=1024', 'MCS_CATS=1024', 'SEMOD_EXP=/usr/bin/semodule_expand', `APPS_MODS=${CLIP_SEPARATE}`];
const confBefore = fs.readFileSync(path.join(tree, 'policy/modules.conf'), 'utf8');
const corenetBefore = fs.readFileSync(path.join(tree, 'policy/modules/kernel/corenetwork.te.in'), 'utf8');

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
let done;
const indexed = new Promise(r => (done = r));
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') done(); });
for (const n of ['textDocument/publishDiagnostics', 'selinux/checks', 'selinux/build', 'window/logMessage', 'selinux/inactiveRanges', 'selinux/trees']) conn.onNotification(n, () => {});
conn.listen();
const uri = (f) => URI.file(f).toString();
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + (typeof extra === 'string' ? extra : JSON.stringify(extra, null, 1)).slice(0, 3000).replace(/\n/g, '\n     ')); }
};
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const versions = {};
async function write(plan) {
  for (const f of plan.files.filter(x => x.changed)) {
    fs.mkdirSync(path.dirname(f.path), { recursive: true });
    fs.writeFileSync(f.path, f.text);
    if (/\.(te|if|fc)$/.test(f.path)) {
      if (versions[f.path]) conn.sendNotification('textDocument/didChange', { textDocument: { uri: uri(f.path), version: ++versions[f.path] }, contentChanges: [{ text: f.text }] });
      else { versions[f.path] = 1; conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(f.path), languageId: f.path.endsWith('.fc') ? 'selinux-fc' : 'selinux', version: 1, text: f.text } }); }
    }
  }
  await sleep(800);
}

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {}, initializationOptions: { trusted: true, build: { tree: { makeArgs } } } });
  conn.sendNotification('initialized', {});
  await indexed;

  // The form offers both kinds; standalone uses the devel headers.
  const inTree = await conn.sendRequest('selinux/serviceInfo', {});
  check(inTree.mode === 'tree' && inTree.canStandalone && !inTree.standalone, 'tree workspace: new services in the tree, standalone offered');
  const info = await conn.sendRequest('selinux/serviceInfo', { standalone: true });
  check(info.standalone && info.mode === 'module' && !info.layers && info.folderSuffix === '-selinux', 'standalone: a folder, not a layer');
  const runtime = info.catalog.fileKinds.find(k => k.id === 'runtime');
  const treeRuntime = inTree.catalog.fileKinds.find(k => k.id === 'runtime');
  check(runtime && runtime.suffix === '_var_run_t' && treeRuntime.suffix === '_runtime_t',
    `runtime files: ${runtime && runtime.suffix} from RHEL's devel headers (files_pid_file; the CLIP tree: ${treeRuntime.suffix}, files_runtime_file)`, runtime);
  check(info.interfaces.length > 1000 && info.interfaces.length < inTree.interfaces.length + 5000, `interfaces offered from the devel headers: ${info.interfaces.length} (tree: ${inTree.interfaces.length})`);

  const model = svc.newModel();
  Object.assign(model, { name: 'pkgsvc', summary: 'Packaging test daemon', exec: ['/usr/sbin/pkgsvc'] });
  model.files = [{ kind: 'runtime', paths: ['/run/pkgsvc/'], access: 'manage' }, { kind: 'log', paths: ['/var/log/pkgsvc/'], access: 'manage' }];
  model.access = ['syslog'].filter(a => info.catalog.access.some(x => x.id === a));
  model.ports = [{ name: '', nums: [{ proto: 'tcp', port: '47130', level: '' }], _new: true }];
  model.net.listen = [{ proto: 'tcp', port: 'pkgsvc' }];
  let plan = await conn.sendRequest('selinux/servicePlan', { model, module: null, where: null, standalone: true });
  const kinds = plan.files.map(f => f.kind).join(',');
  const dir = path.join(ws, 'pkgsvc-selinux');
  check(!(plan.problems || []).some(p => !p.startsWith('Note:')), 'plan has no problems', plan.problems);
  check(kinds === 'te,if,fc,spec,make' && plan.files.every(f => path.dirname(f.path) === dir), `files: ${kinds} in pkgsvc-selinux/ (no modules.conf, no corenetwork.te.in)`, plan.files.map(f => f.path));
  const teText = plan.files.find(f => f.kind === 'te').text;
  check(/files_pid_file\(pkgsvc_var_run_t\)/.test(teText) && !/files_runtime_file/.test(teText), 'the .te uses files_pid_file / pkgsvc_var_run_t', teText.slice(0, 1500));
  check(/type pkgsvc_port_t;/.test(teText) && /semanage port -a -t pkgsvc_port_t -p tcp 47130/.test(teText), 'the port type is declared in the module, with the semanage command');
  const spec = plan.files.find(f => f.kind === 'spec').text;
  check(/^Name:\s+%\{modulename\}-selinux$/m.test(spec) && /^Version:\s+1\.0\.0$/m.test(spec) && /%selinux_modules_install -s %\{selinuxtype\}/.test(spec)
    && /semanage port -a -t pkgsvc_port_t -p tcp 47130/.test(spec) && /Requires\(post\): policycoreutils-python-utils/.test(spec), 'spec: package, version, install macros, port labels', spec);

  // A CLIP-only interface is refused for a standalone module.
  const devNames = new Set(info.interfaces.map(x => x.n));
  const treeOnly = inTree.interfaces.map(x => x.n).find(n => !devNames.has(n));
  const bad = await conn.sendRequest('selinux/servicePlan', { model: { ...model, extra: [treeOnly] }, module: null, where: null, standalone: true });
  check(treeOnly && (bad.problems || []).some(p => p.includes(treeOnly)), `an interface only the tree has (${treeOnly}) is refused`, bad.problems);

  // Write it, build it (devel Makefile, although the workspace is a tree), package it.
  await write(plan);
  const te = path.join(dir, 'pkgsvc.te');
  const b = await conn.sendRequest('selinux/build', { uri: uri(te) });
  check(b.ok && !b.tree && b.module === 'pkgsvc', `the standalone module builds with the devel Makefile (${b.ms} ms)`, b.ok ? undefined : b.log);
  const t0 = Date.now();
  let out = '';
  try { out = cp.execFileSync('make', ['rpm'], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { out = `${e.stdout}\n${e.stderr}`; }
  const rpm = (out.match(/\S+\/pkgsvc-selinux-1\.0\.0-1[^\s/]*\.noarch\.rpm/) || [])[0];
  check(rpm && fs.existsSync(rpm), `make rpm builds ${rpm ? path.relative(dir, rpm) : 'nothing'} (${Math.round((Date.now() - t0) / 1000)} s)`, out.slice(-2500));
  if (rpm) {
    const files = cp.execFileSync('rpm', ['-qpl', rpm], { encoding: 'utf8' });
    check(/\/usr\/share\/selinux\/packages\/targeted\/pkgsvc\.pp\.bz2/.test(files) && /\/usr\/share\/selinux\/devel\/include\/distributed\/pkgsvc\.if/.test(files), 'the RPM has the module and its interface file', files);
    const scripts = cp.execFileSync('rpm', ['-qp', '--scripts', rpm], { encoding: 'utf8' });
    check(/semodule/.test(scripts) && /semanage port -a -t pkgsvc_port_t -p tcp 47130/.test(scripts) && /semanage port -d -t pkgsvc_port_t/.test(scripts), 'its scripts install/remove the module and label the port', scripts.slice(0, 2500));
    const reqs = cp.execFileSync('rpm', ['-qpR', rpm], { encoding: 'utf8' });
    check(/selinux-policy-targeted/.test(reqs), 'it requires the targeted policy');
    const pp = cp.execFileSync('sh', ['-c', `rpm2cpio '${rpm}' | cpio -i --to-stdout './usr/share/selinux/packages/targeted/pkgsvc.pp.bz2' 2>/dev/null | bzip2 -dc | od -An -tx1 -N4`], { encoding: 'utf8' }).trim();
    check(pp === '8f ff 7c f9', `the packaged module is a policy package (magic ${pp})`);
  }

  // Install Module packages it (what it then hands to sudo semodule -i).
  const pk = await conn.sendRequest('selinux/build', { uri: uri(te), package: true });
  check(pk.ok && pk.package && fs.existsSync(pk.package) && path.dirname(pk.package) === dir, `Install Module's package build: ${pk.package && path.relative(ws, pk.package)}`, pk.ok ? pk : pk.log);
  // The denial assistant writes fixes into it, optional per the devel headers.
  let fx = await conn.sendRequest('selinux/denialFix', { domain: 'pkgsvc_t', call: 'files_rw_etc_files(pkgsvc_t)' });
  check(fx.path === te && !fx.optional, 'denial fix into the standalone module: files_rw_etc_files at the top level', fx);
  fx = await conn.sendRequest('selinux/denialFix', { domain: 'pkgsvc_t', call: 'apache_read_sys_content(pkgsvc_t)' });
  check(fx.path === te && fx.optional, 'denial fix: apache_read_sys_content in optional_policy (contrib in the devel headers)', fx);

  // It reads back into the form as a standalone module; an edit leaves the packaging alone.
  const list = await conn.sendRequest('selinux/serviceList');
  check(list.modules.some(m => m.module === 'pkgsvc'), 'listed among the services');
  const again = await conn.sendRequest('selinux/serviceInfo', { module: 'pkgsvc' });
  check(again.standalone && again.model.ports.length === 1 && again.model.ports[0].nums[0].port === '47130', 'reads back as standalone, with its port type', again.model && again.model.ports);
  const m2 = { ...again.model, caps: [...(again.model.caps || []), 'net_bind_service'] };
  plan = await conn.sendRequest('selinux/servicePlan', { model: m2, module: 'pkgsvc' });
  check(plan.files.filter(f => f.changed).map(f => f.kind).join() === 'te' && plan.files.every(f => !['spec', 'make', 'conf', 'net'].includes(f.kind)), `an edit changes only the .te: ${plan.files.filter(f => f.changed).map(f => f.kind)}`, plan.files.map(f => [f.kind, f.changed]));

  // The tree is untouched and still builds.
  check(fs.readFileSync(path.join(tree, 'policy/modules.conf'), 'utf8') === confBefore && fs.readFileSync(path.join(tree, 'policy/modules/kernel/corenetwork.te.in'), 'utf8') === corenetBefore, 'modules.conf and corenetwork.te.in unchanged');
  const logging = path.join(tree, 'policy/modules/system/logging.te');
  conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(logging), languageId: 'selinux', version: 1, text: fs.readFileSync(logging, 'utf8') } });
  const tb = await conn.sendRequest('selinux/build', { uri: uri(logging) });
  check(tb.ok && tb.tree, `the tree still builds as a tree (${tb.ms} ms)`, tb.ok ? undefined : tb.log && tb.log.slice(-1500));

  console.log(failures ? `\n${failures} check(s) failed` : '\nall packaging checks passed');
  proc.kill();
  fs.rmSync(ws, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); fs.rmSync(ws, { recursive: true, force: true }); process.exit(1); });
