// Per-server scratch areas: two language servers (two VS Code windows) on the
// same workspace build in separate directories; one exiting doesn't remove
// the other's; areas of servers that died are swept by the next server.
// Uses a small standalone module (needs make, m4, checkpolicy, selinux-policy-devel).
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');
const { detectToolchain } = require('../server/build');

const tc = detectToolchain('/usr/share/selinux/devel/Makefile');
if (!tc.ok) { console.log(`SKIP: ${tc.reason}`); process.exit(0); }

const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-scratch-e2e-'));
fs.writeFileSync(path.join(ws, 'myapp.te'), 'policy_module(myapp, 1.0.0)\ntype myapp_t;\ntype myapp_exec_t;\ninit_daemon_domain(myapp_t, myapp_exec_t)\n');
const uri = URI.file(path.join(ws, 'myapp.te')).toString();
const BASE = path.join(os.tmpdir(), `selinux-policy-tools-${process.getuid()}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (cond, what, extra) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`); if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra)); } };

async function server() {
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  let done;
  const indexed = new Promise(r => (done = r));
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') done(); });
  for (const n of ['selinux/build', 'textDocument/publishDiagnostics', 'window/logMessage', 'selinux/inactiveChanged', 'selinux/checks']) conn.onNotification(n, () => {});
  conn.listen();
  await conn.sendRequest('initialize', { processId: null, rootUri: URI.file(ws).toString(), capabilities: {} });
  conn.sendNotification('initialized', {});
  await indexed;
  const stop = async () => {
    await conn.sendRequest('shutdown');
    const exited = new Promise(res => proc.on('exit', res));
    conn.sendNotification('exit');
    await Promise.race([exited, sleep(5000)]);
  };
  return { proc, conn, stop, area: path.join(BASE, String(proc.pid)) };
}

(async () => {
  const a = await server(), b = await server();
  const ra = await a.conn.sendRequest('selinux/build', { uri }), rb = await b.conn.sendRequest('selinux/build', { uri });
  check(ra.ok && rb.ok && ra.workDir !== rb.workDir && ra.workDir.startsWith(a.area) && rb.workDir.startsWith(b.area),
    `two servers on one workspace build in separate areas (${path.basename(a.area)}, ${path.basename(b.area)})`, { ra: ra.workDir, rb: rb.workDir });
  check((fs.statSync(BASE).mode & 0o777) === 0o700, `scratch base is private (${(fs.statSync(BASE).mode & 0o777).toString(8)})`);

  await a.stop();
  check(!fs.existsSync(a.area) && fs.existsSync(rb.workDir), "the first server's exit removes only its own area");
  const rb2 = await b.conn.sendRequest('selinux/build', { uri });
  check(rb2.ok, 'the other server keeps building');

  // A server killed without cleanup leaves its area; the next server sweeps it,
  // but not areas of processes that are still running (here: this test's pid).
  const alive = path.join(BASE, String(process.pid));
  fs.mkdirSync(alive, { recursive: true });
  b.proc.kill('SIGKILL');
  await sleep(500);
  check(fs.existsSync(b.area), 'a killed server leaves its area behind');
  const c = await server();
  check(!fs.existsSync(b.area) && fs.existsSync(alive), "the next server sweeps the dead server's area, not a live process's");
  fs.rmSync(alive, { recursive: true, force: true });
  await c.stop();
  check(!fs.existsSync(c.area), 'clean exit removes the area');

  console.log(failures ? `\n${failures} check(s) failed` : '\nall scratch area checks passed');
  fs.rmSync(ws, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); fs.rmSync(ws, { recursive: true, force: true }); process.exit(1); });
