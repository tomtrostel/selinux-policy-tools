// The .te require check in a tree without modules.conf (a bare upstream
// refpolicy checkout): module kinds as `make conf` would write them
// (base when the .if says <required val="true">, else loadable), and none
// loadable with MONOLITHIC=y. Drives the server over stdio LSP; no build.
//   node test/conf-defaults-e2e.js [refpolicy-dir]
// Default: ~/sepol-test/refpolicy (git clone --depth 1 https://github.com/SELinuxProject/refpolicy).
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');

const src = process.argv[2] || path.join(os.homedir(), 'sepol-test/refpolicy');
if (!fs.existsSync(path.join(src, 'Rules.modular'))) { console.log(`SKIP: no refpolicy tree at ${src}`); process.exit(0); }
const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-confdef-e2e-'));
fs.cpSync(src, ws, { recursive: true, filter: (p) => !/[\\/](\.git|tmp)$/.test(p) });
fs.rmSync(path.join(ws, 'policy/modules.conf'), { force: true });
const SSH = path.join(ws, 'policy/modules/services/ssh.te');      // loadable by default
const TERM = path.join(ws, 'policy/modules/kernel/terminal.te');  // <required val="true"> → base

const uri = (f) => URI.file(f).toString();
const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 1500).replace(/\n/g, '\n     ')); }
};

/** Start a server with `makeArgs`, open both files with a foreign type added, return their require diagnostics. */
async function session(makeArgs) {
  const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
  const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
  const diags = {};
  let doneIndex;
  const indexed = new Promise(r => (doneIndex = r));
  conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
  conn.onNotification('selinux/indexing', p => { if (p.state === 'done') doneIndex(p.stats); });
  conn.onNotification('window/logMessage', () => {});
  conn.listen();
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), capabilities: {},
    initializationOptions: { build: { tree: { makeArgs } } } });
  conn.sendNotification('initialized', {});
  const stats = await indexed;
  const out = { stats };
  for (const [name, file, line] of [['ssh', SSH, 'allow sshd_t httpd_t:process signal;'], ['terminal', TERM, 'allow devpts_t httpd_t:process signal;']]) {
    const text = fs.readFileSync(file, 'utf8') + '\n' + line + '\n';
    conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(file), languageId: 'selinux', version: 1, text } });
    out[name] = { line: text.split('\n').indexOf(line) };
  }
  await sleep(1500);
  for (const [name, file] of [['ssh', SSH], ['terminal', TERM]]) out[name].diags = (diags[uri(file)] || []).filter(d => d.code === 'missing-te-require');
  await conn.sendRequest('shutdown');
  conn.sendNotification('exit');
  await sleep(200);
  proc.kill();
  return out;
}

(async () => {
  const mod = await session([]);
  check(mod.stats.buildMode === 'tree', `refpolicy tree without modules.conf detected (${mod.stats.modules} modules)`, mod.stats);
  const d = mod.ssh.diags.find(x => x.range.start.line === mod.ssh.line);
  check(d && /httpd_t/.test(d.message) && /apache/.test(d.message), `ssh.te (loadable by make conf default): missing require for httpd_t (${d && d.message.slice(0, 60)}…)`, mod.ssh.diags);
  check(mod.terminal.diags.length === 0, 'terminal.te (required → base): no require warnings', mod.terminal.diags);
  const mono = await session(['MONOLITHIC=y']);
  check(mono.ssh.diags.length === 0 && mono.terminal.diags.length === 0, 'MONOLITHIC=y: no module is loadable, no require warnings', [mono.ssh.diags, mono.terminal.diags]);
  fs.rmSync(ws, { recursive: true, force: true });
  console.log(failures ? `\n${failures} check(s) failed` : '\nall conf-defaults checks passed');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
