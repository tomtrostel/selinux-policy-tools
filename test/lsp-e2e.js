// Drive the language server over stdio exactly as VS Code would.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');

const ws = process.argv[2] || path.join(os.tmpdir(), 'selinux-e2e-ws');
const te = path.join(ws, 'policy/modules/local/myapp.te');
const iff = path.join(ws, 'policy/modules/local/myapp.if');
const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
const diags = {};
let doneIndex;
const indexed = new Promise(r => (doneIndex = r));
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') { console.log('indexed:', p.stats); doneIndex(); } });
conn.onNotification('window/logMessage', () => {});
conn.listen();
const sleep = ms => new Promise(r => setTimeout(r, ms));
const uri = p => URI.file(p).toString();
const show = (label, v) => console.log(`\n### ${label}\n` + (typeof v === 'string' ? v : JSON.stringify(v, null, 1)));
const posOf = (file, needle, k = 0) => {
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  for (let l = 0; l < lines.length; l++) { const c = lines[l].indexOf(needle); if (c >= 0) return { line: l, character: c + k }; }
  throw new Error('not found ' + needle);
};

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), workspaceFolders: [{ uri: uri(ws), name: 'ws' }], capabilities: {} });
  conn.sendNotification('initialized', {});
  await indexed;
  for (const f of [te, iff]) conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(f), languageId: 'selinux', version: 1, text: fs.readFileSync(f, 'utf8') } });
  await sleep(800);

  show('diagnostics myapp.te', diags[uri(te)].map(d => `${d.range.start.line + 1}:${d.range.start.character} [${d.code}] ${d.message}`).join('\n'));
  show('diagnostics myapp.if', diags[uri(iff)].map(d => `${d.range.start.line + 1}:${d.range.start.character} [${d.code}] ${d.message}`).join('\n'));

  const h = await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(te) }, position: posOf(te, 'init_daemon_domain', 3) });
  show('hover init_daemon_domain', h.contents.value);
  const h2 = await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(te) }, position: posOf(te, 'corenet_tcp_bind_http_port', 3) });
  show('hover corenet_tcp_bind_http_port (generated)', h2.contents.value);
  const h3 = await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(te) }, position: posOf(te, 'myapp_exec_t', 2) });
  show('hover myapp_exec_t', h3.contents.value);

  const def = await conn.sendRequest('textDocument/definition', { textDocument: { uri: uri(te) }, position: posOf(te, 'files_config_file', 2) });
  show('definition files_config_file', def.map(d => `${d.uri.replace(uri(ws), '')}:${d.range.start.line + 1}`));
  const refs = await conn.sendRequest('textDocument/references', { textDocument: { uri: uri(te) }, position: posOf(te, 'files_config_file', 2), context: { includeDeclaration: true } });
  show('references files_config_file', `${refs.length} references`);

  // completion: permissions after class
  const lines = fs.readFileSync(te, 'utf8').split('\n');
  const pl = lines.findIndex(l => l.includes('sigkil'));
  let c = await conn.sendRequest('textDocument/completion', { textDocument: { uri: uri(te) }, position: { line: pl, character: lines[pl].indexOf('sigkil') + 4 } });
  show('completion perms at "sigk"', c.items.map(i => i.label));
  const cl = lines.findIndex(l => l.includes(':fiel'));
  c = await conn.sendRequest('textDocument/completion', { textDocument: { uri: uri(te) }, position: { line: cl, character: lines[cl].indexOf(':fiel') + 3 } });
  show('completion classes at ":fi"', c.items.map(i => i.label));
  const fl = lines.findIndex(l => l.includes('files_read_etc_filez'));
  c = await conn.sendRequest('textDocument/completion', { textDocument: { uri: uri(te) }, position: { line: fl, character: 'files_read_etc_f'.length } });
  show('completion interfaces "files_read_etc_f"', c.items.slice(0, 5).map(i => `${i.label}  →  ${i.insertText}`));

  const sh = await conn.sendRequest('textDocument/signatureHelp', { textDocument: { uri: uri(te) }, position: { line: 4, character: 'init_daemon_domain(myapp_t, '.length } });
  show('signature help in init_daemon_domain(myapp_t, |', { label: sh.signatures[0].label, active: sh.activeParameter, params: sh.signatures[0].parameters });

  const allDiags = diags[uri(te)].concat([]);
  const ca = await conn.sendRequest('textDocument/codeAction', { textDocument: { uri: uri(te) }, range: allDiags[0].range, context: { diagnostics: allDiags } });
  show('quick fixes (.te)', ca.map(a => a.title));
  const ca2 = await conn.sendRequest('textDocument/codeAction', { textDocument: { uri: uri(iff) }, range: diags[uri(iff)][0].range, context: { diagnostics: diags[uri(iff)] } });
  show('quick fixes (.if)', ca2.map(a => a.title + '  ' + JSON.stringify(Object.values(a.edit.changes)[0])));

  const syms = await conn.sendRequest('textDocument/documentSymbol', { textDocument: { uri: uri(te) } });
  show('outline myapp.te', syms.map(s => s.name));
  const ws1 = await conn.sendRequest('workspace/symbol', { query: 'ntpd_' });
  show('workspace symbols "ntpd_"', ws1.slice(0, 8).map(s => s.name));
  const mods = await conn.sendRequest('selinux/modules');
  show('modules', `${mods.length} modules; local: ${JSON.stringify(mods.filter(m => m.layer === 'local'))}`);

  // edit: fix the .if by adding the require, check diagnostics clear
  const edit = Object.values(ca2[0].edit.changes)[0][0];
  const ifText = fs.readFileSync(iff, 'utf8').split('\n');
  ifText.splice(edit.range.start.line, 0, edit.newText.replace(/\n$/, ''));
  conn.sendNotification('textDocument/didChange', { textDocument: { uri: uri(iff), version: 2 }, contentChanges: [{ text: ifText.join('\n') }] });
  await sleep(800);
  show('.if diagnostics after applying quick fix', diags[uri(iff)].map(d => d.message));
  show('.if after fix', ifText.slice(12, 20).join('\n'));
  proc.kill();
  process.exit(0);
})().catch(e => { console.error(e); proc.kill(); process.exit(1); });
