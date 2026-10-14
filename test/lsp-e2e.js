// Drive the language server over stdio exactly as VS Code would, against a
// copy of the Fedora selinux-policy tree with a seeded module containing
// deliberate mistakes (policy/modules/local/myapp.*). Any OS, no toolchain.
//   node test/lsp-e2e.js [workspace]
// The workspace (default <tmp>/selinux-e2e-ws) is created when missing from
// a selinux-policy checkout: $SELINUX_POLICY_SRC, or ../selinux-policy next
// to this repository (git clone --depth 1 https://github.com/fedora-selinux/selinux-policy.git).
// Skips when neither exists.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rpc = require('vscode-jsonrpc/node');
const { URI } = require('vscode-uri');

const ws = process.argv[2] || path.join(os.tmpdir(), 'selinux-e2e-ws');
const te = path.join(ws, 'policy/modules/local/myapp.te');
const iff = path.join(ws, 'policy/modules/local/myapp.if');

const MYAPP_TE = `policy_module(myapp, 1.0.0)

type myapp_t;
type myapp_exec_t;
init_daemon_domain(myapp_t, myapp_exec_t)

type myapp_conf_t;
files_config_file(myapp_conf_t)

allow myapp_t self:process { signal sigkil };
allow myapp_t myapp_conf_t:fiel read_file_perms;

corenet_tcp_bind_http_port(myapp_t)
files_read_etc_filez(myapp_t)
`;
const MYAPP_IF = `## <summary>Example application seeded for the LSP e2e test.</summary>

########################################
## <summary>
##	Read myapp configuration files.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(\`myapp_read_config',\`
	gen_require(\`
		type myapp_t;
	')

	allow $1 myapp_conf_t:file read_file_perms;
')
`;

if (!fs.existsSync(path.join(ws, 'policy/modules/kernel/files.if'))) {
  const src = process.env.SELINUX_POLICY_SRC || path.join(__dirname, '../../selinux-policy');
  if (!fs.existsSync(path.join(src, 'policy/modules/kernel/files.if'))) {
    console.log(`SKIP: no workspace at ${ws} and no selinux-policy checkout at ${src} to make one`);
    process.exit(0);
  }
  fs.mkdirSync(ws, { recursive: true });
  fs.cpSync(path.join(src, 'policy'), path.join(ws, 'policy'), { recursive: true });
  console.log(`workspace made from ${src}`);
}
// The seeded module is rewritten every run, so an earlier run's edits never leak in.
fs.mkdirSync(path.dirname(te), { recursive: true });
fs.writeFileSync(te, MYAPP_TE);
fs.writeFileSync(iff, MYAPP_IF);

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2000).replace(/\n/g, '\n     ')); }
};

const proc = cp.spawn('node', [path.join(__dirname, '../server/server.js'), '--stdio']);
const conn = rpc.createMessageConnection(new rpc.StreamMessageReader(proc.stdout), new rpc.StreamMessageWriter(proc.stdin));
const diags = {};
let doneIndex, stats = null;
const indexed = new Promise(r => (doneIndex = r));
conn.onNotification('textDocument/publishDiagnostics', p => { diags[p.uri] = p.diagnostics; });
conn.onNotification('selinux/indexing', p => { if (p.state === 'done') { stats = p.stats; doneIndex(); } });
conn.onNotification('window/logMessage', () => {});
conn.listen();
const sleep = ms => new Promise(r => setTimeout(r, ms));
const uri = p => URI.file(p).toString();
const posOf = (file, needle, k = 0) => {
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  for (let l = 0; l < lines.length; l++) { const c = lines[l].indexOf(needle); if (c >= 0) return { line: l, character: c + k }; }
  throw new Error('not found ' + needle);
};
const lineOf = (text, needle) => text.split('\n').findIndex(l => l.includes(needle));

(async () => {
  await conn.sendRequest('initialize', { processId: null, rootUri: uri(ws), workspaceFolders: [{ uri: uri(ws), name: 'ws' }], capabilities: {} });
  conn.sendNotification('initialized', {});
  await indexed;
  check(stats && stats.modules > 300 && stats.interfaces > 5000 && stats.types > 3000, `indexed the tree (${stats && `${stats.modules} modules, ${stats.interfaces} interfaces, ${stats.types} types`})`, stats);
  for (const f of [te, iff]) conn.sendNotification('textDocument/didOpen', { textDocument: { uri: uri(f), languageId: 'selinux', version: 1, text: fs.readFileSync(f, 'utf8') } });
  for (let t = 0; t < 50 && !(diags[uri(te)] && diags[uri(iff)]); t++) await sleep(100);
  await sleep(300);

  // Diagnostics: exactly the three seeded mistakes in the .te, one in the .if.
  const dt = diags[uri(te)] || [];
  const at = (code, l) => dt.find(d => d.code === code && d.range.start.line === l);
  check(dt.length === 3, `myapp.te: 3 diagnostics (${dt.map(d => d.code).join(', ')})`, dt.map(d => d.message));
  check(at('unknown-macro', lineOf(MYAPP_TE, 'files_read_etc_filez')) && /files_read_etc_filez/.test(at('unknown-macro', lineOf(MYAPP_TE, 'files_read_etc_filez')).message), 'misspelled interface: unknown-macro on its line');
  check(at('unknown-perm', lineOf(MYAPP_TE, 'sigkil')) && /'sigkil' is not defined for class process/.test(at('unknown-perm', lineOf(MYAPP_TE, 'sigkil')).message), 'misspelled permission: unknown-perm');
  check(at('unknown-class', lineOf(MYAPP_TE, ':fiel')) && /'fiel'/.test(at('unknown-class', lineOf(MYAPP_TE, ':fiel')).message), 'misspelled class: unknown-class');
  const di = diags[uri(iff)] || [];
  check(di.length === 1 && di[0].code === 'missing-require' && /'myapp_conf_t' is used in myapp_read_config/.test(di[0].message), `myapp.if: missing gen_require entry (${di.map(d => d.message).join(' | ')})`);

  // Hover: interface docs, a template-generated interface, a declaration.
  const h = await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(te) }, position: posOf(te, 'init_daemon_domain', 3) });
  check(h && /interface init_daemon_domain\(domain, entry_point\)/.test(h.contents.value) && /\*\*Requires:\*\*.*init_t/.test(h.contents.value) && /init\.if:\d+/.test(h.contents.value), 'hover on an interface: signature, docs, requires, where defined');
  const h2 = await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(te) }, position: posOf(te, 'corenet_tcp_bind_http_port', 3) });
  check(h2 && /Generated by `network_port` at .*corenetwork\.te\.in:\d+/.test(h2.contents.value), 'hover on a generated interface: the network_port call that generates it', h2 && h2.contents.value);
  const h3 = await conn.sendRequest('textDocument/hover', { textDocument: { uri: uri(te) }, position: posOf(te, 'myapp_exec_t', 2) });
  check(h3 && /type myapp_exec_t/.test(h3.contents.value) && /myapp\.te:4/.test(h3.contents.value), 'hover on a type: its declaration');

  // Definition and references.
  const def = await conn.sendRequest('textDocument/definition', { textDocument: { uri: uri(te) }, position: posOf(te, 'files_config_file', 2) });
  check(def && def.length === 1 && /kernel\/files\.if$/.test(URI.parse(def[0].uri).path), `definition of files_config_file in files.if:${def && def[0] && def[0].range.start.line + 1}`);
  const refs = await conn.sendRequest('textDocument/references', { textDocument: { uri: uri(te) }, position: posOf(te, 'files_config_file', 2), context: { includeDeclaration: true } });
  check(refs && refs.length > 50 && refs.some(r => URI.parse(r.uri).path.endsWith('myapp.te')), `references of files_config_file (${refs && refs.length}), including myapp.te`);
  const gdef = await conn.sendRequest('textDocument/definition', { textDocument: { uri: uri(te) }, position: posOf(te, 'corenet_tcp_bind_http_port', 3) });
  check(gdef && gdef.length && /corenetwork\.te\.in$/.test(URI.parse(gdef[0].uri).path), 'definition of a generated name: the generating call');

  // Completion: permissions, classes, interfaces (with a snippet).
  const lines = MYAPP_TE.split('\n');
  const pl = lineOf(MYAPP_TE, 'sigkil');
  let c = await conn.sendRequest('textDocument/completion', { textDocument: { uri: uri(te) }, position: { line: pl, character: lines[pl].indexOf('sigkil') + 4 } });
  check(c.items.map(i => i.label).join() === 'sigkill', `permissions of the class at "sigk": ${c.items.map(i => i.label).join(', ')}`);
  const cl = lineOf(MYAPP_TE, ':fiel');
  c = await conn.sendRequest('textDocument/completion', { textDocument: { uri: uri(te) }, position: { line: cl, character: lines[cl].indexOf(':fiel') + 3 } });
  check(c.items.some(i => i.label === 'file') && c.items.some(i => i.label === 'filesystem') && c.items.every(i => i.label.startsWith('fi')), `classes at ":fi": ${c.items.map(i => i.label).join(', ')}`);
  const fl = lineOf(MYAPP_TE, 'files_read_etc_filez');
  c = await conn.sendRequest('textDocument/completion', { textDocument: { uri: uri(te) }, position: { line: fl, character: 'files_read_etc_f'.length } });
  const fi = c.items.find(i => i.label === 'files_read_etc_files');
  check(fi && fi.insertText === 'files_read_etc_files(${1:domain})', 'interface completion inserts a snippet with its parameters', c.items.slice(0, 3));

  // Signature help.
  const sh = await conn.sendRequest('textDocument/signatureHelp', { textDocument: { uri: uri(te) }, position: { line: 4, character: 'init_daemon_domain(myapp_t, '.length } });
  check(sh && sh.signatures[0].label === 'init_daemon_domain(domain, entry_point)' && sh.activeParameter === 1 && sh.signatures[0].parameters.length === 2, 'signature help: second parameter active');

  // Quick fixes.
  const ca = await conn.sendRequest('textDocument/codeAction', { textDocument: { uri: uri(te) }, range: dt[0].range, context: { diagnostics: dt } });
  const titles = ca.map(a => a.title);
  check(["Change to 'files_read_etc_files'", "Change to 'sigkill'", "Change to 'file'"].every(t => titles.includes(t)), `quick fixes for the .te: ${titles.slice(0, 5).join(' | ')}`);
  const ca2 = await conn.sendRequest('textDocument/codeAction', { textDocument: { uri: uri(iff) }, range: di[0].range, context: { diagnostics: di } });
  check(ca2[0] && ca2[0].title === "Add 'type myapp_conf_t;' to gen_require", `quick fix for the .if: ${ca2[0] && ca2[0].title}`);

  // Outline, workspace symbols, modules.
  const syms = await conn.sendRequest('textDocument/documentSymbol', { textDocument: { uri: uri(te) } });
  check(['myapp_t', 'myapp_exec_t', 'myapp_conf_t'].every(n => syms.some(s => s.name === n)), `outline: ${syms.map(s => s.name).join(', ')}`);
  const ws1 = await conn.sendRequest('workspace/symbol', { query: 'ntpd_' });
  check(ws1.length && ws1.every(s => /ntpd_/.test(s.name)) && ws1.some(s => s.name === 'ntpd_t'), `workspace symbols "ntpd_": ${ws1.slice(0, 4).map(s => s.name).join(', ')}`);
  const mods = await conn.sendRequest('selinux/modules');
  check(mods.some(m => m.layer === 'local' && m.module === 'myapp'), `selinux/modules lists the seeded module (${mods.length} modules)`);

  // Applying the .if quick fix clears its diagnostic.
  const edit = Object.values(ca2[0].edit.changes)[0][0];
  const ifText = MYAPP_IF.split('\n');
  ifText.splice(edit.range.start.line, 0, edit.newText.replace(/\n$/, ''));
  conn.sendNotification('textDocument/didChange', { textDocument: { uri: uri(iff), version: 2 }, contentChanges: [{ text: ifText.join('\n') }] });
  for (let t = 0; t < 30 && (diags[uri(iff)] || []).length; t++) await sleep(100);
  check((diags[uri(iff)] || []).length === 0 && /\t\ttype myapp_conf_t;/.test(ifText.join('\n')), 'after the quick fix the .if is clean');
  // Fixing the misspelled interface brings the next problem forward: nothing else is wrong.
  const fixedTe = MYAPP_TE.replace('files_read_etc_filez', 'files_read_etc_files').replace('sigkil ', 'sigkill ').replace(':fiel ', ':file ');
  conn.sendNotification('textDocument/didChange', { textDocument: { uri: uri(te), version: 2 }, contentChanges: [{ text: fixedTe }] });
  for (let t = 0; t < 30 && (diags[uri(te)] || []).length; t++) await sleep(100);
  check((diags[uri(te)] || []).length === 0, 'with the three mistakes fixed the .te is clean', diags[uri(te)]);

  proc.kill();
  console.log(failures ? `\n${failures} check(s) failed` : '\nall LSP checks passed');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); proc.kill(); process.exit(1); });
