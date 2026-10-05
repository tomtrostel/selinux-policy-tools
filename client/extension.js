'use strict';
const path = require('path');
const vscode = require('vscode');
const { LanguageClient, TransportKind } = require('vscode-languageclient/node');

let client;
let status;

const CHECKS_TEMPLATE = `# SELinux property checks: assertions about the compiled policy, checked
# after every build and whenever this file is saved. One per line:
#
#   only    <names> may <perms> <targets>[:<classes>]   nobody else may
#   never   <names> may <perms> <targets>[:<classes>]   none of these may ('*' = every domain)
#   never   <names> reaches <names>                     no domain-transition path, direct or indirect
#   never   <types> flows to <types> [except <types>]   no information flow through any chain of
#                                                       domains and files (except: trusted to pass it on;
#                                                       add 'weight 1' to count covert channels too)
#   require <names> may <perms> <targets>[:<classes>]   must stay allowed
#   only|never <roles> may run <types>                  which roles may run a domain
#   only|never <users> may use <roles>                  which SELinux users may have a role
#
# names: types or attributes (attributes stand for all their member types).
# perms: read | write | execute | any (groups), a permission, or { perm perm ... }
# (exactly those: { read } is only read, while read also means open and map).
# classes default to the file-like ones (require: file).
#
# Examples (edit to match your policy):
# only auditd_t may write auditd_log_t
# never user_t, staff_t may write shadow_t
# never user_t reaches sysadm_t
# never shadow_t flows to user_t except passwd_t chkpwd_t
# require syslogd_t may { append create } var_log_t:file
# only sysadm_r may run sysadm_t
# never user_u may use sysadm_r
`;

/* ---------------- several policy trees in one workspace ---------------- */

let policyTrees = [];       // [{ root, name, active }] from the last indexing
let switching = null;

/** Make `root` the policy tree the server indexes and builds (remembered for the workspace). */
async function selectTree(root, auto) {
  if (switching) return;
  switching = root;
  try {
    const r = await client.sendRequest('selinux/selectTree', { root });
    if (r.error) { vscode.window.showWarningMessage(r.error); return; }
    await extensionContext.workspaceState.update('selinux.activeTree', r.tree);
    if (!r.unchanged) vscode.window.setStatusBarMessage(`$(shield) SELinux: ${auto ? 'switched to' : 'now working on'} ${r.name}`, 4000);
  } finally {
    switching = null;
  }
}

/** Opening a file of another tree switches to it (after a short pause, so tabbing through doesn't reindex each time). */
function watchTreeOfEditor(context) {
  let timer = null;
  context.subscriptions.push(vscode.window.onDidChangeActiveTextEditor((ed) => {
    clearTimeout(timer);
    if (!ed || ed.document.uri.scheme !== 'file' || policyTrees.length < 2) return;
    if (vscode.workspace.getConfiguration('selinux').get('tree.autoSwitch') === false) return;
    const p = ed.document.uri.fsPath;
    const t = policyTrees.find(x => p === x.root || p.startsWith(x.root + path.sep));
    if (!t || t.active) return;
    timer = setTimeout(() => {
      const now = vscode.window.activeTextEditor;
      if (now && now.document.uri.fsPath === p) selectTree(t.root, true);
    }, 800);
  }));
}

/** Run `sudo semodule -i <pkg>` in a terminal on the policy host, so the user sees it and types the password. */
function installPackage(pkg) {
  let term = vscode.window.terminals.find(t => t.name === 'SELinux Install');
  if (!term) term = vscode.window.createTerminal({ name: 'SELinux Install', cwd: path.dirname(pkg) });
  term.show();
  term.sendText(`sudo semodule -i '${pkg.replace(/'/g, `'\\''`)}'`);
}

/** "1 module", "2 modules", "1 class", "3 classes" */
const count = (n, word) => `${n} ${n === 1 ? word : word + (/(s|x|ch|sh)$/.test(word) ? 'es' : 's')}`;

let extensionContext = null;

function activate(context) {
  extensionContext = context;
  watchTreeOfEditor(context);
  const serverModule = context.asAbsolutePath(path.join('server', 'server.js'));
  const cfg = () => vscode.workspace.getConfiguration('selinux');

  client = new LanguageClient('selinux', 'SELinux Policy', {
    run: { module: serverModule, transport: TransportKind.ipc },
    debug: { module: serverModule, transport: TransportKind.ipc, options: { execArgv: ['--nolazy', '--inspect=6019'] } },
  }, {
    documentSelector: [{ scheme: 'file', language: 'selinux' }, { scheme: 'file', language: 'selinux-fc' }, { scheme: 'file', language: 'selinux-checks' }],
    synchronize: {
      configurationSection: 'selinux',
      fileEvents: vscode.workspace.createFileSystemWatcher('**/{*.te,*.if,*.fc,*.spt,*.m4,*.in,access_vectors,security_classes,*.checks,modules*.conf,*.lst}'),
    },
    initializationOptions: {
      extraIncludePaths: cfg().get('extraIncludePaths'),
      useDevelHeaders: cfg().get('useDevelHeaders'),
      develHeadersPath: cfg().get('develHeadersPath'),
      diagnostics: cfg().get('diagnostics'),
      build: cfg().get('build'),
      trusted: vscode.workspace.isTrusted,
      // The policy tree last worked on, when the workspace has several.
      activeTree: context.workspaceState.get('selinux.activeTree') || null,
    },
  });
  context.subscriptions.push(vscode.workspace.onDidGrantWorkspaceTrust(() => {
    if (client && client.isRunning()) client.sendNotification('selinux/setTrusted', { trusted: true });
  }));
  const buildOutput = vscode.window.createOutputChannel('SELinux Build');
  context.subscriptions.push(buildOutput);
  const expanded = new ExpandedPolicyProvider();
  let statusMsg = null; // one build message at a time; each phase replaces the last
  const buildStatus = (text, ms) => { if (statusMsg) statusMsg.dispose(); statusMsg = vscode.window.setStatusBarMessage(text, ms); };

  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 10);
  status.text = '$(shield) SELinux: starting…';
  status.command = 'selinux.showStats';
  status.show();
  context.subscriptions.push(status);
  const checksStatus = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 9);
  checksStatus.command = 'selinux.openChecks';
  context.subscriptions.push(checksStatus);

  const explorer = new PolicyExplorer();
  context.subscriptions.push(vscode.window.registerTreeDataProvider('selinuxPolicyExplorer', explorer));
  const compiled = new CompiledPolicyView();
  const compiledView = vscode.window.createTreeView('selinuxCompiledPolicy', { treeDataProvider: compiled, showCollapseAll: true });
  context.subscriptions.push(compiledView);
  const changes = new ChangesView();
  context.subscriptions.push(vscode.window.registerTreeDataProvider('selinuxChanges', changes));
  const preview = new ModulePreviewView();
  context.subscriptions.push(vscode.window.registerTreeDataProvider('selinuxModulePreview', preview));

  // Dim ifdef/ifndef branches the build flags turn off, like inactive #ifdef code.
  const inactiveDeco = vscode.window.createTextEditorDecorationType({ opacity: '0.45' });
  context.subscriptions.push(inactiveDeco);
  const dim = async (ed) => {
    if (!ed || !/^selinux/.test(ed.document.languageId) || ed.document.uri.scheme !== 'file' || !client.isRunning()) return;
    const ranges = await client.sendRequest('selinux/inactiveRanges', { uri: ed.document.uri.toString() });
    ed.setDecorations(inactiveDeco, ranges.map(r => ({
      range: new vscode.Range(r.range.start.line, r.range.start.character, r.range.end.line, r.range.end.character),
      hoverMessage: r.reason,
    })));
  };
  const dimAll = () => vscode.window.visibleTextEditors.forEach(ed => dim(ed).catch(() => {}));
  let dimTimer = null;
  context.subscriptions.push(
    vscode.window.onDidChangeVisibleTextEditors(dimAll),
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (!/^selinux/.test(e.document.languageId)) return;
      clearTimeout(dimTimer);
      dimTimer = setTimeout(dimAll, 500);
    }),
  );

  client.start().then(() => {
    client.onNotification('selinux/inactiveChanged', dimAll);
    client.onNotification('selinux/checks', (s) => {
      if (!s.total) return;
      checksStatus.text = s.failed ? `$(error) ${s.failed}/${s.total} checks fail` : s.note ? `$(circle-outline) checks: ${s.note}` : `$(pass) ${s.total} checks hold`;
      checksStatus.tooltip = 'SELinux property checks (selinux.checks) against the last build. Click to open.';
      checksStatus.show();
    });
    client.onNotification('selinux/indexing', (p) => {
      if (p.state === 'start') status.text = '$(sync~spin) SELinux: indexing…';
      else {
        const s = p.stats;
        policyTrees = s.trees || [];
        const several = policyTrees.length > 1;
        const active = policyTrees.find(t => t.active);
        status.text = `$(shield) SELinux: ${several && active ? `${active.name} · ` : ''}${count(s.modules, 'module')}, ${count(s.interfaces, 'interface')}`;
        status.tooltip = `${count(s.files, 'file')}, ${count(s.types, 'type')}, ${count(s.classes, 'class')}. Indexed in ${s.ms} ms.` +
          (several ? `\nPolicy tree: ${active ? active.name : '?'} (${policyTrees.length} in this workspace). Click to switch.` : ' Click for details.');
        status.command = several ? 'selinux.selectTree' : 'selinux.showStats';
        explorer.refresh();
        compiled.refresh();
        dimAll();
      }
    });
    client.onNotification('selinux/build', (p) => {
      if (p.state === 'start') { buildStatus(`$(sync~spin) Building ${p.module}…`, 60000); return; }
      if (p.state === 'validating') { buildStatus(`$(sync~spin) ${p.module} compiled (${p.ms} ms); validating link…`, 60000); return; }
      if (p.state === 'baseline') { buildStatus(`$(sync~spin) Building HEAD (${p.short}) of ${p.module} for comparison…`, 120000); return; }
      if (p.state === 'cil') { buildStatus(`$(sync~spin) Building ${p.module} with semodule (CIL)…`, 180000); return; }
      if (p.state === 'linking') { buildStatus(`$(sync~spin) Linking ${p.module} with the installed policy…`, 120000); return; }
      if (p.state === 'linked') {
        buildStatus(p.ok ? `$(check) ${p.module} linked with the installed policy (${(p.ms / 1000).toFixed(1)} s)` : `$(error) ${p.module}: linking with the installed policy failed (see the SELinux output)`, 8000);
        compiled.refresh();
        return;
      }
      const what = p.tree ? `${count(p.packages, 'package')}${p.validated ? ', link validated' : ''}` : '';
      buildOutput.appendLine(`=== ${p.module}: ${p.ok ? 'built' : 'FAILED'} in ${p.ms} ms (${count(p.errors, 'error')}, ${count(p.warnings, 'warning')})${what ? '; ' + what : ''} ===`);
      if (p.tree) buildOutput.appendLine(`Output: ${p.outputDir}${p.policyBin ? `  (kernel policy: ${p.policyBin})` : ''}`);
      buildOutput.appendLine(p.log.trimEnd());
      buildStatus(p.ok ? `$(check) ${p.module} built (${p.ms} ms${what ? ', ' + what : ''})` : `$(error) ${p.module}: build failed, see Problems`, 8000);
      expanded.refresh();
      compiled.refresh(); // a module build is linked with the installed policy when the view (or a check) needs it
      if (p.tree && p.ok) changes.afterBuild();
    });
  });

  context.subscriptions.push(
    vscode.commands.registerCommand('selinux.reindex', async () => {
      await client.sendRequest('selinux/reindex');
    }),
    vscode.commands.registerCommand('selinux.showStats', async () => {
      const s = await client.sendRequest('selinux/stats');
      vscode.window.showInformationMessage(
        `SELinux index: ${count(s.modules, 'module')}, ${count(s.interfaces, 'interface')}, ${count(s.templates, 'template')}, ${count(s.types, 'type')}, ${count(s.classes, 'class')} (${count(s.files, 'file')}).`);
    }),
    vscode.commands.registerCommand('selinux.openLocation', async (p, line, col) => {
      const doc = await vscode.workspace.openTextDocument(p);
      const pos = new vscode.Position(line, col || 0);
      await vscode.window.showTextDocument(doc, { selection: new vscode.Range(pos, pos) });
    }),
    vscode.commands.registerCommand('selinux.findModule', async () => {
      const mods = await client.sendRequest('selinux/modules');
      const pick = await vscode.window.showQuickPick(mods.map(m => ({ label: m.module, description: m.layer, m })), { placeHolder: 'Open SELinux policy module' });
      if (!pick) return;
      const f = pick.m.files.te || pick.m.files.if || pick.m.files.fc;
      vscode.commands.executeCommand('selinux.openLocation', f, 0, 0);
    }),
    vscode.commands.registerCommand('selinux.openCompanion', async (ext) => {
      const ed = vscode.window.activeTextEditor;
      if (!ed) return;
      const p = ed.document.uri.fsPath.replace(/\.(te|if|fc)$/, `.${ext}`);
      try { await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(p)); }
      catch { vscode.window.showWarningMessage(`No ${path.basename(p)} next to this file.`); }
    }),
    vscode.commands.registerCommand('selinux.buildModule', async () => {
      const ed = vscode.window.activeTextEditor && vscode.window.activeTextEditor.document.uri.scheme === 'file' ? vscode.window.activeTextEditor : null;
      // Without a policy editor (e.g. from the Compiled Policy view), build the workspace's tree.
      const target = ed ? ed.document.uri : (vscode.workspace.workspaceFolders || [])[0] && vscode.workspace.workspaceFolders[0].uri;
      if (!target) return;
      if (ed) await ed.document.save();
      const r = await vscode.window.withProgress({ location: { viewId: 'selinuxCompiledPolicy' } },
        () => client.sendRequest('selinux/build', { uri: target.toString(), package: true }));
      if (r.unavailable) { vscode.window.showWarningMessage(r.unavailable); return; }
      if (!r.ok) { buildOutput.show(true); return; }
      if (r.exportError) vscode.window.showWarningMessage(`Built, but copying the outputs failed: ${r.exportError}`);
      let msg;
      if (!r.tree) msg = `Built ${path.basename(r.package)} in ${path.dirname(r.package)}.`;
      else {
        msg = `Built ${r.module}: ${count(r.packages, 'module package')}${r.validated ? ', link validated' : ''} (${(r.ms / 1000).toFixed(1)} s). ` +
          (r.exportDir ? `Copied ${count(r.exportedFiles, 'file')} to ${r.exportDir}.`
            : `Outputs are in ${r.outputDir}, which is removed when VS Code closes; set selinux.build.tree.outputDir to keep them.`);
      }
      const buttons = [...(!r.tree ? ['Install'] : []), ...(ed ? ['Show Expanded Policy'] : []), ...(r.tree ? ['Show Compiled Policy'] : []),
        ...(r.tree && !r.exportDir ? ['Set Output Folder'] : [])];
      const choice = await vscode.window.showInformationMessage(msg, ...buttons);
      if (choice === 'Install') installPackage(r.package);
      if (choice === 'Show Expanded Policy') vscode.commands.executeCommand('selinux.showExpanded', ed.document.uri);
      if (choice === 'Show Compiled Policy') vscode.commands.executeCommand('selinuxCompiledPolicy.focus');
      if (choice === 'Set Output Folder') vscode.commands.executeCommand('workbench.action.openWorkspaceSettings', 'selinux.build.tree.outputDir');
    }),
    vscode.commands.registerCommand('selinux.installModule', async () => {
      const ed = vscode.window.activeTextEditor;
      if (!ed || ed.document.uri.scheme !== 'file') return;
      await ed.document.save();
      // Always package first, so what gets installed matches the sources.
      const r = await client.sendRequest('selinux/build', { uri: ed.document.uri.toString(), package: true });
      if (r.unavailable) { vscode.window.showWarningMessage(r.unavailable); return; }
      if (r.tree) { vscode.window.showWarningMessage('Install Module is for standalone modules. For a full policy, copy its outputs (selinux.build.tree.outputDir) to a test system and install them there.'); return; }
      if (!r.ok) { buildOutput.show(true); vscode.window.showErrorMessage(`${r.module} did not build; fix the errors first.`); return; }
      installPackage(r.package);
    }),
    vscode.commands.registerCommand('selinux.configureFromSpec', async () => {
      const picked = await vscode.window.showOpenDialog({ canSelectMany: false, openLabel: 'Use this spec',
        title: 'selinux-policy.spec (from an unpacked source RPM or a dist-git checkout, next to its modules-*.conf / modules-*.lst files)',
        filters: { 'RPM spec': ['spec'] } });
      if (!picked || !picked.length) return;
      const r = await client.sendRequest('selinux/specBuildConfig', { specPath: picked[0].fsPath });
      if (r.error || !r.configs || !r.configs.length) { vscode.window.showErrorMessage(r.error || 'No %makeCmds policy variants found in that spec.'); return; }
      const pick = await vscode.window.showQuickPick(r.configs.map(c => ({
        label: c.variant, description: c.makeArgs.filter(a => /^(NAME|TYPE|UNK_PERMS)=/.test(a)).join(' '),
        detail: `${Object.keys(c.files).join(', ')}${c.missing.length ? `   ⚠ missing: ${c.missing.map(m => path.basename(m)).join(', ')}` : ''}${(c.notes || []).length ? `   ⚠ ${c.notes.join('; ')}` : ''}`, c,
      })), { placeHolder: 'Policy variant to build' });
      if (!pick) return;
      const conf = vscode.workspace.getConfiguration('selinux');
      const active = policyTrees.find(t => t.active);
      if (policyTrees.length > 1 && active) {
        // Several trees: these settings belong to the active one (selinux.build.trees).
        const per = { ...(conf.get('build.trees') || {}) };
        per[active.key] = { ...(per[active.key] || {}), makeArgs: pick.c.makeArgs, files: pick.c.files };
        await conf.update('build.trees', per, vscode.ConfigurationTarget.Workspace);
      } else {
        await conf.update('build.tree.makeArgs', pick.c.makeArgs, vscode.ConfigurationTarget.Workspace);
        await conf.update('build.tree.files', pick.c.files, vscode.ConfigurationTarget.Workspace);
      }
      const go = await vscode.window.showInformationMessage(
        `${policyTrees.length > 1 && active ? `Build settings for ${active.name}` : 'Workspace build settings'} now match the spec's ${pick.c.variant} build (${count(pick.c.makeArgs.length, 'make variable')}, ${count(Object.keys(pick.c.files).length, 'config file')}).`, 'Build Now');
      if (go) vscode.commands.executeCommand('selinux.buildModule');
    }),
    vscode.commands.registerCommand('selinux.selectTree', async () => {
      const r = await client.sendRequest('selinux/trees');
      if (!r.trees.length) { vscode.window.showInformationMessage('No refpolicy source tree in this workspace.'); return; }
      const pick = await vscode.window.showQuickPick(r.trees.map(t => ({ label: t.name, description: t.active ? 'active' : '', detail: t.root, t })),
        { placeHolder: 'Policy tree to work on (indexed, built and shown in the views)' });
      if (pick) await selectTree(pick.t.root, false);
    }),
    vscode.commands.registerCommand('selinux.refreshCompiled', () => compiled.refresh()),
    vscode.commands.registerCommand('selinux.openChecks', async () => {
      const r = await client.sendRequest('selinux/checksFile');
      if (r.unavailable) { vscode.window.showWarningMessage(r.unavailable); return; }
      if (!r.exists) {
        const go = await vscode.window.showInformationMessage(`No ${path.basename(r.path)} yet. Create one with examples at the tree root?`, 'Create');
        if (!go) return;
        require('fs').writeFileSync(r.path, CHECKS_TEMPLATE);
      }
      await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(r.path));
    }),
    vscode.commands.registerCommand('selinux.transitionGraph', async (arg) => {
      // From a Compiled Policy domain node, a name, the word under the cursor, or a pick.
      let name = arg && arg.key ? arg.key.replace(/^t:/, '') : typeof arg === 'string' ? arg : null;
      const d = await client.sendRequest('selinux/domains');
      if (d.unavailable) { vscode.window.showWarningMessage(d.unavailable); return; }
      if (!name) {
        const ed = vscode.window.activeTextEditor;
        const w = ed && ed.document.getText(ed.document.getWordRangeAtPosition(ed.selection.active, /[A-Za-z0-9_]+/));
        if (w && d.domains.includes(w)) name = w;
      }
      if (!name) {
        const items = d.domains.map(x => ({ label: x }));
        items.sort((a, b) => (b.label === 'init_t') - (a.label === 'init_t'));
        const pick = await vscode.window.showQuickPick(items, { placeHolder: 'Domain to start the transition graph from' });
        if (!pick) return;
        name = pick.label;
      }
      showTransitionGraph(context, name, 'out');
    }),
    vscode.commands.registerCommand('selinux.previewModule', async (arg) => {
      const st = await client.sendRequest('selinux/moduleStates');
      if (st.unavailable) { vscode.window.showWarningMessage(st.unavailable); return; }
      // From the Policy Explorer (module node), a module name, or the active editor's module.
      let name = arg && arg.m ? arg.m.module : typeof arg === 'string' ? arg : null;
      const ed = vscode.window.activeTextEditor;
      const edMod = ed && /\.(te|if|fc)$/.test(ed.document.fileName) ? path.basename(ed.document.fileName).replace(/\.(te|if|fc)$/, '') : null;
      if (!name) {
        const items = st.modules.map(m => ({ label: m.module, description: `${m.state}${m.apps ? ' (APPS_MODS)' : ''}`, m }));
        if (edMod) items.sort((a, b) => (b.label === edMod) - (a.label === edMod));
        const pick = await vscode.window.showQuickPick(items, { placeHolder: 'Module to preview turning off or on', matchOnDescription: true });
        if (!pick) return;
        name = pick.label;
      }
      const cur = st.modules.find(m => m.module === name);
      if (!cur) { vscode.window.showWarningMessage(`${name} is not a module of this tree.`); return; }
      const targets = ['off', 'module', 'base'].filter(t => t !== cur.state && !(cur.state === 'unlisted' && t === 'off'));
      const to = targets.length === 1 ? targets[0] : (await vscode.window.showQuickPick(targets.map(t => ({ label: t, description: t === 'off' ? 'turn it off' : t === 'module' ? 'build it as a loadable module' : 'build it into base' })), { placeHolder: `${name} is ${cur.state}${cur.apps ? ' (forced on by APPS_MODS)' : ''}; preview it as…` }) || {}).label;
      if (!to) return;
      vscode.commands.executeCommand('selinuxModulePreview.focus');
      const p = await vscode.window.withProgress({ location: { viewId: 'selinuxModulePreview' } }, () => preview.run(name, to));
      if (p && p.unavailable) vscode.window.showWarningMessage(p.unavailable);
    }),
    vscode.commands.registerCommand('selinux.applyModulePreview', async () => {
      const p = preview.preview;
      if (!p || !p.apply) return;
      const doc = await vscode.workspace.openTextDocument(p.apply.path);
      const edit = new vscode.WorkspaceEdit();
      if (p.apply.line != null) {
        const line = doc.lineAt(p.apply.line);
        edit.replace(doc.uri, line.range, line.text.replace(/=\s*\w+\s*$/, `= ${p.to}`));
      } else {
        edit.insert(doc.uri, doc.lineAt(doc.lineCount - 1).range.end, `${doc.getText().endsWith('\n') ? '' : '\n'}${p.module} = ${p.to}\n`);
      }
      await vscode.workspace.applyEdit(edit);
      const shown = await vscode.window.showTextDocument(doc);
      if (p.apply.line != null) shown.revealRange(doc.lineAt(p.apply.line).range, vscode.TextEditorRevealType.InCenter);
      if (p.appsMods && p.to === 'off') {
        const go = await vscode.window.showInformationMessage(`${p.module} is also forced on by APPS_MODS. Remove it from selinux.build.tree.makeArgs in the workspace settings? (For CLIP, also remove it from SEPARATE_PKGS in packages/selinux-policy/Makefile.)`, 'Remove from APPS_MODS');
        if (go) {
          const conf = vscode.workspace.getConfiguration('selinux');
          const args = (conf.get('build.tree.makeArgs') || []).map(a => (/^APPS_MODS=/.test(a) ? a.replace(new RegExp(`(^APPS_MODS=|\\s)${p.module}(?=\\s|$)`), '$1').replace(/\s+/g, ' ').replace('= ', '=').trim() : a));
          await conf.update('build.tree.makeArgs', args, vscode.ConfigurationTarget.Workspace);
        }
      } else {
        vscode.window.showInformationMessage(`Set ${p.module} = ${p.to}. Review and save ${path.basename(p.apply.path)}; saving rebuilds.`);
      }
    }),
    vscode.commands.registerCommand('selinux.compareWith', async () => {
      const r = await client.sendRequest('selinux/gitRefs');
      const refItems = (r.unavailable ? [] : [
        { label: 'HEAD', description: 'last commit', p: { base: 'HEAD' } },
        ...r.tags.map(x => ({ label: `$(tag) ${x.name}`, description: `${x.short} · ${x.when}`, detail: x.subject, p: { base: x.name } })),
        ...r.branches.map(x => ({ label: `$(git-branch) ${x.name}`, description: `${x.short} · ${x.when}`, detail: x.subject, p: { base: x.name } })),
        ...r.commits.slice(1).map(x => ({ label: `$(git-commit) ${x.short}`, description: x.when, detail: x.subject, p: { base: x.short } })),
      ]);
      const items = [
        ...refItems,
        { label: '$(edit) Enter a ref…', description: 'branch, tag, commit, HEAD~3, …', kind: 'enter' },
        ...(r.unavailable ? [] : [{ label: '$(git-compare) Between two refs…', description: 'e.g. two release tags; leaves the working tree out', kind: 'two' }]),
        { label: '$(save) Saved build…', description: 'a directory exported with selinux.build.tree.outputDir', kind: 'saved' },
      ];
      const pick = await vscode.window.showQuickPick(items, { placeHolder: 'Compare the working tree\'s build with…', matchOnDescription: true, matchOnDetail: true });
      if (!pick) return;
      let params = pick.p;
      const pickRef = async (placeHolder) => {
        const q = await vscode.window.showQuickPick([...refItems, { label: '$(edit) Enter a ref…', kind: 'enter' }], { placeHolder, matchOnDescription: true, matchOnDetail: true });
        if (!q) return null;
        if (q.kind === 'enter') return vscode.window.showInputBox({ prompt: 'Git ref (branch, tag, commit, HEAD~3, …)' });
        return q.p.base;
      };
      if (pick.kind === 'enter') {
        const ref = await vscode.window.showInputBox({ prompt: 'Git ref to compare the working tree with (branch, tag, commit, HEAD~3, …)' });
        if (!ref) return;
        params = { base: ref.trim() };
      } else if (pick.kind === 'two') {
        const base = await pickRef('Base (older) ref');
        if (!base) return;
        const target = await pickRef(`Compare ${base} with… (newer ref)`);
        if (!target) return;
        params = { base, target };
      } else if (pick.kind === 'saved') {
        const dir = await vscode.window.showOpenDialog({ canSelectFiles: false, canSelectFolders: true, openLabel: 'Compare with this build', title: 'Directory with an exported build (policy.bin, build-info.json)' });
        if (!dir || !dir.length) return;
        params = { saved: dir[0].fsPath };
      }
      vscode.commands.executeCommand('selinuxChanges.focus');
      const d = await vscode.window.withProgress({ location: { viewId: 'selinuxChanges' } }, () => changes.compareWith(params));
      if (d && d.unavailable) vscode.window.showWarningMessage(d.unavailable);
    }),
    vscode.commands.registerCommand('selinux.compareInstalled', async () => {
      const r = await client.sendRequest('selinux/installedPolicies');
      if (!r.policies.length) { vscode.window.showWarningMessage('No installed policy found under /etc/selinux/*/policy on this host.'); return; }
      let name = (r.policies.find(p => p.name === r.buildName) || r.policies.find(p => p.active) || r.policies[0]).name;
      if (r.policies.length > 1) {
        const pick = await vscode.window.showQuickPick(r.policies.map(p => ({ label: p.name, description: `${p.policy}${p.active ? ' · active' : ''}${p.name === r.buildName ? ' · same NAME as the build' : ''}` })),
          { placeHolder: `Installed policy to compare the build (NAME=${r.buildName}) with` });
        if (!pick) return;
        name = pick.label;
      }
      vscode.commands.executeCommand('selinuxChanges.focus');
      const d = await vscode.window.withProgress({ location: { viewId: 'selinuxChanges' } }, () => changes.compareInstalled(name));
      if (d && d.unavailable) vscode.window.showWarningMessage(d.unavailable);
    }),
    vscode.commands.registerCommand('selinux.compareHead', async () => {
      vscode.commands.executeCommand('selinuxChanges.focus');
      const d = await vscode.window.withProgress({ location: { viewId: 'selinuxChanges' } }, () => changes.compare());
      if (d && d.unavailable) vscode.window.showWarningMessage(d.unavailable);
    }),
    vscode.commands.registerCommand('selinux.findInPolicy', async () => {
      await compiled.getChildren();
      const m = compiled.model;
      if (!m) { vscode.window.showWarningMessage(compiled.message ? compiled.message.unavailable : 'No compiled policy yet.'); return; }
      const items = [];
      const add = (kind, icon, list, detail) => { for (const e of list) items.push({ label: `$(${icon}) ${e.name}`, description: `${kind}${e.loc && e.loc.m ? ' · ' + e.loc.m : ''}`, detail: detail ? detail(e) : undefined, kind, e }); };
      add('type', 'symbol-class', m.types, t => t.attrs.join(' '));
      add('attribute', 'symbol-interface', m.attributes);
      add('role', 'organization', m.roles);
      add('user', 'person', m.users);
      add('bool', 'symbol-boolean', m.bools);
      add('class', 'symbol-structure', m.classes);
      const pick = await vscode.window.showQuickPick(items, { placeHolder: `Find in compiled policy (${items.length} elements)`, matchOnDescription: true });
      if (!pick) return;
      const n = compiled.canonical(pick.kind, pick.e.name);
      if (n) await compiledView.reveal(n, { select: true, focus: false, expand: true });
      if (pick.e.loc) vscode.commands.executeCommand('selinux.openLocation', pick.e.loc.p, pick.e.loc.l, pick.e.loc.c);
    }),
    vscode.commands.registerCommand('selinux.showExpanded', async (srcUri) => {
      const src = srcUri || (vscode.window.activeTextEditor && vscode.window.activeTextEditor.document.uri);
      if (!src || src.scheme !== 'file') return;
      const mod = path.basename(src.fsPath).replace(/\.(te|if|fc)$/, '');
      const uri = vscode.Uri.from({ scheme: EXPANDED_SCHEME, path: `/${mod} (expanded)`, query: src.toString() });
      const doc = await vscode.workspace.openTextDocument(uri);
      await vscode.languages.setTextDocumentLanguage(doc, 'selinux');
      await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
    }),
    vscode.workspace.registerTextDocumentContentProvider(EXPANDED_SCHEME, expanded),
    vscode.commands.registerCommand('selinux.openTe', () =>vscode.commands.executeCommand('selinux.openCompanion', 'te')),
    vscode.commands.registerCommand('selinux.openIf', () => vscode.commands.executeCommand('selinux.openCompanion', 'if')),
    vscode.commands.registerCommand('selinux.openFc', () => vscode.commands.executeCommand('selinux.openCompanion', 'fc')),
  );
}

/* ---------------- domain transition graph (webview) ---------------- */

let transitionPanel = null;

/** Open (or retarget) the transition graph panel at `root`, `dir` = 'out' | 'in'. */
function showTransitionGraph(context, root, dir = 'out') {
  if (transitionPanel) {
    transitionPanel.reveal(vscode.ViewColumn.Active);
    transitionPanel.webview.postMessage({ cmd: 'init', root, dir, domains: transitionPanel.domains });
    return;
  }
  const panel = vscode.window.createWebviewPanel('selinuxTransitions', `Transitions: ${root}`, vscode.ViewColumn.Active,
    { enableScripts: true, retainContextWhenHidden: true, localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'media')] });
  transitionPanel = panel;
  const nonce = [...Array(24)].map(() => Math.random().toString(36)[2]).join('');
  const script = panel.webview.asWebviewUri(vscode.Uri.joinPath(context.extensionUri, 'media', 'transitions.js'));
  panel.webview.html = `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${panel.webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
<style>
  body { font-family: var(--vscode-font-family); font-size: var(--vscode-font-size); color: var(--vscode-foreground); background: var(--vscode-editor-background); margin: 0; }
  #bar { position: sticky; top: 0; z-index: 1; display: flex; flex-wrap: wrap; gap: 14px; align-items: center; padding: 8px 12px;
    background: var(--vscode-editorWidget-background); border-bottom: 1px solid var(--vscode-panel-border); }
  #title { font-weight: 600; }
  input[type=text] { background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border, transparent); padding: 3px 6px; }
  .muted { opacity: .75; }
  .legend svg { vertical-align: middle; }
  #wrap { overflow: auto; }
  .node { cursor: pointer; }
  .node rect { fill: var(--vscode-editorWidget-background); stroke: var(--vscode-editorWidget-border, #888); }
  .node.open rect { stroke: var(--vscode-focusBorder); stroke-width: 1.5; }
  .node.root rect { fill: var(--vscode-button-background); }
  .node.root text { fill: var(--vscode-button-foreground); }
  .node text { fill: var(--vscode-foreground); font-size: 12px; }
  .node:hover rect { stroke: var(--vscode-focusBorder); }
  .edge { fill: none; stroke: var(--vscode-charts-blue, #3794ff); stroke-width: 1.2; opacity: .85; }
  .edge.cond { stroke: var(--vscode-charts-orange, #d18616); }
  .edge:hover { stroke-width: 2.5; opacity: 1; }
  .arrowhead { fill: var(--vscode-foreground); opacity: .7; }
</style></head><body>
<div id="bar">
  <span id="title"></span>
  <label>Root <input id="root" type="text" list="domains" size="28" spellcheck="false"></label><datalist id="domains"></datalist>
  <label><input type="radio" name="dir" value="out" checked> transitions from</label>
  <label><input type="radio" name="dir" value="in"> who can enter</label>
  <label>Filter <input id="filter" type="text" size="18" spellcheck="false" placeholder="name contains…"></label>
  <span class="legend muted">
    <svg width="30" height="8"><line x1="0" y1="4" x2="30" y2="4" stroke="var(--vscode-charts-blue,#3794ff)"/></svg> automatic
    <svg width="30" height="8"><line x1="0" y1="4" x2="30" y2="4" stroke="var(--vscode-charts-blue,#3794ff)" stroke-dasharray="6 4"/></svg> explicit (setexec)
    <svg width="30" height="8"><line x1="0" y1="4" x2="30" y2="4" stroke="var(--vscode-charts-blue,#3794ff)" stroke-dasharray="2 3"/></svg> dynamic
    <svg width="30" height="8"><line x1="0" y1="4" x2="30" y2="4" stroke="var(--vscode-charts-orange,#d18616)"/></svg> boolean-controlled
  </span>
  <span id="status" class="muted"></span>
  <span class="muted">click: expand · double-click: source · alt-click: make root · hover an arrow for entrypoints</span>
</div>
<div id="wrap"><svg id="graph" xmlns="http://www.w3.org/2000/svg"></svg></div>
<script nonce="${nonce}" src="${script}"></script>
</body></html>`;
  panel.webview.onDidReceiveMessage(async (m) => {
    if (m.cmd === 'ready') {
      const d = await client.sendRequest('selinux/domains');
      panel.domains = d.domains || [];
      if (d.unavailable) vscode.window.showWarningMessage(d.unavailable);
      panel.webview.postMessage({ cmd: 'init', root, dir, domains: panel.domains });
    } else if (m.cmd === 'expand') {
      const r = await client.sendRequest('selinux/transitions', { name: m.name, dir: m.dir });
      if (r.unavailable) panel.webview.postMessage({ cmd: 'error', name: m.name, msg: r.unavailable });
      else panel.webview.postMessage({ cmd: 'transitions', name: m.name, dir: m.dir, transitions: r.transitions, locs: r.locs });
    } else if (m.cmd === 'rooted') {
      panel.title = m.dir === 'in' ? `Entering: ${m.root}` : `Transitions: ${m.root}`;
    } else if (m.cmd === 'open') {
      if (m.loc) vscode.commands.executeCommand('selinux.openLocation', m.loc.p, m.loc.l, m.loc.c);
      else vscode.window.showInformationMessage(`No source declaration found for ${m.name}.`);
    }
  }, undefined, context.subscriptions);
  panel.onDidDispose(() => { transitionPanel = null; }, undefined, context.subscriptions);
}

/* ---------------- expanded policy (read-only m4 output) ---------------- */

const EXPANDED_SCHEME = 'selinux-expanded';

class ExpandedPolicyProvider {
  constructor() {
    this._emitter = new vscode.EventEmitter();
    this.onDidChange = this._emitter.event;
  }
  /** Re-render open views after a build. */
  refresh() {
    for (const d of vscode.workspace.textDocuments) if (d.uri.scheme === EXPANDED_SCHEME) this._emitter.fire(d.uri);
  }
  async provideTextDocumentContent(uri) {
    const r = await client.sendRequest('selinux/expandedPolicy', { uri: uri.query });
    if (r.unavailable) return `# ${r.unavailable}\n`;
    return `# ${r.module}: policy as m4 expanded it in the last build (read-only, refreshes on rebuild).\n` +
      `# Each "────" header names the source line that produced the statements below it.\n\n${r.text}`;
  }
}

/* ---------------- Compiled Policy tree (what the last build produced) ---------------- */

/*
 * Every node is { id, item, parent, kids() }. Elements can be reached along
 * many paths (a type under its module, its attributes, roles, transitions...),
 * so ids are path-based; `reveal()` uses the canonical path under the
 * top-level groups.
 */
class CompiledPolicyView {
  /** `request` is injectable so tests can drive the tree without VS Code. */
  constructor(request) {
    this.request = request || ((method, params) => client.sendRequest(method, params));
    this.ready = request ? () => true : () => !!client && client.isRunning();
    this._emitter = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._emitter.event;
    this.model = null;
    this.message = null;
    this.roots = null;
  }

  /** Forget everything loaded, including a "build first" message, and reload on next render. */
  refresh() { this.model = null; this.message = null; this.roots = null; this._emitter.fire(); }

  async load() {
    if (this.model || this.message) return;
    const m = await this.request('selinux/policyModel');
    if (m.unavailable) { this.message = m; return; }
    this.model = m;
    // Indexes for relationships.
    m.typeByName = new Map(m.types.map(t => [t.name, t]));
    m.attrByName = new Map(m.attributes.map(a => [a.name, a]));
    m.roleByName = new Map(m.roles.map(r => [r.name, r]));
    m.members = new Map(m.attributes.map(a => [a.name, []]));
    for (const t of m.types) for (const a of t.attrs) if (m.members.has(a)) m.members.get(a).push(t.name);
    m.rolesOf = new Map();
    for (const r of m.roles) for (const t of r.types) { if (!m.rolesOf.has(t)) m.rolesOf.set(t, []); m.rolesOf.get(t).push(r.name); }
    m.transOut = new Map(); m.transIn = new Map();
    const add = (map, k, v) => { if (!map.has(k)) map.set(k, []); map.get(k).push(v); };
    for (const x of m.transitions) { add(m.transOut, x.source, x); add(m.transIn, x.result, x); }
    m.byModule = new Map();
    const noSource = m.linked ? '(installed policy)' : '(no source found)';
    const modOf = (e, kind) => { const mod = (e.loc && e.loc.m) || noSource; if (!m.byModule.has(mod)) m.byModule.set(mod, { types: [], attributes: [], bools: [], roles: [] }); m.byModule.get(mod)[kind].push(e); };
    for (const t of m.types) modOf(t, 'types');
    for (const a of m.attributes) modOf(a, 'attributes');
    for (const b of m.bools) modOf(b, 'bools');
    for (const r of m.roles) modOf(r, 'roles');
  }

  getTreeItem(n) { return n.item; }
  getParent(n) { return n.parent; }

  async getChildren(n) {
    if (!this.ready()) return [];
    if (n) return n.kids ? n.kids() : [];
    await this.load();
    if (this.message) {
      const item = new vscode.TreeItem(this.message.unavailable);
      item.iconPath = new vscode.ThemeIcon(this.message.needsBuild ? 'tools' : 'info');
      if (this.message.needsBuild) item.command = { command: 'selinux.buildModule', title: 'Build' };
      item.tooltip = this.message.needsBuild ? 'Click to build the policy' : undefined;
      return [{ id: 'msg', item }];
    }
    if (!this.roots) this.roots = this.topLevel();
    return this.roots;
  }

  /* ----- node builders ----- */

  node(parent, key, label, opts = {}) {
    const id = `${parent ? parent.id : ''}/${key}`;
    const item = new vscode.TreeItem(label, opts.kids ? (opts.expanded ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.Collapsed) : vscode.TreeItemCollapsibleState.None);
    item.id = id;
    if (opts.context) item.contextValue = opts.context;
    if (opts.desc !== undefined) item.description = String(opts.desc);
    if (opts.icon) item.iconPath = new vscode.ThemeIcon(opts.icon);
    if (opts.tooltip) item.tooltip = opts.tooltip;
    if (opts.loc) {
      item.command = { command: 'selinux.openLocation', title: 'Go to declaration', arguments: [opts.loc.p, opts.loc.l, opts.loc.c] };
      item.resourceUri = undefined;
    }
    const n = { id, item, parent, key };
    if (opts.kids) n.kids = () => opts.kids(n);
    return n;
  }

  group(parent, key, label, list, make, icon = 'list-tree') {
    return this.node(parent, key, label, { desc: list.length, icon, kids: (n) => list.map(x => make(n, x)) });
  }

  where(loc) {
    if (!loc) return 'No source declaration found in the index.';
    return `${loc.via ? `Generated by ${loc.via}(…) at ` : 'Declared in '}${vscode.workspace.asRelativePath(loc.p)}:${loc.l + 1}${loc.m ? ` (module ${loc.m})` : ''}`;
  }

  topLevel() {
    const m = this.model;
    const domains = m.types.filter(t => t.attrs.includes('domain'));
    const byName = (a, b) => a.name.localeCompare(b.name);
    const sorted = (l) => [...l].sort(byName);
    const header = this.node(null, 'hdr', m.linked ? `${m.linked.module} + installed policy.${m.version}` : `policy.${m.version}${m.mls ? ' · MLS/MCS' : ''} · unknown=${m.handleUnknown}`, {
      icon: 'shield', desc: new Date(m.builtAt).toLocaleTimeString(),
      tooltip: `${m.linked ? `The module as built, linked with ${m.linked.kernelPolicy}${m.linked.installed ? ` (which already has a copy of ${m.linked.module}: its installed rules are included too)` : ''}\n` : ''}${m.bin}\n${Object.entries(m.counts).map(([k, v]) => `${k}: ${v}`).join('\n')}`,
    });
    return [
      header,
      this.node(null, 'modules', 'Modules', { desc: m.byModule.size, icon: 'package', kids: (n) =>
        [...m.byModule.keys()].sort().map(mod => this.moduleNode(n, mod)) }),
      this.group(null, 'users', 'Users', sorted(m.users), (n, u) => this.userNode(n, u), 'person'),
      this.group(null, 'roles', 'Roles', sorted(m.roles), (n, r) => this.roleNode(n, r), 'organization'),
      this.group(null, 'domains', 'Domains', sorted(domains), (n, t) => this.typeNode(n, t), 'server-process'),
      this.group(null, 'types', 'Types', sorted(m.types), (n, t) => this.typeNode(n, t), 'symbol-class'),
      this.group(null, 'attributes', 'Attributes', sorted(m.attributes), (n, a) => this.attrNode(n, a), 'symbol-interface'),
      this.group(null, 'booleans', 'Booleans', sorted(m.bools), (n, b) => this.boolNode(n, b), 'symbol-boolean'),
      this.group(null, 'classes', 'Classes', sorted(m.classes), (n, c) => this.classNode(n, c), 'symbol-structure'),
    ];
  }

  moduleNode(parent, mod) {
    const e = this.model.byModule.get(mod);
    const parts = [['Types', e.types, (n, t) => this.typeNode(n, t), 'symbol-class'], ['Attributes', e.attributes, (n, a) => this.attrNode(n, a), 'symbol-interface'],
      ['Booleans', e.bools, (n, b) => this.boolNode(n, b), 'symbol-boolean'], ['Roles', e.roles, (n, r) => this.roleNode(n, r), 'organization']].filter(x => x[1].length);
    return this.node(parent, `m:${mod}`, mod, { icon: 'package', desc: `${e.types.length} types`,
      kids: (n) => parts.map(([label, list, make, icon]) => this.group(n, label, label, [...list].sort((a, b) => a.name.localeCompare(b.name)), make, icon)) });
  }

  typeRef(parent, name, desc) {
    const t = this.model.typeByName.get(name);
    if (t) return this.typeNode(parent, t, desc);
    const a = this.model.attrByName.get(name);
    if (a) return this.attrNode(parent, a);
    return this.node(parent, `x:${name}`, name, { icon: 'question', desc });
  }

  typeNode(parent, t, desc) {
    const m = this.model;
    const isDomain = t.attrs.includes('domain');
    return this.node(parent, `t:${t.name}`, t.name, {
      icon: isDomain ? 'server-process' : 'symbol-class', loc: t.loc, context: isDomain ? 'domain' : 'type',
      desc: desc !== undefined ? desc : (t.loc && t.loc.m) || '',
      tooltip: `${isDomain ? 'domain' : 'type'} ${t.name}${t.permissive ? ' (permissive)' : ''}\n${this.where(t.loc)}`,
      kids: (n) => {
        const out = [];
        if (t.attrs.length) out.push(this.group(n, 'attrs', 'Attributes', t.attrs, (k, a) => this.typeRef(k, a), 'symbol-interface'));
        if (t.aliases.length) out.push(this.node(n, 'aliases', 'Aliases', { desc: t.aliases.join(', '), icon: 'link' }));
        const roles = m.rolesOf.get(t.name) || [];
        if (roles.length) out.push(this.group(n, 'roles', 'Roles', roles, (k, r) => this.roleNode(k, m.roleByName.get(r)), 'organization'));
        const outT = m.transOut.get(t.name) || [];
        if (outT.length) out.push(this.group(n, 'out', 'Transitions to', outT, (k, x) => this.typeRef(k, x.result, `via ${x.entry}`), 'arrow-right'));
        const inT = m.transIn.get(t.name) || [];
        if (inT.length) out.push(this.group(n, 'in', 'Entered from', inT, (k, x) => this.typeRef(k, x.source, `via ${x.entry}`), 'arrow-left'));
        return out.concat(this.ruleGroups(n, t.name));
      },
    });
  }

  attrNode(parent, a) {
    const members = (this.model.members.get(a.name) || []).slice().sort();
    return this.node(parent, `a:${a.name}`, a.name, { icon: 'symbol-interface', loc: a.loc, desc: `${members.length} types`,
      tooltip: `attribute ${a.name}\n${this.where(a.loc)}`,
      kids: (n) => [...(members.length ? [this.group(n, 'members', 'Member types', members, (k, t) => this.typeRef(k, t), 'symbol-class')] : []),
        ...this.ruleGroups(n, a.name)] });
  }

  /* ----- rules (queried on demand from the last build) ----- */

  /** "Can access" / "Accessed by" / "Other rules" groups for a type or attribute. */
  ruleGroups(parent, name) {
    const OTHER = ['dontaudit', 'auditallow', 'type_transition', 'type_change', 'type_member'];
    return [
      this.rulesNode(parent, 'r-src', 'Can access', name, 'source', ['allow'], r => r.t, 'arrow-right'),
      this.rulesNode(parent, 'r-tgt', 'Accessed by', name, 'target', ['allow'], r => r.s, 'arrow-left'),
      this.rulesNode(parent, 'r-oth', 'Other rules', name, 'source', OTHER, r => r.rt, 'list-unordered'),
    ];
  }

  rulesNode(parent, key, label, name, dir, kinds, groupOf, icon) {
    return this.node(parent, key, label, { icon, tooltip: `${label}: rules from the last build where ${name} (or one of its attributes) is the ${dir}.`,
      kids: async (n) => {
        const r = await this.request('selinux/typeRules', { name, dir, kinds });
        if (r.unavailable) return [this.node(n, 'na', r.unavailable, { icon: 'info' })];
        if (!r.rules.length) return [this.node(n, 'none', 'none', { icon: 'circle-slash' })];
        n.item.description = String(r.count);
        const groups = new Map();
        for (const rule of r.rules) { const g = groupOf(rule); if (!groups.has(g)) groups.set(g, []); groups.get(g).push(rule); }
        return [...groups.keys()].sort().map((g) => {
          const ref = this.model.typeByName.get(g) || this.model.attrByName.get(g);
          return this.node(n, `g:${g}`, g, { icon: this.model.attrByName.has(g) ? 'symbol-interface' : kinds.includes('allow') ? 'symbol-class' : 'symbol-event',
            desc: groups.get(g).length, loc: ref && ref.loc, tooltip: ref ? this.where(ref.loc) : undefined,
            kids: (k) => groups.get(g).map((rule, i) => this.ruleNode(k, rule, i, name, dir)) });
        });
      } });
  }

  ruleNode(parent, r, i, name, dir) {
    const own = dir === 'source' ? r.s : r.t;
    const isTT = /^type_/.test(r.rt);
    const perms = isTT ? `→ ${r.perms[0]}` : `{ ${r.perms.join(' ')} }`;
    const label = `${r.rt === 'allow' ? '' : r.rt + ' '}${dir === 'source' && r.rt !== 'allow' ? r.t + ':' : ''}${r.c} ${perms}`;
    const via = own !== name && own !== 'self' ? `via ${own}` : '';
    const text = `${r.rt} ${r.s} ${r.t}:${r.c} ${isTT ? r.perms[0] : `{ ${r.perms.join(' ')} }`};`;
    return this.node(parent, `rule:${i}`, label, {
      icon: r.rt === 'allow' ? 'pass' : r.rt === 'dontaudit' ? 'mute' : isTT ? 'arrow-swap' : 'eye',
      desc: [via, r.cond ? `[${r.cond}]` : ''].filter(Boolean).join(' '),
      tooltip: `${text}${r.cond ? `\nonly when ${r.cond}` : ''}\n\nExpand to see the source statements that produce it.`,
      kids: async (n) => {
        const x = await this.request('selinux/ruleOrigins', { rule: r });
        const out = x.origins.map((o, j) => this.node(n, `o:${j}`, `${vscode.workspace.asRelativePath(o.path)}:${o.line + 1}`, {
          icon: 'go-to-file', loc: { p: o.path, l: o.line, c: 0 }, desc: o.via ? `via ${o.via}` : o.text,
          tooltip: `${o.text}${o.chain && o.chain.length ? `\n\nthrough ${o.chain.join(' → ')}` : ''}` }));
        if (x.more) out.push(this.node(n, 'more', `… ${x.more} more statements also produce this`, { icon: 'ellipsis' }));
        if (!out.length) out.push(this.node(n, 'none', 'no source statement found', { icon: 'question' }));
        return out;
      },
    });
  }

  roleNode(parent, r) {
    const m = this.model;
    const switchTo = (m.roleAllows || []).filter(a => a.source === r.name).map(a => a.target);
    const trans = (m.roleTransitions || []).filter(x => x.source === r.name);
    const users = m.users.filter(u => u.roles.includes(r.name));
    return this.node(parent, `r:${r.name}`, r.name, { icon: 'organization', loc: r.loc, desc: `${r.types.length} types · ${users.length} user${users.length === 1 ? '' : 's'}`,
      tooltip: `role ${r.name}\n${this.where(r.loc)}`,
      kids: (n) => [
        ...(r.types.length ? [this.group(n, 'types', 'Types', r.types, (k, t) => this.typeRef(k, t), 'symbol-class')] : []),
        ...(switchTo.length ? [this.group(n, 'allow', 'May switch to', switchTo, (k, x) => this.roleNode(k, m.roleByName.get(x) || { name: x, types: [] }), 'arrow-swap')] : []),
        ...(trans.length ? [this.group(n, 'rtrans', 'Role transitions', trans, (k, x) => this.node(k, `rt:${x.target}:${x.result}`, `${x.target} → ${x.result}`,
          { icon: 'arrow-right', desc: `on executing (${x.class})`, tooltip: `role_transition ${x.source} ${x.target}:${x.class} ${x.result};\nRunning ${x.target} from role ${x.source} switches to role ${x.result}.` }), 'arrow-right')] : []),
        ...(users.length ? [this.group(n, 'users', 'Users', users.map(u => u), (k, u) => this.userNode(k, u), 'person')] : []),
      ] });
  }

  userNode(parent, u) {
    const logins = u.logins || [];
    return this.node(parent, `u:${u.name}`, u.name, { icon: 'person', loc: u.loc, desc: [u.range, logins.length ? `${logins.length} login mapping${logins.length > 1 ? 's' : ''}` : ''].filter(Boolean).join(' · '),
      tooltip: `user ${u.name}${u.range ? `\nrange ${u.range}, default level ${u.level}` : ''}${logins.length ? `\nLinux logins: ${logins.map(x => x.login).join(', ')}` : ''}\n${this.where(u.loc)}`,
      kids: (n) => [
        this.group(n, 'roles', 'Roles', u.roles, (k, r) => this.roleNode(k, this.model.roleByName.get(r) || { name: r, types: [] }), 'organization'),
        ...(logins.length ? [this.group(n, 'logins', 'Linux logins (seusers)', logins, (k, x) => this.node(k, `login:${x.login}`, x.login === '__default__' ? '__default__ (every other login)' : x.login,
          { icon: 'account', desc: x.range || '', loc: x.loc, tooltip: `${x.login}:${x.user}${x.range ? ':' + x.range : ''}\n${vscode.workspace.asRelativePath(x.loc.p)}:${x.loc.l + 1}` }), 'account')] : []),
      ] });
  }

  boolNode(parent, b) {
    return this.node(parent, `b:${b.name}`, b.name, { icon: 'symbol-boolean', loc: b.loc, desc: b.state ? 'true' : 'false',
      tooltip: `boolean ${b.name} (default ${b.state})\n${this.where(b.loc)}` });
  }

  classNode(parent, c) {
    const perms = [...c.perms, ...c.inherited].sort();
    return this.node(parent, `c:${c.name}`, c.name, { icon: 'symbol-structure', loc: c.loc, desc: `${perms.length} permissions`,
      tooltip: `class ${c.name}${c.common ? ` inherits ${c.common}` : ''}`,
      kids: (n) => perms.map(p => this.node(n, `p:${p}`, p, { icon: 'symbol-enum-member', desc: c.inherited.includes(p) ? `from ${c.common}` : '' })) });
  }

  /** Canonical node for an element (for reveal): under its top-level group. */
  canonical(kind, name) {
    if (!this.roots) return null;
    const groupKey = { type: 'types', attribute: 'attributes', role: 'roles', user: 'users', bool: 'booleans', class: 'classes' }[kind];
    const g = this.roots.find(r => r.key === groupKey);
    return g && g.kids().find(k => k.key.endsWith(`:${name}`));
  }
}

/* ---------------- Changes since HEAD (compiled policy diff, traced to source) ---------------- */

class ChangesView {
  /** `request` is injectable so tests can drive the tree without VS Code. */
  constructor(request) {
    this.request = request || ((method, params) => client.sendRequest(method, params));
    this._emitter = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._emitter.event;
    this.diff = null;      // last result
    this.wanted = false;   // the user asked for a comparison; refresh it after builds
    this.loading = false;
  }

  /** Run (or re-run) the comparison with HEAD. */
  compare() { return this.compareWith({ base: 'HEAD' }); }

  /**
   * Compare { base: ref | saved: dir, target: ref | null (working tree) }.
   * Refreshed after builds when the working tree is one side.
   */
  async compareWith(params) {
    this.mode = 'ref';
    this.params = params;
    this.wanted = !params.target;
    this.loading = true;
    this._emitter.fire();
    try { this.diff = await this.request('selinux/policyDiff', params); } finally { this.loading = false; }
    this._emitter.fire();
    return this.diff;
  }

  /** Compare a semodule (CIL) build of the tree with an installed policy. */
  async compareInstalled(name) {
    this.mode = 'installed';
    this.wanted = false; // a CIL rebuild takes a while: refresh on request only
    this.loading = true;
    this._emitter.fire();
    try { this.diff = await this.request('selinux/compareInstalled', { name }); } finally { this.loading = false; }
    this._emitter.fire();
    return this.diff;
  }

  /** After a build: refresh only if a comparison with HEAD is being shown. */
  afterBuild() { if (this.wanted && this.mode === 'ref' && !this.loading) this.compareWith(this.params).catch(() => {}); }

  getTreeItem(n) { return n.item; }

  item(label, opts = {}) {
    const it = new vscode.TreeItem(label, opts.kids ? (opts.expanded ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.Collapsed) : vscode.TreeItemCollapsibleState.None);
    if (opts.desc !== undefined) it.description = String(opts.desc);
    if (opts.icon) it.iconPath = new vscode.ThemeIcon(opts.icon, opts.color ? new vscode.ThemeColor(opts.color) : undefined);
    if (opts.tooltip) it.tooltip = opts.tooltip;
    if (opts.command) it.command = opts.command;
    return { item: it, kids: opts.kids };
  }

  /** A source statement that produces a change; HEAD-side ones open the HEAD copy. */
  origin(o, prefix = '') {
    const file = o.head ? o.real : o.path;
    const label = `${prefix}${vscode.workspace.asRelativePath(file)}:${o.line + 1}${o.head ? ` (${o.ref || 'HEAD'})` : ''}`;
    const because = o.because || [];
    return this.item(label, {
      desc: o.via ? `via ${o.via}` : o.text,
      icon: o.head ? 'history' : 'go-to-file',
      tooltip: `${o.text}${o.chain && o.chain.length ? `\n\nthrough ${o.chain.join(' → ')}` : ''}${o.head ? `\n\nAs of ${o.ref || 'HEAD'}; opens that version of the file.` : ''}`,
      command: { command: 'selinux.openLocation', title: 'Open', arguments: [o.path, o.line, 0] },
      kids: because.length ? () => because.map(b => this.origin(b, 'because: ')) : undefined,
    });
  }

  explained(x, sign) {
    if (!x) return [];
    const out = x.origins.map(o => this.origin(o, sign));
    if (x.more) out.push(this.item(`… ${x.more} more statement${x.more > 1 ? 's' : ''} also produce this`, { icon: 'ellipsis' }));
    if (!x.origins.length && x.noSource) out.push(this.item(`${sign}only in the installed policy (no sources to trace)`, { icon: 'server', tooltip: 'This comes from the policy installed on the host: e.g. a separately packaged module (container-selinux, cockpit, …), a local module, or a local customization (semanage / setsebool -P).' }));
    else if (!x.origins.length) out.push(this.item(`${sign}no source statement found`, { icon: 'question', tooltip: 'The rule changed, but no single statement in the build output matches it (e.g. it comes from an attribute rule whose membership changed elsewhere, or uses a complement/wildcard).' }));
    return out;
  }

  ruleNode(r) {
    const icon = { added: 'diff-added', removed: 'diff-removed', modified: 'diff-modified' }[r.kind];
    const color = { added: 'gitDecoration.addedResourceForeground', removed: 'gitDecoration.deletedResourceForeground', modified: 'gitDecoration.modifiedResourceForeground' }[r.kind];
    const perms = [...r.add.map(p => `+${p}`), ...r.del.map(p => `−${p}`)].join(' ');
    const cond = r.cond ? `  [${r.cond}]` : '';
    return this.item(`${r.rt} ${r.s} ${r.t}:${r.c}`, {
      icon, color, desc: perms + cond,
      tooltip: `${r.kind} ${r.rt} ${r.s} ${r.t}:${r.c}${cond}\n${r.add.length ? `added: ${r.add.join(' ')}\n` : ''}${r.del.length ? `removed: ${r.del.join(' ')}\n` : ''}${r.had.length ? `unchanged: ${r.had.join(' ')}` : ''}`,
      kids: () => [...this.explained(r.addFrom, r.del.length ? '+ ' : ''), ...this.explained(r.delFrom, '− ')],
    });
  }

  async getChildren(n) {
    if (n) return n.kids ? n.kids() : [];
    if (this.loading) {
      const p = this.params || {};
      const what = this.mode === 'installed' ? 'Building with semodule (CIL) and comparing with the installed policy…'
        : `Comparing ${p.saved ? 'with a saved build' : `${p.base || 'HEAD'} with ${p.target || 'the working tree'}`}… (builds committed trees the first time)`;
      return [this.item(what, { icon: 'sync~spin' })];
    }
    const d = this.diff;
    if (!d) return [
      this.item('Compare the last build with HEAD', { icon: 'git-compare', command: { command: 'selinux.compareHead', title: 'Compare' }, tooltip: 'Build HEAD with the same settings and show what your changes add or remove in the compiled policy.' }),
      this.item('Compare with a branch, tag, commit or saved build…', { icon: 'git-branch', command: { command: 'selinux.compareWith', title: 'Compare' }, tooltip: 'e.g. what changed since the last release tag, or between two tags.' }),
      this.item('Compare the build with the installed policy', { icon: 'server', command: { command: 'selinux.compareInstalled', title: 'Compare' }, tooltip: 'Build the policy the way an installed system does (semodule, CIL) and show what would change on this host if you installed it.' }),
    ];
    if (d.unavailable) return [this.item(d.unavailable, { icon: 'info', command: { command: this.mode === 'installed' ? 'selinux.compareInstalled' : 'selinux.compareWith', title: 'Compare again' } })];
    if (this.mode === 'installed') {
      const out = [
        this.item(`vs installed ${d.installed.name}`, { icon: 'server', desc: d.installed.policy,
          tooltip: `Installed: ${d.installed.policy}${d.installed.active ? ' (the active policy)' : ''}\nBuild: ${d.cil.policy} (semodule, ${d.cil.packages} packages, ${(d.cil.ms / 1000).toFixed(1)} s)\nCompared in ${(d.ms.total / 1000).toFixed(1)} s. Run the command again after changes; it doesn't refresh on its own.` }),
        this.item('+ only in your build · − only on this host', { icon: 'info', tooltip: '"+" would be added to this host by installing your build. "−" exists on the host but not in your build: separately packaged modules, local modules or customizations, or things your build removes.' }),
      ];
      const groups = this.diffGroups(d);
      if (!groups.length) out.push(this.item('No difference: the build compiles to the installed policy.', { icon: 'pass' }));
      return out.concat(groups);
    }
    const b = d.base || { label: 'HEAD', short: d.head.short, subject: d.head.subject };
    const t = d.target || { working: true, label: 'working tree' };
    const name = (x) => (x.working ? 'working tree' : x.saved ? x.label : `${x.label}${x.short && x.label !== x.short ? ` (${x.short})` : ''}`);
    const header = b.label === 'HEAD' && t.working ? `vs HEAD ${b.short}` : `${name(b)} → ${name(t)}`;
    const out = [this.item(header, { icon: b.saved ? 'save' : 'git-commit', desc: b.subject,
      tooltip: `Base: ${name(b)}${b.subject ? ` — ${b.subject}` : ''}${b.when ? ` (${b.when})` : ''}\nTarget: ${name(t)}${t.subject ? ` — ${t.subject}` : ''}\n\n"+" is in the target and not the base, "−" the reverse.${t.working ? `\nWorking tree side: last build at ${new Date(d.builtAt).toLocaleTimeString()}.` : ''}\nCompared in ${(d.ms.total / 1000).toFixed(1)} s.` })];
    const groups = this.diffGroups(d);
    if (!groups.length) out.push(this.item(`No effective policy change: ${name(t)} compiles to the same policy as ${name(b)}.`, { icon: 'pass' }));
    return out.concat(groups);
  }

  /** Tree groups for a policy_diff result (rules by source, membership, elements). */
  diffGroups(d) {
    const groups = [];
    if (d.ruleCount) {
      const bySource = new Map();
      for (const r of d.rules) { if (!bySource.has(r.s)) bySource.set(r.s, []); bySource.get(r.s).push(r); }
      groups.push(this.item('Rules', { icon: 'list-tree', expanded: true, desc: `${d.ruleCount}${d.truncated ? ` (first ${d.rules.length} shown)` : ''}`,
        kids: () => [...bySource.keys()].sort().map(s => this.item(s, { icon: 'symbol-class', desc: bySource.get(s).length, expanded: bySource.size <= 5,
          kids: () => bySource.get(s).map(r => this.ruleNode(r)) })) }));
    }
    if (d.membership.length) {
      groups.push(this.item('Attribute membership', { icon: 'symbol-interface', desc: d.membership.length, kids: () => d.membership.flatMap(m => [
        ...m.addFrom.map(x => this.item(`${m.type} +${x.attr}`, { icon: 'diff-added', kids: () => this.explained({ origins: x.origins, more: 0 }, '') })),
        ...m.delFrom.map(x => this.item(`${m.type} −${x.attr}`, { icon: 'diff-removed', kids: () => this.explained({ origins: x.origins, more: 0 }, '') })),
      ]) }));
    }
    const elems = [];
    const both = (label, sd, icon, loc) => {
      for (const n of sd.added) elems.push(this.item(`+ ${label} ${n}`, { icon: 'diff-added', command: loc && loc[n] ? { command: 'selinux.openLocation', title: 'Open', arguments: [loc[n].p, loc[n].l, loc[n].c] } : undefined }));
      for (const n of sd.removed) elems.push(this.item(`− ${label} ${n}`, { icon: 'diff-removed' }));
    };
    both('type', d.types, 'symbol-class', d.typeLocations);
    both('attribute', d.attributes);
    both('role', d.roles);
    both('user', d.users);
    both('boolean', d.bools);
    both('class', d.classes);
    for (const b of d.boolDefaults) elems.push(this.item(`boolean ${b.name}`, { icon: 'diff-modified', desc: `default ${b.from} → ${b.to}` }));
    for (const r of d.roleTypes) elems.push(this.item(`role ${r.role}`, { icon: 'diff-modified', desc: [...r.added.map(t => `+${t}`), ...r.removed.map(t => `−${t}`)].join(' ') }));
    for (const u of d.userRoles) elems.push(this.item(`user ${u.user}`, { icon: 'diff-modified', desc: [...u.added.map(t => `+${t}`), ...u.removed.map(t => `−${t}`)].join(' ') }));
    if (elems.length) groups.push(this.item('Types, roles, users, booleans', { icon: 'symbol-structure', desc: elems.length, expanded: true, kids: () => elems }));
    return groups;
  }
}

/* ---------------- Module Preview (what turning a module off/on would do) ---------------- */

class ModulePreviewView extends ChangesView {
  constructor(request) {
    super(request);
    this.preview = null;
    this.target = null; // { module, to }
  }

  async run(module, to) {
    this.target = { module, to };
    this.loading = true;
    this._emitter.fire();
    try { this.preview = await this.request('selinux/modulePreview', { module, to }); } finally { this.loading = false; }
    this._emitter.fire();
    return this.preview;
  }

  afterBuild() { /* a preview is a snapshot; re-run it explicitly */ }

  async getChildren(n) {
    if (n) return n.kids ? n.kids() : [];
    if (this.loading) return [this.item(`Building with ${this.target.module} ${this.target.to === 'off' ? 'turned off' : 'turned on'}…`, { icon: 'sync~spin' })];
    const p = this.preview;
    if (!p) return [this.item('Preview turning a module off or on', { icon: 'package', command: { command: 'selinux.previewModule', title: 'Preview' }, tooltip: 'Build the policy with one module flipped in modules.conf and see what it would change, before editing anything.' })];
    if (p.unavailable && !p.module) return [this.item(p.unavailable, { icon: 'info' })];
    const verb = p.to === 'off' ? 'off' : `on (${p.to})`;
    const out = [this.item(`${p.module}: ${p.from} → ${p.to}`, {
      icon: p.to === 'off' ? 'circle-slash' : 'add', desc: p.ok ? 'links' : 'fails to link',
      tooltip: `Preview of turning ${p.module} ${verb}${p.appsChanged ? ', also dropping it from APPS_MODS' : ''}. Nothing has been changed yet.${p.ms ? `\nBuilt and compared in ${(p.ms.total / 1000).toFixed(1)} s.` : ''}`,
    })];
    if (p.apply) {
      out.push(this.item(`Apply: set ${p.module} = ${p.to} in ${vscode.workspace.asRelativePath(p.apply.path)}`, {
        icon: 'check', desc: p.appsMods && p.to === 'off' ? 'also remove it from APPS_MODS' : '',
        command: { command: 'selinux.applyModulePreview', title: 'Apply' },
        tooltip: `Edits ${p.apply.path}${p.apply.line != null ? ` line ${p.apply.line + 1}` : ' (adds a line)'}; review and save it yourself.${p.appsMods && p.to === 'off' ? '\nThe module is also forced on by APPS_MODS in selinux.build.tree.makeArgs (and, for CLIP, SEPARATE_PKGS in packages/selinux-policy/Makefile).' : ''}`,
      }));
    }
    if (!p.ok) {
      out.push(this.item('Link errors', { icon: 'error', expanded: true, desc: (p.errors || []).length, kids: () => (p.errors || []).map(e => this.item(e.path ? `${vscode.workspace.asRelativePath(e.path)}:${e.l + 1}` : e.file || 'build', {
        icon: 'error', desc: e.msg, tooltip: e.msg,
        command: e.path ? { command: 'selinux.openLocation', title: 'Open', arguments: [e.path, e.l, 0] } : undefined })) }));
    }
    const blocks = p.optionalBlocks || [];
    if (blocks.length) {
      const label = p.to === 'off' ? 'optional_policy blocks that drop out' : 'optional_policy blocks that come alive';
      const byMod = new Map();
      for (const b of blocks) { if (!byMod.has(b.module)) byMod.set(b.module, []); byMod.get(b.module).push(b); }
      out.push(this.item(label, { icon: 'symbol-namespace', desc: `${blocks.length} in ${byMod.size} modules`,
        tooltip: p.to === 'off' ? 'm4 drops a whole optional_policy block when any of its requirements is missing: every statement in these blocks goes, not just the calls into this module.' : 'These blocks are skipped today because they need this module.',
        kids: () => [...byMod.keys()].sort().map(m => this.item(m, { icon: 'package', desc: byMod.get(m).length,
          kids: () => byMod.get(m).map(b => this.item(`${vscode.workspace.asRelativePath(b.path)}:${b.l + 1}`, {
            icon: 'symbol-namespace', desc: `uses ${b.uses.join(', ')}${b.calls > b.uses.length ? ` · ${b.calls} calls in the block` : ''}`,
            command: { command: 'selinux.openLocation', title: 'Open', arguments: [b.path, b.l, b.c] } })) })) }));
    }
    if (p.diff) {
      const groups = this.diffGroups(p.diff);
      if (!groups.length) out.push(this.item('No change to the compiled policy.', { icon: 'pass' }));
      out.push(...groups);
    }
    return out;
  }
}

/* ---------------- Policy Explorer tree ---------------- */

class PolicyExplorer {
  constructor() {
    this._emitter = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._emitter.event;
    this.modules = null;
  }
  refresh() { this.modules = null; this._emitter.fire(); }

  getTreeItem(node) { return node.item; }

  async getChildren(node) {
    if (!client || !client.isRunning()) return [];
    if (!node) {
      if (!this.modules) this.modules = await client.sendRequest('selinux/modules');
      const layers = [...new Set(this.modules.map(m => m.layer))];
      return layers.map(layer => {
        const n = this.modules.filter(m => m.layer === layer).length;
        const item = new vscode.TreeItem(layer, vscode.TreeItemCollapsibleState.Collapsed);
        item.description = count(n, 'module');
        item.iconPath = new vscode.ThemeIcon('folder-library');
        return { type: 'layer', layer, item };
      });
    }
    if (node.type === 'layer') {
      return this.modules.filter(m => m.layer === node.layer).map(m => {
        const item = new vscode.TreeItem(m.module, vscode.TreeItemCollapsibleState.Collapsed);
        item.iconPath = new vscode.ThemeIcon('package');
        item.description = ['te', 'if', 'fc'].filter(x => m.files[x]).join(' ');
        item.contextValue = 'module';
        return { type: 'module', m, item };
      });
    }
    if (node.type === 'module') {
      const p = node.m.files.te || node.m.files.if;
      const c = await client.sendRequest('selinux/moduleContents', { path: p });
      const groups = [
        ['Types', 'symbol-class', c.types],
        ['Attributes', 'symbol-interface', c.attributes],
        ['Booleans', 'symbol-boolean', c.booleans],
        ['Interfaces & templates', 'symbol-method', c.interfaces],
        ['File contexts', 'file', c.fileContexts],
      ].filter(g => g[2].length);
      const files = Object.entries(node.m.files).map(([ext, f]) => {
        const item = new vscode.TreeItem(path.basename(f), vscode.TreeItemCollapsibleState.None);
        item.iconPath = new vscode.ThemeIcon('go-to-file');
        item.command = { command: 'selinux.openLocation', title: 'Open', arguments: [f, 0, 0] };
        return { type: 'leaf', item };
      });
      return files.concat(groups.map(([label, icon, entries]) => {
        const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.Collapsed);
        item.description = String(entries.length);
        item.iconPath = new vscode.ThemeIcon(icon);
        return { type: 'group', icon, entries, item };
      }));
    }
    if (node.type === 'group') {
      return node.entries.map(e => {
        const item = new vscode.TreeItem(e.name, vscode.TreeItemCollapsibleState.None);
        item.iconPath = new vscode.ThemeIcon(node.icon);
        if (e.summary) { item.tooltip = e.summary; item.description = e.summary; }
        item.command = { command: 'selinux.openLocation', title: 'Open', arguments: [e.path, e.l, e.c] };
        return { type: 'leaf', item };
      });
    }
    return [];
  }
}

function deactivate() { return client ? client.stop() : undefined; }

module.exports = { activate, deactivate, CompiledPolicyView, ChangesView, ModulePreviewView };
