'use strict';
const path = require('path');
const vscode = require('vscode');
const { LanguageClient, TransportKind } = require('vscode-languageclient/node');

let client;
let status;

/** "1 module", "2 modules", "1 class", "3 classes" */
const count = (n, word) => `${n} ${n === 1 ? word : word + (/(s|x|ch|sh)$/.test(word) ? 'es' : 's')}`;

function activate(context) {
  const serverModule = context.asAbsolutePath(path.join('server', 'server.js'));
  const cfg = () => vscode.workspace.getConfiguration('selinux');

  client = new LanguageClient('selinux', 'SELinux Policy', {
    run: { module: serverModule, transport: TransportKind.ipc },
    debug: { module: serverModule, transport: TransportKind.ipc, options: { execArgv: ['--nolazy', '--inspect=6019'] } },
  }, {
    documentSelector: [{ scheme: 'file', language: 'selinux' }, { scheme: 'file', language: 'selinux-fc' }],
    synchronize: {
      configurationSection: 'selinux',
      fileEvents: vscode.workspace.createFileSystemWatcher('**/{*.te,*.if,*.fc,*.spt,*.m4,*.in,access_vectors,security_classes}'),
    },
    initializationOptions: {
      extraIncludePaths: cfg().get('extraIncludePaths'),
      useDevelHeaders: cfg().get('useDevelHeaders'),
      develHeadersPath: cfg().get('develHeadersPath'),
      diagnostics: cfg().get('diagnostics'),
      build: cfg().get('build'),
    },
  });
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

  const explorer = new PolicyExplorer();
  context.subscriptions.push(vscode.window.registerTreeDataProvider('selinuxPolicyExplorer', explorer));
  const compiled = new CompiledPolicyView();
  const compiledView = vscode.window.createTreeView('selinuxCompiledPolicy', { treeDataProvider: compiled, showCollapseAll: true });
  context.subscriptions.push(compiledView);

  client.start().then(() => {
    client.onNotification('selinux/indexing', (p) => {
      if (p.state === 'start') status.text = '$(sync~spin) SELinux: indexing…';
      else {
        const s = p.stats;
        status.text = `$(shield) SELinux: ${count(s.modules, 'module')}, ${count(s.interfaces, 'interface')}`;
        status.tooltip = `${count(s.files, 'file')}, ${count(s.types, 'type')}, ${count(s.classes, 'class')}. Indexed in ${s.ms} ms. Click for details.`;
        explorer.refresh();
        compiled.refresh();
      }
    });
    client.onNotification('selinux/build', (p) => {
      if (p.state === 'start') { buildStatus(`$(sync~spin) Building ${p.module}…`, 60000); return; }
      if (p.state === 'validating') { buildStatus(`$(sync~spin) ${p.module} compiled (${p.ms} ms); validating link…`, 60000); return; }
      const what = p.tree ? `${count(p.packages, 'package')}${p.validated ? ', link validated' : ''}` : '';
      buildOutput.appendLine(`=== ${p.module}: ${p.ok ? 'built' : 'FAILED'} in ${p.ms} ms (${count(p.errors, 'error')}, ${count(p.warnings, 'warning')})${what ? '; ' + what : ''} ===`);
      if (p.tree) buildOutput.appendLine(`Output: ${p.outputDir}${p.policyBin ? `  (kernel policy: ${p.policyBin})` : ''}`);
      buildOutput.appendLine(p.log.trimEnd());
      buildStatus(p.ok ? `$(check) ${p.module} built (${p.ms} ms${what ? ', ' + what : ''})` : `$(error) ${p.module}: build failed, see Problems`, 8000);
      expanded.refresh();
      if (p.tree) compiled.refresh();
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
      const msg = r.tree
        ? `Built ${r.module}: ${count(r.packages, 'module package')}${r.validated ? ', link validated' : ''}${r.policyBin ? ', kernel policy ' + path.basename(r.policyBin) : ''} (${(r.ms / 1000).toFixed(1)} s). Output: ${r.outputDir}`
        : `Built ${path.basename(r.package)} in ${path.dirname(r.package)}. Install it with: sudo semodule -i ${path.basename(r.package)}`;
      const choice = await vscode.window.showInformationMessage(msg, ...(ed ? ['Show Expanded Policy'] : []), ...(r.tree ? ['Show Compiled Policy'] : []));
      if (choice === 'Show Expanded Policy') vscode.commands.executeCommand('selinux.showExpanded', ed.document.uri);
      if (choice === 'Show Compiled Policy') vscode.commands.executeCommand('selinuxCompiledPolicy.focus');
    }),
    vscode.commands.registerCommand('selinux.refreshCompiled', () => compiled.refresh()),
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

  refresh() { this.model = null; this.roots = null; this._emitter.fire(); }

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
    const modOf = (e, kind) => { const mod = (e.loc && e.loc.m) || '(no source found)'; if (!m.byModule.has(mod)) m.byModule.set(mod, { types: [], attributes: [], bools: [], roles: [] }); m.byModule.get(mod)[kind].push(e); };
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
    const header = this.node(null, 'hdr', `policy.${m.version}${m.mls ? ' · MLS/MCS' : ''} · unknown=${m.handleUnknown}`, {
      icon: 'shield', desc: new Date(m.builtAt).toLocaleTimeString(),
      tooltip: `${m.bin}\n${Object.entries(m.counts).map(([k, v]) => `${k}: ${v}`).join('\n')}`,
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
      icon: isDomain ? 'server-process' : 'symbol-class', loc: t.loc,
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
        return out;
      },
    });
  }

  attrNode(parent, a) {
    const members = (this.model.members.get(a.name) || []).slice().sort();
    return this.node(parent, `a:${a.name}`, a.name, { icon: 'symbol-interface', loc: a.loc, desc: `${members.length} types`,
      tooltip: `attribute ${a.name}\n${this.where(a.loc)}`,
      kids: members.length ? (n) => members.map(t => this.typeRef(n, t)) : undefined });
  }

  roleNode(parent, r) {
    return this.node(parent, `r:${r.name}`, r.name, { icon: 'organization', loc: r.loc, desc: `${r.types.length} types`,
      tooltip: `role ${r.name}\n${this.where(r.loc)}`,
      kids: r.types.length ? (n) => r.types.map(t => this.typeRef(n, t)) : undefined });
  }

  userNode(parent, u) {
    return this.node(parent, `u:${u.name}`, u.name, { icon: 'person', loc: u.loc, desc: u.range || '',
      tooltip: `user ${u.name}${u.range ? `\nrange ${u.range}, default level ${u.level}` : ''}\n${this.where(u.loc)}`,
      kids: (n) => u.roles.map(r => this.roleNode(n, this.model.roleByName.get(r) || { name: r, types: [] })) });
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

module.exports = { activate, deactivate, CompiledPolicyView };
