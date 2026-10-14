'use strict';
// Client pieces with a stand-in vscode module (any OS): the All Features
// menu, Add check writing to selinux.checks, and the Configure Build from
// Spec File… pick items (RHEL and CLIP).
//   node test/client-test.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const Module = require('module');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2000).replace(/\n/g, '\n     ')); }
};

// A minimal vscode: documents are files on disk, edits are applied to them.
const calls = { quickPick: null, executed: [], warnings: [], shown: [] };
let pickAnswer = null;
const docOf = (p) => {
  const text = () => fs.readFileSync(p, 'utf8');
  const lines = () => text().split('\n');
  return {
    uri: { fsPath: p }, getText: text, get lineCount() { return lines().length; },
    lineAt: (i) => ({ text: lines()[i], range: { end: { line: i, character: lines()[i].length } } }),
    save: async () => true,
  };
};
class WorkspaceEdit { constructor() { this.ops = []; } insert(uri, pos, text) { this.ops.push({ uri, pos, text }); } }
const vscode = {
  QuickPickItemKind: { Separator: -1 }, ViewColumn: { Beside: -2, Active: -1 },
  Selection: class { constructor(a, b, c, d) { this.range = [a, b, c, d]; } },
  WorkspaceEdit,
  window: {
    showQuickPick: async (items, opts) => { calls.quickPick = { items, opts }; return pickAnswer ? pickAnswer(items) : undefined; },
    showWarningMessage: (m) => { calls.warnings.push(m); },
    showTextDocument: async (doc, opts) => { calls.shown.push({ doc, opts }); return { selection: null }; },
  },
  workspace: {
    openTextDocument: async (p) => docOf(p),
    applyEdit: async (edit) => {
      for (const op of edit.ops) {
        const lines = fs.readFileSync(op.uri.fsPath, 'utf8').split('\n');
        const l = op.pos.line;
        lines[l] = lines[l].slice(0, op.pos.character) + op.text + lines[l].slice(op.pos.character);
        fs.writeFileSync(op.uri.fsPath, lines.join('\n'));
      }
      return true;
    },
  },
  commands: { executeCommand: (...a) => { calls.executed.push(a); } },
};
const load = Module._load;
Module._load = function (req, ...rest) { return req === 'vscode' ? vscode : req === 'vscode-languageclient/node' ? { LanguageClient: class {}, TransportKind: {} } : load.call(this, req, ...rest); };
const ext = require('../client/extension');
Module._load = load;
const pkg = require('../package.json');

(async () => {
  /* ---------- All Features menu ---------- */
  const contributed = new Set(pkg.contributes.commands.map(c => c.command));
  const all = ext.FEATURES.flatMap(([, list]) => list);
  const cmds = all.map(([c]) => c);
  check(cmds.every(c => contributed.has(c)),
    'every menu entry is a contributed command', cmds.filter(c => !contributed.has(c)));
  check(new Set(cmds).size === cmds.length, 'no command twice in the menu');
  check(['selinux.lookUpFile', 'selinux.showLogins', 'selinux.showLevels', 'selinux.newWrapper', 'selinux.editWrapper', 'selinux.newUser', 'selinux.analyzeDenials', 'selinux.configureFromSpec', 'selinux.openChecks'].every(c => cmds.includes(c)),
    'the newer features are in the menu (file labels, logins, levels, wrappers, users, denials, spec, checks)');
  check(all.every(([, icon, title, detail]) => /^[a-z-]+$/.test(icon) && title && detail && detail.length > 20), 'each entry has an icon, a title and a line saying what it does');
  pickAnswer = (items) => items.find(i => i.command === 'selinux.showLevels');
  await ext.showFeatures();
  const items = calls.quickPick.items;
  check(items.filter(i => i.kind === -1).map(i => i.label).join('|') === ext.FEATURES.map(([g]) => g).join('|') && items.some(i => /\$\(layers\) Levels and Categories…/.test(i.label)),
    'the quick pick: one separator per group, entries with their icons', items.slice(0, 4));
  check(calls.executed.some(a => a[0] === 'selinux.showLevels') && calls.quickPick.opts.matchOnDetail, 'picking an entry runs its command (and the details are searchable)');
  pickAnswer = null;
  calls.executed = [];
  await ext.showFeatures();
  check(!calls.executed.length, 'escape runs nothing');

  /* ---------- Add check ---------- */
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'selinux-client-test-'));
  const checksPath = path.join(tmp, 'selinux.checks');
  let reply = { path: checksPath, exists: false };
  ext._setClient({ sendRequest: async (m) => (m === 'selinux/checksFile' ? reply : null) });
  let msg = await ext.addCheckLine('never container_t may ignore levels');
  let text = fs.readFileSync(checksPath, 'utf8');
  check(/^# SELinux property checks/.test(text) && text.trimEnd().endsWith('never container_t may ignore levels') && /it is checked now and after every build/.test(msg),
    'no checks file yet: created from the template, the line appended', { msg, tail: text.slice(-80) });
  check(/ignore levels/.test(text.split('\n').find(l => /may ignore levels \[on <classes>\]/.test(l)) || ''), 'the template documents the levels checks');
  reply = { path: checksPath, exists: true };
  fs.writeFileSync(checksPath, 'only auditd_t may write auditd_log_t');   // no newline at the end
  msg = await ext.addCheckLine('require container_t isolated by levels');
  text = fs.readFileSync(checksPath, 'utf8');
  check(text === 'only auditd_t may write auditd_log_t\nrequire container_t isolated by levels\n', 'appended on a line of its own (a missing final newline added)', text);
  msg = await ext.addCheckLine('require container_t isolated by levels');
  check(/already has that check/.test(msg) && fs.readFileSync(checksPath, 'utf8') === text, 'the same check twice: not added again');
  check(calls.shown.length >= 3 && calls.shown.every(s => s.opts.viewColumn === -2), 'the checks file is shown beside the panel');
  reply = { unavailable: 'Property checks need a policy source tree or a standalone module directory.' };
  msg = await ext.addCheckLine('never x_t may ignore levels');
  check(msg === reply.unavailable && calls.warnings.includes(reply.unavailable), 'without a tree: the reason, as a warning');
  fs.rmSync(tmp, { recursive: true, force: true });

  /* ---------- Configure Build from Spec File… items ---------- */
  const rhel = ext.specPickItem({ variant: 'targeted', makeArgs: ['DISTRO=redhat', 'UNK_PERMS=allow', 'NAME=targeted', 'TYPE=mcs'], files: { 'policy/booleans.conf': ['/s/b'], 'policy/modules.conf': ['/s/m1', '/s/m2'] }, missing: ['/s/users-targeted'], notes: [] });
  check(rhel.label === 'targeted' && rhel.description === 'UNK_PERMS=allow NAME=targeted TYPE=mcs' && rhel.detail === 'policy/booleans.conf, policy/modules.conf   ⚠ missing: users-targeted', 'RHEL variant: name/type in the description, files and what is missing in the detail', rhel);
  const clip = ext.specPickItem({ variant: 'mcs', clip: true, makeArgs: ['UNK_PERMS=deny', 'NAME=mcs', 'TYPE=mcs', 'APPS_MODS=ssh aide postfix'], files: {}, missing: [], notes: ['no Makefile next to the spec'] });
  check(clip.detail === "CLIP: the tree's own modules.conf, plus 3 separately packaged modules (APPS_MODS)   ⚠ no Makefile next to the spec", 'CLIP variant: its modules.conf, the APPS_MODS count, notes', clip.detail);
  check(ext.specPickItem({ variant: 'mcs', clip: true, makeArgs: ['APPS_MODS=ssh'], files: {}, missing: [] }).detail.includes('1 separately packaged module '), 'one module: singular');

  console.log(failures ? `\n${failures} check(s) failed` : '\nall client checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
