// The tutorials (contributes.walkthroughs in package.json, media/walkthroughs,
// media/practice) stay consistent with the extension: every page exists, every
// button and completion event names a real command, view or setting, every
// "SELinux: …" command a page mentions exists, and every contributed command is
// registered by the client. Any OS.
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const c = pkg.contributes;
let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2000).replace(/\n/g, '\n     ')); }
};

const commands = new Set(c.commands.map(x => x.command));
const titles = new Set(c.commands.map(x => x.title));
const views = new Set(Object.values(c.views).flat().map(v => v.id));
const settings = new Set(Object.keys(c.configuration.properties));
// VS Code's own commands the tutorials use.
const BUILTIN = new Set(['workbench.action.files.openFolder', 'workbench.action.terminal.new', 'workbench.actions.view.problems', 'workbench.action.showAllSymbols']);
const knownCommand = (n) => commands.has(n) || BUILTIN.has(n) || (n.endsWith('.focus') && views.has(n.slice(0, -6)));
const walkthroughs = c.walkthroughs || [];
const wids = new Set(walkthroughs.map(w => w.id));

check(walkthroughs.length === 4 && wids.size === 4, `${walkthroughs.length} walkthroughs: ${[...wids].join(', ')}`);
const bad = [];
let steps = 0;
for (const w of walkthroughs) {
  if (!w.title || !w.description) bad.push(`${w.id}: title/description`);
  const ids = new Set();
  for (const s of w.steps) {
    steps++;
    const where = `${w.id}/${s.id}`;
    if (ids.has(s.id)) bad.push(`${where}: duplicate step id`);
    ids.add(s.id);
    if (!s.title || !s.description) bad.push(`${where}: title/description`);
    const mdPath = s.media && s.media.markdown && path.join(root, s.media.markdown);
    if (!mdPath || !fs.existsSync(mdPath) || fs.statSync(mdPath).size < 200) bad.push(`${where}: markdown ${s.media && s.media.markdown}`);
    for (const m of s.description.matchAll(/\]\(command:([\w.]+)(\?([^)]*))?\)/g)) {
      if (!knownCommand(m[1])) bad.push(`${where}: button runs unknown command ${m[1]}`);
      if (m[1] === 'selinux.openTutorials' && m[3]) {
        const [id] = JSON.parse(decodeURIComponent(m[3]));
        if (!wids.has(id)) bad.push(`${where}: links to unknown walkthrough ${id}`);
      }
    }
    for (const e of s.completionEvents || []) {
      const [kind, arg] = [e.slice(0, e.indexOf(':')), e.slice(e.indexOf(':') + 1)];
      if (kind === 'onCommand' && !knownCommand(arg)) bad.push(`${where}: completes on unknown command ${arg}`);
      else if (kind === 'onView' && !views.has(arg)) bad.push(`${where}: completes on unknown view ${arg}`);
      else if (kind === 'onSettingChanged' && !settings.has(arg)) bad.push(`${where}: completes on unknown setting ${arg}`);
      else if (!['onCommand', 'onView', 'onSettingChanged', 'onContext', 'onLink'].includes(kind)) bad.push(`${where}: unknown completion event ${e}`);
    }
  }
}
check(!bad.length, `${steps} steps: pages exist, buttons and completion events name real commands, views, settings and walkthroughs`, bad);

// Commands the pages and the practice instructions name in bold.
const pages = [...walkthroughs.flatMap(w => w.steps.map(s => s.media.markdown)), 'media/practice/TUTORIAL.md'];
const named = [];
for (const p of pages) {
  const text = fs.readFileSync(path.join(root, p), 'utf8').replace(/\s*\n\s*/g, ' ');
  for (const m of text.matchAll(/\*\*(SELinux: [^*]+?)\*\*/g)) if (!titles.has(m[1])) named.push(`${p}: ${m[1]}`);
}
check(!named.length, 'every "SELinux: …" command the pages mention exists', named);

// Settings the pages mention.
const unknownSettings = [];
for (const p of pages) for (const m of fs.readFileSync(path.join(root, p), 'utf8').matchAll(/`(selinux\.[\w.]+)`/g)) if (!settings.has(m[1]) && m[1] !== 'selinux.checks') unknownSettings.push(`${p}: ${m[1]}`);
check(!unknownSettings.length, 'every selinux.* setting the pages mention exists', unknownSettings);

// Every contributed command is registered by the client.
const client = fs.readFileSync(path.join(root, 'client', 'extension.js'), 'utf8');
const unregistered = [...commands].filter(n => !client.includes(`registerCommand('${n}'`));
check(!unregistered.length, `all ${commands.size} contributed commands are registered`, unregistered);

// The practice module ships in the .vsix.
const ignoreFile = path.join(root, '.vscodeignore');
const ignore = (fs.existsSync(ignoreFile) ? fs.readFileSync(ignoreFile, 'utf8') : '').split('\n').map(l => l.trim()).filter(Boolean);
const practice = fs.readdirSync(path.join(root, 'media', 'practice'));
check(['notesd.te', 'notesd.if', 'notesd.fc', 'selinux.checks', 'TUTORIAL.md'].every(f => practice.includes(f)) && !ignore.some(l => /^media/.test(l)), `practice module files: ${practice.join(', ')}`);
check(c.viewsWelcome && c.viewsWelcome.some(v => v.view === 'selinuxPolicyExplorer' && /selinux\.openTutorials/.test(v.contents)), 'the empty Policy Explorer offers the tutorials');

console.log(failures ? `\n${failures} check(s) failed` : '\nall walkthrough checks passed');
process.exit(failures ? 1 : 0);
