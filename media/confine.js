// The confinement checklist for one service module (webview of client/extension.js showConfine,
// facts and steps from server/confine.js via selinux/confineStatus): each step with its state and
// the action that moves it on, the exercise commands run on the target, enforce-and-verify.
(function () {
  const vscode = acquireVsCodeApi();
  const $ = (id) => document.getElementById(id);
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'class') el.className = v;
      else if (k === 'checked' || k === 'disabled' || k === 'hidden' || k === 'open' || k === 'selected') el[k] = !!v;
      else el.setAttribute(k, v);
    }
    const add = (x) => { if (x == null || x === false) return; if (Array.isArray(x)) x.forEach(add); else el.append(typeof x === 'string' || typeof x === 'number' ? document.createTextNode(String(x)) : x); };
    kids.forEach(add);
    return el;
  }
  const SINCE = [['recent', 'last 10 minutes'], ['this-hour', 'this hour'], ['boot', 'since boot'], ['today', 'today'], ['push', 'since the last push'], ['verify', 'since the last verify']];
  const MARK = { done: '✓', todo: '○', bad: '✗', unknown: '?', skip: '–' };

  let module = '', targets = [], target = null, since = 'today', result = null, key = 0, loading = false;
  let exerciseText = '', exerciseRun = null, verifyRun = null, busy = '';

  function fillBar() {
    const ts = $('target');
    ts.textContent = '';
    ts.append(h('option', { value: '' }, targets.length ? 'pick a target host' : 'no target connected'));
    for (const t of targets) ts.append(h('option', { value: t.id, selected: t.id === target }, `${t.id}${t.mode ? ` (${t.mode})` : ''}${t.root ? '' : ', not root'}`));
    ts.value = target || '';
    const ss = $('since');
    ss.textContent = '';
    for (const [v, l] of SINCE) if (v !== 'verify' || verifyRun) ss.append(h('option', { value: v }, l));
    if (since === 'verify' && !verifyRun) since = 'today';
    ss.value = since;
  }
  function load(reset = false) {
    key++;
    loading = true;
    $('status').textContent = target ? `Looking at ${module} on ${target}…` : `Looking at ${module}…`;
    vscode.postMessage({ cmd: 'load', key, target, since, exercise: exerciseRun, reset });
  }
  const commands = () => exerciseText.split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#'));
  const run = (what, extra) => { busy = what; render(); vscode.postMessage({ cmd: what, target, ...extra }); };

  function actions(step) {
    const r = result;
    const m = r.module;
    const D = m ? m.domain : null;
    const out = [];
    const btn = (label, title, onclick, primary) => h('button', { class: primary ? 'primary' : null, title, disabled: !!busy, onclick }, label);
    switch (step.id) {
      case 'module':
        if (!m) out.push(btn('New Service…', 'Open the service editor for a new service', () => vscode.postMessage({ cmd: 'newService' }), true));
        else { out.push(btn('Edit Service…', `Open ${m.name} in the service editor`, () => vscode.postMessage({ cmd: 'editService' }))); if (m.files && m.files.te) out.push(h('button', { class: 'link', title: m.files.te, onclick: () => vscode.postMessage({ cmd: 'open', path: m.files.te }) }, `${m.name}.te`)); }
        break;
      case 'build':
        if (m && step.state !== 'skip') out.push(btn('Build', r.build && r.build.kind === 'module' ? 'Build the module (SELinux: Build Current Module)' : 'Build the tree', () => vscode.postMessage({ cmd: 'build', te: m.files.te, standalone: !!m.standalone }), step.state === 'todo'));
        break;
      case 'target':
        if (step.state === 'todo') out.push(btn('Connect…', 'SELinux: Connect to Target Host…', () => vscode.postMessage({ cmd: 'connect' }), true));
        break;
      case 'push':
        if (step.state === 'todo' && m) out.push(btn(`Push ${m.name}`, `Install the build's ${m.name} on ${target} (the installed module is backed up first; Roll Back in SELinux: Target Host… undoes it)`, () => run('push', {}), true));
        break;
      case 'permissive':
        if (step.state === 'todo' && D) out.push(btn('Make permissive', `semanage permissive -a ${D} on ${target}: its denials are logged, nothing is stopped`, () => run('permissive', { domain: D, on: true }), true));
        else if (step.state === 'done' && r.target && (r.target.permissive || []).includes(D)) out.push(btn('Enforce again', `semanage permissive -d ${D} on ${target}`, () => run('permissive', { domain: D, on: false })));
        else if (step.state === 'done' && D && r.target && r.target.mode !== 'Permissive') out.push(btn('Make permissive', `semanage permissive -a ${D} on ${target}: for another test run after more changes`, () => run('permissive', { domain: D, on: true })));
        break;
      case 'running':
        if (r.units && r.units.length) out.push(btn(`Restart ${r.units.join(', ')}`, `systemctl restart on ${target}, so the service starts under the pushed policy`, () => run('restart', { units: r.units }), step.state === 'todo'));
        break;
      case 'exercise':
        if (step.state !== 'skip') {
          out.push(h('div', { style: 'flex-basis: 100%' },
            h('textarea', { rows: Math.max(3, Math.min(10, exerciseText.split('\n').length + 1)), spellcheck: 'false', placeholder: `# commands run on ${target || 'the target'} as root, one per line, e.g.\nsystemctl reload ${m ? m.name : 'NAME'}\ncurl -s http://localhost/ > /dev/null`, title: 'Commands that exercise the service on the target: a client request, a reload, what it does in production. Kept with this workspace.',
              oninput: (e) => { exerciseText = e.target.value; vscode.postMessage({ cmd: 'saveExercise', text: exerciseText }); } }, exerciseText),
            h('div', { class: 'actions' }, btn('Run on the target', 'Run the commands on the target, one after the other, and show what each printed', () => run('exercise', { commands: commands() }), step.state === 'todo'),
              busy === 'exercise' ? h('span', { class: 'muted' }, 'Running…') : null),
            exerciseRun && exerciseRun.error ? h('div', { class: 'problem bad' }, exerciseRun.error) : null,
            exerciseRun && exerciseRun.ran ? exerciseRun.ran.map(x => h('div', { class: 'out' }, `$ ${x.cmd}${x.code ? `   (exit ${x.code}, ${x.ms} ms)` : `   (${x.ms} ms)`}\n${x.out}`)) : null));
        }
        break;
      case 'denials':
        if (step.state !== 'skip') out.push(btn('Read again', 'Read the denials on the target again', () => load()));
        if (step.state === 'todo' && r.denials && r.denials.text) out.push(btn('Apply to the form…', `Open ${m.name} in the service editor with these denials in its "From a permissive run" section: each becomes a setting of the form`, () => vscode.postMessage({ cmd: 'applyDenials', text: r.denials.text, status: `${r.denials.count} denials of ${D} read from ${target} (${r.denials.since}).` }), true));
        break;
      case 'verify':
        if (step.state !== 'skip') {
          out.push(btn('Enforce and verify', `On ${target}: enforce ${D} again, restart ${r.units && r.units.length ? r.units.join(', ') : 'nothing (no unit found)'}, run the exercise commands, then read what was denied and which domain the service runs in`, () => run('verify', { units: r.units || [], commands: commands(), programs: r.programs || [] }), step.state === 'todo'));
          if (busy === 'verify') out.push(h('span', { class: 'muted' }, 'Verifying…'));
          if (verifyRun) {
            const v = verifyRun;
            if (v.error) out.push(h('div', { class: 'problem bad', style: 'flex-basis: 100%' }, v.error));
            else {
              out.push(h('div', { style: 'flex-basis: 100%' },
                h('div', { class: v.ok ? 'ok' : 'bad' }, h('b', {}, v.ok ? 'Verified: ' : 'Not yet: '), v.verdict.text),
                v.verdict.problems.length ? h('ul', {}, v.verdict.problems.map(p => h('li', {}, p))) : null,
                v.denials && v.denials.count && v.denials.text ? h('details', {}, h('summary', {}, `${v.denials.count} denials while enforcing`), h('div', { class: 'out' }, v.denials.text),
                  h('div', { class: 'actions' }, btn('Make permissive again', `semanage permissive -a ${D} on ${target}`, () => run('permissive', { domain: D, on: true })), btn('Apply to the form…', 'Open the module in the service editor with these denials', () => vscode.postMessage({ cmd: 'applyDenials', text: v.denials.text, status: `${v.denials.count} denials of ${D} while enforcing on ${target}.` }), true))) : null,
                (v.exercise || []).length ? h('details', {}, h('summary', {}, `${v.exercise.length} exercise command${v.exercise.length === 1 ? '' : 's'}`), v.exercise.map(x => h('div', { class: 'out' }, `$ ${x.cmd}${x.code ? `   (exit ${x.code})` : ''}\n${x.out}`))) : null));
            }
          }
        }
        break;
      default: break;
    }
    return out;
  }

  function render() {
    const main = $('main');
    main.textContent = '';
    if (!result) return;
    const r = result;
    if (r.error) { main.append(h('div', { class: 'problem bad' }, r.error)); return; }
    const done = r.steps.filter(s => s.state === 'done').length, total = r.steps.filter(s => s.state !== 'skip').length;
    main.append(h('p', { class: 'intro' }, 'From a written module to a service that runs enforced on a test host with nothing denied. Each step says where it stands and what moves it on; the loop is: make the domain permissive, run the service through its paces, read what it was denied into the form, build, push, and when a run logs nothing, enforce and verify.'),
      h('div', { class: 'verdict' }, `${done} of ${total} steps done${r.target ? ` on ${r.target.id}` : ' (no target host picked)'}.`));
    for (const s of r.steps) {
      main.append(h('div', { class: `step ${s.state}` }, h('div', { class: 'mark', title: s.state }, MARK[s.state] || '?'),
        h('div', { style: 'flex: 1' }, h('div', { class: 'stitle' }, s.title), h('div', { class: 'stext' }, s.text), h('div', { class: 'actions' }, actions(s)))));
    }
  }

  $('target').addEventListener('change', (e) => { target = e.target.value || null; verifyRun = null; load(); });
  $('since').addEventListener('change', (e) => { since = e.target.value; load(); });
  $('refresh').addEventListener('click', () => load());
  $('reset').addEventListener('click', () => { exerciseRun = null; verifyRun = null; if (since === 'verify') since = 'today'; fillBar(); load(true); });

  window.addEventListener('message', (e) => {
    const m = e.data;
    if (m.cmd === 'init') {
      module = m.module; targets = m.targets || []; exerciseText = m.exercise || '';
      target = m.target && targets.some(t => t.id === m.target) ? m.target : (targets[0] ? targets[0].id : null);
      fillBar();
      load();
    } else if (m.cmd === 'result') {
      if (m.key !== key) return;
      loading = false;
      result = m.result;
      $('status').textContent = result && result.error ? result.error : '';
      render();
    } else if (m.cmd === 'targets') {
      targets = m.targets || [];
      if (target && !targets.some(t => t.id === target)) target = null;
      if (!target && targets.length) target = targets[0].id;
      fillBar();
      load();
    } else if (m.cmd === 'target') {
      if (m.target && targets.some(t => t.id === m.target)) { target = m.target; fillBar(); load(); }
    } else if (m.cmd === 'done') {
      busy = '';
      if (m.what === 'exercise') exerciseRun = m.result;
      else if (m.what === 'verify') { verifyRun = m.result; if (m.result && m.result.exercise && m.result.exercise.length) exerciseRun = { ran: m.result.exercise, at: Date.now() }; if (m.result && !m.result.error) { since = 'verify'; fillBar(); } }
      load();
    } else if (m.cmd === 'built') {
      if (!busy) load();
    } else if (m.cmd === 'error') {
      busy = '';
      $('status').textContent = m.text;
      render();
    }
  });
  vscode.postMessage({ cmd: 'ready' });
})();
