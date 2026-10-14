// Host Changes webview: a host's local SELinux changes (semanage export,
// semodule --list-modules=full) compared with a policy, with each change
// written into the policy source or copied. Plain JS, no deps.
/* global acquireVsCodeApi */
(function () {
  const vscode = acquireVsCodeApi();
  const $ = (id) => document.getElementById(id);
  function h(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (k === 'class') e.className = v;
      else e.setAttribute(k, v === true ? '' : v);
    }
    for (const c of kids.flat(Infinity)) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
    return e;
  }

  const GROUPS = [
    ['fcontext', 'File contexts'], ['equivalence', 'Equivalences'], ['port', 'Ports'], ['boolean', 'Booleans'], ['login', 'Logins'], ['user', 'SELinux users'],
    ['module-disabled', 'Modules turned off'], ['local-module', 'Modules added'], ['permissive', 'Permissive domains'], ['interface', 'Network interfaces'], ['node', 'Network nodes'],
    ['ibpkey', 'InfiniBand pkeys'], ['ibendport', 'InfiniBand end ports'],
  ];
  const STATE = {
    local: ['only on the host', 'The host has it; your policy doesn\'t. Write it into the policy, or leave it as a local change.'],
    override: ['overrides your policy', 'The host changes something your policy sets differently.'],
    present: ['already in your policy', 'Your policy has the same thing: the local change is redundant there.'],
    redundant: ['same as the default', 'The host sets what your policy already defaults to.'],
    broken: ['not in your policy', 'It names a type, user, role or boolean your policy doesn\'t have: on a host running your policy it would fail.'],
    info: ['note', ''],
  };
  const ORDER = ['broken', 'override', 'local', 'redundant', 'present', 'info'];

  let policies = [], against = null, result = null, text = '', fixes = new Map(), showRaw = false;

  const send = () => { result = 'checking'; render(); vscode.postMessage({ cmd: 'compare', text, against }); };

  function sourceCard() {
    const ta = h('textarea', { id: 'export', spellcheck: 'false', rows: 6, placeholder: 'Paste the output of: sudo semanage export (and optionally a "#### modules" line followed by sudo semodule --list-modules=full)' });
    ta.value = text;
    ta.addEventListener('input', () => { text = ta.value; });
    const cmd = "sudo sh -c 'semanage export; echo \"#### modules\"; semodule --list-modules=full' > host-changes.txt";
    return h('div', { class: 'card' }, h('div', { class: 'body' },
      h('p', { class: 'intro' }, 'Local changes are what an administrator changed on a host with semanage (file contexts, ports, booleans, logins, users, modules turned off, permissive domains) or semodule -i (modules added). They survive policy updates, so a host can drift from the policy you ship. Compare them with your policy, and write the ones that belong into its source.'),
      h('div', { class: 'row' },
        h('button', { class: 'primary', title: 'Runs semanage export and semodule in a terminal with sudo (enter your password there); the result comes back here', onclick: () => { result = 'waiting'; render(); vscode.postMessage({ cmd: 'sudo' }); } }, 'Read this host (sudo)'), ' ',
        h('button', { title: 'Without root: file_contexts.local, file_contexts.subs and booleans whose value differs from the default. Ports, logins, users and modules need sudo.', onclick: () => vscode.postMessage({ cmd: 'local' }) }, 'Read without sudo'), ' ',
        h('button', { title: 'An export saved on another host', onclick: () => vscode.postMessage({ cmd: 'openFile' }) }, 'Open file…'), ' ',
        h('button', { title: 'Compare the text below', onclick: send }, 'Compare')),
      ta,
      h('div', { class: 'note muted' }, 'On another host: ', h('code', {}, cmd), ' ', h('button', { class: 'link', onclick: () => vscode.postMessage({ cmd: 'copy', text: cmd }) }, 'copy'), ', then open the file here.')));
  }

  function fixBox(it, key) {
    const f = fixes.get(key);
    if (!f) return null;
    if (f === 'planning' || f === 'applying') return h('span', { class: 'muted' }, f === 'planning' ? ' preparing…' : ' writing…');
    if (f.error) return h('div', { class: 'note bad' }, f.error);
    if (f.already) return h('div', { class: 'note muted' }, `${f.path.split('/').pop()} has it already.`);
    if (f.applied) return h('div', { class: 'note ok' }, `Written to ${f.path.split('/').pop()} (saved; the build checks it).`);
    return h('div', { class: 'plan' }, h('div', { class: 'muted' }, `Adds to ${f.path}:`), h('pre', {}, f.inserted.join('\n')),
      h('button', { class: 'primary', onclick: () => { fixes.set(key, 'applying'); render(); vscode.postMessage({ cmd: 'apply', key, plan: f }); } }, 'Write it'), ' ',
      h('button', { onclick: () => { fixes.delete(key); render(); } }, 'Cancel'));
  }

  function row(it, i) {
    const key = `${it.kind}:${it.l}:${i}`;
    const [label, tip] = STATE[it.state] || [it.state, ''];
    return h('div', { class: `item ${it.state}${it.severity === 'warn' ? ' warn' : ''}` },
      h('div', {}, h('span', { class: `badge ${it.state}`, title: tip }, label), ' ', h('code', {}, it.text),
        it.fixable && it.state !== 'present' && it.state !== 'redundant' && it.state !== 'broken' ? [' ', h('button', { class: 'link', title: 'Write this change into the policy source (shows the edit first)', onclick: () => { fixes.set(key, 'planning'); render(); vscode.postMessage({ cmd: 'plan', key, item: it, against }); } }, 'write into the policy')] : null,
        it.snippet ? [' ', h('button', { class: 'link', title: `Copy the source line for it:\n${it.snippet}`, onclick: () => vscode.postMessage({ cmd: 'copy', text: it.snippet }) }, 'copy line')] : null),
      h('div', { class: `note${it.severity === 'warn' ? ' warn' : ' muted'}` }, it.note),
      showRaw ? h('div', { class: 'raw muted' }, h('code', {}, it.raw)) : null,
      fixBox(it, key));
  }

  function resultView() {
    const r = result;
    if (!r) return null;
    if (r === 'checking') return h('div', { class: 'muted' }, 'Comparing…');
    if (r === 'waiting') return h('div', { class: 'muted' }, 'Waiting for the terminal (enter your sudo password there)…');
    if (r.error) return h('div', { class: 'note bad' }, r.error);
    const out = [];
    if (r.note) out.push(h('div', { class: 'note' }, r.note));
    if (r.containsLocal) out.push(h('div', { class: 'note warn' }, 'You are comparing with an installed policy: on the host it came from, its own local changes are part of it and show as "already in your policy". Compare with your workspace build to see what your policy lacks.'));
    if (r.partial) out.push(h('div', { class: 'note muted' }, 'Read without root: only file contexts, equivalences and booleans whose value differs from the default (which may not be persistent). Use "Read this host (sudo)" for everything.'));
    const counts = {};
    for (const it of r.items) counts[it.state] = (counts[it.state] || 0) + 1;
    if (r.items.length) {
      out.push(h('div', { class: 'summary' }, `${r.items.length} local change${r.items.length === 1 ? '' : 's'}: `,
        ORDER.filter(s => counts[s]).map((s, i) => [i ? ' · ' : '', h('span', { class: `badge ${s}` }, `${counts[s]} ${(STATE[s] || [s])[0]}`)]),
        ' ', h('label', { class: 'muted' }, h('input', { type: 'checkbox', checked: showRaw || null, onchange: (e) => { showRaw = e.target.checked; render(); } }), ' show export lines')));
      if (!r.modulesListed) out.push(h('div', { class: 'note muted' }, 'Modules added on the host aren\'t listed: include the "#### modules" part (semodule --list-modules=full) to see them.'));
    }
    for (const [kind, title] of GROUPS) {
      const its = r.items.map((it, i) => [it, i]).filter(([it]) => it.kind === kind).sort((a, b) => ORDER.indexOf(a[0].state) - ORDER.indexOf(b[0].state));
      if (!its.length) continue;
      out.push(h('details', { class: 'card', open: true }, h('summary', {}, h('span', { class: 'fname' }, title), h('span', { class: 'muted' }, ` ${its.length}`)),
        h('div', { class: 'body' }, its.map(([it, i]) => row(it, i)))));
    }
    if ((r.unknown || []).length) out.push(h('details', { class: 'card' }, h('summary', {}, h('span', { class: 'fname' }, 'Lines not understood'), h('span', { class: 'muted' }, ` ${r.unknown.length}`)),
      h('div', { class: 'body' }, r.unknown.map(u => h('div', {}, h('code', {}, u.text))))));
    return h('div', {}, out);
  }

  function render() {
    const sel = $('against');
    sel.textContent = '';
    for (const p of policies) sel.append(h('option', { value: p.id, selected: p.id === against || null }, p.label));
    const main = $('main');
    main.textContent = '';
    main.append(sourceCard(), resultView() || '');
  }

  $('against').addEventListener('change', () => { against = $('against').value; if (text.trim()) send(); });

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (m.cmd === 'policies') { policies = m.policies || []; if (!against) { const b = policies.find(p => p.build) || policies.find(p => p.active); against = b ? b.id : null; } render(); }
    else if (m.cmd === 'export') { text = m.text || ''; result = null; fixes = new Map(); send(); }
    else if (m.cmd === 'result') {
      result = m.result;
      if (m.result && m.result.policies && m.result.policies.length) policies = m.result.policies;
      if (m.result && m.result.policy) against = m.result.policy.id;
      // The no-root read marks its text with this header line.
      if (result && !result.error && /^# Read without root/.test(text)) result.partial = true;
      render();
    } else if (m.cmd === 'plan') {
      fixes.set(m.key, m.plan);
      render();
    } else if (m.cmd === 'applied') {
      const f = fixes.get(m.key);
      fixes.set(m.key, m.error ? { error: m.error } : { ...(typeof f === 'object' ? f : {}), applied: true, path: m.path });
      render();
    } else if (m.cmd === 'built') {
      if (text.trim() && policies.some(p => p.id === against && p.build)) send();
    } else if (m.cmd === 'status') {
      $('status').textContent = m.text;
      if (result === 'waiting' && m.done) { result = null; render(); }
    } else if (m.cmd === 'error') {
      $('status').textContent = m.text;
    }
  });

  render();
  vscode.postMessage({ cmd: 'ready' });
}());
