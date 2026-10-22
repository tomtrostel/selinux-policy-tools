// Context Files webview: whether the contexts a policy's configuration names
// load (file_contexts, its home-directory lines as genhomedircon writes them,
// file_contexts.local, and the application context files in contexts/), and
// what breaks where one doesn't. Plain JS, no deps.
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

  const SEV = { error: ['✗', 'bad', 'Error'], warning: ['⚠', 'warn', 'Warning'], info: ['ℹ', 'muted', 'Info'] };
  let result = null, against = null, key = 0, loading = false;
  const open = new Map();

  const base = (p) => String(p || '').split('/').pop();
  const loc = (file, l, text) => (file ? h('button', { class: 'link', title: `Open ${file}:${l + 1}`, onclick: () => vscode.postMessage({ cmd: 'open', loc: { p: file, l, c: 0 } }) }, text || `${base(file)}:${l + 1}`) : null);
  const card = (id, title, hint, body, defOpen) => {
    const d = h('details', { class: 'card', open: (open.has(id) ? open.get(id) : defOpen) || null }, h('summary', {}, h('span', { class: 'fname' }, title), hint ? h('span', { class: 'muted' }, hint) : null), h('div', { class: 'body' }, body));
    d.addEventListener('toggle', () => open.set(id, d.open));
    return d;
  };
  const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
  const entries = (n) => `${n} entr${n === 1 ? 'y' : 'ies'}`;

  function load() {
    loading = true;
    vscode.postMessage({ cmd: 'load', key: ++key, against });
    render();
  }

  function problemRow(p, i) {
    const [icon, cls, word] = SEV[p.severity] || SEV.info;
    const rel = (p.related || []).length
      ? h('details', { class: 'rel' }, h('summary', { class: 'muted small' }, `${p.related.length} line${p.related.length > 1 ? 's' : ''} involved`),
        h('ul', {}, p.related.map(x => h('li', {}, loc(x.file, x.l), ' ', h('code', {}, x.text)))))
      : null;
    return h('div', { class: `problem ${cls}`, 'data-i': i },
      h('div', {}, h('span', { class: `sev ${cls}`, title: word }, icon), ' ', h('span', { class: 'ptext' }, p.text)),
      h('div', { class: 'where small' }, loc(p.file, p.l)),
      rel);
  }

  function filesCard() {
    const rows = result.files.map(f => h('tr', {},
      h('td', {}, f.exists ? loc(f.path, 0, f.name) : h('span', { class: 'muted' }, f.name)),
      h('td', {}, f.program),
      h('td', {}, !f.exists ? h('span', { class: 'muted' }, 'not in this policy') : f.unused ? h('span', { class: 'muted' }, `${entries(f.entries)}; nothing in the policy reads it`)
        : f.problems ? h('span', { class: 'warn' }, `${plural(f.problems, 'problem')} in ${entries(f.entries)}`) : h('span', { class: 'ok' }, `✓ ${entries(f.entries)}`))));
    const present = result.files.filter(f => f.exists).length;
    return card('files', 'Application context files', `${present} of ${result.files.length} present`,
      h('table', {}, h('tr', {}, h('th', {}, 'File'), h('th', {}, 'Read by'), h('th', {}, 'Result')), rows), false);
  }

  function fcCard() {
    const fc = result.fc;
    const row = (k, what) => (fc[k] && fc[k].count ? h('tr', {}, h('td', {}, fc[k].label || what), h('td', {}, String(fc[k].count)),
      h('td', {}, fc[k].invalid ? h('span', { class: 'bad' }, `${fc[k].invalid} invalid`) : h('span', { class: 'ok' }, '✓ all valid'))) : null);
    const homes = (result.homes || []).length
      ? h('table', {}, h('tr', {}, h('th', {}, 'SELinux user'), h('th', {}, 'Logins'), h('th', {}, 'Prefix'), h('th', {}, 'Home lines')),
        result.homes.map(x => h('tr', {},
          h('td', {}, h('code', {}, x.user), x.level ? h('span', { class: 'muted' }, ` ${x.level}`) : null),
          h('td', {}, x.logins.join(', ')),
          h('td', {}, h('code', {}, x.prefix), x.role ? h('span', { class: x.role === 'object_r' ? 'muted' : 'warn' }, ` (role ${x.role})`) : null),
          h('td', {}, x.dropped ? h('span', { class: 'warn' }, `${x.lines - x.dropped} of ${x.lines} written`) : h('span', { class: 'ok' }, `✓ all ${x.lines} written`)))))
      : null;
    return card('fc', 'File contexts', `${fc.associateChecked} types checked`, [
      h('table', {}, h('tr', {}, h('th', {}, 'File'), h('th', {}, 'Lines'), h('th', {}, 'Contexts')), row('main', 'file_contexts'), row('local', 'file_contexts.local'), row('homedirs', 'file_contexts.homedirs')),
      fc.templates ? h('p', { class: 'small' }, `${plural(fc.templates, 'home-directory template line')}, written once per user by genhomedircon:`) : null,
      homes,
    ], false);
  }

  function render() {
    const main = $('main');
    main.textContent = '';
    $('status').textContent = loading ? 'Checking…' : '';
    const sel = $('against');
    sel.textContent = '';
    for (const p of (result && result.policies) || []) sel.append(h('option', { value: p.id, selected: (result.policy && result.policy.id === p.id) || null }, p.label));
    main.append(h('p', { class: 'intro' },
      'Whether every context the policy\'s configuration names is one the policy accepts, and what breaks where one isn\'t. ',
      'semodule refuses a file_contexts with an invalid context or two lines for one path; one stale line in file_contexts.local makes every semodule and semanage change fail; ',
      'genhomedircon silently leaves out home-directory lines whose context isn\'t valid for a user; restorecon can\'t give a file a type that may not be on a filesystem; ',
      'and the programs reading the other context files (run_init, the X server, dbus-daemon, sshd, libvirt, container runtimes, newrole) fail or skip entries they can\'t use.'));
    if (!result) return;
    if (result.error) { main.append(h('div', { class: 'note bad' }, result.error)); return; }
    const count = (s) => result.problems.filter(p => p.severity === s).length;
    const ne = count('error'), nw = count('warning'), ni = count('info');
    main.append(h('div', { class: 'verdict' }, ne || nw ? h('span', { class: ne ? 'bad' : 'warn' }, `${plural(ne, 'error')}, ${plural(nw, 'warning')}`) : h('span', { class: 'ok' }, '✓ Every context loads'),
      ni ? h('span', { class: 'muted' }, ` · ${plural(ni, 'note')}`) : null,
      h('span', { class: 'muted' }, ` · ${result.policy && result.policy.label}`)));
    if (result.problems.length) main.append(card('problems', 'Problems', `${result.problems.length}`, result.problems.map(problemRow), true));
    main.append(fcCard());
    main.append(filesCard());
    if ((result.notes || []).length) main.append(h('div', { class: 'notes' }, result.notes.map(n => h('div', { class: 'note muted' }, n))));
  }

  $('against').addEventListener('change', () => { against = $('against').value; load(); });
  $('refresh').addEventListener('click', load);
  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (m.cmd === 'result') {
      if (m.key !== key) return;
      loading = false;
      result = m.result;
      if (result && result.policy) against = result.policy.id;
      render();
    } else if (m.cmd === 'built') {
      if (!result || !result.policy || result.policy.build) load();
    } else if (m.cmd === 'error') {
      loading = false;
      result = { error: m.text, policies: (result && result.policies) || [] };
      render();
    }
  });
  render();
  load();
}());
