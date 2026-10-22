// Login Contexts webview: whether each login of a policy gets a valid context
// for each way in ("Unable to get valid context for <user>" before a host sees
// it), as libselinux 3.x (RHEL 9, 10) and 2.x (RHEL 8) decide. Plain JS, no deps.
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
      h('div', { class: 'where small' }, loc(p.file, p.l), p.source ? h('span', { class: 'muted' }, ` · from ${p.source}`) : null),
      rel);
  }

  function wayRow(m, w) {
    const res = (works, pick) => (works ? h('code', { class: 'ok', title: pick.how === 'failsafe' ? 'the failsafe context' : 'the first valid listed context' }, pick.ctx + (pick.how === 'failsafe' ? ' (failsafe)' : ''))
      : h('span', { class: 'bad' }, '✗ no session'));
    const cands = h('details', { class: 'cands' }, h('summary', { class: 'muted small' }, `${w.candidates.length} listed context${w.candidates.length === 1 ? '' : 's'}`),
      h('table', {}, h('tr', {}, h('th', {}, 'Listed'), h('th', {}, 'RHEL 9+ (libselinux 3.x)'), h('th', {}, 'RHEL 8 (kernel computes)'), h('th', {}, 'Line')),
        w.candidates.map(c => h('tr', {},
          h('td', {}, h('code', {}, `${c.role}:${c.type}`)),
          h('td', {}, c.valid ? (c.transition.ok ? h('span', { class: 'ok' }, 'valid') : h('span', { class: 'warn' }, `valid, but ${c.transition.text}`)) : h('span', { class: 'bad' }, c.reasons.map(r => r.text).join('; '))),
          h('td', {}, !c.ctx2 ? h('span', { class: 'bad' }, w.v2rangeError || 'no session range') : c.valid2 ? (c.transition2 && c.transition2.ok ? h('span', { class: 'ok' }, `reachable at ${c.ctx2.split(':').slice(3).join(':') || '—'}`) : h('span', { class: 'bad' }, c.transition2 ? c.transition2.text : '')) : h('span', { class: 'bad' }, c.reasons2.map(r => r.text).join('; '))),
          h('td', {}, loc(c.file, c.l, `${base(c.file)}:${c.l + 1}${c.own ? ' (own)' : ''}`))))),
      w.failsafe ? h('div', { class: 'small' }, 'Failsafe: ', h('code', {}, w.failsafe.ctx), ' — ', w.failsafe.valid ? (w.failsafe.transition.ok ? h('span', { class: 'ok' }, 'valid') : h('span', { class: 'warn' }, `valid, but ${w.failsafe.transition.text}`)) : h('span', { class: 'bad' }, w.failsafe.reasons.map(r => r.text).join('; '))) : null);
    return h('tr', {},
      h('td', {}, h('span', { title: w.fromcon }, w.label)),
      h('td', {}, res(w.works3, w.v3 || {})),
      h('td', {}, res(w.works2, w.v2 || {})),
      h('td', {}, cands));
  }

  function mappingCard(m, i) {
    const who = m.hypothetical ? m.login : `${m.group ? '%' : ''}${m.login}`;
    const bad = m.ways.filter(w => !w.works3 || !w.works2).length;
    const hint = `${m.hypothetical ? '' : `→ ${m.user}${m.range ? ` ${m.range}` : ''} · `}${m.ways.length} way${m.ways.length === 1 ? '' : 's'} in${bad ? ` · ${bad} failing` : ''}`;
    return card(`m${i}:${who}`, who, hint, [
      h('div', { class: 'small muted' }, m.hypothetical ? `No seusers line maps a login to ${m.user}; checked as if one did, at ${m.level || 'its default level'}. ` : `seusers line `, m.hypothetical ? loc(m.file, m.l, `${base(m.file)}`) : loc(m.file, m.l)),
      m.ways.length ? h('table', { class: 'ways' }, h('tr', {}, h('th', {}, 'Way in'), h('th', {}, 'RHEL 9 and later'), h('th', {}, 'RHEL 8'), h('th', {}, '')), m.ways.map(w => wayRow(m, w)))
        : h('div', { class: 'muted' }, 'No contexts file offers it a way in.'),
    ], bad > 0);
  }

  function render() {
    const main = $('main');
    main.textContent = '';
    $('status').textContent = loading ? 'Checking…' : '';
    const sel = $('against');
    sel.textContent = '';
    for (const p of (result && result.policies) || []) sel.append(h('option', { value: p.id, selected: (result.policy && result.policy.id === p.id) || null }, p.label));
    main.append(h('p', { class: 'intro' },
      'Whether each login gets a valid SELinux context for each way in (ssh, console, graphical, cron, …), the way libselinux decides it when a session starts. ',
      'A policy can compile and still lock people out with "Unable to get valid context for <user>": seusers maps a login to a user without the right role, a contexts file lists a role:type the user can\'t have, a range is outside the user\'s, or the login program may not transition to the user\'s domain. ',
      'RHEL 9 and later (libselinux 3.x) take the first valid listed context; RHEL 8 (2.x) lets the kernel compute the reachable ones, so the two can differ.'));
    if (!result) return;
    if (result.error) { main.append(h('div', { class: 'note bad' }, result.error)); return; }
    const count = (s) => result.problems.filter(p => p.severity === s).length;
    const ne = count('error'), nw = count('warning'), ni = count('info');
    main.append(h('div', { class: 'verdict' }, ne || nw ? h('span', { class: ne ? 'bad' : 'warn' }, `${ne} error${ne === 1 ? '' : 's'}, ${nw} warning${nw === 1 ? '' : 's'}`) : h('span', { class: 'ok' }, '✓ Every login gets a valid context'),
      ni ? h('span', { class: 'muted' }, ` · ${ni} note${ni === 1 ? '' : 's'}`) : null,
      h('span', { class: 'muted' }, ` · ${result.policy && result.policy.label}`)));
    if (result.problems.length) main.append(card('problems', 'Problems', `${result.problems.length}`, result.problems.map(problemRow), true));
    main.append(card('logins', 'Logins and their ways in', `${result.mappings.length} seusers line${result.mappings.length === 1 ? '' : 's'}`, result.mappings.map(mappingCard), true));
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
      if (m.ok && (!result || !result.policy || result.policy.build)) load();
    } else if (m.cmd === 'error') {
      loading = false;
      result = { error: m.text, policies: (result && result.policies) || [] };
      render();
    }
  });
  render();
  load();
}());
