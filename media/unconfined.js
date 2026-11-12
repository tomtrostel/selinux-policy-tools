// Unconfined Programs webview: this host's services and processes, the label
// each program gets, the domain it runs in here and the one the chosen policy
// would start it in; the ones without a domain of their own first, each a
// click from a new service module. Plain JS, no deps.
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

  let result = null, against = null, key = 0, loading = false, filter = '';
  const open = new Map();
  const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
  const card = (id, title, hint, body, defOpen) => {
    const d = h('details', { class: 'card', open: (open.has(id) ? open.get(id) : defOpen) || null }, h('summary', {}, h('span', { class: 'fname' }, title), hint ? h('span', { class: 'muted' }, hint) : null), h('div', { class: 'body' }, body));
    d.addEventListener('toggle', () => open.set(id, d.open));
    return d;
  };
  const typeLink = (name) => {
    const l = result && result.locs && result.locs[name];
    return l ? h('button', { class: 'link', title: `Open the declaration of ${name}`, onclick: () => vscode.postMessage({ cmd: 'open', loc: l }) }, name) : h('code', {}, name);
  };

  function load() {
    loading = true;
    vscode.postMessage({ cmd: 'load', key: ++key, against });
    render();
  }

  const GROUPS = [
    ['unconfined', 'Run unconfined', 'These programs run (or would run) in a domain that confines nothing: a denial can never stop them. Each is a candidate for a service module of its own.', true],
    ['nostart', "The policy can't start them", 'init_t may not run programs of this label at all under the chosen policy (no transition and no execute_no_trans): the service would fail to start on a host running it.', true],
    ['confined', 'Confined', 'A domain of their own, entered by a type_transition from init_t.', false],
    ['unknown', 'Not labeled or not running', 'No file context labels the program under this policy, or it is not running and nothing says what would start it.', false],
  ];

  function row(r) {
    const units = r.units.map(u => h('span', { class: 'small', title: `${u.id}: ${u.active || '?'} (${u.sub || '?'})${u.user ? `, User=${u.user}` : ''}${u.nnp ? ', NoNewPrivileges' : ''}` }, u.id, u.active === 'active' ? '' : h('span', { class: 'muted' }, ` (${u.active || '?'})`), ' '));
    const runs = r.hostDomains.length ? h('span', {}, r.hostDomains.map((d, i) => [i ? ', ' : null, typeLink(d)])) : h('span', { class: 'muted' }, 'not running');
    const would = r.policyDomain ? typeLink(r.policyDomain) : r.how === 'manual' ? h('span', { class: 'muted' }, 'only with setexec') : r.how === 'none' ? h('span', { class: 'bad' }, "can't start it") : r.how === 'stays' ? typeLink('init_t') : h('span', { class: 'muted' }, '?');
    const label = r.type ? h('span', {}, h('code', {}, r.type), r.generic ? h('span', { class: 'warn small', title: 'A generic file type: nothing singles this program out, so no domain of its own can be entered through it' }, ' generic') : null) : h('span', { class: 'muted' }, 'none');
    return h('tr', {},
      h('td', {}, h('button', { class: 'link', title: `Look up ${r.real} in File Labels`, onclick: () => vscode.postMessage({ cmd: 'lookUp', path: r.real }) }, r.exe), r.exe !== r.real ? h('div', { class: 'muted small' }, `→ ${r.real}`) : null, r.pkg ? h('div', { class: 'muted small' }, r.pkg) : null),
      h('td', {}, label),
      h('td', {}, runs, r.differs ? h('div', { class: 'small' }, h('span', { class: 'muted' }, 'policy: '), would) : null, !r.hostDomains.length && r.type ? h('div', { class: 'small' }, h('span', { class: 'muted' }, 'would start as '), would) : null),
      h('td', {}, units.length ? units : h('span', { class: 'muted small' }, r.pids.length ? `pid ${r.pids.slice(0, 3).join(', ')}${r.users.length ? ` (${r.users.join(', ')})` : ''}` : '')),
      h('td', {}, r.listens.length ? r.listens.map(l => `${l.proto} ${l.port}`).join(', ') : ''),
      h('td', {}, h('button', { title: `Confine ${r.real}: open the service editor with it as the program`, onclick: () => vscode.postMessage({ cmd: 'newService', exec: r.real }) }, 'New Service…')));
  }

  function table(rows) {
    return h('table', {}, h('tr', {}, h('th', {}, 'Program'), h('th', {}, 'Label'), h('th', {}, 'Runs as'), h('th', {}, 'Service'), h('th', {}, 'Listens'), h('th', {}, '')), rows.map(row));
  }

  const matches = (r) => {
    if (!filter) return true;
    const f = filter.toLowerCase();
    return [r.exe, r.real, r.type, r.pkg, ...r.hostDomains, r.policyDomain, ...r.units.map(u => u.id), ...r.listens.map(l => `${l.proto} ${l.port}`)].some(x => x && String(x).toLowerCase().includes(f));
  };

  function render() {
    const main = $('main');
    main.textContent = '';
    $('status').textContent = loading ? 'Looking at this host…' : '';
    const sel = $('against');
    sel.textContent = '';
    for (const p of (result && result.policies) || []) sel.append(h('option', { value: p.id, selected: (result.policy && result.policy.id === p.id) || null }, p.label));
    main.append(h('p', { class: 'intro' },
      'The services systemd starts on this host and the processes running now, with the label each program gets, the domain it runs in here and the one the chosen policy would start it in ',
      '(the type_transition from init_t on the program\'s type). A program in a domain that confines nothing (unconfined_service_t, initrc_t, init_t itself) is the usual starting point for a lockdown: ',
      h('b', {}, 'New Service…'), ' opens the service editor with it as the program. Pick a tree build as the policy to see what the lockdown would do to this host\'s services.'));
    if (!result) return;
    if (result.error) { main.append(h('div', { class: 'note bad' }, result.error)); return; }
    const s = result.summary;
    main.append(h('div', { class: 'verdict' },
      s.unconfined ? h('span', { class: 'bad' }, `${plural(s.unconfined, 'program')} run unconfined${s.listening ? ` (${s.listening} listening on the network)` : ''}`) : h('span', { class: 'ok' }, '✓ Every program runs in a domain of its own'),
      s.nostart ? h('span', { class: 'warn' }, ` · ${s.nostart} the policy can't start`) : null,
      h('span', { class: 'muted' }, ` · ${plural(s.confined, 'confined program')} · ${result.host.hostname}: ${plural(result.host.units, 'service')}, ${result.host.processes} process${result.host.processes === 1 ? '' : 'es'} · ${result.policy && result.policy.label}`)));
    main.append(h('div', { class: 'small' }, h('label', {}, 'Filter ', h('input', { id: 'filter', value: filter, placeholder: 'program, label, domain, service, port', oninput: (ev) => { filter = ev.target.value; renderGroups(); } })),
      h('span', { class: 'muted' }, ` · domains that confine nothing in this policy: ${(result.unconfined || []).join(', ') || 'none'}`)));
    groupsEl = h('div', { id: 'groups' });
    main.append(groupsEl);
    renderGroups();
    for (const n of (result.host.limits || [])) main.append(h('div', { class: 'note muted small' }, n));
  }

  let groupsEl = null;
  function renderGroups() {
    const g = groupsEl;
    if (!g || !result || !result.rows) return;
    g.textContent = '';
    for (const [id, title, hint, defOpen] of GROUPS) {
      const rows = result.rows.filter(r => r.verdict === id && matches(r));
      const all = result.rows.filter(r => r.verdict === id).length;
      if (!all) continue;
      g.append(card(id, title, `${rows.length === all ? all : `${rows.length} of ${all}`}`, [h('div', { class: 'muted small' }, hint), rows.length ? table(rows) : h('div', { class: 'muted' }, 'none match the filter')], defOpen && all > 0));
    }
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
