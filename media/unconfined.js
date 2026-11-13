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
  let host; // undefined = the server's choice (a connected target when there is one), '' = this host, else a target id
  let since = 'today', targets = [];
  const SINCE = [['recent', 'last 10 minutes'], ['this-hour', 'this hour'], ['boot', 'since boot'], ['today', 'today'], ['this-week', 'this week'], ['push', 'since the last push']];
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
    vscode.postMessage({ cmd: 'load', key: ++key, against, params: { host, since: host ? since : null } });
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
    const d = r.denials;
    const onTarget = !!(result.host && result.host.target);
    const where = onTarget ? result.host.target : 'this host';
    const denialsCell = d ? h('div', { class: 'small' },
      h('span', { class: 'bad', title: `${d.count} denials of ${d.domains.join(', ')} since ${result.host.denials.since}${d.errors ? ` (${d.errors} SELINUX_ERR)` : ''}; classes: ${d.classes.join(', ') || '-'}; targets: ${d.targets.join(', ') || '-'}` }, `${plural(d.count, 'denial')}`),
      d.classes.length ? h('span', { class: 'muted' }, ` on ${d.classes.slice(0, 4).join(', ')}${d.classes.length > 4 ? ', …' : ''}`) : null) : null;
    const permissive = r.permissive ? h('span', { class: 'warn small', title: 'This domain is permissive on the host: its denials are logged, nothing is stopped' }, ' permissive') : null;
    const fix = d && r.module ? h('button', { class: 'primary', title: `Open the module ${r.module} in the service editor with these ${d.count} denials in its "From a permissive run" section: each becomes a setting of the form`, onclick: () => vscode.postMessage({ cmd: 'fixService', module: r.module, domain: d.domains[0], text: r.denialText || '', status: `${plural(d.count, 'denial')} of ${d.domains.join(', ')} read from ${where} (${result.host.denials.since}).` }) }, 'Fix in Service Editor…')
      : r.module ? h('button', { title: `Open the module ${r.module} in the service editor`, onclick: () => vscode.postMessage({ cmd: 'fixService', module: r.module, domain: null, text: '', status: '' }) }, 'Edit Service…') : null;
    const checklist = r.module ? h('button', { title: `The confinement checklist for ${r.module}: built, pushed to the target, permissive, running in its domain, exercised, denials into the form, enforced and verified`, onclick: () => vscode.postMessage({ cmd: 'confine', module: r.module, target: onTarget ? result.host.target : null }) }, 'Checklist…') : null;
    const dom = r.hostDomains[0] || r.policyDomain;
    const perm = onTarget && dom && !(result.unconfined || []).includes(dom) ? h('button', { class: 'link small', title: r.permissive ? `semanage permissive -d ${dom} on ${where}: the domain is enforced again` : `semanage permissive -a ${dom} on ${where}: its denials are logged, nothing is stopped (for a test run)`,
      onclick: () => vscode.postMessage({ cmd: 'permissive', target: result.host.target, domain: dom, on: !r.permissive }) }, r.permissive ? 'enforce again' : 'make permissive') : null;
    return h('tr', {},
      h('td', {}, h('button', { class: 'link', title: `Look up ${r.real} in File Labels`, onclick: () => vscode.postMessage({ cmd: 'lookUp', path: r.real }) }, r.exe), r.exe !== r.real ? h('div', { class: 'muted small' }, `→ ${r.real}`) : null, r.pkg ? h('div', { class: 'muted small' }, r.pkg) : null),
      h('td', {}, label),
      h('td', {}, runs, permissive, perm ? [' ', perm] : null, r.differs ? h('div', { class: 'small' }, h('span', { class: 'muted' }, 'policy: '), would) : null, !r.hostDomains.length && r.type ? h('div', { class: 'small' }, h('span', { class: 'muted' }, 'would start as '), would) : null, denialsCell),
      h('td', {}, units.length ? units : h('span', { class: 'muted small' }, r.pids.length ? `pid ${r.pids.slice(0, 3).join(', ')}${r.users.length ? ` (${r.users.join(', ')})` : ''}` : '')),
      h('td', {}, r.listens.length ? r.listens.map(l => `${l.proto} ${l.port}`).join(', ') : ''),
      h('td', {}, fix, fix ? ' ' : null, checklist, checklist ? ' ' : null, h('button', { title: `Confine ${r.real}: open the service editor with it as the program`, onclick: () => vscode.postMessage({ cmd: 'newService', exec: r.real, host: result && result.host ? result.host.target || '' : '' }) }, 'New Service…')));
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
    const onTarget = !!(result && result.host && result.host.target);
    main.append(h('p', { class: 'intro' },
      `The services systemd starts on ${onTarget ? result.host.target : 'this host'} and the processes running now, with the label each program gets, the domain it runs in there and the one the chosen policy would start it in `,
      '(the type_transition from init_t on the program\'s type). A program in a domain that confines nothing (unconfined_service_t, initrc_t, init_t itself) is the usual starting point for a lockdown: ',
      h('b', {}, 'New Service…'), ' opens the service editor with it as the program. Pick a tree build as the policy to see what the lockdown would do to the host\'s services. ',
      'With a target host, each service shows the denials logged there for its domain, and ', h('b', {}, 'Fix in Service Editor…'), ' opens its module with them in the "From a permissive run" section.'));
    // Whose programs, and how far back to read the denials, when a target host is connected.
    if (targets.length || (result && result.host && result.host.target)) {
      const hostSel = h('select', { title: 'Whose services and processes: this host, or a connected target host (read over its ssh connection)', onchange: (ev) => { host = ev.target.value; load(); } },
        h('option', { value: '', selected: !host || null }, 'this host'), ...targets.map(t => h('option', { value: t.id, selected: host === t.id || null }, `${t.id}${t.mode ? ` (${t.mode})` : ''}`)));
      const sinceSel = h('select', { title: 'How far back to read the target\'s audit log for each service\'s denials', onchange: (ev) => { since = ev.target.value; load(); } }, SINCE.map(([v, l]) => h('option', { value: v, selected: since === v || null }, l)));
      main.append(h('div', { class: 'small', id: 'hostbar' }, h('label', {}, 'Programs on ', hostSel), host ? h('label', {}, ' · denials since ', sinceSel) : null,
        host ? h('button', { title: `Install the last build's changed modules on ${host} (with a backup), then restart its services and read the new denials`, onclick: () => vscode.postMessage({ cmd: 'pushTarget', target: host }) }, ' Push build to target…') : null));
    }
    if (!result) return;
    if (result.error) { main.append(h('div', { class: 'note bad' }, result.error)); return; }
    const s = result.summary;
    main.append(h('div', { class: 'verdict' },
      s.unconfined ? h('span', { class: 'bad' }, `${plural(s.unconfined, 'program')} run unconfined${s.listening ? ` (${s.listening} listening on the network)` : ''}`) : h('span', { class: 'ok' }, '✓ Every program runs in a domain of its own'),
      s.nostart ? h('span', { class: 'warn' }, ` · ${s.nostart} the policy can't start`) : null,
      h('span', { class: 'muted' }, ` · ${plural(s.confined, 'confined program')} · ${result.host.hostname}: ${plural(result.host.units, 'service')}, ${result.host.processes} process${result.host.processes === 1 ? '' : 'es'} · ${result.policy && result.policy.label}`),
      result.host.denials && result.host.denials.since ? h('span', { class: result.host.denials.error ? 'warn' : result.host.denials.total ? 'bad' : 'ok' }, ` · ${result.host.denials.error ? result.host.denials.error : `${plural(result.host.denials.total, 'denial')} of these programs since ${result.host.denials.since}${result.host.denials.mode ? ` (${result.host.denials.mode.toLowerCase()})` : ''}`}`) : null,
      result.host.permissive && result.host.permissive.length ? h('span', { class: 'muted' }, ` · permissive there: ${result.host.permissive.slice(0, 6).join(', ')}${result.host.permissive.length > 6 ? ', …' : ''}`) : null));
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
      if (result && result.targets) targets = result.targets;
      if (result && result.host) host = result.host.target || '';
      render();
    } else if (m.cmd === 'reload') {
      load();
    } else if (m.cmd === 'targets') {
      targets = m.targets || [];
      if (host && !targets.some(t => t.id === host)) { host = ''; load(); } else render();
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
