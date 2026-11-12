// Booleans webview: every boolean of a policy with where its value comes from
// (the tunable's declaration, booleans.conf, the compiled default, the running
// value) and what it switches on or off; set it in booleans.conf (a tree) or
// with setsebool (a host). Plain JS, no deps.
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

  let result = null, against = null, key = 0, loading = false, filter = '', only = 'all';
  const openRows = new Set();
  const pending = new Map(); // name → 'planning' | 'applying' | 'applied' | { plan }
  const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
  const val = (v) => (v == null ? h('span', { class: 'muted' }, '—') : h('span', { class: v ? 'ok' : 'muted' }, v ? 'on' : 'off'));
  const ruleText = (r) => `${r.rt} ${r.s} ${r.t}:${r.c} { ${r.perms.join(' ')} }`;

  function load() {
    loading = true;
    vscode.postMessage({ cmd: 'load', key: ++key, against });
    render();
  }

  const matches = (r) => {
    if (only === 'on' && r.effective !== true) return false;
    if (only === 'off' && r.effective !== false) return false;
    if (only === 'changed' && !r.changed) return false;
    if (!filter) return true;
    const f = filter.toLowerCase();
    return [r.name, r.desc, r.module, ...((r.on && r.on.domains) || []), ...((r.off && r.off.domains) || [])].some(x => x && String(x).toLowerCase().includes(f));
  };

  function effectCell(r) {
    const parts = [];
    if (r.on && r.on.count) parts.push(h('span', {}, `on: ${plural(r.on.count, 'rule')} for ${r.on.domains.slice(0, 3).join(', ')}${r.on.domains.length > 3 ? ', …' : ''}`));
    if (r.off && r.off.count) parts.push(h('span', {}, `off: ${plural(r.off.count, 'rule')} for ${r.off.domains.slice(0, 3).join(', ')}${r.off.domains.length > 3 ? ', …' : ''}`));
    if (r.mixed) parts.push(h('span', { class: 'muted' }, `${r.mixed} with other booleans`));
    if (!parts.length) return h('span', { class: 'muted' }, r.inPolicy ? 'nothing in the compiled policy' : 'not in this policy');
    return h('div', {}, parts.flatMap((p, i) => (i ? [h('br'), p] : [p])));
  }

  function setButtons(r) {
    const st = pending.get(r.name);
    if (st === 'planning') return h('span', { class: 'muted' }, 'planning…');
    if (st === 'applying') return h('span', { class: 'muted' }, 'writing…');
    if (st === 'applied') return h('span', { class: 'ok' }, '✓ written; building…');
    if (st && st.plan) {
      const pl = st.plan;
      if (pl.error) return h('span', { class: 'bad' }, pl.error);
      if (pl.already) return h('span', { class: 'muted' }, 'already so in booleans.conf');
      return h('span', {}, h('button', { class: 'primary', title: `Write it to ${pl.path} and save (builds)`, onclick: () => { pending.set(r.name, 'applying'); vscode.postMessage({ cmd: 'applyFix', key: ++key, plan: pl, name: r.name }); render(); } }, `Apply to booleans.conf`),
        ' ', h('code', { class: 'small' }, (pl.inserted || []).join(' ')), pl.created ? h('span', { class: 'muted' }, ' (new file)') : null);
    }
    const target = r.effective !== true;
    if (result.conf && result.conf.editable) {
      return h('button', { title: `Set ${r.name} = ${target ? 'true' : 'false'} in ${result.conf.path} (the tree's default)`, onclick: () => { pending.set(r.name, 'planning'); vscode.postMessage({ cmd: 'set', key: ++key, name: r.name, value: target }); render(); } }, `Set ${target ? 'on' : 'off'} in booleans.conf`);
    }
    if (result.policy && result.policy.active) {
      return h('button', { title: `Run sudo setsebool -P ${r.name} ${target ? 'on' : 'off'} in a terminal (it asks for your password there)`, onclick: () => vscode.postMessage({ cmd: 'setsebool', name: r.name, value: target }) }, `setsebool -P ${target ? 'on' : 'off'}`);
    }
    return null;
  }

  function row(r) {
    const open = openRows.has(r.name);
    const nameCell = r.loc ? h('button', { class: 'link', title: `Open the declaration of ${r.name}${r.module ? ` (${r.module})` : ''}`, onclick: () => vscode.postMessage({ cmd: 'open', loc: r.loc }) }, r.name) : h('code', {}, r.name);
    const sources = [];
    if (r.source != null) sources.push(`declared ${r.source ? 'on' : 'off'}`);
    if (r.conf != null) sources.push(`booleans.conf ${r.conf ? 'on' : 'off'}`);
    if (r.compiled != null) sources.push(`compiled ${r.compiled ? 'on' : 'off'}`);
    if (r.running != null) sources.push(`running ${r.running ? 'on' : 'off'}`);
    const tr = h('tr', { class: r.changed ? 'changed' : null },
      h('td', {}, nameCell, r.tunable === false ? h('span', { class: 'muted small', title: 'gen_bool: a boolean of the base policy, not a tunable' }, ' (bool)') : null, r.desc ? h('div', { class: 'muted small' }, r.desc.slice(0, 160)) : null),
      h('td', {}, val(r.effective), r.changed ? h('span', { class: 'badge new', title: 'Set away from its declared default (booleans.conf), or changed on the running host' }, ' changed') : null, h('div', { class: 'muted small' }, sources.join(', '))),
      h('td', {}, effectCell(r), (r.on && r.on.count) || (r.off && r.off.count) ? h('div', {}, h('button', { class: 'link small', onclick: () => { if (open) openRows.delete(r.name); else openRows.add(r.name); render(); } }, open ? 'hide the rules' : 'show the rules')) : null),
      h('td', {}, setButtons(r)));
    if (!open) return tr;
    const rules = (side, label) => (side && side.rules.length ? [h('div', { class: 'sub small' }, `When ${label} (${plural(side.count, 'rule')}${side.rules.length < side.count ? `, the first ${side.rules.length}` : ''}):`), h('ul', { class: 'small' }, side.rules.map(x => h('li', {}, h('code', {}, ruleText(x)))))] : []);
    return [tr, h('tr', {}, h('td', { colspan: 4, class: 'rules' }, ...rules(r.on, 'on'), ...rules(r.off, 'off'), (r.exprs || []).length > 1 ? h('div', { class: 'muted small' }, `Conditions: ${r.exprs.join('; ')}`) : null))];
  }

  function render() {
    const main = $('main');
    main.textContent = '';
    $('status').textContent = loading ? 'Reading the booleans…' : '';
    const sel = $('against');
    sel.textContent = '';
    for (const p of (result && result.policies) || []) sel.append(h('option', { value: p.id, selected: (result.policy && result.policy.id === p.id) || null }, p.label));
    main.append(h('p', { class: 'intro' }, 'Every boolean of the policy: what it switches on or off (the conditional rules of the compiled policy, with the other booleans at their defaults), and where its value comes from — ',
      'its declaration in the sources (gen_tunable / gen_bool), booleans.conf (the tree\'s defaults, or the spec\'s overlay), the compiled policy, and the running policy on this host. ',
      'In a tree build, Set writes the value into booleans.conf; on a host, setsebool -P changes it (in a terminal, with sudo).'));
    if (!result) return;
    if (result.error) { main.append(h('div', { class: 'note bad' }, result.error)); return; }
    const s = result.summary;
    main.append(h('div', { class: 'verdict' }, `${plural(s.total, 'boolean')}: ${s.on} on, ${s.off} off`, s.changed ? h('span', { class: 'warn' }, ` · ${s.changed} changed from the declared default`) : null,
      s.undeclared ? h('span', { class: 'muted' }, ` · ${s.undeclared} not declared in this tree's sources`) : null, s.confOnly ? h('span', { class: 'warn' }, ` · ${s.confOnly} in booleans.conf but not in the policy`) : null,
      h('span', { class: 'muted' }, ` · ${result.policy && result.policy.label}${result.conf && result.conf.path ? ` · booleans.conf: ${result.conf.path.split('/').pop()}${result.conf.exists ? '' : ' (absent)'}` : ''}`)));
    main.append(h('div', { class: 'small' }, h('label', {}, 'Filter ', h('input', { id: 'filter', value: filter, placeholder: 'name, description, domain', oninput: (ev) => { filter = ev.target.value; renderTable(); } })), ' ',
      h('label', {}, 'Show ', h('select', { onchange: (ev) => { only = ev.target.value; renderTable(); } }, [['all', 'all'], ['on', 'on'], ['off', 'off'], ['changed', 'changed from the default']].map(([v, l]) => h('option', { value: v, selected: only === v || null }, l))))));
    tableEl = h('div');
    main.append(tableEl);
    renderTable();
  }
  let tableEl = null;
  function renderTable() {
    if (!tableEl || !result || !result.rows) return;
    tableEl.textContent = '';
    const rows = result.rows.filter(matches);
    tableEl.append(h('div', { class: 'muted small' }, `${rows.length === result.rows.length ? rows.length : `${rows.length} of ${result.rows.length}`} shown`));
    tableEl.append(h('table', {}, h('tr', {}, h('th', {}, 'Boolean'), h('th', {}, 'Value'), h('th', {}, 'Switches'), h('th', {}, '')), rows.slice(0, 400).map(row)));
    if (rows.length > 400) tableEl.append(h('div', { class: 'muted' }, `${rows.length - 400} more: narrow the filter.`));
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
      pending.clear();
      render();
    } else if (m.cmd === 'setPlan') {
      pending.set(m.name, { plan: m.plan || { error: 'No answer.' } });
      render();
    } else if (m.cmd === 'applied') {
      pending.set(m.name, 'applied');
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
