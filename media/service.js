// Service editor webview: a form over the service model (server/service.js),
// a live preview of the file changes, and Create/Apply. Plain JS, no deps.
/* global acquireVsCodeApi */
(function () {
  const vscode = acquireVsCodeApi();
  let info = null;   // from selinux/serviceInfo
  let model = null;  // edited copy
  let plan = null;   // last selinux/servicePlan result
  let tab = 'te';
  let where = null;  // layer (tree) or folder (standalone) for a new module
  let planTimer = null;
  let dirty = false;

  const $ = (id) => document.getElementById(id);
  function h(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (k === 'class') e.className = v;
      else if (k === 'value') e.value = v;
      else if (k === 'checked') e.checked = !!v;
      else e.setAttribute(k, v === true ? '' : v);
    }
    for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
    return e;
  }
  const kindOf = (id) => info.catalog.fileKinds.find(k => k.id === id) || { id, label: id, access: ['none'], suffix: '_t' };
  const sub = (s) => (s || '').replace(/%/g, model.name || 'NAME');
  const typeOf = (row) => row.type ? sub(row.type) : `${model.name || 'NAME'}${kindOf(row.kind).suffix}`;

  function changed() {
    dirty = true;
    clearTimeout(planTimer);
    planTimer = setTimeout(() => vscode.postMessage({ cmd: 'plan', model, where }), 250);
  }

  /* ---------- sections ---------- */

  function section(title, hint, body, open = true) {
    return h('details', { class: 'card', open }, h('summary', {}, h('span', { class: 'title' }, title), hint ? h('span', { class: 'hint' }, hint) : null), h('div', { class: 'body' }, body));
  }
  function check(label, on, set, extra) {
    return h('label', { class: 'check' + (extra && extra.risky ? ' risky' : '') }, h('input', { type: 'checkbox', checked: on, disabled: extra && extra.disabled, onchange: (e) => { set(e.target.checked); changed(); } }),
      h('span', {}, label, extra && extra.risky ? h('span', { class: 'warn', title: 'Grants a lot; make sure the service needs it' }, ' ⚠') : null, extra && extra.code ? h('code', { class: 'code' }, extra.code) : null, extra && extra.note ? h('span', { class: 'muted' }, ' ' + extra.note) : null));
  }
  const lines = (arr) => (arr || []).join('\n');
  const unlines = (s) => s.split('\n').map(x => x.trim()).filter(Boolean);

  function serviceSection() {
    const rows = [];
    if (info.isNew) {
      rows.push(h('div', { class: 'row' }, h('label', { class: 'lbl', for: 'name' }, 'Module name'),
        h('input', { id: 'name', type: 'text', value: model.name, placeholder: 'e.g. mydaemon', spellcheck: 'false', size: 24,
          oninput: (e) => { model.name = e.target.value.trim(); refreshTypes(); changed(); } }),
        h('span', { class: 'muted' }, ' lowercase letters, digits, _; types are named after it')));
      if (info.layers) {
        rows.push(h('div', { class: 'row' }, h('label', { class: 'lbl' }, 'Layer'),
          h('select', { onchange: (e) => { where = e.target.value; changed(); } }, info.layers.map(l => h('option', { value: l, selected: l === where }, l))),
          h('span', { class: 'muted' }, ' policy/modules/<layer>/; added to modules.conf as a loadable module')));
      } else {
        rows.push(h('div', { class: 'row' }, h('label', { class: 'lbl' }, 'Folder'),
          h('input', { type: 'text', value: where || '', placeholder: `${info.folder || ''}/<name>`, size: 40, spellcheck: 'false', oninput: (e) => { where = e.target.value.trim() || null; changed(); } })));
      }
    } else {
      rows.push(h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Module'), h('b', {}, model.name), h('span', { class: 'muted' }, ` (${info.layer})`),
        info.domains.length > 1 ? h('span', {}, h('span', { class: 'lbl', style: 'margin-left:16px' }, 'Domain'),
          h('select', { onchange: (e) => vscode.postMessage({ cmd: 'domain', domain: e.target.value }) }, info.domains.map(d => h('option', { value: d.domain, selected: d.domain === model.domain }, d.domain)))) : h('span', { class: 'muted' }, `  domain ${model.domain}`)));
    }
    rows.push(h('div', { class: 'row' }, h('label', { class: 'lbl' }, 'Description'),
      h('input', { type: 'text', value: model.summary || '', placeholder: 'What the service does (one line)', size: 50, disabled: !info.isNew,
        title: info.isNew ? '' : 'The summary at the top of the .if; edit it there', oninput: (e) => { model.summary = e.target.value; changed(); } })));
    rows.push(h('div', { class: 'row top' }, h('label', { class: 'lbl' }, 'Program'),
      h('textarea', { rows: Math.max(1, (model.exec || []).length), cols: 40, spellcheck: 'false', placeholder: '/usr/bin/%', oninput: (e) => { model.exec = unlines(e.target.value); changed(); } }, lines(model.exec)),
      h('span', { class: 'muted' }, ' one path per line; it runs in ', h('code', {}, model.domain || `${model.name || 'NAME'}_t`), ' when systemd starts it')));
    rows.push(check('Permissive while testing (denials are logged, not enforced)', model.permissive, (v) => { model.permissive = v; }));
    if (info.isNew) rows.push(h('div', { class: 'muted small' }, '% in paths and names stands for the module name.'));
    return section('Service', null, rows);
  }

  function filesSection() {
    const kinds = info.catalog.fileKinds;
    const table = h('div', { class: 'files' });
    const head = h('div', { class: 'frow head' }, h('span', {}, 'Kind'), h('span', {}, 'Type'), h('span', {}, 'Paths'), h('span', {}, 'Access'), h('span'));
    table.append(head);
    model.files.forEach((row, i) => {
      const k = kindOf(row.kind);
      const fresh = !row.type || info.isNew || row._new;
      const accessOpts = k.access.includes(row.access) ? k.access : [row.access, ...k.access];
      table.append(h('div', { class: 'frow' },
        h('span', { title: k.where }, k.label, k.where ? h('div', { class: 'muted small' }, k.where) : null),
        fresh ? h('input', { type: 'text', class: 'typein', value: row.type || '', placeholder: typeOf({ kind: row.kind }), spellcheck: 'false',
          oninput: (e) => { row.type = e.target.value.trim(); changed(); } }) : h('code', {}, row.type),
        ['tmp', 'tmpfs', 'lock'].includes(k.id) && !row.paths.length
          ? h('span', { class: 'muted small' }, 'labeled when the service creates them')
          : h('textarea', { rows: Math.max(1, row.paths.length), spellcheck: 'false', placeholder: k.path || '/path/', oninput: (e) => { row.paths = unlines(e.target.value); changed(); } }, lines(row.paths)),
        h('select', { onchange: (e) => { row.access = e.target.value; changed(); }, title: info.catalog.accessLabels[row.access] },
          accessOpts.map(a => h('option', { value: a, selected: a === row.access }, info.catalog.accessLabels[a] || a))),
        h('button', { class: 'icon', title: 'Remove this file type (and the rules for it)', onclick: () => { model.files.splice(i, 1); render(); changed(); } }, '✕')));
    });
    const add = h('div', { class: 'adds' }, h('span', { class: 'muted' }, 'Add: '),
      kinds.map(k => h('button', { class: 'chip', title: k.where || k.label, onclick: () => {
        model.files.push({ kind: k.id, type: '', paths: k.path ? [k.path] : [], access: k.access[0], _new: true });
        render(); changed();
      } }, '+ ' + k.label)));
    const hint = `${model.files.length} file type${model.files.length === 1 ? '' : 's'}`;
    return section('Files', hint, [h('div', { class: 'muted small' }, 'A path ending in / means the directory and everything in it. Types the service creates at run time (in /run, /tmp, …) get their label automatically.'), table, add]);
  }

  function netSection() {
    const ports = info.ports;
    const portList = h('datalist', { id: 'ports' }, h('option', { value: 'all' }, 'any port'), ports.map(p => h('option', { value: p.name }, p.nums ? `${p.name}_port_t: ${p.nums}` : `${p.name}_port_t`)));
    const block = (dir, title, help) => {
      const items = model.net[dir];
      return h('div', { class: 'netblock' }, h('div', { class: 'sub' }, title, h('span', { class: 'muted' }, ' ' + help)),
        items.map((it, i) => {
          const p = ports.find(x => x.name === it.port);
          return h('div', { class: 'row' },
            h('select', { onchange: (e) => { it.proto = e.target.value; changed(); } }, ['tcp', 'udp'].map(x => h('option', { value: x, selected: x === it.proto }, x.toUpperCase()))),
            h('input', { type: 'text', list: 'ports', value: it.port, size: 22, spellcheck: 'false', placeholder: 'port type, e.g. http',
              onchange: (e) => { it.port = e.target.value.trim().replace(/_port_t$/, ''); render(); changed(); } }),
            h('span', { class: 'muted' }, it.port === 'all' ? ' any port' : p ? ` ${p.name}_port_t${p.nums ? ': ' + p.nums : ''}` : it.port ? ' (no such port type)' : ''),
            h('button', { class: 'icon', title: 'Remove', onclick: () => { items.splice(i, 1); render(); changed(); } }, '✕'));
        }),
        h('button', { class: 'chip', onclick: () => { items.push({ proto: 'tcp', port: '' }); render(); } }, '+ Add port'));
    };
    const n = model.net.listen.length + model.net.connect.length;
    return section('Network', n ? `${n} port${n === 1 ? '' : 's'}` : 'none', [portList,
      block('listen', 'Listens on', 'ports clients connect to'),
      block('connect', 'Connects to', 'ports of other servers'),
      h('div', { class: 'muted small' }, 'Port types come from corenetwork; a new port number needs a port type there (or semanage port -a).')], n > 0 || info.isNew);
  }

  function accessSection() {
    const on = new Set(model.access);
    const groups = info.catalog.access.map(g => h('div', { class: 'group' }, h('div', { class: 'sub' }, g.group),
      g.items.map(it => check(it.label, on.has(it.id), (v) => { model.access = v ? [...model.access, it.id] : model.access.filter(x => x !== it.id); }, { code: it.calls.join(', '), note: it.optional ? '(optional_policy)' : '' }))));
    return section('System access', `${model.access.length} selected`, h('div', { class: 'cols' }, groups));
  }

  function selfSection() {
    const self = new Set(model.self), caps = new Set(model.caps);
    return section('Process and capabilities', `${model.caps.length} capabilit${model.caps.length === 1 ? 'y' : 'ies'}`, [
      h('div', { class: 'sub' }, 'Its own processes'),
      h('div', { class: 'cols' }, info.catalog.self.map(s => check(s.label, self.has(s.id), (v) => { model.self = v ? [...model.self, s.id] : model.self.filter(x => x !== s.id); }, { risky: s.risky, code: s.rule }))),
      h('div', { class: 'sub' }, 'Linux capabilities ', h('span', { class: 'muted' }, 'root powers it keeps; usually setuid/setgid to drop root, nothing else')),
      h('div', { class: 'cols caps' }, info.catalog.caps.map(c => check(c.label, caps.has(c.name), (v) => { model.caps = v ? [...model.caps, c.name] : model.caps.filter(x => x !== c.name); }, { risky: c.risky, code: c.name }))),
    ]);
  }

  function extraSection() {
    const byName = new Map(info.interfaces.map(i => [i.n, i]));
    const chips = h('div', { class: 'chips' }, model.extra.map((n, i) => {
      const d = byName.get(n);
      return h('span', { class: 'chip on', title: d ? d.s : '' }, h('code', {}, n), d && d.s ? h('span', { class: 'muted' }, ' ' + d.s.slice(0, 70)) : null,
        h('button', { class: 'icon', title: 'Remove', onclick: () => { model.extra.splice(i, 1); render(); changed(); } }, '✕'));
    }));
    const results = h('div', { class: 'results' });
    const search = h('input', { type: 'text', size: 40, spellcheck: 'false', placeholder: 'Search interfaces: name or words from the summary', oninput: () => {
      const q = search.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
      results.textContent = '';
      if (!q.length) return;
      const hits = info.interfaces.filter(i => !model.extra.includes(i.n) && q.every(w => i.n.includes(w) || i.s.toLowerCase().includes(w))).slice(0, 40);
      for (const it of hits) results.append(h('div', { class: 'hit', onclick: () => { model.extra.push(it.n); search.value = ''; render(); changed(); } }, h('code', {}, it.n), h('span', { class: 'muted' }, ` ${it.m} — ${it.s}`)));
      if (!hits.length) results.append(h('div', { class: 'muted' }, 'No interface taking just a domain matches.'));
    } });
    return section('Other interfaces', `${model.extra.length}`, [h('div', { class: 'muted small' }, 'Any interface that takes just the domain. Calls into modules that can be turned off go in optional_policy.'), chips, search, results], model.extra.length > 0 || info.isNew);
  }

  function providesSection() {
    const have = new Set(info.provided || []);
    const on = new Set(model.provides || []);
    const kinds = new Set(model.files.map(r => r.kind));
    return section('Interfaces for other modules', `${on.size}`, [
      h('div', { class: 'muted small' }, 'What the module’s .if offers, so other modules (and administrators’ roles) can use the service. Existing interfaces are kept.'),
      h('div', { class: 'cols' }, info.catalog.provides.map(p => {
        const name = p.name.replace(/%/g, model.name || 'NAME');
        const exists = have.has(name);
        const missing = p.needs && !kinds.has(p.needs);
        return check(p.label, exists || on.has(p.id), (v) => { model.provides = v ? [...(model.provides || []), p.id] : (model.provides || []).filter(x => x !== p.id); },
          { code: name, disabled: exists || missing, note: exists ? '(already in the .if)' : missing ? `(needs a ${kindOf(p.needs).label.toLowerCase()} type)` : '' });
      })),
    ], info.isNew);
  }

  function keptSection() {
    if (info.isNew || !info.kept || !info.kept.length) return null;
    return section('Kept as is', `${info.kept.length} statement${info.kept.length === 1 ? '' : 's'}`, [
      h('div', { class: 'muted small' }, 'Rules on the domain the editor doesn’t model (conditional, or with other types). They stay unchanged; click to edit them in the .te.'),
      h('div', { class: 'kept' }, info.kept.map(k => h('div', { class: 'keptline', onclick: () => vscode.postMessage({ cmd: 'open', path: info.files.te, line: k.l }) }, h('span', { class: 'ln' }, k.l + 1), h('code', {}, k.text.slice(0, 160))))),
    ], false);
  }

  /* ---------- preview ---------- */

  function renderPreview() {
    const box = $('preview');
    box.textContent = '';
    if (!plan) { box.append(h('div', { class: 'muted pad' }, 'Preparing preview…')); return; }
    const probs = plan.problems || [];
    const blocking = probs.filter(p => !p.startsWith('Note:'));
    if (probs.length) box.append(h('div', { class: 'problems' }, probs.map(p => h('div', { class: p.startsWith('Note:') ? 'note' : 'error' }, p))));
    const files = plan.files || [];
    const nChanged = files.filter(f => f.changed).length;
    const apply = $('apply');
    apply.disabled = !!blocking.length || !nChanged;
    apply.textContent = info.isNew ? 'Create module' : 'Apply changes';
    $('status').textContent = blocking.length ? `${blocking.length} problem${blocking.length > 1 ? 's' : ''}` : nChanged ? `${nChanged} file${nChanged > 1 ? 's' : ''} to ${info.isNew ? 'create' : 'change'}` : 'no changes';
    if (!files.length) return;
    if (!files.some(f => f.kind === tab)) tab = files[0].kind;
    const tabs = h('div', { class: 'tabs' }, files.map(f => h('button', { class: 'tab' + (f.kind === tab ? ' sel' : ''), onclick: () => { tab = f.kind; renderPreview(); }, title: f.path },
      f.path.split(/[\\/]/).pop(), f.changed ? h('span', { class: 'dot' }, ' ●') : null)));
    box.append(tabs);
    const f = files.find(x => x.kind === tab);
    const pre = h('pre', { class: 'diff' });
    const newFile = !f.exists;
    if (!f.changed) pre.append(h('div', { class: 'muted' }, 'No changes to this file.'));
    else if (newFile) pre.append(f.text);
    else {
      // Changed lines with 3 lines of context.
      const d = f.diff;
      const show = new Array(d.length).fill(false);
      d.forEach((x, i) => { if (x[0] !== ' ') for (let j = Math.max(0, i - 3); j <= Math.min(d.length - 1, i + 3); j++) show[j] = true; });
      let gap = false;
      d.forEach((x, i) => {
        if (!show[i]) { if (!gap) pre.append(h('div', { class: 'gap' }, '⋯')); gap = true; return; }
        gap = false;
        pre.append(h('div', { class: x[0] === '+' ? 'add' : x[0] === '-' ? 'del' : 'ctx' }, (x[0] === ' ' ? '  ' : x[0] + ' ') + x[1]));
      });
    }
    box.append(pre);
  }

  /* ---------- top level ---------- */

  function refreshTypes() {
    for (const el of document.querySelectorAll('.typein')) {
      const i = [...document.querySelectorAll('.typein')].indexOf(el);
      const rows = model.files.filter(r => !r.type || info.isNew || r._new);
      if (rows[i]) el.placeholder = typeOf({ kind: rows[i].kind });
    }
  }

  function render() {
    const form = $('form');
    const scroll = form.scrollTop;
    const open = [...form.querySelectorAll('details')].map(d => d.open);
    form.textContent = '';
    const secs = [serviceSection(), filesSection(), netSection(), accessSection(), selfSection(), extraSection(), providesSection(), keptSection()].filter(Boolean);
    secs.forEach((s, i) => { if (open.length === secs.length) s.open = open[i]; form.append(s); });
    form.scrollTop = scroll;
    $('title').textContent = info.isNew ? 'New service' : `Service: ${model.name}`;
  }

  window.addEventListener('message', (e) => {
    const m = e.data;
    if (m.cmd === 'init') {
      info = m.info;
      model = JSON.parse(JSON.stringify(info.model));
      model.provides = model.provides || [];
      where = info.isNew ? (info.defaultLayer || null) : null;
      plan = null; dirty = false;
      $('form').textContent = '';
      render();
      $('stale').hidden = true;
      vscode.postMessage({ cmd: 'plan', model, where });
    } else if (m.cmd === 'plan') {
      plan = m.plan;
      renderPreview();
    } else if (m.cmd === 'error') {
      $('form').textContent = '';
      $('form').append(h('div', { class: 'pad' }, m.msg));
    } else if (m.cmd === 'stale') {
      if (dirty) $('stale').hidden = false;
      else vscode.postMessage({ cmd: 'reload' });
    } else if (m.cmd === 'busy') {
      $('apply').disabled = true;
      $('status').textContent = m.text;
    }
  });
  $('apply').addEventListener('click', () => vscode.postMessage({ cmd: 'apply', model, where }));
  $('reload').addEventListener('click', () => vscode.postMessage({ cmd: 'reload' }));
  vscode.postMessage({ cmd: 'ready' });
})();
