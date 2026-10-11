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
    for (const c of kids.flat(Infinity)) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
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

  const NAME_TIP = 'The module’s name: names its files (NAME.te, .if, .fc) and, by default, its types (NAME_t, NAME_exec_t, …)';
  const LAYER_TIP = 'The directory under policy/modules/ the module goes in; it is also added to modules.conf as a loadable module';
  const FOLDER_TIP = 'Where to write the module’s files (a new folder named after the module by default)';
  const DESC_TIP = 'One line saying what the service does; becomes the summary at the top of the .if';
  const PROG_TIP = 'The daemon’s executable(s), one per line. They are labeled NAME_exec_t, and when systemd (init) runs them the process enters the service’s domain';
  const PERM_TIP = 'Adds permissive NAME_t: the service is not blocked, but everything it would be denied is logged. Use it to find missing rules (ausearch -m avc), then turn it off';
  const PORT_TIP = 'A port type from corenetwork (e.g. http for http_port_t); type to see the list with their port numbers. “all” means any port';
  const accessHelp = (a) => (info.catalog.accessHelp || {})[a] || info.catalog.accessLabels[a] || a;

  function section(title, hint, body, open = true) {
    return h('details', { class: 'card', open }, h('summary', {}, h('span', { class: 'title' }, title), hint ? h('span', { class: 'hint' }, hint) : null), h('div', { class: 'body' }, body));
  }
  function check(label, on, set, extra) {
    return h('label', { class: 'check' + (extra && extra.risky ? ' risky' : ''), title: extra && extra.help }, h('input', { type: 'checkbox', checked: on, disabled: extra && extra.disabled, onchange: (e) => { set(e.target.checked); changed(); } }),
      h('span', {}, label, extra && extra.risky ? h('span', { class: 'warn', title: 'Grants a lot; make sure the service needs it' }, ' ⚠') : null, extra && extra.code ? h('code', { class: 'code' }, extra.code) : null, extra && extra.note ? h('span', { class: 'muted' }, ' ' + extra.note) : null));
  }
  // Hover text that mentions the module name (% in it), worked out when the mouse arrives.
  const tipOf = (text) => ({ title: sub(text), onmouseenter: (e) => { e.currentTarget.title = sub(text); } });
  const lines = (arr) => (arr || []).join('\n');
  const unlines = (s) => s.split('\n').map(x => x.trim()).filter(Boolean);

  function serviceSection() {
    const rows = [];
    if (info.isNew) {
      rows.push(h('div', { class: 'row' }, h('label', { class: 'lbl', for: 'name', title: NAME_TIP }, 'Module name'),
        h('input', { id: 'name', type: 'text', value: model.name, placeholder: 'e.g. mydaemon', spellcheck: 'false', size: 24, title: NAME_TIP,
          oninput: (e) => { model.name = e.target.value.trim(); refreshTypes(); changed(); } }),
        h('span', { class: 'muted' }, ' lowercase letters, digits, _; types are named after it')));
      if (info.layers) {
        rows.push(h('div', { class: 'row' }, h('label', { class: 'lbl', title: LAYER_TIP }, 'Layer'),
          h('select', { title: LAYER_TIP, onchange: (e) => { where = e.target.value; changed(); } }, info.layers.map(l => h('option', { value: l, selected: l === where }, l))),
          h('span', { class: 'muted' }, ' policy/modules/<layer>/; added to modules.conf as a loadable module')));
      } else {
        rows.push(h('div', { class: 'row' }, h('label', { class: 'lbl', title: FOLDER_TIP }, 'Folder'),
          h('input', { type: 'text', title: FOLDER_TIP, value: where || '', placeholder: `${info.folder || ''}/<name>`, size: 40, spellcheck: 'false', oninput: (e) => { where = e.target.value.trim() || null; changed(); } })));
      }
    } else {
      rows.push(h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Module'), h('b', {}, model.name), h('span', { class: 'muted' }, ` (${info.layer})`),
        info.domains.length > 1 ? h('span', {}, h('span', { class: 'lbl', style: 'margin-left:16px' }, 'Domain'),
          h('select', { title: 'This module has several daemon domains; pick the one to edit', onchange: (e) => vscode.postMessage({ cmd: 'domain', domain: e.target.value }) }, info.domains.map(d => h('option', { value: d.domain, selected: d.domain === model.domain }, d.domain)))) : h('span', { class: 'muted' }, `  domain ${model.domain}`)));
    }
    rows.push(h('div', { class: 'row' }, h('label', { class: 'lbl', title: DESC_TIP }, 'Description'),
      h('input', { type: 'text', value: model.summary || '', placeholder: 'What the service does (one line)', size: 50, disabled: !info.isNew,
        title: info.isNew ? DESC_TIP : 'The summary at the top of the .if; edit it there', oninput: (e) => { model.summary = e.target.value; changed(); } })));
    rows.push(h('div', { class: 'row top' }, h('label', { class: 'lbl', title: PROG_TIP }, 'Program'),
      h('textarea', { title: PROG_TIP, rows: Math.max(1, (model.exec || []).length), cols: 40, spellcheck: 'false', placeholder: '/usr/bin/%', oninput: (e) => { model.exec = unlines(e.target.value); changed(); } }, lines(model.exec)),
      h('span', { class: 'muted' }, ' one path per line; it runs in ', h('code', {}, model.domain || `${model.name || 'NAME'}_t`), ' when systemd starts it')));
    rows.push(check('Permissive while testing (denials are logged, not enforced)', model.permissive, (v) => { model.permissive = v; }, { help: PERM_TIP }));
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
        h('span', tipOf(k.help || k.where), k.label, k.where ? h('div', { class: 'muted small' }, k.where) : null),
        fresh ? h('input', { type: 'text', class: 'typein', value: row.type || '', placeholder: typeOf({ kind: row.kind }), spellcheck: 'false',
          title: 'The type name; leave empty for the suggested one', oninput: (e) => { row.type = e.target.value.trim(); changed(); } }) : h('code', {}, row.type),
        ['tmp', 'tmpfs', 'lock'].includes(k.id) && !row.paths.length
          ? h('span', { class: 'muted small', title: 'The service creates these at run time; a type transition gives them their label, so no path is needed' }, 'labeled when the service creates them')
          : h('textarea', { rows: Math.max(1, row.paths.length), spellcheck: 'false', placeholder: k.path || '/path/', title: 'One path per line, written to the .fc file. A path ending in / means the directory and everything in it; % is the module name', oninput: (e) => { row.paths = unlines(e.target.value); changed(); } }, lines(row.paths)),
        h('select', { onchange: (e) => { row.access = e.target.value; e.target.title = `What the service may do with these files: ${accessHelp(row.access)}`; changed(); }, title: `What the service may do with these files: ${accessHelp(row.access)}` },
          accessOpts.map(a => h('option', { value: a, selected: a === row.access, title: accessHelp(a) }, info.catalog.accessLabels[a] || a))),
        h('button', { class: 'icon', title: 'Remove this file type (and the rules for it)', onclick: () => { model.files.splice(i, 1); render(); changed(); } }, '✕')));
    });
    const add = h('div', { class: 'adds' }, h('span', { class: 'muted' }, 'Add: '),
      kinds.map(k => h('button', { class: 'chip', ...tipOf(k.help || k.where || k.label), onclick: () => {
        model.files.push({ kind: k.id, type: '', paths: k.path ? [k.path] : [], access: k.access[0], _new: true });
        render(); changed();
      } }, '+ ' + k.label)));
    const hint = `${model.files.length} file type${model.files.length === 1 ? '' : 's'}`;
    return section('Files', hint, [h('div', { class: 'muted small' }, 'A path ending in / means the directory and everything in it. Types the service creates at run time (in /run, /tmp, …) get their label automatically.'), table, add]);
  }

  function netSection() {
    const ports = info.ports;
    const portList = h('datalist', { id: 'ports' }, h('option', { value: 'all' }, 'any port'), ports.map(p => h('option', { value: p.name }, p.nums ? `${p.name}_port_t: ${p.nums}` : `${p.name}_port_t`)));
    const block = (dir, title, help, addTip) => {
      const items = model.net[dir];
      return h('div', { class: 'netblock' }, h('div', { class: 'sub' }, title, h('span', { class: 'muted' }, ' ' + help)),
        items.map((it, i) => {
          const p = ports.find(x => x.name === it.port);
          return h('div', { class: 'row' },
            h('select', { title: 'TCP or UDP', onchange: (e) => { it.proto = e.target.value; changed(); } }, ['tcp', 'udp'].map(x => h('option', { value: x, selected: x === it.proto }, x.toUpperCase()))),
            h('input', { type: 'text', list: 'ports', value: it.port, size: 22, spellcheck: 'false', placeholder: 'port type, e.g. http', title: PORT_TIP,
              onchange: (e) => { it.port = e.target.value.trim().replace(/_port_t$/, ''); render(); changed(); } }),
            h('span', { class: 'muted' }, it.port === 'all' ? ' any port' : p ? ` ${p.name}_port_t${p.nums ? ': ' + p.nums : ''}` : it.port ? ' (no such port type)' : ''),
            h('button', { class: 'icon', title: 'Remove this port', onclick: () => { items.splice(i, 1); render(); changed(); } }, '✕'));
        }),
        h('button', { class: 'chip', title: addTip, onclick: () => { items.push({ proto: 'tcp', port: '' }); render(); } }, '+ Add port'));
    };
    const n = model.net.listen.length + model.net.connect.length;
    return section('Network', n ? `${n} port${n === 1 ? '' : 's'}` : 'none', [portList,
      block('listen', 'Listens on', 'ports clients connect to', 'Add a port the service accepts connections (or UDP packets) on: allows binding and listening on that port type, plus the socket rules for it'),
      block('connect', 'Connects to', 'ports of other servers', 'Add a port of another server the service connects (or sends UDP) to: allows connecting to that port type, plus the socket rules for it'),
      h('div', { class: 'muted small' }, 'Port types come from corenetwork; a new port number needs a port type there (or semanage port -a).')], n > 0 || info.isNew);
  }

  function accessSection() {
    const on = new Set(model.access);
    const groups = info.catalog.access.map(g => h('div', { class: 'group' }, h('div', { class: 'sub' }, g.group),
      g.items.map(it => check(it.label, on.has(it.id), (v) => { model.access = v ? [...model.access, it.id] : model.access.filter(x => x !== it.id); }, { help: it.help, code: it.calls.join(', '), note: it.optional ? '(optional_policy)' : '' }))));
    return section('System access', `${model.access.length} selected`, h('div', { class: 'cols' }, groups));
  }

  function selfSection() {
    const self = new Set(model.self), caps = new Set(model.caps);
    return section('Process and capabilities', `${model.caps.length} capabilit${model.caps.length === 1 ? 'y' : 'ies'}`, [
      h('div', { class: 'sub' }, 'Its own processes'),
      h('div', { class: 'cols' }, info.catalog.self.map(s => check(s.label, self.has(s.id), (v) => { model.self = v ? [...model.self, s.id] : model.self.filter(x => x !== s.id); }, { help: s.help, risky: s.risky, code: s.rule }))),
      h('div', { class: 'sub' }, 'Linux capabilities ', h('span', { class: 'muted' }, 'root powers it keeps; usually setuid/setgid to drop root, nothing else')),
      h('div', { class: 'cols caps' }, info.catalog.caps.map(c => check(c.label, caps.has(c.name), (v) => { model.caps = v ? [...model.caps, c.name] : model.caps.filter(x => x !== c.name); }, { help: c.help, risky: c.risky, code: c.name }))),
    ]);
  }

  /** Search box over the interfaces taking just a domain; onPick(name). */
  function ifaceSearch(exclude, onPick, keep = () => true) {
    const results = h('div', { class: 'results' });
    const search = h('input', { type: 'text', size: 40, spellcheck: 'false', placeholder: 'Search interfaces: name or words from the summary', title: 'Type part of an interface name or words from its description, then click a result to add it. Only interfaces that take just the domain are listed', oninput: () => {
      const q = search.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
      results.textContent = '';
      if (!q.length) return;
      const hits = info.interfaces.filter(i => !exclude.includes(i.n) && keep(i) && q.every(w => i.n.includes(w) || i.s.toLowerCase().includes(w))).slice(0, 40);
      for (const it of hits) results.append(h('div', { class: 'hit', title: `Add ${it.n}: ${it.s}`, onclick: () => { search.value = ''; onPick(it.n); } }, h('code', {}, it.n), h('span', { class: 'muted' }, ` ${it.m} — ${it.s}`)));
      if (!hits.length) results.append(h('div', { class: 'muted' }, 'No interface taking just a domain matches.'));
    } });
    return [search, results];
  }

  function extraSection() {
    const byName = new Map(info.interfaces.map(i => [i.n, i]));
    const chips = h('div', { class: 'chips' }, model.extra.map((n, i) => {
      const d = byName.get(n);
      return h('span', { class: 'chip on', title: d ? d.s : '' }, h('code', {}, n), d && d.s ? h('span', { class: 'muted' }, ' ' + d.s.slice(0, 70)) : null,
        h('button', { class: 'icon', title: 'Remove this interface call', onclick: () => { model.extra.splice(i, 1); render(); changed(); } }, '✕'));
    }));
    return section('Other interfaces', `${model.extra.length}`, [h('div', { class: 'muted small' }, 'Any interface that takes just the domain. Calls into modules that can be turned off go in optional_policy.'), chips,
      ...ifaceSearch(model.extra, (n) => { model.extra.push(n); render(); changed(); })], model.extra.length > 0 || info.isNew);
  }

  const emptyGrants = () => ({ self: [], caps: [], net: { listen: [], connect: [] }, access: [], extra: [] });

  function boolsSection() {
    model.booleans = model.booleans || [];
    const accessBy = new Map(info.catalog.access.flatMap(g => g.items).map(i => [i.id, i]));
    const selfBy = new Map(info.catalog.self.map(s => [s.id, s]));
    const capBy = new Map(info.catalog.caps.map(c => [c.name, c]));
    const boolBy = new Map((info.bools || []).map(b => [b.n, b]));
    const byName = new Map(info.interfaces.map(i => [i.n, i]));
    const cards = model.booleans.map((b, bi) => {
      const g = b.grants = Object.assign(emptyGrants(), b.grants || {});
      g.net = Object.assign({ listen: [], connect: [] }, g.net || {});
      const fresh = b._new || info.isNew;
      const ext = boolBy.get(b.name);
      const head = h('div', { class: 'row' },
        b.external
          ? h('span', {}, h('code', {}, b.name), h('span', { class: 'muted' }, ext ? ` existing boolean (${ext.m}${ext.def ? `, default ${ext.def}` : ''})` : ' existing boolean'))
          : fresh ? h('input', { type: 'text', value: b.name, size: 30, spellcheck: 'false', placeholder: `e.g. ${model.name || 'NAME'}_connect_any`, title: 'The boolean’s name, used with setsebool and getsebool; usually starts with the module name', oninput: (e) => { b.name = e.target.value.trim(); changed(); } })
            : h('code', {}, b.name),
        b.external ? null : h('label', { title: 'Whether the boolean is on or off until an administrator changes it' }, ' default ', h('select', { title: 'Off or on until an administrator changes it (setsebool -P)', onchange: (e) => { b.default = e.target.value === 'on'; changed(); } },
          h('option', { value: 'off', selected: !b.default }, 'off'), h('option', { value: 'on', selected: !!b.default }, 'on'))),
        h('button', { class: 'icon', title: 'Remove this boolean and what it allows', onclick: () => { model.booleans.splice(bi, 1); render(); changed(); } }, '✕'));
      const desc = b.external
        ? (ext && ext.s ? h('div', { class: 'muted small' }, ext.s) : null)
        : h('textarea', { rows: 2, spellcheck: 'true', placeholder: 'What switching it on allows (semanage boolean -l shows this)', title: 'Written as the comment above gen_tunable; semanage boolean -l shows it to administrators', oninput: (e) => { b.desc = e.target.value; changed(); } }, b.desc || '');
      // What it grants, as removable chips.
      const chip = (label, code, remove, help) => h('span', { class: 'chip on', title: help }, label, code ? h('code', { class: 'code' }, code) : null,
        h('button', { class: 'icon', title: 'No longer allow this when the boolean is on', onclick: () => { remove(); render(); changed(); } }, '✕'));
      const chips = h('div', { class: 'chips' },
        g.access.map((id, i) => chip((accessBy.get(id) || { label: id }).label, '', () => g.access.splice(i, 1), (accessBy.get(id) || {}).help)),
        g.self.map((id, i) => chip((selfBy.get(id) || { label: id }).label, '', () => g.self.splice(i, 1), (selfBy.get(id) || {}).help)),
        g.caps.map((c, i) => chip((capBy.get(c) || { label: c }).label, c, () => g.caps.splice(i, 1), (capBy.get(c) || {}).help)),
        ['listen', 'connect'].flatMap(dir => g.net[dir].map((it, i) => chip(`${dir === 'listen' ? 'Listen on' : 'Connect to'} ${it.proto.toUpperCase()} ${it.port === 'all' ? 'any port' : it.port + '_port_t'}`, '', () => g.net[dir].splice(i, 1)))),
        g.extra.map((n, i) => chip('', n, () => g.extra.splice(i, 1), (byName.get(n) || {}).s)));
      // Adding: one menu for the catalog, a port row, an interface search.
      const menu = h('select', { title: 'Pick something the service may do only while the boolean is on. Things it is always allowed aren’t listed', onchange: (e) => {
        const [kind, id] = e.target.value.split(':');
        if (kind === 'access') g.access.push(id); else if (kind === 'self') g.self.push(id); else if (kind === 'cap') g.caps.push(id);
        render(); changed();
      } }, h('option', { value: '' }, 'Add system access, process right or capability…'),
        // Not what is already always allowed; items whose interfaces conditional policy refuses are shown disabled.
        info.catalog.access.map(gr => h('optgroup', { label: gr.group }, gr.items.filter(i => !g.access.includes(i.id) && !model.access.includes(i.id)).map(i => h('option', { value: `access:${i.id}`, disabled: i.cond === false, title: i.cond === false ? 'Its interface declares attributes or contains optional blocks, which conditional policy can’t hold; grant it always or not at all' : i.help }, i.cond === false ? `${i.label} (can't be under a boolean)` : i.label)))),
        h('optgroup', { label: 'Its own processes' }, info.catalog.self.filter(s => !g.self.includes(s.id) && !model.self.includes(s.id)).map(s => h('option', { value: `self:${s.id}`, title: s.help }, s.label))),
        h('optgroup', { label: 'Capabilities' }, info.catalog.caps.filter(c => !g.caps.includes(c.name) && !model.caps.includes(c.name)).map(c => h('option', { value: `cap:${c.name}`, title: c.help }, `${c.name}: ${c.label}${c.risky ? ' ⚠' : ''}`))));
      const dir = h('select', { title: 'Connect to another server’s port, or listen on one for clients' }, h('option', { value: 'connect' }, 'connect to'), h('option', { value: 'listen' }, 'listen on'));
      const proto = h('select', { title: 'TCP or UDP' }, h('option', { value: 'tcp' }, 'TCP'), h('option', { value: 'udp' }, 'UDP'));
      const port = h('input', { type: 'text', list: 'ports', size: 18, spellcheck: 'false', placeholder: 'port type or all', title: PORT_TIP });
      const portRow = h('div', { class: 'row' }, h('span', { class: 'muted' }, 'Port:'), dir, proto, port, h('button', { class: 'chip', title: 'Allow this port only while the boolean is on', onclick: () => {
        const p = port.value.trim().replace(/_port_t$/, '');
        if (!p) return;
        g.net[dir.value].push({ proto: proto.value, port: p });
        render(); changed();
      } }, '+ Add'));
      const [search, results] = ifaceSearch([...g.extra, ...model.extra], (n) => { g.extra.push(n); render(); changed(); }, (i) => !i.u);
      return h('div', { class: 'bool' }, head, desc, h('div', { class: 'sub small' }, 'When on, also allow'), chips, h('div', { class: 'row' }, menu), portRow, h('div', { class: 'row' }, search), results);
    });
    const existing = h('input', { type: 'text', list: 'bools', size: 30, spellcheck: 'false', placeholder: 'e.g. use_nfs_home_dirs', title: 'A boolean another module (or the tree’s global tunables) already declares; type to search' });
    const add = h('div', { class: 'adds' },
      h('button', { class: 'chip', title: 'Declare a new boolean in this module (gen_tunable) with a name, a description and a default, then choose what it allows while on', onclick: () => { model.booleans.push({ name: '', desc: '', default: false, external: false, _new: true, grants: emptyGrants() }); render(); changed(); } }, '+ New boolean'),
      h('span', { class: 'muted' }, '  or use an existing one: '), existing,
      h('datalist', { id: 'bools' }, (info.bools || []).map(b => h('option', { value: b.n }, `${b.m}: ${b.s.slice(0, 80)}`))),
      h('button', { class: 'chip', title: 'Use the existing boolean named on the left: choose what this service may do while it is on. Its declaration stays where it is', onclick: () => {
        const n = existing.value.trim();
        if (!n || model.booleans.some(b => b.name === n)) return;
        model.booleans.push({ name: n, external: true, grants: emptyGrants() });
        render(); changed();
      } }, '+ Add'));
    return section('Booleans', `${model.booleans.length}`, [
      h('div', { class: 'muted small' }, 'Rights an administrator can switch on at run time (setsebool). Everything above is always allowed; what you add here only while the boolean is on.'),
      cards, add], model.booleans.length > 0 || info.isNew);
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
          { help: p.help, code: name, disabled: exists || missing, note: exists ? '(already in the .if)' : missing ? `(needs a ${kindOf(p.needs).label.toLowerCase()} type)` : '' });
      })),
    ], info.isNew);
  }

  function keptSection() {
    if (info.isNew || !info.kept || !info.kept.length) return null;
    return section('Kept as is', `${info.kept.length} statement${info.kept.length === 1 ? '' : 's'}`, [
      h('div', { class: 'muted small' }, 'Rules on the domain the editor doesn’t model (conditional, or with other types). They stay unchanged; click to edit them in the .te.'),
      h('div', { class: 'kept' }, info.kept.map(k => h('div', { class: 'keptline', title: 'Open this line in the .te', onclick: () => vscode.postMessage({ cmd: 'open', path: info.files.te, line: k.l }) }, h('span', { class: 'ln' }, k.l + 1), h('code', {}, k.text.slice(0, 160))))),
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
    apply.title = blocking.length ? 'Fix the problems listed above first' : !nChanged ? 'Nothing to change yet'
      : info.isNew ? 'Write the module’s files shown in the preview (and its modules.conf line) and save them' : 'Make the changes shown in the preview and save the files';
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
    const secs = [serviceSection(), filesSection(), netSection(), accessSection(), selfSection(), extraSection(), boolsSection(), providesSection(), keptSection()].filter(Boolean);
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
