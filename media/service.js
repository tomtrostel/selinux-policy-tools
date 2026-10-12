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
  let license = null; // License: of the RPM spec (standalone modules)
  let customLicense = false; // entering a license of one's own
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
    planTimer = setTimeout(() => vscode.postMessage({ cmd: 'plan', model, where, standalone: !!info.standalone, license }), 250);
  }

  /* ---------- sections ---------- */

  const NAME_TIP = 'The module’s name: names its files (NAME.te, .if, .fc) and, by default, its types (NAME_t, NAME_exec_t, …)';
  const LAYER_TIP = 'The directory under policy/modules/ the module goes in; it is also added to modules.conf as a loadable module';
  const FOLDER_TIP = 'Where to write the module’s files (a new folder named after the module by default)';
  const KIND_TIP = 'In the policy tree: the module becomes part of this tree’s policy (policy/modules/<layer>, modules.conf). Standalone: a module of its own, built against this host’s selinux-policy-devel headers, with an RPM spec so it can be packaged (NAME-selinux) and installed next to the service';
  const LICENSE_TIP = 'The license of this policy module, written into the RPM spec (License:). Pick a common open source license, one you saved, or Custom… to enter your own (an SPDX expression such as LicenseRef-Acme-Proprietary or "MIT AND BSD-3-Clause")';
  const SA_NOTE = 'Built against the devel headers of this host; only their interfaces are offered. Adds NAME-selinux.spec and a Makefile (make rpm builds the RPM).';
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

  /** License for the RPM spec: common ones, the user's saved ones, or Custom… (with Save to my list / Save as my default). */
  function licenseRow() {
    const L = info.licenses;
    if (!L) return null;
    const known = [...L.common.map(x => x.id), ...L.custom];
    const custom = customLicense || (license && !known.includes(license));
    const opts = [
      ...L.common.map(x => h('option', { value: x.id, selected: !custom && x.id === license }, x.id === x.label ? x.id : `${x.label} (${x.id})`)),
      ...L.custom.filter(x => !L.common.some(c => c.id === x)).map(x => h('option', { value: x, selected: !custom && x === license }, `${x} (saved)`)),
      h('option', { value: '__custom__', selected: custom }, 'Custom…'),
    ];
    const sel = h('select', { title: LICENSE_TIP, onchange: (e) => {
      if (e.target.value === '__custom__') { customLicense = true; license = ''; render(); changed(); return; }
      customLicense = false; license = e.target.value; render(); changed();
    } }, opts);
    const save = (asDefault) => h('button', { class: 'chip', title: asDefault ? 'Store this license in your settings and make it the one new standalone modules start with' : 'Store this license in your settings (selinux.packaging.customLicenses) so it is offered next time, in any workspace',
      onclick: () => vscode.postMessage({ cmd: 'saveLicense', license, asDefault }) }, asDefault ? 'Save as my default' : 'Save to my list');
    const parts = [h('span', { class: 'lbl', title: LICENSE_TIP }, 'License'), sel];
    if (custom) {
      parts.push(h('input', { type: 'text', value: license || '', placeholder: 'e.g. LicenseRef-Acme-Proprietary', size: 30, spellcheck: 'false', title: 'Your license, as it should appear after License: in the spec (no %, # or line breaks)',
        oninput: (e) => { license = e.target.value.trim(); changed(); } }), save(false), save(true));
    } else if (license === L.default) {
      parts.push(h('span', { class: 'muted' }, ' your default'));
    } else {
      parts.push(h('button', { class: 'chip', title: 'Make this the license new standalone modules start with (selinux.packaging.license)', onclick: () => vscode.postMessage({ cmd: 'saveLicense', license, asDefault: true, defaultOnly: true }) }, 'Make it my default'));
    }
    return h('div', { class: 'row' }, parts);
  }

  function serviceSection() {
    const rows = [];
    if (info.isNew) {
      if (info.canStandalone) {
        const radio = (val, label) => h('label', { class: 'check', title: KIND_TIP }, h('input', { type: 'radio', name: 'kind', checked: !!info.standalone === val,
          onchange: () => { if (!!info.standalone !== val) vscode.postMessage({ cmd: 'standalone', on: val }); } }), h('span', {}, label));
        rows.push(h('div', { class: 'row' }, h('span', { class: 'lbl', title: KIND_TIP }, 'Module'), radio(false, 'In the policy tree'), radio(true, 'Standalone module (packaged as an RPM)')));
      }
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
          h('input', { type: 'text', title: FOLDER_TIP, value: where || '', placeholder: `${info.folder || ''}/<name>${info.folderSuffix || ''}`, size: 40, spellcheck: 'false', oninput: (e) => { where = e.target.value.trim() || null; changed(); } })));
        if (info.standalone && info.canStandalone) rows.push(h('div', { class: 'muted small', ...tipOf(SA_NOTE) }, sub(SA_NOTE)));
      }
      const lic = licenseRow();
      if (lic) rows.push(lic);
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
        h('select', { onchange: (e) => { row.access = e.target.value; e.target.title = `What the service may do with these files: ${accessHelp(row.access)}`; if (row.rules) render(); changed(); }, title: `What the service may do with these files: ${accessHelp(row.access)}` },
          accessOpts.map(a => h('option', { value: a, selected: a === row.access, title: accessHelp(a) }, info.catalog.accessLabels[a] || a))),
        h('button', { class: 'icon', title: 'Remove this file type (and the rules for it)', onclick: () => { const t = typeOf(row); model.files.splice(i, 1); for (const hp of model.helpers || []) hp.files = (hp.files || []).filter(x => x.type !== t); render(); changed(); } }, '✕')));
      // Rules that match no level: kept as written, shown (and openable, and expandable) so the choice is informed.
      if (row.rules && row.rules.length) table.append(customRules(row));
    });
    const add = h('div', { class: 'adds' }, h('span', { class: 'muted' }, 'Add: '),
      kinds.map(k => h('button', { class: 'chip', ...tipOf(k.help || k.where || k.label), onclick: () => {
        model.files.push({ kind: k.id, type: '', paths: k.path ? [k.path] : [], access: k.access[0], _new: true });
        render(); changed();
      } }, '+ ' + k.label)));
    const hint = `${model.files.length} file type${model.files.length === 1 ? '' : 's'}`;
    return section('Files', hint, [h('div', { class: 'muted small' }, 'A path ending in / means the directory and everything in it. Types the service creates at run time (in /run, /tmp, …) get their label automatically.'), table, add]);
  }

  /* ---------- custom file access: the rules, where they are, what they allow ---------- */

  const expanded = new Map(); // row type → { result } | 'loading'
  const ruleKey = (row) => `${row.type}|${row.rules.join('\n')}`;
  /** What the kept rules allow together: per target and class, the permissions (from their m4 expansion). */
  function allowSummary(row, result) {
    const D = domainName();
    const by = new Map();
    const tt = [];
    for (const r of result.results || []) for (const x of r.rules) {
      if (x.rt === 'type_transition') { tt.push(x.text); continue; }
      if (x.rt !== 'allow' || !x.s.includes(D)) continue;
      for (const t of x.t) for (const c of x.c) {
        const k = `${t === 'self' ? D : t} ${c}`;
        if (!by.has(k)) by.set(k, new Set());
        for (const p of x.perms) by.get(k).add(p);
      }
    }
    const lines = [...by].sort((a, b) => (b[0].startsWith(row.type) - a[0].startsWith(row.type)) || a[0].localeCompare(b[0])).map(([k, ps]) => `${k}: ${[...ps].sort().join(' ')}`);
    return [h('div', { class: 'small' }, h('b', {}, `Together they let ${D}:`)), h('pre', { class: 'grants' }, lines.join('\n') || 'nothing for the domain itself'),
      tt.length ? [h('div', { class: 'small muted' }, 'and give new files these types (type transitions):'), h('pre', { class: 'grants' }, tt.join('\n'))] : null];
  }
  function customRules(row) {
    const ex = expanded.get(ruleKey(row));
    const custom = row.access === 'custom';
    const te = info.files && info.files.te;
    const ruleRows = row.rules.map((txt, i) => {
      const box = h('div', { class: 'grantsbox' });
      box.hidden = true;
      const fill = () => {
        box.textContent = '';
        const r = ex && ex !== 'loading' && ex.result && ex.result.results ? ex.result.results[i] : null;
        box.append(r ? h('pre', { class: 'grants' }, r.rules.map(x => x.text).join('\n') || 'no rules') : h('div', { class: 'muted small' }, ex && ex.result && ex.result.error ? ex.result.error : 'Use “Show what they allow”.'));
      };
      const tog = h('button', { class: 'icon', title: 'Show the rules this line compiles to', onclick: (e) => {
        if (e && e.stopPropagation) e.stopPropagation();
        if (!ex) { expanded.set(ruleKey(row), 'loading'); vscode.postMessage({ cmd: 'expand', key: ruleKey(row), items: row.rules }); }
        box.hidden = !box.hidden; tog.textContent = box.hidden ? '▸' : '▾'; fill();
      } }, '▸');
      const line = row.ruleLines && row.ruleLines[i] != null ? row.ruleLines[i] : null;
      return h('div', {}, h('div', { class: 'keptline', title: line != null && te ? `Open line ${line + 1} of ${te.split(/[\\/]/).pop()}` : '', onclick: () => { if (line != null && te) vscode.postMessage({ cmd: 'open', path: te, line }); } },
        tog, line != null ? h('span', { class: 'ln' }, line + 1) : null, h('code', {}, txt)), box);
    });
    return h('div', { class: 'frules', title: accessHelp('custom') },
      h('div', { class: custom ? 'muted small' : 'warn small' }, custom
        ? `The service's access to ${row.type}, kept as written (click a line to open it):`
        : `Choosing “${info.catalog.accessLabels[row.access] || row.access}” replaces these rules with its standard ones (see the preview):`),
      ruleRows,
      ex === 'loading' ? h('div', { class: 'muted small' }, 'Expanding them with m4…')
        : ex && ex.result && ex.result.error ? h('div', { class: 'warn small' }, ex.result.error)
        : ex ? allowSummary(row, ex.result)
        : h('button', { class: 'chip', title: `Expand these rules with this policy's m4 and show, per class, what ${domainName()} may do with ${row.type} and anything else they touch`, onclick: () => {
          expanded.set(ruleKey(row), 'loading'); vscode.postMessage({ cmd: 'expand', key: ruleKey(row), items: row.rules }); render();
        } }, 'Show what they allow'));
  }

  /** The service's own port types (resolved names), which the port pickers offer too. */
  const ownPortNames = () => (model.ports || []).map(p => sub((p.name || '').trim() || '%')).filter(n => /^\w+$/.test(n));

  function portTypesBlock() {
    model.ports = model.ports || [];
    const tree = info.mode === 'tree';
    const protoSel = (x) => h('select', { title: 'TCP or UDP', onchange: (e) => { x.proto = e.target.value; changed(); } },
      [...new Set(['tcp', 'udp', x.proto || 'tcp'])].map(p => h('option', { value: p, selected: p === (x.proto || 'tcp') }, p.toUpperCase())));
    const rows = model.ports.map((p, pi) => {
      const fresh = p._new || info.isNew;
      return h('div', { class: 'row' },
        fresh ? h('input', { type: 'text', class: 'portname', value: p.name || '', placeholder: model.name || 'NAME', size: 18, spellcheck: 'false',
          title: 'The port type’s name without _port_t; leave empty to use the module name. Pick it by this name under Listens on or Connects to',
          onchange: (e) => { p.name = e.target.value.trim().replace(/_port_t$/, ''); render(); changed(); } }) : h('code', { title: tree ? 'Defined in corenetwork.te.in; its numbers can be changed here' : 'Declared in this module' }, p.name),
        h('span', { class: 'muted' }, '_port_t '),
        (p.nums = p.nums || []).map((x, xi) => h('span', { class: 'portnum' }, protoSel(x),
          h('input', { type: 'text', value: x.port || '', size: 11, spellcheck: 'false', placeholder: 'e.g. 8080', title: 'A port number, or a range like 8000-8010',
            oninput: (e) => { x.port = e.target.value.trim(); changed(); } }),
          h('button', { class: 'icon', title: 'Remove this port number', onclick: () => { p.nums.splice(xi, 1); render(); changed(); } }, '✕'))),
        h('button', { class: 'chip', title: 'Add another port number or range to this port type', onclick: () => { p.nums.push({ proto: (p.nums[p.nums.length - 1] || {}).proto || 'tcp', port: '' }); render(); } }, '+ Number'),
        fresh ? h('button', { class: 'icon', title: 'Remove this new port type', onclick: () => { model.ports.splice(pi, 1); render(); changed(); } }, '✕') : null);
    });
    const newTip = tree
      ? 'Define a new port type for this service in corenetwork.te.in (a network_port line), with the port numbers it covers. Then pick it under Listens on or Connects to'
      : 'Declare a new port type in this module. A loadable module can’t set port numbers, so the numbers you enter become the semanage commands to run after installing. Then pick it under Listens on or Connects to';
    return h('div', { class: 'netblock' },
      h('div', { class: 'sub' }, 'Port types of this service', h('span', { class: 'muted' }, tree ? ' for port numbers no existing port type covers (written to corenetwork.te.in)' : ' declared in the module; numbers set with semanage after installing')),
      rows,
      h('button', { class: 'chip', title: newTip, onclick: () => { model.ports.push({ name: '', nums: [{ proto: 'tcp', port: '' }], _new: true }); render(); changed(); } }, '+ New port type'));
  }

  function netSection() {
    const ports = info.ports;
    const known = new Set(ports.map(p => p.name));
    const own = ownPortNames().filter(n => !known.has(n));
    const portList = h('datalist', { id: 'ports' }, h('option', { value: 'all' }, 'any port'), own.map(n => h('option', { value: n }, `${n}_port_t: this service’s new port type`)),
      ports.map(p => h('option', { value: p.name }, p.nums ? `${p.name}_port_t: ${p.nums}` : `${p.name}_port_t`)));
    const block = (dir, title, help, addTip) => {
      const items = model.net[dir];
      return h('div', { class: 'netblock' }, h('div', { class: 'sub' }, title, h('span', { class: 'muted' }, ' ' + help)),
        items.map((it, i) => {
          const p = ports.find(x => x.name === it.port);
          return h('div', { class: 'row' },
            h('select', { title: 'TCP or UDP', onchange: (e) => { it.proto = e.target.value; changed(); } }, ['tcp', 'udp'].map(x => h('option', { value: x, selected: x === it.proto }, x.toUpperCase()))),
            h('input', { type: 'text', list: 'ports', value: it.port, size: 22, spellcheck: 'false', placeholder: 'port type, e.g. http', title: PORT_TIP,
              onchange: (e) => { it.port = e.target.value.trim().replace(/_port_t$/, ''); render(); changed(); } }),
            h('span', { class: 'muted' }, it.port === 'all' ? ' any port' : p ? ` ${p.name}_port_t${p.nums ? ': ' + p.nums : ''}` : ownPortNames().includes(it.port) ? ` ${it.port}_port_t (this service’s)` : it.port ? ' (no such port type)' : ''),
            h('button', { class: 'icon', title: 'Remove this port', onclick: () => { items.splice(i, 1); render(); changed(); } }, '✕'));
        }),
        h('button', { class: 'chip', title: addTip, onclick: () => { items.push({ proto: 'tcp', port: '' }); render(); } }, '+ Add port'));
    };
    const n = model.net.listen.length + model.net.connect.length;
    return section('Network', n ? `${n} port${n === 1 ? '' : 's'}` : 'none', [portList,
      portTypesBlock(),
      block('listen', 'Listens on', 'ports clients connect to', 'Add a port the service accepts connections (or UDP packets) on: allows binding and listening on that port type, plus the socket rules for it'),
      block('connect', 'Connects to', 'ports of other servers', 'Add a port of another server the service connects (or sends UDP) to: allows connecting to that port type, plus the socket rules for it'),
      h('div', { class: 'muted small' }, 'Port types come from corenetwork; for a port number no port type covers, add a port type of this service above.')], n > 0 || info.isNew || (model.ports || []).length > 0);
  }

  function accessSection() {
    const on = new Set(model.access);
    const lp = info.catalog.loginPty;
    const ptyType = () => `${(model.domain || `${model.name || 'NAME'}_t`).replace(/_t$/, '')}_devpts_t`;
    const groups = info.catalog.access.map(g => h('div', { class: 'group' }, h('div', { class: 'sub' }, g.group),
      g.items.map(it => check(it.label, on.has(it.id), (v) => { model.access = v ? [...model.access, it.id] : model.access.filter(x => x !== it.id); }, { help: it.help, code: it.calls.join(', '), note: it.optional ? '(optional_policy)' : '' })),
      g.group === 'Logins' && lp ? (() => {
        const clash = model.files.some(r => typeOf(r) === ptyType());
        return check(lp.label, !!model.loginPty, (v) => { model.loginPty = v; }, { help: clash ? `${ptyType()} is already a file type of this module (see Files)` : lp.help.replace('DOMAIN_devpts_t', ptyType()), code: `${ptyType()}, term_login_pty, term_create_pty`, disabled: clash && !model.loginPty, note: clash ? '(already a file type)' : '' });
      })() : null));
    return section('System access', `${model.access.length + (model.loginPty ? 1 : 0)} selected`, h('div', { class: 'cols' }, groups));
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
  /* ---------- what an interface really grants (m4), shown on demand ---------- */

  const grantsInfo = new Map();   // interface → { rules, attrs, cond } | 'loading' | { error }
  let grantsSlots = new Map();    // interface → [elements showing its rules] (rebuilt by each render)
  const domainName = () => model.domain || `${model.name || 'NAME'}_t`;
  function fillGrants(el, n) {
    const g = grantsInfo.get(n);
    el.textContent = '';
    if (!g || g === 'loading') { el.append(h('div', { class: 'muted small' }, 'Working out what it compiles to…')); return; }
    if (g.error) { el.append(h('div', { class: 'warn small' }, g.error)); return; }
    const lines = g.rules.map(r => r.text + (r.cond ? '   [under a boolean]' : ''));
    el.append(h('pre', { class: 'grants' }, lines.length ? lines.slice(0, 30).join('\n') + (lines.length > 30 ? `\n… and ${lines.length - 30} more` : '') : 'No rules for the domain itself.'),
      g.attrs.length ? h('div', { class: 'muted small', title: 'Attributes give the domain every rule written for them elsewhere' }, `and adds the attributes ${g.attrs.join(', ')}`) : null);
  }
  /** A ▸ button that shows (and asks for) what interface n grants to this service's domain. */
  function grantsToggle(n) {
    const box = h('div', { class: 'grantsbox' });
    box.hidden = true;
    if (!grantsSlots.has(n)) grantsSlots.set(n, []);
    grantsSlots.get(n).push(box);
    const btn = h('button', { class: 'icon', title: `Show the rules ${n}(${domainName()}) compiles to (m4 with this policy's own Makefile)`, onclick: (e) => {
      if (e && e.stopPropagation) e.stopPropagation();
      box.hidden = !box.hidden;
      btn.textContent = box.hidden ? '▸' : '▾';
      if (!box.hidden) {
        if (!grantsInfo.has(n)) { grantsInfo.set(n, 'loading'); vscode.postMessage({ cmd: 'grants', domain: domainName(), names: [n] }); }
        fillGrants(box, n);
      }
    } }, '▸');
    return { btn, box };
  }

  /* ---------- finding an interface by what the service needs ---------- */

  // What to allow on a kind of object: label → exact permissions (the narrowest interface covering them wins).
  const NEEDS = {
    file: [['read', ['open', 'read']], ['write', ['open', 'write']], ['append', ['open', 'append']], ['create', ['create']], ['create, write and delete', ['create', 'write', 'unlink', 'rename']], ['execute', ['execute']], ['memory-map', ['map']], ['see attributes', ['getattr']]],
    dir: [['list', ['read', 'search']], ['search', ['search']], ['add and remove entries', ['add_name', 'remove_name', 'write']], ['create and delete', ['create', 'rmdir']], ['see attributes', ['getattr']]],
    lnk_file: [['read', ['read']], ['create and delete', ['create', 'unlink']]],
    sock_file: [['write (connect through it)', ['write']], ['create and delete', ['create', 'unlink']]],
    chr_file: [['read', ['open', 'read']], ['write', ['open', 'write']], ['read and write', ['open', 'read', 'write']]],
    blk_file: [['read', ['open', 'read']], ['read and write', ['open', 'read', 'write']]],
    fifo_file: [['read', ['read']], ['write', ['write']]],
    unix_stream_socket: [['connect', ['connectto']]],
    unix_dgram_socket: [['send to', ['sendto']]],
    tcp_socket: [['connect to the port', ['name_connect']], ['bind the port', ['name_bind']]],
    udp_socket: [['bind the port', ['name_bind']]],
    process: [['send signals', ['signal']], ['check it is alive (signull)', ['signull']], ['kill', ['sigkill']], ['see its state', ['getattr']]],
    dbus: [['send messages', ['send_msg']]],
  };
  const NEED_TIP = 'Find the interfaces that give this service exactly an access: a type (e.g. etc_t, or the port type http_port_t for tcp_socket) or a path (looked up in the file contexts), the kind of object and what to do with it. They are ranked as the denial assistant ranks them: from what each interface really compiles to, narrowest first';
  let findSeq = 0;
  const findTargets = new Map();  // request id → results element
  function findByNeed(exclude, onPick) {
    const results = h('div', { class: 'results' });
    const what = h('input', { type: 'text', size: 26, spellcheck: 'false', placeholder: 'type or path, e.g. etc_t or /var/log/x.log', title: 'A type (etc_t, http_port_t, syslogd_t) or an absolute path; a path is looked up in the file contexts' });
    const cls = h('select', { title: 'The kind of object: file classes for files and directories, sockets for ports and other processes' }, Object.keys(NEEDS).map(c => h('option', { value: c }, c)));
    const act = h('select', { title: 'What the service must be able to do with it' });
    const custom = h('input', { type: 'text', size: 18, spellcheck: 'false', placeholder: 'e.g. read write', title: 'Exactly these permissions (space separated)' });
    custom.hidden = true;
    const fillAct = () => {
      act.textContent = '';
      for (const [label, perms] of NEEDS[cls.value] || []) act.append(h('option', { value: perms.join(' ') }, label));
      act.append(h('option', { value: '__custom__' }, 'exactly these permissions…'));
      custom.hidden = true;
    };
    cls.addEventListener('change', fillAct);
    act.addEventListener('change', () => { custom.hidden = act.value !== '__custom__'; });
    cls.value = 'file';
    fillAct();
    const go = h('button', { class: 'chip', title: NEED_TIP, onclick: () => {
      const q = what.value.trim();
      const perms = (act.value === '__custom__' ? custom.value : act.value).split(/\s+/).filter(Boolean);
      if (!q || !perms.length) { results.textContent = ''; results.append(h('div', { class: 'muted' }, 'Give a type or a path, and what to do with it.')); return; }
      const id = ++findSeq;
      findTargets.set(id, { results, exclude, onPick });
      results.textContent = '';
      results.append(h('div', { class: 'muted' }, 'Expanding the candidates with m4…'));
      vscode.postMessage({ cmd: 'find', id, query: { domain: domainName(), ...(q.startsWith('/') ? { path: q } : { target: q }), tclass: cls.value, perms } });
    } }, 'Find');
    return [h('div', { class: 'row', title: NEED_TIP }, h('span', { class: 'lbl' }, 'Find by need'), what, cls, act, custom, go), results];
  }
  function showFound(id, r) {
    const t = findTargets.get(id);
    if (!t) return;
    const { results, exclude, onPick } = t;
    results.textContent = '';
    if (r.error) { results.append(h('div', { class: 'warn' }, r.error)); return; }
    if (r.resolved) results.append(h('div', { class: 'muted small' }, `${r.resolved.path} is ${r.resolved.type} (${r.resolved.from}).`));
    const s = r.suggest;
    for (const n of r.notes || []) results.append(h('div', { class: 'muted small' }, n));
    if (!s) return;
    if (s.own) { results.append(h('div', { class: 'muted' }, `${r.target} belongs to this module: give the service access to it in Files (or a plain allow rule in the .te).`)); return; }
    (s.list || []).forEach((x, k) => {
      const g = grantsToggle(x.name);
      const tags = [k === 0 && x.covers ? h('span', { class: 'tag best', title: 'Covers it with the fewest other rights' }, 'narrowest') : null,
        x.owner ? h('span', { class: 'tag', title: `Defined by the module that owns ${r.target}` }, 'owner') : null,
        x.broad ? h('span', { class: 'tag warn', title: 'Grants far more than the narrowest one' }, 'broad') : null,
        x.writes && r.readOnly ? h('span', { class: 'tag warn', title: 'Also lets the service write, create, delete or run things beyond what you asked for' }, 'writes') : null,
        !x.covers ? h('span', { class: 'tag warn', title: 'Grants only part of it' }, `lacks ${x.missing.join(' ')}`) : null];
      const have = exclude.includes(x.name) || model.extra.includes(x.name);
      results.append(h('div', { class: 'iface' },
        h('div', { class: 'row' }, g.btn, h('code', {}, x.name), tags,
          h('button', { class: 'chip', disabled: have, title: have ? 'Already added' : `Add ${x.name} to this service`, onclick: () => onPick(x.name) }, have ? 'added' : 'Add')),
        x.summary ? h('div', { class: 'muted small' }, x.summary) : null,
        x.grants && x.grants.length ? h('div', { class: 'small', title: 'What it grants besides that access (largest first)' }, h('span', { class: 'muted' }, 'also grants: '), x.grants.join('; ')) : h('div', { class: 'muted small' }, 'grants nothing else'),
        g.box));
    });
    for (const c of s.combos || []) {
      results.append(h('div', { class: 'iface' }, h('div', { class: 'row' }, h('span', { class: 'muted' }, 'together: '), c.items.map(x => h('code', {}, x.name + ' ')),
        h('button', { class: 'chip', title: 'Add both', onclick: () => c.items.forEach(x => { if (!model.extra.includes(x.name)) onPick(x.name); }) }, 'Add both'))));
    }
    if (s.newIface) results.append(h('div', { class: 'muted' }, `No interface grants it. The module that owns ${r.target} (${s.newIface.module}) could get one, e.g. ${s.newIface.name}; the denial assistant writes it (SELinux: Analyze Denials…).`));
    if (s.note && !(s.list || []).length) results.append(h('div', { class: 'muted' }, s.note));
  }

  /* ---------- keyword search, ranked ---------- */

  // Words people type → how refpolicy names things.
  const SYNONYMS = {
    password: ['shadow', 'passwd', 'chkpwd'], passwords: ['shadow', 'passwd'], random: ['urand', 'rand', 'urandom'], log: ['logs', 'logging'], logs: ['log', 'logging'],
    config: ['conf', 'etc'], configuration: ['conf', 'etc'], temp: ['tmp'], temporary: ['tmp'], pid: ['runtime', 'pids', 'run'], runtime: ['pid', 'pids', 'run'],
    socket: ['sock', 'stream', 'dgram'], sockets: ['sock', 'stream', 'dgram'], dns: ['name_resolve', 'resolve'], resolve: ['name_resolve', 'dns'],
    write: ['rw', 'manage', 'append'], delete: ['manage', 'unlink'], create: ['manage'], run: ['exec', 'domtrans'], execute: ['exec'], start: ['domtrans', 'exec'],
    home: ['userdom', 'home'], user: ['userdom'], users: ['userdom'], certificate: ['cert', 'certs'], certificates: ['cert', 'certs'], tls: ['cert', 'certs'], ssl: ['cert', 'certs'],
    terminal: ['tty', 'pty', 'term'], terminals: ['tty', 'pty', 'term'], kernel: ['kernel'], network: ['corenet', 'net'], mail: ['mta', 'sendmail'],
  };
  /**
   * How well an interface matches the words: whole parts of its name count most, then
   * parts of the types it uses, the summary, and other spellings (SYNONYMS); every word must
   * match somewhere. dontaudit interfaces sink unless asked for. 0 = no match.
   */
  const RARE = new Set(['stub', 'mounton', 'relabel', 'relabelfrom', 'relabelto', 'execmod', 'kill', 'sigchld', 'signull', 'sigkill', 'sigstop', 'ptrace', 'noatsecure', 'rlimitinh', 'siginh', 'unconfined', 'filetrans', 'transition', 'watch', 'quotaon', 'swapon']);
  function ifaceScore(it, words) {
    const parts = it.n.split('_');
    const typeParts = (it.t || []).flatMap(t => t.replace(/_t$/, '').split('_'));
    const sum = it.s.toLowerCase();
    const sumWords = sum.split(/[^a-z0-9]+/);
    let score = 0;
    for (const raw of words) {
      // A type name (etc_t): interfaces that use exactly that type first; then like the word "etc".
      const w = raw.replace(/_t$/, '');
      const alts = [w, ...(SYNONYMS[w] || [])];
      let best = raw !== w && (it.t || []).includes(raw) ? 6 : 0;
      for (const [k, a] of alts.entries()) {
        const f = k ? 0.6 : 1; // another spelling counts a bit less
        let v = 0;
        if (parts.includes(a)) v = 4;
        else if (it.m === a) v = 3.5;
        else if (typeParts.includes(a)) v = 3;
        else if (it.n.includes(a)) v = 2;
        else if (sumWords.includes(a)) v = 2;
        else if ((it.t || []).some(t => t.includes(a))) v = 1.5;
        else if (sum.includes(a)) v = 1;
        best = Math.max(best, v * f);
      }
      if (!best) return 0;
      score += best;
    }
    const joined = words.map(x => x.replace(/_t$/, '')).join('_');
    if (it.n === joined || it.n.startsWith(`${joined}_`)) score += 3;
    score += Math.log10(1 + (it.c || 0)) * 0.8; // widely used interfaces first among equals (up to ~2 for hundreds of modules)
    if (/(^|_)dontaudit(_|$)/.test(it.n) && !words.includes('dontaudit')) score -= 3;
    // Rarely what a service needs, unless asked for by name.
    const rare = parts.find(p => RARE.has(p));
    if (rare && !words.includes(rare)) score -= 1.5;
    return score - it.n.length / 100;
  }

  function ifaceSearch(exclude, onPick, keep = () => true) {
    const results = h('div', { class: 'results' });
    let shown = 25;
    const search = h('input', { type: 'text', size: 40, spellcheck: 'false', placeholder: 'Search interfaces: words, a name, a type or a module', title: 'Words from what it should do (“read shadow”, “write logs”), part of an interface name, a type (etc_t) or a module name; best matches first, matching names, the types interfaces use and their descriptions. Click a result to add it. Only interfaces that take just the domain are listed', oninput: () => { shown = 25; list(); } });
    const list = () => {
      const q = search.value.trim().toLowerCase().split(/[\s,]+/).filter(Boolean);
      results.textContent = '';
      if (!q.length) return;
      const scored = info.interfaces.filter(i => !exclude.includes(i.n) && keep(i)).map(i => [i, ifaceScore(i, q)]).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1] || a[0].n.localeCompare(b[0].n));
      const hits = scored.slice(0, shown).map(([i]) => i);
      for (const it of hits) {
        const g = grantsToggle(it.n);
        results.append(h('div', {}, h('div', { class: 'hit', title: `Add ${it.n}: ${it.s}`, onclick: () => { search.value = ''; onPick(it.n); } }, g.btn, h('code', {}, it.n), h('span', { class: 'muted' }, ` ${it.m} — ${it.s}`)), g.box));
      }
      if (scored.length > shown) results.append(h('button', { class: 'chip', title: 'Show the next matches', onclick: () => { shown += 50; list(); } }, `${scored.length - shown} more…`));
      if (!hits.length) results.append(h('div', { class: 'muted' }, `No interface taking just a domain matches. Try other words, or Find by need below${q.some(w => /^(port|ports|connect|bind|listen|http|tcp|udp)$/.test(w)) ? '; ports are in Network (port types such as http)' : ''}.`));
    };
    return [search, results];
  }

  // Long lists of other interfaces (sshd, xdm, …) are grouped by module, with a filter.
  const GROUP_AT = 12;
  const openGroups = new Set();
  let extraFilter = '';

  function extraSection() {
    const byName = new Map(info.interfaces.map(i => [i.n, i]));
    const modOf = (n) => (byName.get(n) || {}).m || n.split('_')[0];
    const chipOf = (n) => {
      const d = byName.get(n);
      const g = grantsToggle(n);
      const c = h('span', { class: 'chip on extra', title: d ? d.s : '' }, g.btn, h('code', {}, n), d && d.s ? h('span', { class: 'muted' }, ' ' + d.s.slice(0, 70)) : null,
        h('button', { class: 'icon', title: 'Remove this interface call', onclick: () => { model.extra = model.extra.filter(x => x !== n); render(); changed(); } }, '✕'), g.box);
      c.match = `${n} ${d ? d.s : ''} ${modOf(n)}`.toLowerCase();
      return c;
    };
    const add = (n) => { if (!model.extra.includes(n)) model.extra.push(n); render(); changed(); };
    let list;
    if (model.extra.length > GROUP_AT) {
      const groups = new Map();
      for (const n of model.extra) { const m = modOf(n); if (!groups.has(m)) groups.set(m, []); groups.get(m).push(n); }
      const boxes = [...groups.keys()].sort().map(m => {
        const chips = groups.get(m).slice().sort().map(chipOf);
        const count = h('span', { class: 'muted' }, ` ${chips.length}`);
        const d = h('details', { class: 'egroup', open: openGroups.has(m) ? true : null, ontoggle: (e) => { if (!extraFilter) { if (e.target.open) openGroups.add(m); else openGroups.delete(m); } } },
          h('summary', { title: `Interfaces of the ${m} module this service calls` }, h('b', {}, m), count), h('div', { class: 'chips' }, chips));
        Object.assign(d, { chipsOf: chips, countEl: count, module: m });
        return d;
      });
      // Narrow the list in place as the filter is typed (no re-render: the field keeps its focus).
      const applyFilter = () => {
        const words = extraFilter.toLowerCase().split(/\s+/).filter(Boolean);
        let shown = 0;
        for (const d of boxes) {
          let n = 0;
          for (const c of d.chipsOf) { const ok = words.every(w => c.match.includes(w)); c.hidden = !ok; if (ok) n++; }
          d.hidden = !n;
          d.countEl.textContent = words.length ? ` ${n} of ${d.chipsOf.length}` : ` ${d.chipsOf.length}`;
          d.open = words.length ? n > 0 : openGroups.has(d.module);
          shown += n;
        }
        status.textContent = words.length ? `${shown} of ${model.extra.length} match` : `${model.extra.length} in ${boxes.length} modules`;
      };
      const status = h('span', { class: 'muted' });
      const filter = h('input', { type: 'text', size: 28, spellcheck: 'false', value: extraFilter, placeholder: 'Filter: name, words, module',
        title: 'Show only the interfaces whose name, description or module contains all these words', oninput: (e) => { extraFilter = e.target.value; applyFilter(); } });
      const all = (open) => h('button', { class: 'chip', title: open ? 'Open every module group' : 'Close every module group', onclick: () => {
        for (const d of boxes) { d.open = open; if (open) openGroups.add(d.module); else openGroups.delete(d.module); }
      } }, open ? 'Expand all' : 'Collapse all');
      list = [h('div', { class: 'row' }, filter, all(true), all(false), status), ...boxes];
      applyFilter();
    } else {
      list = [h('div', { class: 'chips' }, model.extra.map(chipOf))];
    }
    return section('Other interfaces', `${model.extra.length}`, [h('div', { class: 'muted small' }, 'Any interface that takes just the domain. Calls into modules that can be turned off go in optional_policy. ▸ shows what one compiles to.'), ...list,
      ...ifaceSearch(model.extra, add), ...findByNeed(model.extra, add)], model.extra.length > 0 || info.isNew);
  }

  const emptyGrants = () => ({ self: [], caps: [], net: { listen: [], connect: [] }, access: [], extra: [] });

  /**
   * Chips for what g grants, and ways to add more. o: { cond (only what conditional policy allows),
   * also (grants already given elsewhere, not offered again), removeTip, menuTip, portTip }.
   */
  function grantsEditor(g, o) {
    const accessBy = new Map(info.catalog.access.flatMap(gr => gr.items).map(i => [i.id, i]));
    const selfBy = new Map(info.catalog.self.map(x => [x.id, x]));
    const capBy = new Map(info.catalog.caps.map(c => [c.name, c]));
    const byName = new Map(info.interfaces.map(i => [i.n, i]));
    const also = o.also || emptyGrants();
    const chip = (label, code, remove, help) => h('span', { class: 'chip on', title: help }, label, code ? h('code', { class: 'code' }, code) : null,
      h('button', { class: 'icon', title: o.removeTip, onclick: () => { remove(); render(); changed(); } }, '✕'));
    const chips = h('div', { class: 'chips' },
      g.access.map((id, i) => chip((accessBy.get(id) || { label: id }).label, '', () => g.access.splice(i, 1), (accessBy.get(id) || {}).help)),
      g.self.map((id, i) => chip((selfBy.get(id) || { label: id }).label, '', () => g.self.splice(i, 1), (selfBy.get(id) || {}).help)),
      g.caps.map((c, i) => chip((capBy.get(c) || { label: c }).label, c, () => g.caps.splice(i, 1), (capBy.get(c) || {}).help)),
      ['listen', 'connect'].flatMap(dir => g.net[dir].map((it, i) => chip(`${dir === 'listen' ? 'Listen on' : 'Connect to'} ${it.proto.toUpperCase()} ${it.port === 'all' ? 'any port' : it.port + '_port_t'}`, '', () => g.net[dir].splice(i, 1)))),
      g.extra.map((n, i) => chip('', n, () => g.extra.splice(i, 1), (byName.get(n) || {}).s)));
    const condTip = 'Its interface declares attributes or contains optional blocks, which conditional policy can’t hold; grant it always or not at all';
    const menu = h('select', { title: o.menuTip, onchange: (e) => {
      const [kind, id] = e.target.value.split(':');
      if (kind === 'access') g.access.push(id); else if (kind === 'self') g.self.push(id); else if (kind === 'cap') g.caps.push(id);
      render(); changed();
    } }, h('option', { value: '' }, 'Add system access, process right or capability…'),
      // Not what is already given; under a boolean, items whose interfaces conditional policy refuses are shown disabled.
      info.catalog.access.map(gr => h('optgroup', { label: gr.group }, gr.items.filter(i => !g.access.includes(i.id) && !also.access.includes(i.id)).map(i => {
        const bad = o.cond && i.cond === false;
        return h('option', { value: `access:${i.id}`, disabled: bad, title: bad ? condTip : i.help }, bad ? `${i.label} (can't be under a boolean)` : i.label);
      }))),
      h('optgroup', { label: 'Its own processes' }, info.catalog.self.filter(x => !g.self.includes(x.id) && !also.self.includes(x.id)).map(x => h('option', { value: `self:${x.id}`, title: x.help }, x.label))),
      h('optgroup', { label: 'Capabilities' }, info.catalog.caps.filter(c => !g.caps.includes(c.name) && !also.caps.includes(c.name)).map(c => h('option', { value: `cap:${c.name}`, title: c.help }, `${c.name}: ${c.label}${c.risky ? ' ⚠' : ''}`))));
    const dir = h('select', { title: 'Connect to another server’s port, or listen on one for clients' }, h('option', { value: 'connect' }, 'connect to'), h('option', { value: 'listen' }, 'listen on'));
    const proto = h('select', { title: 'TCP or UDP' }, h('option', { value: 'tcp' }, 'TCP'), h('option', { value: 'udp' }, 'UDP'));
    const port = h('input', { type: 'text', list: 'ports', size: 18, spellcheck: 'false', placeholder: 'port type or all', title: PORT_TIP });
    const portRow = h('div', { class: 'row' }, h('span', { class: 'muted' }, 'Port:'), dir, proto, port, h('button', { class: 'chip', title: o.portTip, onclick: () => {
      const p = port.value.trim().replace(/_port_t$/, '');
      if (!p) return;
      g.net[dir.value].push({ proto: proto.value, port: p });
      render(); changed();
    } }, '+ Add'));
    const [search, results] = ifaceSearch([...g.extra, ...also.extra], (n) => { g.extra.push(n); render(); changed(); }, (i) => !o.cond || !i.u);
    return [chips, h('div', { class: 'row' }, menu), portRow, h('div', { class: 'row' }, search), results];
  }

  function boolsSection() {
    model.booleans = model.booleans || [];
    const boolBy = new Map((info.bools || []).map(b => [b.n, b]));
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
      const ed = grantsEditor(g, { cond: true, also: model, removeTip: 'No longer allow this when the boolean is on',
        menuTip: 'Pick something the service may do only while the boolean is on. Things it is always allowed aren’t listed', portTip: 'Allow this port only while the boolean is on' });
      return h('div', { class: 'bool' }, head, desc, h('div', { class: 'sub small' }, 'When on, also allow'), ed);
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

  const HELPER_TIP = 'A program the service runs (a script, a worker, a privileged helper) that gets a domain of its own: started from the service’s domain, it has only the rights you give it here, not the service’s';

  function helpersSection() {
    model.helpers = model.helpers || [];
    const ownFiles = model.files.filter(r => !kindOf(r.kind).file);
    const cards = model.helpers.map((hp, hi) => {
      const g = Object.assign(hp, { ...emptyGrants(), ...hp });
      g.net = Object.assign({ listen: [], connect: [] }, g.net || {});
      hp.files = hp.files || [];
      const fresh = hp._new || info.isNew;
      const base = sub((hp.name || '').trim() || '%_helper');
      const H = hp.domain || `${base}_t`;
      const head = h('div', { class: 'row' },
        fresh ? h('input', { type: 'text', value: hp.name || '', size: 24, spellcheck: 'false', placeholder: `${model.name || 'NAME'}_helper`,
          title: 'The helper’s name: its domain is NAME_t and its program’s type NAME_exec_t. Leave empty for MODULE_helper',
          onchange: (e) => { hp.name = e.target.value.trim().replace(/_t$/, ''); render(); changed(); } }) : h('code', { title: 'The helper’s domain' }, H),
        fresh ? h('span', { class: 'muted' }, '_t') : null,
        h('button', { class: 'icon', title: 'Remove this helper: its domain, its rules and its program’s label', onclick: () => { model.helpers.splice(hi, 1); render(); changed(); } }, '✕'));
      const prog = h('div', { class: 'row top' }, h('label', { class: 'lbl', title: 'The helper’s executable(s), one per line. They are labeled with its _exec_t type; when the service runs them, the process enters the helper’s domain' }, 'Program'),
        h('textarea', { title: 'One path per line; % is the module name', rows: Math.max(1, (hp.exec || []).length), cols: 40, spellcheck: 'false', placeholder: '/usr/libexec/%-helper', oninput: (e) => { hp.exec = unlines(e.target.value); changed(); } }, lines(hp.exec)));
      const sig = check('The service may signal it (e.g. stop it)', !!hp.signal, (v) => { hp.signal = v; }, { help: `Adds allow ${model.domain || `${model.name || 'NAME'}_t`} ${H}:process signal, so the service can stop or notify the helper. It can always wait for it to finish` });
      const files = ownFiles.length ? h('div', { class: 'helperfiles' }, h('div', { class: 'sub small' }, 'Access to the service’s files'), ownFiles.map(r => {
        const T = typeOf(r), k = kindOf(r.kind);
        const cur = (hp.files.find(x => x.type === T) || {}).access || 'none';
        const levels = [...new Set([...k.access, 'none'])];
        return h('div', { class: 'row' }, h('code', { title: `${k.label}${k.where ? ` (${k.where})` : ''}` }, T), ' ',
          h('select', { title: `What the helper may do with these files: ${accessHelp(cur)}`, onchange: (e) => {
            hp.files = hp.files.filter(x => x.type !== T);
            if (e.target.value !== 'none') hp.files.push({ type: T, access: e.target.value });
            e.target.title = `What the helper may do with these files: ${accessHelp(e.target.value)}`;
            changed();
          } }, levels.map(a => h('option', { value: a, selected: a === cur, title: accessHelp(a) }, info.catalog.accessLabels[a] || a))));
      })) : null;
      const ed = grantsEditor(g, { removeTip: 'No longer allow the helper this',
        menuTip: 'Pick something the helper may do. It gets nothing from the service: only what is listed here', portTip: 'Allow the helper this port' });
      return h('div', { class: 'bool helper' }, head, prog, sig, files, h('div', { class: 'sub small' }, 'The helper may also'), ed);
    });
    return section('Helper programs', `${model.helpers.length}`, [
      h('div', { class: 'muted small' }, 'Programs the service starts that should run with other (usually fewer) rights than the service itself. Each gets its own domain, entered when the service runs its program.'),
      cards,
      h('div', { class: 'adds' }, h('button', { class: 'chip', title: HELPER_TIP, onclick: () => {
        model.helpers.push({ name: '', exec: ['/usr/libexec/%-helper'], signal: true, files: [], self: ['fifo'], caps: [], net: { listen: [], connect: [] }, access: ['syslog', 'locale'], extra: [], _new: true });
        render(); changed();
      } }, '+ New helper program'))], model.helpers.length > 0);
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
    grantsSlots = new Map();
    const open = [...form.querySelectorAll('.card')].map(d => d.open); // the sections (not groups inside them)
    form.textContent = '';
    const secs = [serviceSection(), filesSection(), netSection(), accessSection(), selfSection(), extraSection(), boolsSection(), helpersSection(), providesSection(), keptSection()].filter(Boolean);
    secs.forEach((s, i) => { if (open.length === secs.length) s.open = open[i]; form.append(s); });
    form.scrollTop = scroll;
    if (grantsInfo.domain !== domainName()) { grantsInfo.clear(); grantsInfo.domain = domainName(); }
    $('title').textContent = info.isNew ? 'New service' : `Service: ${model.name}`;
  }

  window.addEventListener('message', (e) => {
    const m = e.data;
    if (m.cmd === 'init') {
      info = m.info;
      if (!(m.keep && model)) model = JSON.parse(JSON.stringify(info.model));
      if (!(m.keep && license != null && info.licenses)) { license = info.licenses ? info.licenses.default : null; customLicense = false; }
      model.provides = model.provides || [];
      where = info.isNew ? (info.defaultLayer || null) : null;
      plan = null; dirty = false;
      $('form').textContent = '';
      render();
      $('stale').hidden = true;
      vscode.postMessage({ cmd: 'plan', model, where, standalone: !!info.standalone, license });
    } else if (m.cmd === 'plan') {
      plan = m.plan;
      renderPreview();
    } else if (m.cmd === 'error') {
      $('form').textContent = '';
      $('form').append(h('div', { class: 'pad' }, m.msg));
    } else if (m.cmd === 'stale') {
      if (dirty) $('stale').hidden = false;
      else vscode.postMessage({ cmd: 'reload' });
    } else if (m.cmd === 'expanded') {
      expanded.set(m.key, { result: m.result || {} });
      render();
    } else if (m.cmd === 'found') {
      showFound(m.id, m.result);
    } else if (m.cmd === 'grants') {
      if (m.domain !== domainName()) return;
      const r = m.result || {};
      for (const [n, g] of Object.entries(r.grants || {})) grantsInfo.set(n, g || { error: 'No expansion for it.' });
      if (r.error) for (const [n, v] of grantsInfo) if (v === 'loading') grantsInfo.set(n, { error: r.error });
      for (const [n, els] of grantsSlots) for (const el of els) if (!el.hidden) fillGrants(el, n);
    } else if (m.cmd === 'licenseSaved') {
      info.licenses = m.licenses;
      license = m.license;
      customLicense = false;
      render();
      changed();
    } else if (m.cmd === 'busy') {
      $('apply').disabled = true;
      $('status').textContent = m.text;
    }
  });
  $('apply').addEventListener('click', () => vscode.postMessage({ cmd: 'apply', model, where, standalone: !!info.standalone, license }));
  $('reload').addEventListener('click', () => vscode.postMessage({ cmd: 'reload' }));
  vscode.postMessage({ cmd: 'ready' });
})();
