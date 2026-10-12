// User editor webview: a form for an SELinux user (role module + gen_user line + logins +
// where each way of logging in lands) and a live preview of every file it writes.
// Plain JS, no deps.
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

  const GROUPS = [['admin', 'Administers'], ['apps', 'Applications it may run'], ['run', 'Admin programs it may run']];
  let info = null, model = null, plan = null, tab = 0, timer = null;
  const open = new Map();  // card id → open
  const filters = { calls: '', ifaces: '' };

  $('apply').setAttribute('title', 'Write the files shown on the right (one undoable edit) and save them, which builds the tree');
  $('apply').addEventListener('click', () => { if (model) { $('status').textContent = 'Writing…'; vscode.postMessage({ cmd: 'apply', model, ...extras() }); } });

  const changed = () => {
    clearTimeout(timer);
    timer = setTimeout(() => vscode.postMessage({ cmd: 'plan', model, ...extras() }), 250);
  };
  const toggle = (list, v, on) => { const i = list.indexOf(v); if (on && i < 0) list.push(v); if (!on && i >= 0) list.splice(i, 1); };
  const kindOf = () => (info.catalog.kinds.find(k => k.id === model.user.kind) || info.catalog.kinds[0] || {});
  const card = (id, title, hint, body, defOpen = true) => {
    const d = h('details', { class: 'card', open: (open.has(id) ? open.get(id) : defOpen) || null }, h('summary', {}, h('span', { class: 'title' }, title), hint ? h('span', { class: 'hint' }, hint) : null), h('div', { class: 'body' }, body));
    d.addEventListener('toggle', () => open.set(id, d.open));
    return d;
  };
  const check = (label, on, onchange, attrs = {}) => {
    const box = h('input', { type: 'checkbox', checked: on || null, disabled: attrs.disabled || null });
    box.addEventListener('change', () => onchange(box.checked));
    return h('label', { class: 'check', title: attrs.title || null }, box, h('span', {}, label, attrs.code ? h('span', { class: 'code' }, attrs.code) : null));
  };
  const text = (value, oninput, attrs = {}) => {
    const i = h('input', { type: 'text', value: value || '', size: attrs.size || 24, placeholder: attrs.placeholder || null, title: attrs.title || null });
    i.addEventListener('input', () => oninput(i.value));
    return i;
  };

  // Standalone (new users): the license for the spec, as the service editor does.
  let license = null;
  const extras = () => ({ standalone: !!(info && info.standalone), license: info && info.standalone && info.isNew ? license : undefined });

  /** In the tree, or a standalone module packaged as an RPM (new users, when the host has devel headers). */
  function moduleRow() {
    if (!info.canStandalone && !info.standalone) return null;
    if (!info.canStandalone) return h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Module'), h('span', { class: 'muted small' }, `standalone, built against this host's devel headers, in ${info.folder || 'the workspace folder'}`));
    const opt = (on, label, title) => {
      const r = h('input', { type: 'radio', name: 'where', checked: (!!info.standalone === on) || null });
      r.addEventListener('change', () => vscode.postMessage({ cmd: 'standalone', on, model }));
      return h('label', { class: 'check', title }, r, h('span', {}, label));
    };
    return h('div', { class: 'row top' }, h('span', { class: 'lbl' }, 'Module'), h('div', {},
      opt(false, 'In the tree (policy/modules/roles, the users file, seusers, contexts)', 'The user is part of the tree\'s policy: its gen_user line, role in kernel.te, seusers and contexts files.'),
      opt(true, `Standalone, packaged as an RPM (${(info.folder || '').split(/[\\/]/).pop() || 'workspace'}/${model.name || 'NAME'}${info.folderSuffix || ''}/)`, 'A module of its own built against this host\'s devel headers; the RPM installs it, creates the SELinux user and its logins with semanage, and installs its contexts file.')));
  }

  function licenseRow() {
    if (!info.standalone || !info.isNew || !info.licenses) return null;
    if (license == null) license = info.licenses.default;
    const ids = [...new Set([...info.licenses.common.map(x => x.id), ...info.licenses.custom, license])];
    const sel = h('select', { title: 'The License: tag of the RPM spec (SPDX identifier)' }, ids.map(id => h('option', { value: id, selected: id === license || null }, id)));
    sel.addEventListener('change', () => { license = sel.value; changed(); });
    const other = text('', (v) => { if (v.trim()) { license = v.trim(); changed(); } }, { size: 22, placeholder: 'or another SPDX expression', title: 'Any one-line license expression for the spec' });
    return h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'License'), sel, other);
  }

  function userCard() {
    const n = model.name || 'NAME';
    if (!info.isNew) {
      const k = info.catalog.kinds.find(x => x.id === model.user.kind);
      return card('user', 'User', `${n}_u · role ${n}_r · domain ${n}_t`, [
        h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Module'), h('code', {}, info.module), h('span', { class: 'muted small' }, model.genUser && model.genUser.exists ? ` user ${n}_u` : ` (no ${n}_u of its own: users get ${n}_r through their own gen_user lines)`)),
        h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Kind'), h('span', { title: k ? k.help : '' }, k ? k.label : model.user.kind), h('span', { class: 'code' }, model.declaredBy ? `${model.declaredBy.name}(${model.declaredBy.args.join(', ')})` : '')),
        h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Summary'), text(model.summary, (v) => { model.summary = v; changed(); }, { size: 48, title: 'The module\'s .if summary (only a new module gets it written)' })),
      ]);
    }
    const kinds = info.catalog.kinds.map(k => {
      const r = h('input', { type: 'radio', name: 'kind', value: k.id, checked: model.user.kind === k.id || null });
      r.addEventListener('change', () => {
        model.user.kind = k.id;
        if (!k.login) model.ways = [];
        else if (!model.ways.length) model.ways = ['ssh', 'console'].filter(w => info.catalog.ways.some(x => x.id === w));
        render(); changed();
      });
      return h('label', { class: 'check', title: k.help }, r, h('span', {}, h('b', {}, k.label), h('span', { class: 'code' }, k.template), h('div', { class: 'muted small' }, k.help)));
    });
    return card('user', 'User', `${n}_u · role ${n}_r · domain ${n}_t`, [
      h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Name'), text(model.name, (v) => { model.name = v.trim(); $('title').textContent = model.name ? `New user: ${model.name}_u` : 'New User'; changed(); },
        { placeholder: 'e.g. ops', title: 'The name the user, role and domain are made from: NAME_u, NAME_r, NAME_t. Lowercase letters, digits and _.' })),
      h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Summary'), text(model.summary, (v) => { model.summary = v; changed(); }, { size: 48, placeholder: 'e.g. Operators of the web servers', title: 'One line for the .if summary and the comment above its gen_user line' })),
      moduleRow(), licenseRow(),
      h('div', { class: 'sub' }, 'Kind'), kinds,
    ]);
  }

  function loginsCard() {
    const k = kindOf();
    if (!info.isNew && model.standalone) {
      return card('logins', 'Logins', `${(model.logins || []).length} Linux login(s) · ${model.ways.length} way(s) in`, [
        h('div', { class: 'muted small' }, `Created by the %post of ${(info.specFile || 'its spec').split(/[\\/]/).pop()} with semanage login; change them there:`),
        (model.logins || []).length ? h('div', {}, model.logins.map(l => h('div', {}, h('code', {}, l.login), l.range ? h('span', { class: 'muted' }, ` ${l.range}`) : null))) : h('div', { class: 'muted' }, 'none'),
        h('div', { class: 'sub' }, 'Ways in'), h('div', { class: 'muted small' }, `Its contexts file next to the module (installed as contexts/users/${model.name}_u).`),
        h('div', { class: 'cols' }, info.catalog.ways.map(w => check(w.label, model.ways.includes(w.id), (on) => { toggle(model.ways, w.id, on); render(); changed(); }, { title: w.help, code: w.sources.join(', ') }))),
      ]);
    }
    if (!info.isNew && model.genUser && !model.genUser.exists) return card('logins', 'Logins', 'none: no user of its own', h('div', { class: 'muted' }, `There is no ${model.name}_u, so no login maps to this role directly; users who have ${model.name}_r (see Roles) switch to it.`));
    if (info.isNew && !k.login) return card('logins', 'Logins', 'none: switched to from another role', h('div', { class: 'muted' }, `A ${k.label.toLowerCase()} has no logins of its own: users reach it by switching role (see Roles).`));
    const taken = new Map((info.seusers || []).map(x => [x.login, x.user]));
    const rows = model.logins.map((l, i) => h('div', { class: 'row' },
      text(l.login, (v) => { l.login = v; changed(); }, { size: 18, placeholder: 'login, %group or __default__', title: 'A Linux login name; %name for every member of a group; __default__ for every login without a line of its own' }),
      text(l.range, (v) => { l.range = v; changed(); }, { size: 22, placeholder: 'range (empty: the user’s level)', title: 'The MLS/MCS range of this login’s sessions, e.g. s0 or s0-s0:c0.c1023' }),
      taken.has((l.login || '').trim()) ? h('span', { class: 'warn small' }, `now ${taken.get(l.login.trim())}`) : null,
      h('button', { class: 'icon', title: 'Remove this login', onclick: () => { model.logins.splice(i, 1); render(); changed(); } }, '✕')));
    const ways = info.catalog.ways.map(w => check(w.label, model.ways.includes(w.id), (on) => {
      toggle(model.ways, w.id, on);
      // Cron jobs need the cron role call.
      if (w.id === 'cron' && on && info.catalog.roleCalls.some(c => c.n === 'cron_role')) toggle(model.roleCalls, 'cron_role', true);
      render(); changed();
    }, { title: w.help + ((model.waysDefault || []).includes(w.id) ? ' Offered to it by default_contexts (shared); unticking takes its context off that line there.' : ''),
      code: w.sources.join(', ') + ((model.waysDefault || []).includes(w.id) ? ' · default_contexts' : '') }));
    return card('logins', 'Logins', `${model.logins.filter(l => (l.login || '').trim()).length} Linux login(s) · ${model.ways.length} way(s) in`, [
      h('div', { class: 'muted small' }, 'Linux logins that get this SELinux user (seusers). A login already mapped to another user can’t be mapped twice.'),
      rows, h('button', { onclick: () => { model.logins.push({ login: '', range: '' }); render(); } }, '+ Add login'),
      h('div', { class: 'sub' }, 'Ways in'), h('div', { class: 'muted small' }, info.isNew ? 'How its sessions may start (its own default contexts file); the others aren’t offered to it.'
        : `How its sessions may start: its own contexts file${model.waysFrom === 'own' ? '' : ' (none yet; created when you add one)'}, else default_contexts.`),
      h('div', { class: 'cols' }, ways),
    ]);
  }

  function rolesCard() {
    const R = `${model.name || 'NAME'}_r`;
    const roles = info.catalog.roles.filter(r => r.role !== R);
    const to = roles.filter(r => r.change).map(r => check(r.role, model.switchTo.includes(r.role), (on) => { toggle(model.switchTo, r.role, on); render(); changed(); },
      { code: r.change, title: `Lets ${R} change to ${r.role} (newrole -r, sudo -r): ${r.change}(${R}) in the .te, and ${r.role} in the user's gen_user line` }));
    const from = roles.filter(r => r.changeTo).map(r => check(r.role, model.enteredFrom.includes(r.role), (on) => { toggle(model.enteredFrom, r.role, on); changed(); },
      { code: r.changeTo, title: `Lets ${r.role} change to ${R}: ${r.changeTo}(${R}) in the .te` }));
    const users = info.users.map(u => check(u, model.grantUsers.includes(u), (on) => { toggle(model.grantUsers, u, on); changed(); }, { title: info.standalone ? `The RPM adds ${R} to ${u}'s roles with semanage user -m when installed (and takes it away when removed)` : `Adds ${R} to ${u}'s gen_user line, so ${u} may take the role`, disabled: !info.isNew && model.standalone }));
    const prov = info.catalog.provides.map(p => check(p.label, model.provides.includes(p.id), (on) => { toggle(model.provides, p.id, on); changed(); }, { code: p.name.replace('%', model.name || 'NAME') }));
    return card('roles', 'Roles', `${model.switchTo.length} to · ${model.enteredFrom.length} from`, [
      h('div', { class: 'sub' }, 'May switch to'), h('div', { class: 'cols' }, to.length ? to : h('span', { class: 'muted' }, 'No role has a *_role_change interface in this tree.')),
      h('div', { class: 'sub' }, 'Entered from'), h('div', { class: 'muted small' }, 'Roles that may switch to this one; their users also need the role (below).'), h('div', { class: 'cols' }, from),
      h('div', { class: 'sub' }, 'Users who also get this role'), h('div', { class: 'cols' }, users),
      h('div', { class: 'sub' }, 'Its interfaces (.if)'), prov,
    ], !kindOf().login);
  }

  function callsCard() {
    const all = info.catalog.roleCalls;
    const login = all.filter(c => c.g === 'login').map(c => check(c.n.replace(/_role_template$/, ''), model.roleCalls.includes(c.n), (on) => { toggle(model.roleCalls, c.n, on); render(); changed(); },
      { code: c.n, title: c.s || c.n }));
    const chips = model.roleCalls.filter(n => !all.some(c => c.n === n && c.g === 'login')).map(n => h('span', { class: 'chip on' }, h('code', {}, n),
      h('button', { class: 'icon', title: 'Remove', onclick: () => { toggle(model.roleCalls, n, false); render(); changed(); } }, '✕')));
    const filter = text(filters.calls, (v) => { filters.calls = v; renderResults(); }, { size: 30, placeholder: 'search: apache, log, mozilla…', title: 'Words in the name, summary or module' });
    const results = h('div', { class: 'results' });
    function renderResults() {
      results.textContent = '';
      if (!filters.calls.trim()) { results.append(h('div', { class: 'muted small' }, 'Type to search the role interfaces of this tree.')); return; }
      const words = filters.calls.toLowerCase().split(/\s+/).filter(Boolean);
      const hits = all.filter(c => c.g !== 'login' && !model.roleCalls.includes(c.n) && words.every(w => c.n.toLowerCase().includes(w) || c.s.toLowerCase().includes(w) || c.m.toLowerCase().includes(w))).slice(0, 40);
      for (const [g, label] of GROUPS) {
        const hs = hits.filter(c => c.g === g);
        if (!hs.length) continue;
        results.append(h('div', { class: 'sub small' }, label), ...hs.map(c => h('div', { class: 'hit', title: c.s, onclick: () => { toggle(model.roleCalls, c.n, true); render(); changed(); } }, h('code', {}, c.n), h('span', { class: 'muted small' }, ` ${c.s}`))));
      }
      if (!hits.length) results.append(h('div', { class: 'muted small' }, 'Nothing matches.'));
    }
    renderResults();
    return card('calls', 'Programs and administration', `${model.roleCalls.length} role call(s)`, [
      h('div', { class: 'muted small' }, 'sudo, su and the ssh client get domains of their own for this role:'), h('div', { class: 'cols' }, login),
      h('div', { class: 'sub' }, 'Administers and runs'), h('div', { class: 'muted small' }, 'Services it administers (*_admin), applications and admin programs it may run in their own domains (*_role, *_run).'),
      h('div', { class: 'chips' }, chips), filter, results,
    ]);
  }

  function rightsCard() {
    const caps = info.catalog.caps.map(c => check(c.label, model.caps.includes(c.name), (on) => { toggle(model.caps, c.name, on); changed(); }, { title: c.help, code: c.name }));
    const access = info.catalog.access.map(g => h('div', { class: 'group' }, h('div', { class: 'sub small' }, g.group), g.items.map(it => check(it.label, model.access.includes(it.id), (on) => { toggle(model.access, it.id, on); changed(); }, { title: it.help, code: it.calls.join(', ') }))));
    const chips = model.extra.map(n => h('span', { class: 'chip on' }, h('code', {}, n), h('button', { class: 'icon', title: 'Remove', onclick: () => { toggle(model.extra, n, false); render(); changed(); } }, '✕')));
    const results = h('div', { class: 'results' });
    const filter = text(filters.ifaces, (v) => { filters.ifaces = v; fill(); }, { size: 30, placeholder: 'search other interfaces', title: 'Interfaces that take just a domain' });
    function fill() {
      results.textContent = '';
      const words = filters.ifaces.toLowerCase().split(/\s+/).filter(Boolean);
      if (!words.length) return;
      const hits = info.interfaces.filter(x => !model.extra.includes(x.n) && words.every(w => x.n.toLowerCase().includes(w) || (x.s || '').toLowerCase().includes(w))).slice(0, 30);
      results.append(...hits.map(x => h('div', { class: 'hit', title: x.s, onclick: () => { toggle(model.extra, x.n, true); render(); changed(); } }, h('code', {}, x.n), h('span', { class: 'muted small' }, ` ${x.s || ''}`))));
    }
    fill();
    return card('rights', 'More rights for its domain', `${model.caps.length + model.access.length + model.extra.length} added`, [
      h('div', { class: 'muted small' }, 'The kind’s template already gives what a user of that kind needs; add only what this role must do beyond it.'),
      h('div', { class: 'sub' }, 'Capabilities'), h('div', { class: 'cols' }, caps),
      h('div', { class: 'sub' }, 'System access'), h('div', { class: 'cols' }, access),
      h('div', { class: 'sub' }, 'Other interfaces'), h('div', { class: 'chips' }, chips), filter, results,
    ], false);
  }

  function keptCard() {
    if (info.isNew || !(info.kept || []).length) return null;
    return card('kept', 'Kept as is', `${info.kept.length} line(s) the form doesn't describe`, [
      h('div', { class: 'muted small' }, 'Statements on this role or domain that the form doesn’t model (conditional blocks, ifdefs, rules on other modules’ types, calls with other arguments). Edits leave them exactly as they are; click one to open it.'),
      h('div', { class: 'kept' }, info.kept.map(k => h('div', { class: 'keptline', title: k.text, onclick: () => vscode.postMessage({ cmd: 'open', path: info.files.te, line: k.l }) }, h('span', { class: 'ln' }, k.l + 1), k.text))),
    ], false);
  }

  function mlsCard() {
    if (!info.isNew && model.standalone) {
      return card('mls', 'Levels and home directory', `${model.level || ''} · ${model.range || ''}`, h('div', { class: 'muted' },
        `Level ${model.level || '?'}, range ${model.range || '?'}, prefix ${model.prefix || '?'}: set by semanage user in the spec's %post; change them there.`), false);
    }
    if (!info.isNew && !(model.genUser && model.genUser.exists && model.genUser.simple)) {
      return card('mls', 'Levels and home directory', model.genUser && model.genUser.exists ? 'as written' : 'none of its own', h('div', { class: 'muted' }, model.genUser && model.genUser.exists
        ? `${model.name}_u's gen_user line is written with ifdef() or more than once, so the editor leaves it as it is; edit its levels in ${info.usersFile} by hand.`
        : `There is no ${model.name}_u: its users' own gen_user lines set their levels.`), false);
    }
    return card('mls', 'Levels and home directory', `${model.level} · ${model.range}`, [
      h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Default level'), text(model.level, (v) => { model.level = v; changed(); }, { size: 10, title: 'The level sessions start at (gen_user’s 4th argument), s0 in MCS policies' })),
      h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Range'), text(model.range, (v) => { model.range = v; changed(); }, { size: 22, title: 'The levels the user may have, e.g. s0, or s0 - mls_systemhigh for an administrator' })),
      info.standalone ? null : h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Categories'), text(model.cats, (v) => { model.cats = v; changed(); }, { size: 22, placeholder: 'e.g. mcs_allcats', title: 'gen_user’s optional 6th argument (categories), e.g. mcs_allcats' })),
      h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Home prefix'), text(model.prefix, (v) => { model.prefix = v; changed(); }, { size: 12, placeholder: info.prefixDefault, title: 'gen_user’s prefix: home directories of its logins are labeled PREFIX_home_t etc. This tree mostly uses the one shown.' })),
    ], false);
  }

  function render() {
    const form = $('form');
    form.textContent = '';
    if (!info) return;
    form.append(...[userCard(), loginsCard(), rolesCard(), callsCard(), rightsCard(), mlsCard(), keptCard()].filter(Boolean));
    renderPlan();
  }

  function renderPlan() {
    const pv = $('preview');
    pv.textContent = '';
    if (!plan) { pv.append(h('div', { class: 'pad muted' }, info && !info.isNew ? 'Change something to see the edits.' : 'Fill in a name to see the files.')); $('apply').disabled = true; return; }
    const blocking = plan.problems.filter(p => !p.startsWith('Note:'));
    $('apply').disabled = !!blocking.length || !plan.files.length;
    if (plan.problems.length) pv.append(h('div', { class: 'problems' }, plan.problems.map(p => h('div', { class: p.startsWith('Note:') ? 'note' : 'error' }, p))));
    if (!plan.files.length) { pv.append(h('div', { class: 'pad muted' }, 'No changes.')); return; }
    if (tab >= plan.files.length) tab = 0;
    pv.append(h('div', { class: 'tabs' }, plan.files.map((f, i) => h('button', { class: `tab${i === tab ? ' sel' : ''}`, title: f.path, onclick: () => { tab = i; renderPlan(); } },
      f.path.split(/[\\/]/).pop(), f.exists ? h('span', { class: 'dot' }, ' ●') : ' (new)'))));
    const f = plan.files[tab];
    pv.append(h('div', { class: 'muted small pad' }, f.path), h('pre', { class: 'diff' }, f.diff.map(([k, t]) => h('div', { class: k === '+' ? 'add' : k === '-' ? 'del' : '' }, `${k} ${t}`))));
  }

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (m.cmd === 'init') {
      info = m.info;
      // Switching between the tree and standalone keeps what was filled in (the prefix follows the place).
      if (m.keep && m.model) model = { ...m.model, prefix: m.info.model.prefix, cats: m.info.standalone ? '' : m.model.cats };
      else model = m.info.model;
      plan = null;
      $('title').textContent = info.isNew ? 'New User' : `User: ${model.name}_${model.standalone || (model.genUser && model.genUser.exists) ? 'u' : 'r'} (${info.module})`;
      $('apply').textContent = info.isNew ? 'Create' : 'Apply';
      $('status').textContent = '';
      render();
      if (model.name && info.isNew) changed();
    } else if (m.cmd === 'plan') {
      plan = m.plan;
      $('status').textContent = '';
      renderPlan();
    } else if (m.cmd === 'done') {
      $('status').textContent = m.text;
    } else if (m.cmd === 'error') {
      $('form').textContent = '';
      $('form').append(h('div', { class: 'pad warn' }, m.msg));
    }
  });
  vscode.postMessage({ cmd: 'ready' });
})();
