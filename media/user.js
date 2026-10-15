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
    if (reach && reach !== 'building') reach.stale = true;
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

  /**
   * Automation account: an ordinary user (the template that keeps sudo working; the restricted
   * ones forbid setuid programs) that logs in over ssh and runs cron jobs only, with sudo and the
   * cron role call, and no extra rights. What it may do as root comes from the role it switches to.
   */
  function automationPreset() {
    const has = (n) => info.catalog.roleCalls.some(c => c.n === n);
    model.user.kind = 'unpriv';
    model.ways = ['ssh', 'cron'].filter(w => info.catalog.ways.some(x => x.id === w));
    model.roleCalls = ['sudo_role_template', 'cron_role'].filter(has);
    model.caps = []; model.access = []; model.extra = []; model.self = [];
    if (!model.summary) model.summary = 'Automation account';
    model.preset = 'automation';
    open.set('logins', true); open.set('roles', true);
    render(); changed();
  }

  function presetNote() {
    if (model.preset !== 'automation') return null;
    const sw = model.switchTo[0];
    return h('div', { class: 'note small' },
      h('b', {}, 'Automation account. '), 'Map its Linux account below (e.g. ansible). Give it ', h('b', {}, 'one narrow role'), ' to sudo into under Roles → May switch to: a confined administrator role for just its job (create one with New User → Confined administrator role). sudo itself decides which commands it may run; put the role in /etc/sudoers too:',
      h('pre', { class: 'grants' }, `${(model.logins.find(l => (l.login || '').trim()) || { login: 'ACCOUNT' }).login} ALL=(root) ${sw ? `ROLE=${sw} TYPE=${sw.replace(/_r$/, '_t')} ` : 'ROLE=<role> TYPE=<domain> '}NOPASSWD: /usr/bin/<the commands it runs>`),
      'Preview what it can reach (right) to check it gets no more than that.');
  }

  /**
   * The kinds of user as radio buttons. A kind whose template can't link in this tree (it needs a
   * module that is off) is disabled, unless the user already has it. An existing user keeps its
   * template call while the kind stays; choosing another kind replaces that call.
   */
  function kindChoices() {
    const was = info.isNew ? null : info.kindWas;
    return info.catalog.kinds.map(k => {
      const off = !!k.blocked && k.id !== was;
      const r = h('input', { type: 'radio', name: 'kind', value: k.id, checked: model.user.kind === k.id || null, disabled: off || null });
      r.addEventListener('change', () => {
        model.user.kind = k.id;
        if (!k.login) model.ways = [];
        else if (!model.ways.length) model.ways = ['ssh', 'console'].filter(w => info.catalog.ways.some(x => x.id === w));
        render(); changed();
      });
      const tpl = !info.isNew && k.id === was && model.declaredBy ? `${model.declaredBy.name}(${model.declaredBy.args.join(', ')})` : k.template;
      return h('label', { class: 'check', title: k.blocked ? `${k.help} Not available here: ${k.template} ${k.blocked}.` : k.help }, r, h('span', {}, h('b', {}, k.label), h('span', { class: 'code' }, tpl),
        k.id === was ? h('span', { class: 'muted small' }, ' (now)') : null,
        h('div', { class: 'muted small' }, k.help),
        k.blocked ? h('div', { class: 'warn small' }, `${k.template} ${k.blocked}, so the tree can't link it.`) : null));
    });
  }

  function userCard() {
    const n = model.name || 'NAME';
    if (!info.isNew) {
      return card('user', 'User', `${n}_u · role ${n}_r · domain ${n}_t`, [
        h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Module'), h('code', {}, info.module), h('span', { class: 'muted small' }, model.genUser && model.genUser.exists ? ` user ${n}_u` : ` (no ${n}_u of its own: users get ${n}_r through their own gen_user lines)`)),
        h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Summary'), text(model.summary, (v) => { model.summary = v; changed(); }, { size: 48, title: 'The module\'s .if summary (only a new module gets it written)' })),
        h('div', { class: 'sub' }, 'Kind'), h('div', { class: 'muted small' }, 'Choosing another kind replaces the template call in the .te; the role, logins and the rest stay.'), kindChoices(),
      ]);
    }
    const kinds = kindChoices();
    return card('user', 'User', `${n}_u · role ${n}_r · domain ${n}_t`, [
      h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Name'), text(model.name, (v) => { model.name = v.trim(); $('title').textContent = model.name ? `New user: ${model.name}_u` : 'New User'; changed(); },
        { placeholder: 'e.g. ops', title: 'The name the user, role and domain are made from: NAME_u, NAME_r, NAME_t. Lowercase letters, digits and _.' })),
      h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Summary'), text(model.summary, (v) => { model.summary = v; changed(); }, { size: 48, placeholder: 'e.g. Operators of the web servers', title: 'One line for the .if summary and the comment above its gen_user line' })),
      moduleRow(), licenseRow(),
      h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Start from'),
        h('button', { title: 'An account scripts and tools use (Ansible, backups, monitoring): an ordinary user that logs in over ssh and runs cron jobs, with no console or desktop, and may sudo into one narrow role you pick under Roles.',
          onclick: () => automationPreset() }, 'Automation account')),
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
      presetNote(),
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

  /** What the levels come to (from the plan): the user's level and range as the policy will have them. */
  function levelHelp() {
    const L = plan && plan.levels;
    if (!L) return null;
    const line = (label, x) => (x && x.canon ? h('div', { class: 'small' }, `${label}: `, h('code', {}, x.canon), x.name ? ` — ${x.name}` : '', x.describe ? h('span', { class: 'muted' }, ` (${x.describe})`) : null) : null);
    return h('div', { class: 'note' },
      L.mcsTree ? h('div', { class: 'muted small' }, `In this MCS policy gen_user ignores the default level and range and writes "level s0 range s0${model.cats ? ' - s0:CATEGORIES' : ''}": only the categories count.`) : null,
      line('Level', L.level), line('Range', L.range),
      [...L.level.problems, ...L.range.problems].map(p => h('div', { class: 'warn small' }, p)),
      L.names.length ? h('div', { class: 'muted small' }, `Named levels from ${L.setrans.split('/').pop()} are offered in the fields.`) : null);
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
    const L = plan && plan.levels;
    const mcsTree = L ? L.mcsTree : false;
    const named = h('datalist', { id: 'lvnames' }, ((L && L.names) || []).map(n => h('option', { value: n.raw, label: n.name })));
    const levelIn = text(model.level, (v) => { model.level = v; changed(); }, { size: 10, title: mcsTree ? 'Ignored in this MCS policy: gen_user writes "level s0"' : 'The level sessions start at (gen_user’s 4th argument)' });
    const rangeIn = text(model.range, (v) => { model.range = v; changed(); }, { size: 22, title: mcsTree ? 'Ignored in this MCS policy: the range comes from the categories below' : 'The levels the user may have, e.g. s0, or s0 - mls_systemhigh for an administrator' });
    const catsIn = info.standalone ? null : text(model.cats, (v) => { model.cats = v; changed(); }, { size: 22, placeholder: 'e.g. mcs_allcats', title: 'gen_user’s optional 6th argument: in an MCS policy the user\'s range becomes s0 - s0:CATEGORIES (mcs_allcats = all of them)' });
    for (const i of [levelIn, rangeIn]) i.setAttribute('list', 'lvnames');
    // Quick choices: what most users need.
    const set = (lv, rg, cats) => { if (lv != null) model.level = lv; if (rg != null) model.range = rg; if (cats != null) model.cats = cats; render(); changed(); };
    const quick = L ? h('div', { class: 'row' }, h('span', { class: 'lbl' }, ''),
      h('button', { title: 'Sessions at s0 with no categories: they can use only objects without categories', onclick: () => set('s0', 's0', '') }, 'No categories'),
      ' ', h('button', { title: 'Clearance for every category (an administrator, or someone who manages containers\' files)', onclick: () => (mcsTree ? set('s0', 's0 - mcs_systemhigh', 'mcs_allcats') : set('s0', info.standalone ? `s0-${L.high}` : 's0 - mls_systemhigh', null)) }, 'All categories'),
      ' ', h('button', { title: 'Clearance for some categories: give them below (e.g. c0.c9 or c1,c5)', onclick: () => { const c = (catsIn ? model.cats : '') || 'c0.c9'; if (mcsTree) set('s0', `s0 - s0:${c}`, c); else set('s0', `s0-s0:${c}`, null); } }, 'Some categories…')) : null;
    return card('mls', 'Levels and home directory', `${model.level} · ${model.range}`, [
      named,
      h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Default level'), levelIn),
      h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Range'), rangeIn),
      catsIn ? h('div', { class: 'row' }, h('span', { class: 'lbl' }, 'Categories'), catsIn) : null,
      quick,
      h('div', { id: 'lvhelp' }, levelHelp()),
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

  // Reach preview: the policy built with the planned files in a scratch copy; stale once the model changes.
  let reach = null; // null | 'building' | { result, stale }
  function reachBox(blocked) {
    const btn = h('button', { disabled: blocked || reach === 'building' || null, title: info.standalone ? 'Build the module against this host\'s devel headers, link it with the installed policy, and show where its logins land and what they can reach. Nothing is written.'
      : 'Build the tree with these files in a scratch copy (about as long as a tree build) and show where its logins land and what they can reach, and what changes compared with the last build. Nothing is written.',
    onclick: () => { reach = 'building'; renderPlan(); vscode.postMessage({ cmd: 'preview', model, ...extras() }); } }, reach && reach !== 'building' ? 'Preview again' : 'Preview what it can reach');
    const box = h('div', { class: 'pad reach' }, btn);
    if (reach === 'building') box.append(h('span', { class: 'muted' }, ' Building a scratch copy…'));
    else if (reach && reach.result) {
      const r = reach.result;
      if (r.error) box.append(h('div', { class: 'warn' }, r.error));
      else {
        const pathBox = (p) => (p && p.length ? h('div', { class: 'path small' }, p.map(s => h('div', {}, `↳ ${s.text}`))) : null);
        box.append(h('div', {},
          reach.stale ? h('div', { class: 'warn small' }, 'The form changed since: preview again.') : null,
          h('div', { class: 'muted small' }, `Built in ${(r.buildMs / 1000).toFixed(1)} s${r.standalone ? ' (linked with the installed policy)' : ''}; roles ${r.roles.join(' ')}.`),
          h('div', { class: 'sub' }, 'Ways in'),
          r.ways.length ? r.ways.map(w => h('div', {}, `${w.label}: `, h('code', {}, `${w.contexts[0].role}:${w.contexts[0].type}`), w.contexts.length > 1 ? h('span', { class: 'muted' }, ` (or ${w.contexts.slice(1).map(c => `${c.role}:${c.type}`).join(', ')})`) : null))
            : h('div', { class: 'muted' }, 'none: it is entered by switching role'),
          h('div', { class: 'sub' }, `Reaches ${r.reached} domain${r.reached === 1 ? '' : 's'}${r.before ? ` (was ${r.before.reached}: +${r.gained.length}, −${r.lost.length})` : ''}`),
          r.abilities.length ? r.abilities.map(a => h('div', { class: 'ability' }, h('span', { class: `tag${a.severity === 'high' ? ' warn' : ''}` }, a.severity), ' ', a.label, ' — as ', h('code', {}, a.domain),
            r.before && !r.before.abilities.includes(a.id) ? h('span', { class: 'warn' }, ' (new)') : null, pathBox(a.path)))
            : h('div', { class: 'muted' }, 'None of the risky abilities (unconfined, loading policy, permissive, /etc/shadow, raw disks, booleans).'),
          r.gained.length ? h('details', {}, h('summary', {}, `${r.gained.length} domain(s) it can reach now and couldn't before`), r.gained.map(g => h('div', {}, h('code', {}, g.name), pathBox(g.path)))) : null,
          r.lost.length ? h('details', {}, h('summary', {}, `${r.lost.length} domain(s) it can no longer reach`), h('div', { class: 'small' }, r.lost.join(', '))) : null,
          (r.notes || []).map(n => h('div', { class: 'muted small' }, n))));
      }
    }
    return box;
  }

  function renderPlan() {
    const pv = $('preview');
    pv.textContent = '';
    if (!plan) { pv.append(h('div', { class: 'pad muted' }, info && !info.isNew ? 'Change something to see the edits.' : 'Fill in a name to see the files.')); $('apply').disabled = true; return; }
    const blocking = plan.problems.filter(p => !p.startsWith('Note:'));
    $('apply').disabled = !!blocking.length || !plan.files.length;
    if (plan.problems.length) pv.append(h('div', { class: 'problems' }, plan.problems.map(p => h('div', { class: p.startsWith('Note:') ? 'note' : 'error' }, p))));
    pv.append(reachBox(!!blocking.length));
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
      // The kind as written (an existing user may switch to another).
      info.kindWas = m.info.model && m.info.model.user ? m.info.model.user.kind : null;
      plan = null;
      reach = null;
      $('title').textContent = info.isNew ? 'New User' : `User: ${model.name}_${model.standalone || (model.genUser && model.genUser.exists) ? 'u' : 'r'} (${info.module})`;
      $('apply').textContent = info.isNew ? 'Create' : 'Apply';
      $('status').textContent = '';
      render();
      if (model.name && info.isNew) changed();
    } else if (m.cmd === 'preview') {
      reach = { result: m.result, stale: false };
      renderPlan();
    } else if (m.cmd === 'plan') {
      const hadLevels = !!(plan && plan.levels);
      plan = m.plan;
      $('status').textContent = '';
      renderPlan();
      // The level help follows each plan without redrawing the form (the cursor stays); the first one draws the quick choices.
      if (!hadLevels && plan.levels) render();
      else {
        const box = $('lvhelp');
        if (box) { box.textContent = ''; const x = levelHelp(); if (x) box.append(x); }
      }
    } else if (m.cmd === 'done') {
      $('status').textContent = m.text;
    } else if (m.cmd === 'error') {
      $('form').textContent = '';
      $('form').append(h('div', { class: 'pad warn' }, m.msg));
    }
  });
  vscode.postMessage({ cmd: 'ready' });
})();
