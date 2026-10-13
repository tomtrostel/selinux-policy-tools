// Wrapped programs webview: a chroot's users run wrappers; each wrapper is the
// only domain that may run its protected copy of a program, which runs in the
// original program's domain. Form on the left, the files on the right.
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

  let info = null, model = null, plan = null, tab = 0, timer = null, license = null, where = null;
  const open = new Map();     // card id → open
  const looked = new Map();   // program object → lookup result | 'looking'
  const byKey = new Map();    // lookup key → program object
  let seq = 0;
  let autoDirs = true;        // directories follow the name until edited
  let newPath = '';

  $('apply').setAttribute('title', 'Write the files shown on the right (one undoable edit) and save them, which builds the policy');
  $('apply').addEventListener('click', () => { if (model) { $('status').textContent = 'Writing…'; vscode.postMessage({ cmd: 'apply', model, ...extras() }); } });

  const extras = () => ({ standalone: !!(info && info.standalone), where: info && info.isNew && !info.standalone ? where : undefined, license: info && info.standalone && info.isNew ? license : undefined });
  const changed = () => { clearTimeout(timer); timer = setTimeout(() => vscode.postMessage({ cmd: 'plan', model, ...extras() }), 250); };
  const card = (id, title, hint, body, defOpen = true) => {
    const d = h('details', { class: 'card', open: (open.has(id) ? open.get(id) : defOpen) || null }, h('summary', {}, h('span', { class: 'title' }, title), hint ? h('span', { class: 'hint' }, hint) : null), h('div', { class: 'body' }, body));
    d.addEventListener('toggle', () => open.set(id, d.open));
    return d;
  };
  const text = (value, oninput, attrs = {}) => {
    const i = h('input', { type: 'text', value: value || '', size: attrs.size || 24, placeholder: attrs.placeholder || null, title: attrs.title || null });
    i.addEventListener('input', () => oninput(i.value));
    return i;
  };
  const check = (label, on, onchange, attrs = {}) => {
    const box = h('input', { type: 'checkbox', checked: on || null, disabled: attrs.disabled || null });
    box.addEventListener('change', () => onchange(box.checked));
    return h('label', { class: 'check', title: attrs.title || null }, box, h('span', {}, label, attrs.code ? h('span', { class: 'code' }, attrs.code) : null));
  };
  const toggle = (list, v, on) => { const i = list.indexOf(v); if (on && i < 0) list.push(v); if (!on && i >= 0) list.splice(i, 1); };
  const row = (label, ...kids) => h('div', { class: 'row' }, h('span', { class: 'lbl' }, label), ...kids);
  const N = () => model.name || 'NAME';
  const typesOf = (p) => ({ W: `${N()}_${p.stem || 'PROG'}_t`, WE: `${N()}_${p.stem || 'PROG'}_exec_t`, C: `${N()}_${p.stem || 'PROG'}_real_exec_t` });

  function moduleCard() {
    const rows = [];
    if (info.isNew) {
      rows.push(row('Name', text(model.name, (v) => {
        model.name = v.trim();
        if (autoDirs && model.name) { model.protectedDir = `/.${model.name}`; model.wrapperDir = `/opt/${model.name}/bin`; render(); }
        $('title').textContent = model.name ? `New Wrapped Programs: ${model.name}` : 'New Wrapped Programs';
        changed();
      }, { placeholder: 'e.g. rowrap', title: 'The module name; the types are named from it (NAME_PROG_t, NAME_protected_t). Lowercase letters, digits and _.' })));
    } else rows.push(row('Module', h('code', {}, info.module), h('span', { class: 'muted small' }, info.standalone ? ' standalone' : ' in the tree')));
    rows.push(row('Summary', text(model.summary, (v) => { model.summary = v; changed(); }, { size: 44, placeholder: 'e.g. Programs the read-only users may run', title: 'One line for the module\'s comments and .if summary' })));
    if (info.isNew && (info.canStandalone || info.standalone)) {
      const opt = (on, label, title) => {
        const r = h('input', { type: 'radio', name: 'where', checked: (!!info.standalone === on) || null, disabled: (!info.canStandalone) || null });
        r.addEventListener('change', () => vscode.postMessage({ cmd: 'standalone', on, model }));
        return h('label', { class: 'check', title }, r, h('span', {}, label));
      };
      rows.push(h('div', { class: 'row top' }, h('span', { class: 'lbl' }, 'Where'), h('div', {},
        opt(false, 'In the tree', 'A module of the tree, built with it; the chroot\'s labeling goes into config/file_contexts.subs_dist. Each system needs the copies put in place (commands on the right).'),
        opt(true, `Standalone, packaged (${(info.folder || '').split(/[\\/]/).pop() || 'workspace'}/${model.name || 'NAME'}${info.folderSuffix || ''}/)`, 'A module of its own built against this host\'s devel headers; its package labels the chroot, makes the copies when installed and refreshes them when their packages update.'))));
    }
    if (info.isNew && !info.standalone && info.layers) {
      if (!where) where = info.defaultLayer;
      const sel = h('select', { title: 'The layer directory of policy/modules the module goes into' }, info.layers.map(l => h('option', { value: l, selected: l === where || null }, l)));
      sel.addEventListener('change', () => { where = sel.value; changed(); });
      rows.push(row('Layer', sel));
    }
    if (info.isNew && info.standalone && info.licenses) {
      if (license == null) license = info.licenses.default;
      const ids = [...new Set([...info.licenses.common.map(x => x.id), ...info.licenses.custom, license])];
      const sel = h('select', { title: 'The License: tag of the package spec (SPDX identifier)' }, ids.map(id => h('option', { value: id, selected: id === license || null }, id)));
      sel.addEventListener('change', () => { license = sel.value; changed(); });
      rows.push(row('License', sel, text('', (v) => { if (v.trim()) { license = v.trim(); changed(); } }, { size: 22, placeholder: 'or another SPDX expression' })));
    }
    return card('module', 'Module', model.name || '', rows);
  }

  function chrootCard() {
    const dirs = (k, v) => { model[k] = v.trim(); autoDirs = false; changed(); };
    return card('chroot', 'Chroot', model.chroot || '', [
      h('div', { class: 'muted small' }, 'The users\' sessions run inside this directory (e.g. sshd\'s ChrootDirectory). The wrappers and the protected copies live inside it; the paths below are as the user sees them.'),
      row('Chroot', text(model.chroot, (v) => { model.chroot = v.trim(); changed(); }, { size: 30, placeholder: '/var/chroot/ro', title: 'The chroot directory on the host' })),
      check('Label the chroot like / (its usr/lib64 like /usr/lib64, and so on)', model.likeRoot, (on) => { model.likeRoot = on; render(); changed(); },
        { title: 'An equivalence (semanage fcontext -e / CHROOT): the chroot\'s files get the labels their counterparts outside have. File-context lines for paths inside it are then written as if it were /, so the wrapper and protected directories must be paths the host itself doesn\'t use.' }),
      row('Protected', text(model.protectedDir, (v) => dirs('protectedDir', v), { size: 26, placeholder: '/.NAME', title: 'Where the protected copies go, inside the chroot. The users can\'t list or enter it; only the wrappers may.' })),
      row('Wrappers', text(model.wrapperDir, (v) => dirs('wrapperDir', v), { size: 26, placeholder: '/opt/NAME/bin', title: 'Where your wrapper programs are, inside the chroot. The editor labels them; it doesn\'t write them.' })),
    ]);
  }

  function userCard() {
    const cur = info.users.findIndex(u => u.role === model.role && u.domain === model.domain);
    const opts = [h('option', { value: '', selected: cur < 0 || null }, cur < 0 && model.role ? `${model.role} (${model.domain})` : '(pick one)'),
      ...info.users.map((u, i) => h('option', { value: String(i), selected: i === cur || null }, `${u.role} (${u.domain})`))];
    const sel = h('select', { title: 'The role and domain of the users who run the wrappers' }, opts);
    sel.addEventListener('change', () => { const u = info.users[+sel.value]; if (u) { model.role = u.role; model.domain = u.domain; changed(); render(); } });
    return card('user', 'Who runs the wrappers', model.role ? `${model.role} · ${model.domain}` : '', [
      row('User', sel, h('button', { title: 'Create a user and role first (e.g. a restricted user for the chroot), then pick it here', onclick: () => vscode.postMessage({ cmd: 'newUser' }) }, 'New User…')),
      h('div', { class: 'muted small' }, 'Its domain may run each wrapper; its role gets the wrappers\' domains and the programs\' domains. It may not run, read or even see the protected copies (checked after every build).'),
      row('Logins', text(model.logins, (v) => { model.logins = v; changed(); }, { size: 30, placeholder: '%chrootusers', title: 'The Linux logins (or %groups) of the chroot\'s users, as seusers maps them. The checks then verify, with their SELinux user, roles and ways in, that their sessions reach each program\'s domain only through its wrapper.' })),
    ]);
  }

  function applyLookup(p, r) {
    p.origType = r.origType;
    p.pkg = r.pkg || null;
    const c = r.candidates.find(x => x.domain === r.target);
    p.target = c ? c.domain : '';
    p.selfRules = c ? c.selfRules : [];
    p.roles = c ? c.auto.map(a => a.domain) : [];
  }

  function lookup(p) {
    const key = `p${++seq}`;
    byKey.set(key, p);
    looked.set(p, 'looking');
    vscode.postMessage({ cmd: 'program', key, path: p.original, chroot: model.chroot, standalone: !!info.standalone });
  }

  function readiness(r) {
    if (!r.chroot) return h('div', { class: 'muted small' }, 'Give the chroot to see what the copy will find there.');
    if (!r.chrootExists) return h('div', { class: 'muted small' }, `${r.chroot} isn't on this host, so what the copy will find there can't be checked.`);
    const miss = (r.needs || []).filter(n => !n.present);
    const nc = r.needsCount || (r.needs ? { total: r.needs.length, present: r.needs.length - miss.length } : null);
    return h('details', {}, h('summary', {}, `In the chroot: ${r.libs ? `${r.libs.total - r.libs.missing.length} of ${r.libs.total} libraries` : 'libraries unknown'}${nc ? `, ${nc.present} of ${nc.total} paths its domain uses` : ''}`,
      (r.libs && r.libs.missing.length) || miss.length ? h('span', { class: 'warn' }, ' — some are missing') : null),
    h('div', { class: 'muted small' }, 'The copy only sees the chroot. Paths its domain may use (from its file types in the file contexts) and the libraries it links; bind-mount or copy in what it needs.'),
    r.libs && r.libs.missing.length ? h('div', {}, h('div', { class: 'sub small' }, 'Libraries not in the chroot'), r.libs.missing.map(l => h('div', {}, h('code', {}, l)))) : null,
    (r.needs || []).length ? h('div', {}, h('div', { class: 'sub small' }, 'Paths'), r.needs.map(n => h('div', { class: n.present ? 'muted small' : 'small' }, h('code', {}, n.path), ` ${n.type} (${n.access.join(', ')})`,
      n.present ? ' — present' : h('span', { class: 'warn' }, ' — not in the chroot')))) : null);
  }

  function programCard(p, i) {
    const r = looked.get(p);
    const t = typesOf(p);
    const body = [];
    body.push(row('Program', h('code', {}, p.original), h('button', { title: 'Look its label and domain up again', onclick: () => { lookup(p); render(); } }, r ? 'Look up again' : 'Look up'),
      h('button', { class: 'icon', title: 'Stop wrapping this program', onclick: () => { model.programs.splice(i, 1); render(); changed(); } }, '✕')));
    if (r === 'looking') body.push(h('div', { class: 'muted' }, 'Looking it up…'));
    else if (r && r.error) body.push(h('div', { class: 'warn' }, r.error));
    else if (r) body.push(h('div', { class: 'muted small' }, `${r.policy}: `, h('code', {}, r.context), r.pkg ? ` · package ${r.pkg}` : ' · no package'));
    const cands = r && r !== 'looking' && !r.error ? r.candidates : (p.target ? [{ domain: p.target, selfRules: p.selfRules, auto: (p.roles || []).map(d => ({ domain: d })) }] : []);
    const sel = h('select', { title: 'The domain the copy runs in: the original program\'s, so it keeps its privileges' },
      cands.map(c => h('option', { value: c.domain, selected: c.domain === p.target || null }, `${c.domain}${r && r.target === c.domain ? ' (as the original)' : ''}`)),
      h('option', { value: '', selected: !p.target || null }, 'the wrapper\'s own domain (no transition)'));
    sel.addEventListener('change', () => {
      const c = cands.find(x => x.domain === sel.value);
      p.target = c ? c.domain : '';
      p.selfRules = c ? c.selfRules : [];
      p.roles = c ? c.auto.map(a => a.domain) : [];
      render(); changed();
    });
    body.push(row('Runs as', sel, r && r.generic ? h('span', { class: 'muted small' }, 'it has no domain of its own') : null));
    body.push(row('Wrapper', text(p.wrapper, (v) => { p.wrapper = v.trim(); changed(); }, { size: 18, title: `Your wrapper's file name in ${model.wrapperDir || 'the wrapper directory'}; labeled ${t.WE}` }), h('span', { class: 'code' }, `${(model.wrapperDir || '').replace(/\/+$/, '')}/${p.wrapper}`)));
    body.push(row('Copy', text(p.copy, (v) => { p.copy = v.trim(); changed(); }, { size: 18, title: `The copy's file name in the protected directory; labeled ${t.C}` }), h('span', { class: 'code' }, `${(model.protectedDir || '').replace(/\/+$/, '')}/${p.copy}`)));
    body.push(row('Short name', text(p.stem, (v) => { p.stem = v.trim(); render(); changed(); }, { size: 14, title: 'Names its types: NAME_SHORT_t (wrapper), NAME_SHORT_exec_t, NAME_SHORT_real_exec_t (copy)' }), h('span', { class: 'code' }, `${t.W}, ${t.C}`)));
    if (p.target) {
      const c = cands.find(x => x.domain === p.target);
      const auto = c ? c.auto : [];
      if (auto.length) {
        body.push(h('div', { class: 'sub small' }, `Domains ${p.target} starts on its own (the role needs them)`),
          h('div', { class: 'cols' }, auto.map(a => check(a.domain, (p.roles || []).includes(a.domain), (on) => { p.roles = p.roles || []; toggle(p.roles, a.domain, on); changed(); },
            { title: `${p.target} runs programs that enter ${a.domain}; without it in the role those fail as they would for a user who doesn't have it` }))));
      }
      if ((p.selfRules || []).length) body.push(h('div', { class: 'muted small' }, `Rules ${p.target} has on its own program file, given on the copy too: `, p.selfRules.map(x => h('code', {}, `${x.c} { ${x.perms.join(' ')} } `))));
      if (c && c.conditionalRules) body.push(h('div', { class: 'muted small' }, `${c.conditionalRules} conditional rule group(s) on its program file aren't copied.`));
    }
    const chips = (p.ifaces || []).map(n => h('span', { class: 'chip on' }, h('code', {}, n), h('button', { class: 'icon', title: 'Remove', onclick: () => { toggle(p.ifaces, n, false); render(); changed(); } }, '✕')));
    const results = h('div', { class: 'results' });
    const filter = text('', (v) => {
      results.textContent = '';
      const words = v.toLowerCase().split(/\s+/).filter(Boolean);
      if (!words.length) return;
      const hits = info.interfaces.filter(x => !(p.ifaces || []).includes(x.n) && words.every(w => x.n.toLowerCase().includes(w) || (x.s || '').toLowerCase().includes(w))).slice(0, 25);
      results.append(...hits.map(x => h('div', { class: 'hit', title: x.s, onclick: () => { p.ifaces = p.ifaces || []; toggle(p.ifaces, x.n, true); render(); changed(); } }, h('code', {}, x.n), h('span', { class: 'muted small' }, ` ${x.s || ''}`))));
    }, { size: 28, placeholder: 'search interfaces', title: 'More rights for the wrapper\'s domain, if your wrapper does more than execve' });
    body.push(h('div', { class: 'sub small' }, `What the wrapper (${t.W}) may do besides running the copy`), h('div', { class: 'chips' }, chips), filter, results);
    if (r && r !== 'looking' && !r.error) body.push(readiness(r));
    return card(`prog:${i}`, p.original.split('/').pop() || 'program', p.target ? `runs as ${p.target}` : 'runs in the wrapper\'s domain', body);
  }

  function programsCard() {
    const add = text(newPath, (v) => { newPath = v; }, { size: 30, placeholder: '/usr/sbin/someprog', title: 'The program on this system to copy into the chroot and wrap' });
    const go = () => {
      const pth = newPath.trim();
      if (!/^\/\S+$/.test(pth)) return;
      const base = pth.split('/').pop();
      const stem = base.toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^[^a-z]+/, '').replace(/_+$/, '');
      const p = { stem, original: pth, wrapper: base, copy: `${base}.real`, pkg: null, origType: '', target: '', roles: [], selfRules: [], ifaces: [...(info.defaults || [])] };
      model.programs.push(p);
      newPath = '';
      open.set(`prog:${model.programs.length - 1}`, true);
      lookup(p);
      render(); changed();
    };
    add.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    return [h('div', { class: 'sub' }, 'Programs'), h('div', { class: 'muted small' }, 'Each program gets a wrapper domain of its own; only it may run the program\'s protected copy.'),
      ...model.programs.map((p, i) => programCard(p, i)),
      h('div', { class: 'row' }, add, h('button', { onclick: go, title: 'Look the program up and add it' }, 'Add program'))];
  }

  function keptCard() {
    if (info.isNew || !(info.kept || []).length) return null;
    return card('kept', 'Kept as is', `${info.kept.length} line(s) the form doesn't describe`, [
      h('div', { class: 'muted small' }, 'Lines you added by hand: kept in a "Local additions" section at the end of the file.'),
      h('div', { class: 'kept' }, info.kept.map(k => h('div', { class: 'keptline', title: k.text }, h('span', { class: 'ln' }, k.file), k.text))),
    ], false);
  }

  function render() {
    const form = $('form');
    form.textContent = '';
    if (!info) return;
    form.append(...[moduleCard(), chrootCard(), userCard(), ...programsCard(), keptCard()].filter(Boolean));
    renderPlan();
  }

  function renderPlan() {
    const pv = $('preview');
    pv.textContent = '';
    if (!plan) { pv.append(h('div', { class: 'pad muted' }, info && !info.isNew ? 'Change something to see the edits.' : 'Fill in a name, the chroot, the user and a program to see the files.')); $('apply').disabled = true; return; }
    const blocking = plan.problems.filter(p => !p.startsWith('Note:'));
    $('apply').disabled = !!blocking.length || !plan.files.length;
    if (plan.problems.length) pv.append(h('div', { class: 'problems' }, plan.problems.map(p => h('div', { class: p.startsWith('Note:') ? 'note' : 'error' }, p))));
    if (plan.commands && plan.commands.length) {
      pv.append(h('div', { class: 'pad' }, h('div', { class: 'sub' }, 'On each system, after installing the policy'),
        h('div', { class: 'muted small' }, 'Put the copies in place and label the chroot (again whenever a copied program is updated):'),
        h('pre', { class: 'grants' }, plan.commands.join('\n'))));
    }
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
      model = m.keep && m.model ? m.model : m.info.model;
      autoDirs = info.isNew && !model.protectedDir && !model.wrapperDir;
      plan = null;
      $('title').textContent = info.isNew ? (model.name ? `New Wrapped Programs: ${model.name}` : 'New Wrapped Programs') : `Wrapped Programs: ${info.module}`;
      $('apply').textContent = info.isNew ? 'Create' : 'Apply';
      $('status').textContent = '';
      render();
      if (model.name) changed();
    } else if (m.cmd === 'program') {
      const p = byKey.get(m.key);
      if (!p) return;
      looked.set(p, m.result);
      if (!m.result.error) applyLookup(p, m.result);
      render(); changed();
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
