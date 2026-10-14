// Levels and Categories webview (MLS / MCS): "can this context access that
// one?" (type rules, then each constraint with its comparisons), and which
// domains pass the level constraints whatever the levels. Plain JS, no deps.
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

  const CLASSES = ['file', 'dir', 'lnk_file', 'chr_file', 'blk_file', 'sock_file', 'fifo_file', 'process', 'unix_stream_socket', 'tcp_socket', 'udp_socket', 'key', 'shm', 'sem', 'msgq'];
  const EXAMPLES = [
    { label: 'Two containers', source: 'system_u:system_r:container_t:s0:c1,c2', target: 'system_u:object_r:container_file_t:s0:c1,c3', tclass: 'file', perms: 'read open',
      title: 'A container (categories c1,c2) opening a file of another container (c1,c3)' },
    { label: 'Same container', source: 'system_u:system_r:container_t:s0:c1,c2', target: 'system_u:object_r:container_file_t:s0:c1,c2', tclass: 'file', perms: 'read open',
      title: 'A container opening its own file' },
    { label: 'Admin and a container\'s files', source: 'staff_u:sysadm_r:sysadm_t:s0-s0:c0.c1023', target: 'system_u:object_r:container_file_t:s0:c1,c2', tclass: 'file', perms: 'read open',
      title: 'An administrator (all categories) reading a container\'s file' },
  ];
  // Plain words for constraint operands.
  const OPERAND = {
    l1: 'the process\'s level', h1: 'the process\'s clearance (high level)', l2: 'the object\'s level', h2: 'the object\'s high level',
    t1: 'the process\'s type', t2: 'the object\'s type', u1: 'the process\'s user', u2: 'the object\'s user', r1: 'the process\'s role', r2: 'the object\'s role',
  };

  let policies = [], against = null, levels = null, levelsKey = null, checkKey = 0, seq = 0;
  const iso = { domains: '', weight: 10, all: false, result: null, key: 0, touched: false };
  const state = { source: '', target: '', tclass: 'file', perms: 'read open', path: '' };
  let lastCheck = null, filter = '';
  const open = new Map();

  const card = (id, title, hint, body, defOpen, cls) => {
    const d = h('details', { class: `card${cls ? ` ${cls}` : ''}`, open: (open.has(id) ? open.get(id) : defOpen) || null }, h('summary', {}, h('span', { class: 'fname' }, title), hint ? h('span', { class: 'muted' }, hint) : null), h('div', { class: 'body' }, body));
    d.addEventListener('toggle', () => open.set(id, d.open));
    return d;
  };
  const link = (text, loc, title) => (loc ? h('button', { class: 'link', title: title || `Open ${loc.p.split('/').pop()}:${loc.l + 1}`, onclick: () => vscode.postMessage({ cmd: 'open', loc }) }, text) : h('code', {}, text));
  const input = (key, attrs) => {
    const i = h('input', { type: 'text', value: state[key], spellcheck: 'false', ...attrs });
    i.addEventListener('input', () => { state[key] = i.value; });
    i.addEventListener('keydown', (e) => { if (e.key === 'Enter') runCheck(); });
    return i;
  };

  function runCheck() {
    if (!state.source.trim() || !state.target.trim()) { lastCheck = { error: 'Give both contexts.' }; render(); return; }
    lastCheck = 'checking';
    vscode.postMessage({ cmd: 'check', key: ++checkKey, against, source: state.source, target: state.target, tclass: state.tclass, perms: state.perms });
    render();
  }

  function leafText(l) {
    // "h1 dom h2" → "the process's clearance (s0:c1.c2) covers the object's high level (s0:c1,c3)"
    const m = /^(\w+) (dom|domby|eq|==|!=|incomp) (\w+)$/.exec(l.text);
    if (m && OPERAND[m[1]] && OPERAND[m[3]]) {
      const verb = { dom: 'covers', domby: 'is covered by', eq: 'equals', '==': 'equals', '!=': 'differs from', incomp: 'is incomparable with' }[m[2]];
      return `${OPERAND[m[1]]} (${l.a}) ${verb} ${OPERAND[m[3]]} (${l.b})`;
    }
    const s = /^(\w+) (==|!=) (.*)$/.exec(l.text);
    if (s && OPERAND[s[1]]) return `${OPERAND[s[1]]} (${l.a}) is ${s[2] === '==' ? '' : 'not '}in ${s[3]}`;
    return l.text;
  }

  function checkForm() {
    const cls = h('input', { type: 'text', value: state.tclass, size: 14, list: 'classes', spellcheck: 'false', title: 'The object class (file, dir, process, …)' });
    cls.addEventListener('input', () => { state.tclass = cls.value.trim(); });
    const pathIn = h('input', { type: 'text', value: state.path, size: 28, placeholder: '/var/lib/containers/…', spellcheck: 'false', title: 'Fill the target context from the label this file gets' });
    pathIn.addEventListener('input', () => { state.path = pathIn.value; });
    const lookUp = () => { if (state.path.trim()) vscode.postMessage({ cmd: 'label', key: ++seq, path: state.path.trim(), against }); };
    pathIn.addEventListener('keydown', (e) => { if (e.key === 'Enter') lookUp(); });
    return card('check', 'Can it access?', 'a process context, an object context, a class and permissions', [
      h('div', { class: 'intro' }, 'Is the access allowed by the type rules, and does every constraint hold for these levels? With MCS, a process may use an object only if its clearance covers all of the object\'s categories (for domains MCS applies to).'),
      h('table', {}, h('tbody', {},
        h('tr', {}, h('th', {}, 'Process'), h('td', {}, input('source', { size: 46, placeholder: 'system_u:system_r:container_t:s0:c1,c2', title: 'The process context: user:role:type:level (a range low-high for a process that has one)' }))),
        h('tr', {}, h('th', {}, 'Object'), h('td', {}, input('target', { size: 46, placeholder: 'system_u:object_r:container_file_t:s0:c1,c3', title: 'The object context: for a file, its label (ls -Z)' }),
          ' or from a file ', pathIn, h('button', { onclick: lookUp, title: 'Look up the label this file gets under the selected policy' }, 'Use its label'))),
        h('tr', {}, h('th', {}, 'Class'), h('td', {}, cls, ' Permissions ', input('perms', { size: 24, placeholder: 'read open', title: 'One or more permissions of the class' }))))),
      h('datalist', { id: 'classes' }, CLASSES.map(c => h('option', { value: c }))),
      h('div', { class: 'row' }, h('button', { class: 'primary', onclick: runCheck }, 'Check'), ' ', h('span', { class: 'muted' }, 'Examples: '),
        EXAMPLES.map(x => h('button', { class: 'link', title: x.title, onclick: () => { Object.assign(state, { source: x.source, target: x.target, tclass: x.tclass, perms: x.perms }); runCheck(); } }, x.label)).flatMap((b, i) => (i ? [' · ', b] : [b]))),
      checkResult(),
    ], true);
  }

  function checkResult() {
    const r = lastCheck;
    if (!r) return null;
    if (r === 'checking') return h('div', { class: 'muted' }, 'Checking…');
    if (r.error) return h('div', { class: 'note bad' }, r.error);
    const te = Object.entries(r.te || {});
    const teDenied = te.filter(([, x]) => x.status !== 'allowed');
    const failing = (r.constraints || []).filter(c => !c.ok);
    const passing = (r.constraints || []).filter(c => c.ok);
    const ctxBad = (r.problems || []).filter(p => p.kind !== 'level');
    let verdict, cls;
    if (!teDenied.length && !failing.length) { verdict = 'Allowed'; cls = 'ok'; } else if (teDenied.length && !failing.length) { verdict = 'Denied by the type rules'; cls = 'bad'; } else if (!teDenied.length) { verdict = 'Denied by a constraint (the type rules allow it)'; cls = 'bad'; } else { verdict = 'Denied by the type rules and by a constraint'; cls = 'bad'; }
    const out = [h('div', { class: `verdict ${cls}` }, verdict, r.permissiveDomain ? h('span', { class: 'muted' }, ' — the domain is permissive, so it would only be logged') : null)];
    for (const p of r.problems || []) out.push(h('div', { class: `note ${p.kind === 'level' ? 'muted' : 'warn'}` }, p.text));
    if (ctxBad.length) out.push(h('div', { class: 'note muted' }, 'The answer below is for these contexts as given, even though a process can\'t get the source context.'));
    if (r.levels && r.levels.source) {
      out.push(h('div', { class: 'sub' }, 'Levels'), h('table', {}, h('tbody', {},
        h('tr', {}, h('th', {}, 'Process'), h('td', {}, h('code', {}, r.levels.source.low === r.levels.source.high ? r.levels.source.low : `${r.levels.source.low} – ${r.levels.source.high}`),
          r.levels.source.name ? h('span', {}, ` ${r.levels.source.name}`) : null,
          r.levels.user ? h('span', { class: 'muted' }, `  (its user may have ${r.levels.user.replace(/ - /, '-')}${r.levels.userName ? `, ${r.levels.userName}` : ''})`) : null)),
        h('tr', {}, h('th', {}, 'Object'), h('td', {}, h('code', {}, r.levels.target.low === r.levels.target.high ? r.levels.target.low : `${r.levels.target.low} – ${r.levels.target.high}`),
          r.levels.target.name ? h('span', {}, ` ${r.levels.target.name}`) : null)))),
      r.levels.setrans && (r.levels.source.name || r.levels.target.name) ? h('div', { class: 'note muted' }, `Names from ${r.levels.setrans}.`) : null);
    }
    out.push(h('div', { class: 'sub' }, 'Type rules'), h('div', {}, te.map(([perm, x]) => {
      if (x.status === 'allowed') {
        const rule = x.rules[0];
        return h('div', { class: 'note' }, h('span', { class: 'ok' }, '✓ '), h('code', {}, perm), ` allowed${x.conditional ? ' (under a boolean that is on)' : ''}: `,
          h('code', {}, `allow ${rule.s} ${rule.t}:${rule.c} { ${rule.perms.slice(0, 8).join(' ')}${rule.perms.length > 8 ? ' …' : ''} }`), rule.cond ? h('span', { class: 'muted' }, ` [${rule.cond}]`) : null,
          rule.origin ? [' ', link(`${rule.origin.path.split('/').pop()}:${rule.origin.line + 1}`, { p: rule.origin.path, l: rule.origin.line }, rule.origin.via ? `via ${rule.origin.via}` : null)] : null);
      }
      if (x.status === 'boolean') return h('div', { class: 'note warn' }, '✗ ', h('code', {}, perm), ' only with other boolean settings: ', x.options.map(o => Object.entries(o).map(([b, v]) => `${b}=${v ? 'on' : 'off'}`).join(' ')).join(' or '));
      return h('div', { class: 'note bad' }, '✗ ', h('code', {}, perm), ' no rule allows it');
    })));
    out.push(h('div', { class: 'sub' }, `Constraints (${failing.length} fail, ${passing.length} hold)`));
    if (!r.mls) out.push(h('div', { class: 'note muted' }, 'This policy has no levels (built without MLS or MCS); only plain constraints apply.'));
    for (const c of failing) {
      out.push(h('div', { class: 'cons bad' }, h('div', {}, h('span', { class: 'bad' }, '✗ '), h('code', {}, c.kind), ' on ', h('code', {}, c.perms.join(' ')), ': ', h('code', { class: 'muted' }, c.text)),
        h('ul', {}, c.leaves.map(l => h('li', { class: l.ok ? 'ok' : 'bad' }, l.ok ? '✓ ' : '✗ ', leafText(l))))));
    }
    if (passing.length) {
      out.push(h('details', {}, h('summary', { class: 'muted' }, `${passing.length} constraint${passing.length > 1 ? 's' : ''} hold`),
        passing.map(c => h('div', { class: 'cons' }, h('div', {}, h('span', { class: 'ok' }, '✓ '), h('code', {}, c.kind), ' on ', h('code', {}, c.perms.join(' ')), ': ', h('code', { class: 'muted' }, c.text)),
          h('ul', {}, c.leaves.map(l => h('li', { class: l.ok ? 'ok' : 'muted' }, l.ok ? '✓ ' : '✗ ', leafText(l))))))));
    }
    return h('div', { class: 'result' }, out);
  }

  function levelsCards() {
    const L = levels;
    if (!L) return [h('div', { class: 'muted' }, 'Reading the policy\'s level constraints…')];
    if (L.error) return [h('div', { class: 'note bad' }, L.error)];
    if (!L.mls) return [card('who', 'Who ignores levels', '', [h('div', { class: 'note' }, 'This policy has no levels: it was built without MLS or MCS, so categories and sensitivities don\'t apply.')], true)];
    const held = L.groups.filter(g => !g.constraints.length);
    const heldN = held.reduce((n, g) => n + g.domains.length, 0);
    const passN = L.domains - heldN;
    const summary = h('div', { class: 'intro' },
      `${L.kind === 'mls' ? `MLS policy: ${L.sensitivities} sensitivities` : 'MCS policy: one sensitivity (s0)'} and ${L.categories} categories; ${L.constraints.length} level constraints. `,
      h('b', {}, `${heldN} domain${heldN === 1 ? ' is' : 's are'} held to all of them`), `; ${passN} pass${passN === 1 ? 'es' : ''} some or all of them whatever the levels.`,
      L.groups.some(g => g.via.some(v => /not in .*mcs_constrained_type/.test(v))) ? ' This policy\'s constraints only bind the domains in mcs_constrained_type (containers, virtual machines, sandboxes, where it has them); that is what keeps them apart, and every other domain ignores categories.'
        : L.groups.some(g => g.via.length) ? ' Domains are exempt only through attributes (such as mlsfileread), so the groups below are the exceptions.' : '');
    const f = h('input', { type: 'text', id: 'lvfilter', value: filter, placeholder: 'find a domain', size: 22, spellcheck: 'false', title: 'Show only the groups and domains whose name contains this' });
    f.addEventListener('input', () => { filter = f.value.trim(); renderLevelsOnly(); });
    const body = [summary, h('div', { class: 'row' }, f, ' ', h('span', { class: 'muted' }, L.policyLabel || ''))];
    L.groups.forEach((g, gi) => {
      const doms = filter ? g.domains.filter(d => d.includes(filter)) : g.domains;
      if (filter && !doms.length) return;
      const title = g.constraints.length ? `${g.domains.length} domain${g.domains.length === 1 ? '' : 's'} pass ${g.constraints.length} of ${L.constraints.length} constraints whatever the levels` : `${g.domains.length} domain${g.domains.length === 1 ? '' : 's'} held to every level constraint`;
      const why = g.via.length ? `because: ${g.via.join('; ')}` : (g.constraints.length ? 'for reasons other than their type' : '');
      const chips = h('div', { class: 'chips' }, doms.slice(0, 400).map(d => link(d, L.locs[d], L.locs[d] ? `Open where ${d} is declared` : null)), doms.length > 400 ? h('span', { class: 'muted' }, ` … ${doms.length - 400} more`) : null);
      const rows = Object.entries(g.classes).map(([c, ps]) => h('tr', {}, h('td', {}, h('code', {}, c)), h('td', {}, h('code', { class: 'muted' }, ps.join(' ')))));
      const via = g.via.flatMap(v => (v.match(/[A-Za-z_]\w*/g) || []).filter(n => n !== 'in' && n !== 'not' && L.locs[n]).map(n => link(n, L.locs[n], `Open where ${n} is declared`)));
      const checkLine = g.constraints.length ? null : `never ${g.domains.length <= 12 ? g.domains.join(' ') : g.domains.slice(0, 12).join(' ')} may ignore levels`;
      body.push(card(`g${gi}`, title, why, [
        via.length ? h('div', { class: 'note' }, 'Decided by ', via.flatMap((x, i) => (i ? [', ', x] : [x]))) : null,
        rows.length ? h('details', {}, h('summary', { class: 'muted' }, 'Which classes and permissions'), h('table', {}, h('tbody', {}, rows))) : null,
        g.constraints.length && L.kind !== 'mls' && g.via.some(v => /not in .*mcs_constrained_type/.test(v)) ? h('div', { class: 'note muted' }, 'Categories don\'t limit these domains; only their type rules do. To hold one to its categories, add it to mcs_constrained_type (mcs_constrained(domain)).') : null,
        chips,
        checkLine ? h('div', { class: 'row' }, h('button', { title: 'Add a check to selinux.checks that fails if any of these domains stops being held to the level constraints', onclick: () => vscode.postMessage({ cmd: 'addCheck', text: checkLine }) }, 'Add check'), ' ', h('code', { class: 'muted' }, checkLine)) : null,
      ], !!filter || (!g.constraints.length && gi < 3)));
    });
    if (L.setrans) {
      const s = L.setrans;
      body.push(h('details', {}, h('summary', { class: 'muted' }, `Level names: ${s.entries.length} in `, link(s.path.split('/').pop(), { p: s.path, l: 0 }, `Open ${s.path}`),
        s.skipped ? ` (${s.skipped} line${s.skipped === 1 ? '' : 's'} in mcstrans' advanced format not read)` : ''),
        h('div', { class: 'intro' }, 'setrans.conf gives levels readable names; with mcstrans running, ls -Z and ps -Z show them instead of the raw levels.'),
        h('table', {}, h('tbody', {}, s.entries.map(e => h('tr', {}, h('td', {}, link(e.raw, { p: s.path, l: e.l }, 'Open this line')), h('td', {}, e.name)))))));
    } else if (L.mls) body.push(h('div', { class: 'note muted' }, 'No setrans.conf found for this policy, so levels have no names.'));
    if (L.targetTerms.length) {
      body.push(h('div', { class: 'note muted' }, 'Terms on the object\'s type: ', L.targetTerms.map(t => `${t.term} (${t.types} type${t.types === 1 ? '' : 's'}, ${t.constraints} constraint${t.constraints === 1 ? '' : 's'})`).join('; '),
        '. Objects of these types are treated differently whatever the process.'));
    }
    return [card('who', 'Who ignores levels', `${passN} of ${L.domains} domains`, body, true)];
  }

  function runIsolation() {
    if (!iso.domains.trim()) { iso.result = { error: 'Give one or more domains, e.g. container_t.' }; render(); return; }
    iso.result = 'checking';
    vscode.postMessage({ cmd: 'isolation', key: ++iso.key, against, domains: iso.domains, weight: iso.weight, scope: iso.all ? 'all' : 'own' });
    render();
  }

  function isolationCard() {
    // Suggest the domains held to every level constraint (containers, virtual machines) once known.
    if (!iso.touched && !iso.domains && levels && levels.groups) {
      const held = levels.groups.filter(g => !g.constraints.length).flatMap(g => g.domains);
      const pick = ['container_t', 'svirt_t'].filter(d => held.includes(d));
      iso.domains = (pick.length ? pick : held.slice(0, 2)).join(' ');
    }
    const dom = h('input', { type: 'text', value: iso.domains, size: 30, placeholder: 'container_t', spellcheck: 'false', title: 'The domain(s) whose processes should be kept apart by their levels (e.g. one container from another)' });
    dom.addEventListener('input', () => { iso.domains = dom.value; iso.touched = true; });
    dom.addEventListener('keydown', (e) => { if (e.key === 'Enter') runIsolation(); });
    const wsel = h('select', { title: 'Which permissions count: 10 = reads and writes of data; lower also counts weaker channels (setools\' permission map)' },
      [[10, 'reads and writes of data'], [5, 'also weaker channels'], [1, 'every permission that carries information']].map(([v, t]) => h('option', { value: String(v), selected: iso.weight === v || null }, t)));
    wsel.addEventListener('change', () => { iso.weight = +wsel.value; });
    const all = h('input', { type: 'checkbox', checked: iso.all || null, title: 'Also accesses to objects the domain neither is nor creates, and all socket permissions' });
    all.addEventListener('change', () => { iso.all = all.checked; });
    return card('iso', 'Kept apart by levels?', 'what two processes of a domain can share that levels don\'t check', [
      h('div', { class: 'intro' }, 'Two containers run in the same domain (container_t) and use files of the same types; only their categories tell them apart. This lists the accesses of a domain to objects such processes can share (its own type, types it creates; files, IPC, keys, processes, connecting to another process\'s socket) that no level constraint checks for it.'),
      h('div', { class: 'row' }, 'Domains ', dom, ' Count ', wsel, ' ', h('label', {}, all, ' every target'), ' ', h('button', { class: 'primary', onclick: runIsolation }, 'Check')),
      isolationResult(),
    ], true);
  }

  function isolationResult() {
    const r = iso.result;
    if (!r) return null;
    if (r === 'checking') return h('div', { class: 'muted' }, 'Checking…');
    if (r.error) return h('div', { class: 'note bad' }, r.error);
    return r.results.map((d) => {
      const head = d.binds === 0 ? `${d.domain} ignores levels altogether: categories don't separate its processes`
        : d.count ? `${d.domain}: ${d.count} access${d.count === 1 ? '' : 'es'} levels don't check${d.open < d.count ? ` (${d.count - d.open} only through a descriptor it is given)` : ''}`
          : `${d.domain}: every such access is level-checked`;
      const rows = d.unchecked.map(v => h('tr', { class: v.fdOnly ? 'muted' : null },
        h('td', {}, h('code', {}, `${v.target}:${v.class}`)), h('td', {}, h('code', {}, `{ ${v.perms.join(' ')} }`)), h('td', { class: 'muted' }, v.dirs.join(', ')),
        h('td', {}, v.fdOnly ? h('span', { class: 'muted', title: 'Opening such an object is level-checked, so this needs a descriptor another process passes it' }, 'opening is checked ') : null,
          v.conditional.length ? h('span', { class: 'muted' }, `[${v.conditional.join(', ')}] `) : null,
          v.origin ? link(`${v.origin.path.split('/').pop()}:${v.origin.line + 1}`, { p: v.origin.path, l: v.origin.line }, v.origin.via ? `via ${v.origin.via}` : null)
            : h('code', { class: 'muted' }, `allow ${v.rules[0].s} ${v.rules[0].t}`))));
      const line = `require ${d.domain} isolated by levels${iso.weight !== 10 ? ` weight ${iso.weight}` : ''}`;
      return h('div', { class: 'cons' },
        h('div', { class: d.count || d.binds === 0 ? 'verdict bad' : 'verdict ok' }, head, ' ', link('↗', iso.locs && iso.locs[d.domain], `Open where ${d.domain} is declared`)),
        h('div', { class: 'note muted' }, `Bound by ${d.binds} of ${d.constraints} level constraints.`),
        rows.length ? h('table', {}, h('tbody', {}, rows)) : null,
        d.count > d.unchecked.length ? h('div', { class: 'muted' }, `… ${d.count - d.unchecked.length} more`) : null,
        h('div', { class: 'row' }, h('button', { title: 'Add a check to selinux.checks that fails while such accesses exist (or new ones appear)', onclick: () => vscode.postMessage({ cmd: 'addCheck', text: line }) }, 'Add check'), ' ', h('code', { class: 'muted' }, line)));
    });
  }

  function renderLevelsOnly() {
    const box = $('levelsBox');
    if (!box) return;
    box.textContent = '';
    box.append(...levelsCards());
    const f = $('lvfilter');
    if (f && f.focus) { f.focus(); if (f.setSelectionRange) f.setSelectionRange(filter.length, filter.length); }
  }

  function render() {
    const sel = $('against');
    sel.textContent = '';
    for (const p of policies) sel.append(h('option', { value: p.id, selected: p.id === against || null }, p.label));
    const main = $('main');
    main.textContent = '';
    main.append(checkForm(), isolationCard(), h('div', { id: 'levelsBox' }, levelsCards()));
  }

  function loadLevels() {
    levels = null;
    levelsKey = ++seq;
    vscode.postMessage({ cmd: 'levels', key: levelsKey, against });
  }

  $('against').addEventListener('change', () => { against = $('against').value; loadLevels(); if (lastCheck && lastCheck !== 'checking') runCheck(); render(); });

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (m.cmd === 'levels') {
      if (m.key !== levelsKey) return;
      levels = m.result;
      if (m.result.policies) policies = m.result.policies;
      if (m.result.policy) { against = m.result.policy.id; levels.policyLabel = m.result.policy.label; }
      $('status').textContent = '';
      render();
    } else if (m.cmd === 'isolation') {
      if (m.key !== iso.key) return;
      iso.result = m.result;
      iso.locs = m.result && m.result.locs;
      render();
    } else if (m.cmd === 'check') {
      if (m.key !== checkKey) return;
      lastCheck = m.result;
      render();
    } else if (m.cmd === 'label') {
      const r = m.result || {};
      const pol = (r.policies || []).find(p => p.id === against) || (r.policies || []).find(p => p.context);
      if (r.error || !pol || !pol.context) { lastCheck = { error: r.error || `No file-context line gives ${state.path} a label${pol ? ` in the ${pol.label}` : ''}.` }; render(); return; }
      state.target = pol.context;
      render();
    } else if (m.cmd === 'built') {
      if (policies.some(p => p.id === against && p.build)) loadLevels();
    } else if (m.cmd === 'prefill') {
      Object.assign(state, m.state || {});
      if (state.source && state.target) runCheck(); else render();
    } else if (m.cmd === 'checkAdded') {
      $('status').textContent = m.text;
    } else if (m.cmd === 'error') {
      $('status').textContent = m.text;
    }
  });

  render();
  vscode.postMessage({ cmd: 'ready' });
  loadLevels();
}());
