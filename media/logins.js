// Logins and Users webview: Linux logins → SELinux users, where each way of
// logging in lands, what each user's sessions can reach (risky abilities with
// the path there, every reachable domain on demand, "can it …?" questions),
// and on this host the people's and service accounts. Plain JS, no deps.
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

  // Objects the "Can it …?" box asks about: class → [label, default permissions].
  const ASK = [
    ['file', 'a file', 'read'], ['dir', 'a directory', 'search'], ['lnk_file', 'a symlink', 'read'], ['chr_file', 'a character device', 'read write'],
    ['blk_file', 'a block device', 'write'], ['sock_file', 'a socket file', 'write'], ['security', 'SELinux itself (security_t)', 'load_policy'],
    ['process', 'a process (domain)', 'ptrace'], ['tcp_socket', 'a TCP socket', 'name_connect'],
  ];
  const HOW = { own: 'its own line', group: 'its group', default: '__default__' };
  const RANK = { high: 3, medium: 2, low: 1 };

  $('refresh').setAttribute('title', 'Read the policy and the login configuration again');
  $('against').setAttribute('title', 'Which policy (and its login configuration) to report on: this host\'s installed policy, or the last build of the workspace');

  let report = null;
  let against = null;
  const reach = new Map();    // user → result | 'loading'
  const answers = new Map();  // user → result | 'asking'
  const asks = new Map();     // user → { tclass, perms, target }
  const opened = new Map();   // card key → open

  function load() {
    $('status').textContent = 'Reading the policy and working out what each user can reach…';
    reach.clear();
    answers.clear();
    vscode.postMessage({ cmd: 'load', against });
  }
  $('refresh').addEventListener('click', load);
  if ($('newUser')) {
    $('newUser').setAttribute('title', 'Create an SELinux user in the tree: its role, logins and where they land');
    $('newUser').addEventListener('click', () => vscode.postMessage({ cmd: 'newUser' }));
  }
  $('against').addEventListener('change', () => { against = $('against').value; load(); });

  const open = (loc, text, title) => (loc ? h('button', { class: 'link', title: title || 'Open', onclick: () => vscode.postMessage({ cmd: 'open', loc }) }, text) : h('code', {}, text));
  const ruleText = (r) => `${r.rt} ${r.s} ${r.t}:${r.c} { ${r.perms.join(' ')} };${r.cond ? `   [when ${r.cond.replace(/:true$/, '').replace(/^(.*):false$/, 'not ($1)')}]` : ''}`;
  const ctx = (c) => `${c.role}:${c.type}`;
  const startsOf = (u) => {
    const out = [];
    for (const e of u.entries) for (const c of e.contexts) if (!out.some(x => x.role === c.role && x.type === c.type)) out.push(c);
    return out;
  };
  const pathBox = (steps) => (steps && steps.length ? h('div', { class: 'path' }, steps.map(s => h('div', {}, s.text))) : null);
  const card = (key, cls, summary, body) => {
    const d = h('details', { class: `card ${cls}`, open: opened.get(key) || null }, h('summary', {}, summary), h('div', { class: 'body' }, body));
    d.addEventListener('toggle', () => opened.set(key, d.open));
    return d;
  };

  function mappingsSection(r) {
    const rows = r.mappings.map(m => h('tr', {},
      h('td', {}, open({ p: m.file, l: m.l }, m.group ? `%${m.login}` : m.login, `Open this line of ${m.file}`),
        m.login === '__default__' ? h('span', { class: 'muted' }, ' (every other login)') : m.group ? h('span', { class: 'muted' }, ' (members of the group)') : null),
      h('td', {}, h('code', {}, m.user)),
      h('td', {}, m.range ? h('code', {}, m.range) : h('span', { class: 'muted' }, 'the user\'s default')),
      h('td', {}, m.notes.map(n => h('div', { class: `note ${n.severity}` }, n.text)))));
    return [h('h2', {}, 'Linux logins'),
      h('p', { class: 'intro' }, 'Which SELinux user a Linux login gets (seusers). ', h('code', {}, '__default__'), ' covers every login without a line of its own; ', h('code', {}, '%group'), ' lines cover a group\'s members.'),
      r.mappings.length ? h('table', {}, h('tr', {}, h('th', {}, 'Login'), h('th', {}, 'SELinux user'), h('th', {}, 'Range'), h('th', {}, '')), rows)
        : h('p', { class: 'muted' }, 'No seusers file: logins get the policy\'s defaults.')];
  }

  function peopleSection(r) {
    if (!r.accounts) return null;
    const rows = r.accounts.people.map(p => h('tr', {},
      h('td', {}, h('code', {}, p.name), h('span', { class: 'muted' }, ` (uid ${p.uid})`)),
      h('td', {}, h('code', {}, p.shell || '')),
      h('td', {}, p.mapping ? [h('code', {}, p.mapping.user), h('span', { class: 'muted' }, ` via ${p.mapping.how === 'group' ? `%${p.mapping.login}` : HOW[p.mapping.how]}`)] : h('span', { class: 'note high' }, 'no seusers line applies'))));
    return [h('h2', {}, 'People\'s accounts on this host'),
      h('p', { class: 'intro' }, `Accounts with a UID of ${r.accounts.uidMin} or more, and root, with the seusers line that applies when they log in.`),
      h('table', {}, h('tr', {}, h('th', {}, 'Account'), h('th', {}, 'Shell'), h('th', {}, 'SELinux user')), rows)];
  }

  function servicesSection(r) {
    if (!r.accounts) return null;
    const users = new Map(r.users.map(u => [u.name, u]));
    const rows = r.accounts.services.map(s => {
      const u = s.mapping && users.get(s.mapping.user);
      const risky = s.canLogin && u && u.abilities.some(a => a.severity === 'high');
      return h('tr', {},
        h('td', {}, h('code', {}, s.name), h('span', { class: 'muted' }, ` (uid ${s.uid})`)),
        h('td', {}, h('code', {}, s.shell || ''), s.special ? h('span', { class: 'muted' }, ' (runs one command)') : null),
        h('td', {}, s.canLogin ? h('span', { class: risky ? 'note medium' : '' }, 'yes') : h('span', { class: 'muted' }, 'no')),
        h('td', {}, s.mapping ? [h('code', {}, s.mapping.user), h('span', { class: 'muted' }, ` via ${HOW[s.mapping.how] || s.mapping.how}`)] : '—'),
        h('td', {}, risky ? h('span', { class: 'note medium' }, `Has a login shell and would get ${s.mapping.user}, which ${u.abilities.find(a => a.severity === 'high').label}.`) : null));
    });
    return [h('h2', {}, 'Service accounts on this host'),
      h('p', { class: 'intro' }, 'Accounts services run as (system UIDs). A service\'s processes run as ', h('code', {}, 'system_u'), ' in the service\'s own domain, whichever account it uses: seusers doesn\'t apply to them. It applies only when the account logs in (ssh, ', h('code', {}, 'su -'), ', its own crontab), so an account with a login shell gets the SELinux user shown here.'),
      h('table', {}, h('tr', {}, h('th', {}, 'Account'), h('th', {}, 'Shell'), h('th', {}, 'Can log in'), h('th', {}, 'If it logs in'), h('th', {}, '')), rows)];
  }

  function entriesBox(u) {
    const ways = u.entries.filter(e => e.contexts.length);
    if (!ways.length) return h('div', { class: 'muted' }, 'No way to log in: no line of default_contexts (or its own contexts file) offers a context its roles may use.');
    return h('table', {}, h('tr', {}, h('th', {}, 'Way in'), h('th', {}, 'Lands in'), h('th', {}, 'May also choose')),
      ways.map(e => h('tr', {},
        h('td', {}, open(e.file && { p: e.file, l: e.l }, e.label, `Open the line for ${e.source} in ${e.file}`)),
        h('td', {}, h('code', {}, ctx(e.contexts[0]))),
        h('td', {}, e.contexts.slice(1).map((c, i) => [i ? ', ' : '', h('code', {}, ctx(c))])))));
  }

  function abilitiesBox(u) {
    if (!u.entries.some(e => e.contexts.length)) return null;
    if (!u.abilities.length) return h('div', { class: 'muted' }, 'None of the risky abilities checked (unconfined, loading policy, permissive mode, reading /etc/shadow, writing raw disks, booleans) is within reach.');
    return u.abilities.map(a => h('div', { class: 'ability' },
      h('span', { class: `sev ${a.severity}` }, a.severity), ' ', h('b', {}, a.label), ' — as ', h('code', {}, a.domain),
      a.count > 1 ? h('span', { class: 'muted' }, ` (and ${a.count - 1} more domain${a.count > 2 ? 's' : ''})`) : null,
      a.path.length ? [pathBox(a.path), h('div', { class: 'muted', style: 'margin-left:16px' }, 'Reached by running a program; what a user can make it do also depends on the program.')]
        : h('span', { class: 'muted' }, ' (the session itself)'),
      a.rule ? h('pre', { class: 'rule' }, ruleText(a.rule)) : null));
  }

  function reachBox(u) {
    const r = reach.get(u.name);
    if (!u.reached) return null;
    if (!r) return h('button', { onclick: () => { reach.set(u.name, 'loading'); render(); vscode.postMessage({ cmd: 'reach', against, user: u.name, starts: startsOf(u) }); } }, `Show the ${u.reached} domains`);
    if (r === 'loading') return h('div', { class: 'muted' }, 'Loading…');
    if (r.error) return h('div', { class: 'note high' }, r.error);
    return h('div', { class: 'domains' }, r.domains.map(d => d.depth
      ? h('details', {}, h('summary', {}, d.name, h('span', { class: 'muted' }, ` ${d.role}`)), pathBox(d.path))
      : h('div', {}, d.name, h('span', { class: 'muted' }, ` ${d.role} (logs in here)`))));
  }

  function askBox(u) {
    if (!u.entries.some(e => e.contexts.length)) return null;
    const st = asks.get(u.name) || { tclass: 'file', perms: 'read', target: '' };
    asks.set(u.name, st);
    const cls = h('select', { title: 'What kind of object' }, ASK.map(([c, label]) => h('option', { value: c, selected: c === st.tclass || null }, label)));
    const perms = h('input', { size: 16, value: st.perms, title: 'Permissions, separated by spaces (any of them counts), e.g. read, write, execute' });
    const target = h('input', { size: 30, value: st.target, placeholder: '/etc/shadow or shadow_t', title: 'An absolute path (its label comes from the policy\'s file contexts) or a type' });
    cls.addEventListener('change', () => { st.tclass = cls.value; st.perms = (ASK.find(x => x[0] === cls.value) || [])[2] || ''; perms.value = st.perms; if (cls.value === 'security' && !target.value) target.value = st.target = 'security_t'; });
    perms.addEventListener('input', () => { st.perms = perms.value; });
    target.addEventListener('input', () => { st.target = target.value; });
    const go = () => {
      const t = target.value.trim();
      if (!t) return;
      answers.set(u.name, 'asking');
      render();
      vscode.postMessage({ cmd: 'can', against, user: u.name, starts: startsOf(u), tclass: st.tclass, perms: st.perms.split(/\s+/).filter(Boolean),
        ...(t.startsWith('/') ? { path: t } : { target: t }) });
    };
    target.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    const a = answers.get(u.name);
    let ans = null;
    if (a === 'asking') ans = h('div', { class: 'answer muted' }, 'Checking…');
    else if (a && a.error) ans = h('div', { class: 'answer' }, a.error);
    else if (a && a.can) ans = h('div', { class: 'answer yes' }, h('b', {}, 'Yes'), `: as ${a.domain}${a.resolved ? ` (${a.resolved.path} is ${a.target})` : ''}${a.count > 1 ? `, and ${a.count - 1} more domain${a.count > 2 ? 's' : ''}` : ''}.`,
      a.path.length ? pathBox(a.path) : h('div', { class: 'muted' }, 'Its sessions have it directly.'), h('pre', { class: 'rule' }, ruleText(a.rule)));
    else if (a) ans = h('div', { class: 'answer no' }, h('b', {}, 'No'), `: none of the ${a.reached} domains its sessions can reach may do that to ${a.target}${a.resolved ? ` (${a.resolved.path})` : ''}.`);
    return [h('div', { class: 'ask' }, 'Can it', cls, perms, target, h('button', { class: 'primary', onclick: go }, 'Ask')), ans];
  }

  function userCard(u) {
    const sev = u.abilities.reduce((m, a) => Math.max(m, RANK[a.severity] || 0), 0);
    const canIn = u.entries.some(e => e.contexts.length);
    const cls = !canIn ? 'idle' : sev === 3 ? 'high' : sev === 2 ? 'medium' : 'none';
    const summary = [h('span', { class: 'uname' }, u.name), h('span', {}, u.roles.join(' ')),
      u.logins.length ? h('span', { class: 'badge' }, `${u.logins.length} login${u.logins.length > 1 ? 's' : ''}: ${u.logins.map(l => (l.group ? `%${l.login}` : l.login)).join(', ')}`) : null,
      canIn ? h('span', { class: 'muted' }, `reaches ${u.reached} domain${u.reached === 1 ? '' : 's'}`) : h('span', { class: 'muted' }, 'cannot log in'),
      u.abilities.filter(a => a.severity !== 'low').map(a => h('span', { class: `sev ${a.severity}` }, a.label))];
    const body = [
      u.error ? h('div', { class: 'note high' }, u.error) : null,
      h('div', { class: 'sub' }, 'Linux logins'),
      u.logins.length ? h('div', {}, u.logins.map((l, i) => [i ? ', ' : '', open({ p: l.file, l: l.l }, l.group ? `%${l.login}` : l.login, 'Open its seusers line')]))
        : h('div', { class: 'muted' }, u.name === 'system_u' ? 'None: system_u is for processes the system starts (services), not logins.' : 'None: no seusers line maps a login to it.'),
      h('div', { class: 'sub' }, 'Ways in'), entriesBox(u),
      canIn ? [h('div', { class: 'sub' }, 'Risky abilities within reach'), abilitiesBox(u)] : null,
      canIn ? [h('div', { class: 'sub' }, `Everything its sessions can reach (${u.reached} domains${u.roleSet ? `, roles ${u.roleSet.join(' ')}` : ''})`), reachBox(u)] : null,
      canIn ? [h('div', { class: 'sub' }, 'Ask'), askBox(u)] : null,
      h('div', { class: 'sub' }, 'Defined in'),
      h('div', {}, u.loc ? open(u.loc, 'its gen_user line', 'Open the gen_user line that defines it') : h('span', { class: 'muted' }, 'the compiled policy'),
        u.contextsFile ? [' · ', open({ p: u.contextsFile, l: 0 }, 'its contexts file', u.contextsFile)] : null),
    ];
    return card(`u:${u.name}`, cls, summary, body);
  }

  function render() {
    const main = $('main');
    main.textContent = '';
    if (!report) return;
    if (report.error) { main.append(h('p', { class: 'note high' }, report.error)); return; }
    const r = report;
    if (r.notes && r.notes.length) main.append(h('ul', { class: 'notes' }, r.notes.map(n => h('li', {}, n))));
    main.append(...[mappingsSection(r), peopleSection(r)].flat().filter(Boolean));
    main.append(h('h2', {}, 'SELinux users'),
      h('p', { class: 'intro' }, 'What each user\'s sessions can reach: the domains its ways in land in, and every domain reachable from there by running programs (domain transitions), changing role where the user has the role and the policy allows it (newrole, sudo -r). Booleans are taken as possibly on.'));
    const users = [...r.users].sort((a, b) => (b.logins.length > 0) - (a.logins.length > 0) || a.name.localeCompare(b.name));
    for (const u of users) main.append(userCard(u));
    main.append(...[servicesSection(r)].flat().filter(Boolean));
  }

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (m.cmd === 'report') {
      report = m.report;
      const sel = $('against');
      sel.textContent = '';
      for (const p of report.policies || []) sel.append(h('option', { value: p.id }, p.label));
      if (report.policy) { sel.value = report.policy.id; against = report.policy.id; }
      $('status').textContent = report.error ? '' : `${report.users.length} SELinux users, ${report.mappings.length} seusers line${report.mappings.length === 1 ? '' : 's'} · ${report.policy.configDir}`;
      render();
    } else if (m.cmd === 'reach') {
      reach.set(m.user, m.result);
      render();
    } else if (m.cmd === 'can') {
      answers.set(m.user, m.result);
      render();
    } else if (m.cmd === 'built') {
      if (m.ok && against === 'build') load();
    } else if (m.cmd === 'error') {
      $('status').textContent = m.text;
    }
  });
  load();
})();
