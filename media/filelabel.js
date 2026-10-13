// File Labels webview: for any path, the label each policy gives it (the
// file-context line that sets it and the ones that lose), what the file is
// labeled now on this host, and what the chosen policy lets happen to that
// type: who may access it, which domains it starts and from where, and the
// type transitions that create it. Plain JS, no deps.
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

  const MODES = [['', 'kind: as on this host'], ['file', 'regular file'], ['dir', 'directory'], ['lnk_file', 'symbolic link'], ['chr_file', 'character device'],
    ['blk_file', 'block device'], ['sock_file', 'socket'], ['fifo_file', 'named pipe']];
  const KIND = Object.fromEntries(MODES.slice(1));
  const FLAG_TEXT = { '--': 'regular files', '-d': 'directories', '-l': 'symbolic links', '-c': 'character devices', '-b': 'block devices', '-s': 'sockets', '-p': 'named pipes' };
  const READ = ['read', 'getattr', 'open', 'search', 'lock', 'ioctl', 'map', 'listen'];
  const WRITE = ['write', 'append', 'create', 'unlink', 'rename', 'link', 'add_name', 'remove_name', 'reparent', 'rmdir', 'setattr', 'swapon', 'mounton', 'quotaon'];
  const EXEC = ['execute', 'execute_no_trans', 'entrypoint', 'execmod'];
  const RANK = { relabel: 6, manage: 5, write: 4, enter: 3, execute: 2, read: 1, other: 0 };
  const SHOW_ROWS = 30;

  for (const [v, t] of MODES) $('mode').append(h('option', { value: v }, t));
  $('path').setAttribute('title', 'Any absolute path: a program, a file, a directory, a device. It doesn\'t have to exist on this host.');
  $('mode').setAttribute('title', 'File-context lines can apply to one kind of file only (-- regular files, -d directories, …). For a path that exists here the kind is taken from the file.');
  $('browse').setAttribute('title', 'Pick a file or directory on this host');
  $('against').setAttribute('title', 'Which policy\'s rules to show for the label: an installed policy of this host, or the workspace\'s last build');

  let cards = [];             // [{ key, path, mode, result | null }]
  let against = null;
  let policies = [];
  const infos = new Map();    // `${card key}|${against}|${type}` → result | 'loading'
  const origins = new Map();  // row key → result | 'loading'
  const opened = new Map();   // details key → open
  const showAll = new Set();  // info keys showing every access row
  const filters = new Map();  // info key → filter text
  let seq = 0;

  const post = (m) => vscode.postMessage(m);
  function lookup(p, mode) {
    p = (p || '').trim();
    if (!p) return;
    mode = mode != null ? mode : $('mode').value;
    $('path').value = p;
    cards = cards.filter(c => !(c.path === p && c.mode === mode));
    const card = { key: `c${++seq}`, path: p, mode, result: null };
    cards.unshift(card);
    cards = cards.slice(0, 12);
    opened.set(card.key, true);
    $('status').textContent = `Looking up ${p}…`;
    render();
    post({ cmd: 'label', key: card.key, path: p, mode });
  }
  $('go').addEventListener('click', () => lookup($('path').value));
  $('path').addEventListener('keydown', (e) => { if (e.key === 'Enter') lookup($('path').value); });
  $('browse').addEventListener('click', () => post({ cmd: 'browse', path: $('path').value.trim() }));
  $('against').addEventListener('change', () => { against = $('against').value; for (const c of cards) askInfo(c); render(); });

  const open = (loc, text, title) => (loc ? h('button', { class: 'link', title: title || 'Open', onclick: () => post({ cmd: 'open', loc }) }, text) : h('code', {}, text));
  const short = (p) => (p.id === 'build' ? 'build' : p.id.replace(/^installed:/, ''));
  const typeOf = (ctx) => (ctx && ctx !== '<<none>>' ? ctx.split(':')[2] : null);
  const fileName = (p) => p.split('/').pop();
  const condText = (c) => (c ? ` when ${c.replace(/:true$/, '').replace(/^(.*):false$/, 'not ($1)')}` : '');
  const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

  function levels(perms) {
    const out = [];
    if (perms.some(p => READ.includes(p))) out.push('read');
    if (perms.some(p => WRITE.includes(p))) out.push(perms.includes('create') && perms.includes('unlink') ? 'manage' : 'write');
    if (perms.some(p => EXEC.includes(p))) out.push(perms.includes('entrypoint') ? 'enter' : 'execute');
    if (perms.some(p => p === 'relabelfrom' || p === 'relabelto')) out.push('relabel');
    if (!out.length && perms.length) out.push('other');
    return out;
  }

  /** The policy whose rules are shown and the type it gives the card's path. */
  function chosen(c) {
    const r = c.result;
    if (!r || r.error) return null;
    const pol = r.policies.find(p => p.id === against) || r.policies.find(p => p.type) || r.policies[0];
    return pol && pol.type ? { pol, type: pol.type } : null;
  }
  function askInfo(c) {
    const ch = chosen(c);
    if (!ch) return;
    const k = `${c.key}|${ch.pol.id}|${ch.type}`;
    if (infos.has(k)) return;
    infos.set(k, 'loading');
    post({ cmd: 'info', key: k, against: ch.pol.id, type: ch.type });
  }

  const details = (key, summary, body, cls) => {
    const d = h('details', { class: cls || null, open: opened.get(key) || null }, h('summary', {}, summary), body);
    d.addEventListener('toggle', () => opened.set(key, d.open));
    return d;
  };

  function setBy(s) {
    if (!s) return null;
    const where = s.src ? open({ p: s.src.p, l: s.src.l, c: s.src.c }, `${s.src.p.split('/').slice(-2).join('/')}:${s.src.l + 1}`, 'Open the source line')
      : s.file ? open({ p: s.file.p, l: s.file.l }, `${fileName(s.file.p)}:${s.file.l + 1}`, `Open this line of ${s.file.p}`) : null;
    return h('span', {}, h('code', {}, s.spec), s.flag ? h('span', { class: 'muted' }, ` ${s.flag} (${FLAG_TEXT[s.flag] || s.flag} only)`) : null,
      where ? [' · ', where] : null,
      s.module ? h('span', { class: 'muted' }, ` · module ${s.src && s.src.m ? s.src.m : s.module}`) : s.src && s.src.m ? h('span', { class: 'muted' }, ` · module ${s.src.m}`) : null,
      s.local ? h('span', { class: 'muted' }, ' · a local customization (semanage fcontext)') : null,
      s.template ? h('span', { class: 'muted' }, ' · home directory template (taken as /home/<user>)') : null);
  }

  function hostBox(r) {
    const rows = [];
    if (!r.exists) rows.push(h('div', { class: 'note muted' }, `Not on this host: looked up as a ${KIND[r.mode] || r.mode}. Choose another kind above if it will be something else.`));
    else {
      rows.push(h('div', {}, `A ${KIND[r.mode] || r.mode}${r.executable ? ' (executable)' : ''}`, r.pkg ? [' from package ', h('code', {}, r.pkg)] : r.pkg === null ? h('span', { class: 'muted' }, ' (no package owns it)') : null));
      rows.push(h('div', {}, 'Labeled now: ', r.current ? h('code', {}, r.current) : h('span', { class: 'muted' }, 'no label (the file system doesn\'t store one)')));
      if (r.linkTarget) rows.push(h('div', {}, 'A link to ', h('code', {}, r.linkTarget), '. A link has its own label; what runs or is read is the target. ', h('button', { class: 'link', onclick: () => lookup(r.linkTarget, '') }, 'Look up the target')));
    }
    if (r.lookedUp !== r.path) rows.push(h('div', { class: 'muted' }, 'Looked up as ', h('code', {}, r.lookedUp), ': restorecon resolves the directories in the path (not the last part).'));
    return rows;
  }

  function labelsBox(c) {
    const r = c.result;
    const trs = r.policies.map(p => {
      if (p.error) return h('tr', {}, h('td', {}, p.label), h('td', { colspan: 2, class: 'muted' }, p.error));
      const notes = [];
      if (p.key) notes.push(h('div', { class: 'muted' }, 'Looked up as ', h('code', {}, p.key), ' (file_contexts.subs: equivalent directories)'));
      if (!p.winner) notes.push(h('div', { class: 'muted' }, 'No line matches: it has no default label, and restorecon leaves it as it is.'));
      else if (p.context === '<<none>>') notes.push(h('div', { class: 'muted' }, '<<none>>: restorecon and setfiles leave it as it is.'));
      if (p.active && r.current && p.type && typeOf(r.current) !== p.type) {
        notes.push(h('div', { class: 'note warn' }, `Labeled ${typeOf(r.current)} now: restorecon would relabel it to ${p.type}.`));
      }
      if (p.homeAssumed) notes.push(h('div', { class: 'muted' }, 'From a home directory template: the build doesn\'t know the system\'s users, so /home/<user> is assumed.'));
      const others = p.others.length ? details(`${c.key}:o:${p.id}`, h('span', { class: 'muted' }, `${plural(p.others.length, 'other line')} also match${p.others.length === 1 ? 'es, but loses' : ', but lose'}`),
        h('div', {}, h('p', { class: 'intro' }, 'The last matching line wins. Lines are ordered from general to specific: patterns before exact paths, then by the length of the fixed start, the whole length, and whether a file kind is given. Most specific first:'),
          h('table', {}, p.others.map(o => h('tr', {}, h('td', {}, h('code', {}, o.type || o.context)), h('td', {}, setBy(o))))))) : null;
      return h('tr', {},
        h('td', {}, p.label),
        h('td', {}, p.context ? h('code', {}, p.context) : h('span', { class: 'muted' }, 'none')),
        h('td', {}, setBy(p.winner), notes, others));
    });
    return h('table', {}, h('tr', {}, h('th', {}, 'Policy'), h('th', {}, 'Label'), h('th', {}, 'Set by')), trs);
  }

  function programBox(c, info, ch) {
    const r = c.result;
    const isProgram = r.mode === 'file' && (r.executable || /_exec_t$|^bin_t$|^shell_exec_t$/.test(info.type));
    if (info.entrypointOf.length) {
      return [h('div', { class: 'sub' }, 'Running it starts'),
        h('table', {}, info.entrypointOf.map(d => h('tr', {},
          h('td', {}, open(info.locs[d.domain], d.domain, 'Open its declaration'), d.permissive ? [' ', h('span', { class: 'badge' }, 'permissive')] : null),
          h('td', {}, d.from.length ? ['from ', d.from.slice(0, 12).map((f, i) => [i ? ', ' : '', h('code', {}, f.source), h('span', { class: 'muted' }, f.auto ? ' (automatically)' : f.setexec ? ' (when it asks)' : ''), f.conditional.length ? h('span', { class: 'muted' }, condText(f.conditional[0])) : null]),
            d.fromCount > 12 ? h('span', { class: 'muted' }, ` and ${d.fromCount - 12} more`) : null]
            : h('span', { class: 'muted' }, 'no domain may transition into it through this file')),
          h('td', {}, ch.pol.build ? h('button', { class: 'link', title: 'Open the domain transition graph of the last build', onclick: () => post({ cmd: 'graph', domain: d.domain }) }, 'graph') : null)))),
        info.entryViaAttr ? h('div', { class: 'muted' }, `${plural(info.entryViaAttr, 'more domain')} may be entered through rules on its attributes (e.g. container or sandbox domains that run anything).`) : null];
    }
    if (!isProgram) return null;
    return [h('div', { class: 'sub' }, 'Running it'),
      h('div', {}, 'It starts no domain of its own: a program with this label runs in the domain of whoever runs it',
        info.entryViaAttr ? ` (except ${plural(info.entryViaAttr, 'domain')} entered through rules on its attributes)` : '', '.'),
      r.exists && r.executable ? h('div', { class: 'ask' }, h('button', { title: 'Write a policy module that gives this program a domain of its own', onclick: () => post({ cmd: 'newService', exec: r.path }) }, 'Confine it: New Service…')) : null];
  }

  function createdBox(c, info) {
    const out = [];
    const tt = (x) => [h('code', {}, x.s), ` creates a ${x.c}`, x.name ? [' named ', h('code', {}, x.name)] : null, ' in ', h('code', {}, x.t), h('span', { class: 'muted' }, condText(x.cond))];
    if (info.created.length) {
      out.push(h('div', { class: 'sub' }, `Objects get ${info.type} when created (${info.createdCount})`),
        h('div', {}, info.created.slice(0, 15).map(x => h('div', {}, tt(x)))), info.createdCount > 15 ? h('div', { class: 'muted' }, `and ${info.createdCount - 15} more`) : null);
    }
    if (info.inside.length && (c.result.mode === 'dir' || !info.created.length)) {
      out.push(h('div', { class: 'sub' }, `New objects in a ${info.type} directory get another label (${info.insideCount})`),
        h('div', {}, info.inside.slice(0, 15).map(x => h('div', {}, tt(x), ' → ', h('code', {}, x.perms[0])))), info.insideCount > 15 ? h('div', { class: 'muted' }, `and ${info.insideCount - 15} more`) : null);
    }
    return out;
  }

  function accessBox(c, info, ch, ik) {
    const rows = info.access.map(a => {
      const perms = [...new Set(Object.values(a.classes).flat())];
      const lv = levels(perms);
      return { a, lv, rank: Math.max(...lv.map(l => RANK[l] || 0)), direct: a.t === info.type };
    }).sort((x, y) => y.rank - x.rank || (y.direct - x.direct) || x.a.s.localeCompare(y.a.s));
    const f = (filters.get(ik) || '').trim().toLowerCase();
    const shown = rows.filter(x => !f || x.a.s.toLowerCase().includes(f) || x.lv.some(l => l.startsWith(f)) || Object.keys(x.a.classes).some(k => k.includes(f)));
    const list = showAll.has(ik) ? shown : shown.slice(0, SHOW_ROWS);
    const filter = rows.length > 12 ? h('input', { class: 'filter', size: 28, value: filters.get(ik) || '', placeholder: 'filter: domain, read, write, dir…', title: 'Show only rows whose domain, kind of access or class contains this' }) : null;
    if (filter) filter.addEventListener('change', () => { filters.set(ik, filter.value); render(); });
    const trs = list.map(({ a, lv }) => {
      const rk = `${ik}|${a.s}|${a.t}|${a.cond}`;
      const o = origins.get(rk);
      const from = !info.traceable ? null : o === 'loading' ? h('span', { class: 'muted' }, 'finding…')
        : o ? h('div', { class: 'origins' }, o.origins.length ? o.origins.map(x => h('div', {}, open({ p: x.path, l: x.line }, `${x.path.split('/').slice(-2).join('/')}:${x.line + 1}`, x.text), x.via ? h('span', { class: 'muted' }, ` via ${x.via}`) : h('span', { class: 'muted' }, ` ${x.text || ''}`))) : h('span', { class: 'muted' }, 'no source statement found'),
          o.more ? h('div', { class: 'muted' }, `and ${o.more} more`) : null)
          : h('button', { class: 'link', title: 'Find the source statements that write this rule', onclick: () => { origins.set(rk, 'loading'); render(); post({ cmd: 'origins', key: rk, s: a.s, t: a.t, classes: Object.keys(a.classes), perms: a.classes }); } }, 'where from');
      return h('tr', {},
        h('td', {}, h('code', {}, a.s), a.attr ? h('div', { class: 'muted' }, `attribute: ${plural(a.size, 'type')}${a.domains !== a.size ? `, ${plural(a.domains, 'domain')}` : ''}`) : null),
        h('td', {}, lv.map(l => h('span', { class: `lvl ${l}` }, l))),
        h('td', {}, Object.entries(a.classes).map(([cl, ps]) => h('div', {}, h('code', {}, cl), h('span', { class: 'muted' }, ` ${ps.join(' ')}`))),
          a.t !== info.type ? h('div', { class: 'muted' }, ['via its attribute ', h('code', {}, a.t)]) : null,
          a.cond ? h('div', { class: 'muted' }, condText(a.cond).trim()) : null),
        h('td', {}, from));
    });
    const counts = { read: 0, write: 0, execute: 0 };
    for (const x of rows) {
      const n = x.a.attr ? x.a.domains : 1;
      if (x.lv.includes('read')) counts.read += n;
      if (x.lv.some(l => l === 'write' || l === 'manage')) counts.write += n;
      if (x.lv.some(l => l === 'execute' || l === 'enter')) counts.execute += n;
    }
    return [h('div', { class: 'sub' }, `Who may access it (${plural(info.accessCount, 'rule group')})`),
      h('p', { class: 'intro' }, `Allow rules as written, for ${info.type} or one of its attributes; an attribute stands for every type in it. About ${counts.read} domains may read it, ${counts.write} write it, ${counts.execute} execute it (an attribute counts its domains).`),
      filter,
      rows.length ? h('table', {}, h('tr', {}, h('th', {}, 'Who'), h('th', {}, 'Access'), h('th', {}, 'Permissions'), h('th', {}, info.traceable ? 'Source' : '')), trs) : h('div', { class: 'muted' }, 'No allow rule names it.'),
      shown.length > list.length ? h('button', { onclick: () => { showAll.add(ik); render(); } }, `Show all ${shown.length}`) : null,
      info.accessCount > info.access.length ? h('div', { class: 'muted' }, `The first ${info.access.length} are listed.`) : null,
      !info.traceable ? h('div', { class: 'muted' }, 'Source statements can be traced for the workspace\'s build only.') : null];
  }

  function infoBox(c) {
    const ch = chosen(c);
    if (!ch) return null;
    const ik = `${c.key}|${ch.pol.id}|${ch.type}`;
    const info = infos.get(ik);
    const head = h('div', { class: 'sub' }, `What the ${ch.pol.label.replace(/^\w/, x => x.toLowerCase())} lets happen to ${ch.type}`);
    if (!info || info === 'loading') return [head, h('div', { class: 'muted' }, 'Reading the policy…')];
    if (info.error) return [head, h('div', { class: 'note bad' }, info.error)];
    const decl = info.locs[info.type];
    return [head,
      h('div', {}, 'Type ', open(decl, info.type, 'Open its declaration'), decl && decl.m ? h('span', { class: 'muted' }, ` (module ${decl.m})`) : null,
        info.alias ? h('span', { class: 'muted' }, ` (${info.alias} is an alias)`) : null, info.permissive ? [' ', h('span', { class: 'badge' }, 'permissive domain')] : null),
      info.attrs.length ? h('div', { class: 'chips' }, h('span', { class: 'muted' }, 'Attributes: '), info.attrs.map(a => h('code', {}, a))) : null,
      programBox(c, info, ch), createdBox(c, info), accessBox(c, info, ch, ik)];
  }

  function card(c) {
    const r = c.result;
    const sum = [h('span', { class: 'fname' }, c.path)];
    let warn = false;
    if (!r) sum.push(h('span', { class: 'muted' }, 'looking up…'));
    else if (r.error) sum.push(h('span', { class: 'note bad' }, r.error));
    else {
      sum.push(h('span', { class: 'muted' }, KIND[r.mode] || r.mode));
      const types = new Set(r.policies.filter(p => !p.error).map(p => p.type || 'none'));
      for (const p of r.policies) if (!p.error) sum.push(h('span', { class: 'badge', title: p.label }, `${short(p)}: ${p.type || (p.context === '<<none>>' ? '<<none>>' : 'no label')}`));
      const act = r.policies.find(p => p.active);
      if (r.current) sum.push(h('span', { class: 'muted' }, `now ${typeOf(r.current)}`));
      warn = types.size > 1 || !!(act && r.current && act.type && typeOf(r.current) !== act.type);
    }
    const body = !r ? null : r.error ? null : [h('div', { class: 'sub' }, 'On this host'), hostBox(r), h('div', { class: 'sub' }, 'Label'), labelsBox(c), infoBox(c)];
    const d = h('details', { class: `card${warn ? ' warn' : ''}`, open: opened.get(c.key) !== false || null }, h('summary', {}, sum),
      h('div', { class: 'body' }, body, h('div', { class: 'ask' }, h('button', { class: 'link', onclick: () => { cards = cards.filter(x => x !== c); render(); } }, 'remove'))));
    d.addEventListener('toggle', () => opened.set(c.key, d.open));
    return d;
  }

  function render() {
    const main = $('main');
    main.textContent = '';
    if (!cards.length) {
      main.append(h('p', { class: 'intro' }, 'Type any path above, such as ', h('code', {}, '/usr/bin/rpm'), ', or pick one with Browse…. For every policy (this host\'s installed ones and the workspace\'s last build) you see the label the file gets and the file-context line that sets it, what it is labeled now, and what the policy lets happen to it: who may read, write or run it, and which domain running it starts.'));
      return;
    }
    for (const c of cards) main.append(card(c));
  }

  function fillPolicies(list) {
    const ids = list.map(p => p.id).join();
    if (ids === policies.map(p => p.id).join()) return;
    policies = list;
    const sel = $('against');
    sel.textContent = '';
    for (const p of list) sel.append(h('option', { value: p.id }, p.label));
    if (!list.some(p => p.id === against)) against = (list.find(p => p.build) || list.find(p => p.active) || list[0] || {}).id || null;
    sel.value = against;
  }

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (m.cmd === 'lookup') {
      lookup(m.path, m.mode != null ? m.mode : '');
    } else if (m.cmd === 'label') {
      const c = cards.find(x => x.key === m.key);
      if (!c) return;
      c.result = m.result;
      $('status').textContent = '';
      if (m.result && m.result.policies) { fillPolicies(m.result.policies.map(p => ({ id: p.id, label: p.label, build: p.build, active: p.active }))); askInfo(c); }
      render();
    } else if (m.cmd === 'info') {
      infos.set(m.key, m.result);
      render();
    } else if (m.cmd === 'origins') {
      origins.set(m.key, m.result);
      render();
    } else if (m.cmd === 'built') {
      if (!m.ok) return;
      // The build's labels and rules may have changed: look the paths up again.
      for (const k of [...infos.keys()]) if (/\|build\|/.test(k)) infos.delete(k);
      for (const k of [...origins.keys()]) if (/\|build\|/.test(k)) origins.delete(k);
      for (const c of cards) { c.result = null; post({ cmd: 'label', key: c.key, path: c.path, mode: c.mode }); }
      render();
    } else if (m.cmd === 'error') {
      $('status').textContent = m.text;
    }
  });
  render();
  post({ cmd: 'ready' });
})();
