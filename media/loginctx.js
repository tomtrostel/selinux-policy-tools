// Login Contexts webview: whether each login of a policy gets a valid context
// for each way in ("Unable to get valid context for <user>" before a host sees
// it), as libselinux 3.x (RHEL 9, 10) and 2.x (RHEL 8) decide. Plain JS, no deps.
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

  const SEV = { error: ['✗', 'bad', 'Error'], warning: ['⚠', 'warn', 'Warning'], info: ['ℹ', 'muted', 'Info'] };
  let result = null, against = null, key = 0, loading = false;
  const open = new Map();
  // Fixes per problem (by its text): { state: 'loading' | 'done', result, plans: Map call → { state, plan } }.
  const fixes = new Map();
  let fixKey = 0;
  const fixWait = new Map(); // key → { id, k }

  const base = (p) => String(p || '').split('/').pop();
  const loc = (file, l, text) => (file ? h('button', { class: 'link', title: `Open ${file}:${l + 1}`, onclick: () => vscode.postMessage({ cmd: 'open', loc: { p: file, l, c: 0 } }) }, text || `${base(file)}:${l + 1}`) : null);
  const card = (id, title, hint, body, defOpen) => {
    const d = h('details', { class: 'card', open: (open.has(id) ? open.get(id) : defOpen) || null }, h('summary', {}, h('span', { class: 'fname' }, title), hint ? h('span', { class: 'muted' }, hint) : null), h('div', { class: 'body' }, body));
    d.addEventListener('toggle', () => open.set(id, d.open));
    return d;
  };

  function load() {
    loading = true;
    vscode.postMessage({ cmd: 'load', key: ++key, against });
    render();
  }

  function problemRow(p, i) {
    const [icon, cls, word] = SEV[p.severity] || SEV.info;
    const rel = (p.related || []).length
      ? h('details', { class: 'rel' }, h('summary', { class: 'muted small' }, `${p.related.length} line${p.related.length > 1 ? 's' : ''} involved`),
        h('ul', {}, p.related.map(x => h('li', {}, loc(x.file, x.l), ' ', h('code', {}, x.text)))))
      : null;
    const tr = p.trace;
    const causes = (p.causes || []).filter(c => c.origin);
    return h('div', { class: `problem ${cls}`, 'data-i': i },
      h('div', {}, h('span', { class: `sev ${cls}`, title: word }, icon), ' ',
        p.isNew ? h('span', { class: 'badge new', title: (p.since || []).length ? `Files changed since the previous build: ${p.since.join(', ')}` : 'Not there in the previous build' }, 'new with this build') : null, p.isNew ? ' ' : null,
        tr && tr.record !== 'avc' ? h('span', { class: 'badge quiet', title: tr.text }, TRACE_BADGE[tr.record]) : null, tr && tr.record !== 'avc' ? ' ' : null,
        h('span', { class: 'ptext' }, p.text.replace(/^New (with this build|since the last check)[^:]*: /, ''))),
      h('div', { class: 'where small' }, loc(p.file, p.l), p.source ? h('span', { class: 'muted' }, ` · from ${p.source}`) : null),
      causes.length ? h('div', { class: 'small cause' }, causes.map(c => h('div', {}, 'Caused by ', loc(c.origin.path, c.origin.line), ' ', h('code', {}, c.origin.via || c.origin.text || ''), ` ${c.what}.`))) : null,
      tr && tr.record !== 'avc' ? h('div', { class: 'small muted' }, tr.text, (tr.hidden || []).filter(x => x.origin).map(x => h('span', {}, ' Hidden by ', loc(x.origin.path, x.origin.line), x.origin.via ? ` (${x.origin.via})` : '', '.'))) : null,
      rel, p.need || p.roleFix ? fixBox(p) : null);
  }
  /** What a host logs instead of an AVC denial. */
  const TRACE_BADGE = { none: 'no AVC: dontaudit', selinux_err: 'SELINUX_ERR, not AVC', log: 'no audit record' };

  /** How to fix a session-start problem: interfaces of this policy that grant the missing rule, narrowest first. */
  function fixBox(p) {
    const id = p.text;
    const f = fixes.get(id);
    // A missing rule (need), or a role to authorize for a domain (roleFix: invalid computed context).
    const rf = p.need ? null : p.roleFix;
    const need = p.need || { source: rf.domain, target: rf.type, tclass: 'process', perms: [] };
    if (!f) {
      return h('div', { class: 'fix small' }, h('button', { title: rf ? `Find interfaces in this policy that authorize ${rf.role} for ${rf.type}` : `Find interfaces in this policy that allow ${need.source} ${need.target}:${need.tclass} { ${need.perms.join(' ')} }`,
        onclick: () => { fixes.set(id, { state: 'loading', plans: new Map() }); fixWait.set(++fixKey, { id }); vscode.postMessage({ cmd: 'sessionFix', key: fixKey, against, need: p.need || null, attrs: p.attrs || [], role: rf || null }); render(); } }, 'How to fix'));
    }
    if (f.state === 'loading') return h('div', { class: 'fix small muted' }, "Looking for interfaces that grant it… (the first time, the tree's interfaces are expanded with m4)");
    const r = f.result || {};
    if (r.error) return h('div', { class: 'fix small bad' }, r.error);
    const rows = [];
    const addBtn = (domain, call, rule) => {
      const k = call || rule;
      const st = f.plans.get(k);
      if (!r.canEdit) return null;
      if (!st) return h('button', { title: call ? `Add ${call} to ${domain}'s module` : `Add the rule to ${domain}'s module`, onclick: () => { f.plans.set(k, { state: 'planning' }); fixWait.set(++fixKey, { id, k }); vscode.postMessage({ cmd: 'fix', key: fixKey, domain, call, rule }); render(); } }, 'Add…');
      if (st.state === 'planning') return h('span', { class: 'muted' }, 'planning…');
      if (st.state === 'applying') return h('span', { class: 'muted' }, 'writing…');
      if (st.state === 'applied') return h('span', { class: 'ok' }, `✓ added to ${base(st.plan.path)}; building…`);
      const pl = st.plan || {};
      if (pl.already) return h('span', { class: 'muted' }, 'already there');
      if (pl.unavailable) return h('span', { class: 'warn' }, pl.unavailable);
      return h('span', {}, h('button', { class: 'primary', title: `Write it to ${pl.path} and save (builds)`, onclick: () => { st.state = 'applying'; fixWait.set(++fixKey, { id, k }); vscode.postMessage({ cmd: 'applyFix', key: fixKey, plan: pl }); render(); } }, `Apply to ${base(pl.path)}`),
        ' ', h('code', { class: 'small' }, (pl.inserted || []).join(' ').slice(0, 160)), pl.optional ? h('span', { class: 'muted' }, ' (in optional_policy)') : null);
    };
    const s = r.suggest;
    if (s && s.own) {
      rows.push(h('div', {}, 'Both types belong to ', h('code', {}, s.module || 'one module'), ': add the rule there. ', h('code', {}, r.rule), ' ', addBtn(need.source, null, r.rule)));
    } else if (s && (s.list || []).length) {
      rows.push(h('div', { class: 'sub' }, s.roleCalls ? `Interfaces in this policy that authorize ${rf.role} for ${rf.type} (with the transition):` : s.partial ? 'No interface grants all of it; the closest:' : 'Interfaces in this policy that grant it (narrowest first):'));
      rows.push(h('table', {}, s.list.map((x, n) => h('tr', {},
        h('td', {}, h('button', { class: 'link', title: x.summary || `Open ${x.name}`, onclick: () => vscode.postMessage({ cmd: 'open', loc: x.loc }) }, x.call)),
        h('td', { class: 'muted' }, [n === 0 && !s.partial ? 'narrowest' : null, x.owner ? 'owner module' : null, x.off ? 'module off' : null, x.writes ? 'writes' : null, x.attrs && x.attrs.length ? `adds ${x.attrs.join(', ')}` : null].filter(Boolean).join(' · ')),
        h('td', {}, x.summary ? h('span', { class: 'muted' }, x.summary) : null),
        h('td', {}, addBtn(need.source, x.call))))));
    } else if (s && s.note) rows.push(h('div', { class: 'muted' }, s.note));
    if ((r.joins || []).length) {
      rows.push(h('div', { class: 'sub' }, `Or make ${need.target} one of the domains that already have it:`));
      rows.push(h('table', {}, r.joins.map(x => h('tr', {},
        h('td', {}, h('button', { class: 'link', title: `Open ${x.name}`, onclick: () => vscode.postMessage({ cmd: 'open', loc: x.loc }) }, x.call)),
        h('td', { class: 'muted' }, `puts it in ${x.attr}${x.pure ? '' : ' (and more)'}`),
        h('td', {}, addBtn(x.domain, x.call))))));
    }
    if (s && s.roleCalls) rows.push(h('div', {}, 'Or authorize the role only (the transition is already there): ', h('code', {}, r.rule), ' ', addBtn(need.source, null, r.rule)));
    else rows.push(h('div', { class: 'muted' }, 'The rule itself: ', h('code', {}, r.rule), s && s.list && s.list.length ? ' (an interface keeps it in the module that owns the type)' : ''));
    for (const n of r.notes || []) rows.push(h('div', { class: 'muted' }, n));
    return h('div', { class: 'fix small' }, rows);
  }

  const MARK = { true: ['✓', 'ok'], false: ['✗', 'bad'], null: ['?', 'muted'] };
  function sessionsCard() {
    const list = result.sessions || [];
    if (!list.length) return null;
    const failing = list.filter(x => x.checks.some(c => c.ok === false)).length;
    return card('sessions', 'Session starts', `${list.length} checked${failing ? ` · ${failing} failing` : ''}`, [
      h('div', { class: 'small muted' }, "Once a context is picked, the kernel still checks the start: the user's domain enters through the first program (the shell; /bin/sh for cron; systemd for the user instance), loads its libraries, keeps the terminal and descriptors the login program hands over, and, under NoNewPrivileges or from a nosuid mount, needs process2 nnp_transition / nosuid_transition. Any of these failing makes the login bounce although the policy compiles. Hover a check for details."),
      h('table', {}, h('tr', {}, h('th', {}, 'Login'), h('th', {}, 'Way in'), h('th', {}, 'Session'), h('th', {}, 'Checks')),
        list.map(x => h('tr', {},
          h('td', {}, x.group ? `%${x.login}` : x.login),
          h('td', {}, x.way, x.on && x.on !== 'both' ? h('span', { class: 'muted' }, ` (${x.on})`) : null),
          h('td', {}, h('code', {}, x.ctx)),
          h('td', {}, x.checks.map(c => { const [m, cl] = MARK[String(c.ok)]; const q = c.ok === false && c.trace && c.trace.record === 'none'; return h('span', { class: cl, title: q ? `${c.text}\n${c.trace.text}` : c.text, style: 'margin-right:10px' }, `${m} ${c.id}${q ? ' (no AVC)' : ''}`); }))))),
    ], failing > 0);
  }

  /** What each user's sessions run: checked per user, restricted ones further (wrappers and what they start). */
  function runsCard() {
    const list = result.runs || [];
    if (!list.length) return null;
    const failing = list.reduce((n, x) => n + x.items.length, 0);
    return card('runs', 'Programs the sessions run', `${list.length} user${list.length > 1 ? 's' : ''}${failing ? ` · ${failing} failing` : ''}`, [
      h('div', { class: 'small muted' }, 'Every program the users\' domains run with an automatic transition is checked as the kernel does at exec: the computed context must be valid for the role (else SELINUX_ERR, no AVC), the transition and entrypoint allowed, and the new domain must keep the terminal and the pipes it inherits. A restricted user (one that reaches few domains) is followed further, through wrappers to what they start, and its failures are warnings.'),
      h('table', {}, h('tr', {}, h('th', {}, 'User'), h('th', {}, 'Login'), h('th', {}, 'Followed'), h('th', {}, 'Checked'), h('th', {}, 'Failing')),
        list.map(x => h('tr', {},
          h('td', {}, x.user), h('td', {}, x.login),
          h('td', {}, x.restricted ? `restricted: ${x.reached} domains reached` : 'its own domain only'),
          h('td', {}, String(x.checked || 0)),
          h('td', {}, x.items.length ? h('span', { class: x.restricted ? 'warn' : 'muted', title: x.items.map(i => `${i.s} → ${i.e} → ${i.to}: ${i.fails.map(f => f.kind).join(', ')}`).join('\n') }, `${x.items.length}${x.more ? '+' : ''}`) : h('span', { class: 'ok' }, '✓'))))),
    ], failing > 0 && list.some(x => x.restricted && x.items.length));
  }

  function wayRow(m, w) {
    const res = (works, pick) => (works ? h('code', { class: 'ok', title: pick.how === 'failsafe' ? 'the failsafe context' : 'the first valid listed context' }, pick.ctx + (pick.how === 'failsafe' ? ' (failsafe)' : ''))
      : h('span', { class: 'bad' }, '✗ no session'));
    const cands = h('details', { class: 'cands' }, h('summary', { class: 'muted small' }, `${w.candidates.length} listed context${w.candidates.length === 1 ? '' : 's'}`),
      h('table', {}, h('tr', {}, h('th', {}, 'Listed'), h('th', {}, 'RHEL 9+ (libselinux 3.x)'), h('th', {}, 'RHEL 8 (kernel computes)'), h('th', {}, 'Line')),
        w.candidates.map(c => h('tr', {},
          h('td', {}, h('code', {}, `${c.role}:${c.type}`)),
          h('td', {}, c.valid ? (c.transition.ok ? h('span', { class: 'ok' }, 'valid') : h('span', { class: 'warn' }, `valid, but ${c.transition.text}`)) : h('span', { class: 'bad' }, c.reasons.map(r => r.text).join('; '))),
          h('td', {}, !c.ctx2 ? h('span', { class: 'bad' }, w.v2rangeError || 'no session range') : c.valid2 ? (c.transition2 && c.transition2.ok ? h('span', { class: 'ok' }, `reachable at ${c.ctx2.split(':').slice(3).join(':') || '—'}`) : h('span', { class: 'bad' }, c.transition2 ? c.transition2.text : '')) : h('span', { class: 'bad' }, c.reasons2.map(r => r.text).join('; '))),
          h('td', {}, loc(c.file, c.l, `${base(c.file)}:${c.l + 1}${c.own ? ' (own)' : ''}`))))),
      w.failsafe ? h('div', { class: 'small' }, 'Failsafe: ', h('code', {}, w.failsafe.ctx), ' — ', w.failsafe.valid ? (w.failsafe.transition.ok ? h('span', { class: 'ok' }, 'valid') : h('span', { class: 'warn' }, `valid, but ${w.failsafe.transition.text}`)) : h('span', { class: 'bad' }, w.failsafe.reasons.map(r => r.text).join('; '))) : null);
    return h('tr', {},
      h('td', {}, h('span', { title: w.fromcon }, w.label)),
      h('td', {}, res(w.works3, w.v3 || {})),
      h('td', {}, res(w.works2, w.v2 || {})),
      h('td', {}, cands));
  }

  function mappingCard(m, i) {
    const who = m.hypothetical ? m.login : `${m.group ? '%' : ''}${m.login}`;
    const bad = m.ways.filter(w => !w.works3 || !w.works2).length;
    const hint = `${m.hypothetical ? '' : `→ ${m.user}${m.range ? ` ${m.range}` : ''} · `}${m.ways.length} way${m.ways.length === 1 ? '' : 's'} in${bad ? ` · ${bad} failing` : ''}`;
    return card(`m${i}:${who}`, who, hint, [
      h('div', { class: 'small muted' }, m.hypothetical ? `No seusers line maps a login to ${m.user}; checked as if one did, at ${m.level || 'its default level'}. ` : `seusers line `, m.hypothetical ? loc(m.file, m.l, `${base(m.file)}`) : loc(m.file, m.l)),
      m.ways.length ? h('table', { class: 'ways' }, h('tr', {}, h('th', {}, 'Way in'), h('th', {}, 'RHEL 9 and later'), h('th', {}, 'RHEL 8'), h('th', {}, '')), m.ways.map(w => wayRow(m, w)))
        : h('div', { class: 'muted' }, 'No contexts file offers it a way in.'),
    ], bad > 0);
  }

  function render() {
    const main = $('main');
    main.textContent = '';
    $('status').textContent = loading ? 'Checking…' : '';
    const sel = $('against');
    sel.textContent = '';
    for (const p of (result && result.policies) || []) sel.append(h('option', { value: p.id, selected: (result.policy && result.policy.id === p.id) || null }, p.label));
    main.append(h('p', { class: 'intro' },
      'Whether each login gets a valid SELinux context for each way in (ssh, console, graphical, cron, …), the way libselinux decides it when a session starts. ',
      'A policy can compile and still lock people out with "Unable to get valid context for <user>": seusers maps a login to a user without the right role, a contexts file lists a role:type the user can\'t have, a range is outside the user\'s, or the login program may not transition to the user\'s domain. ',
      'RHEL 9 and later (libselinux 3.x) take the first valid listed context; RHEL 8 (2.x) lets the kernel compute the reachable ones, so the two can differ.'));
    if (!result) return;
    if (result.error) { main.append(h('div', { class: 'note bad' }, result.error)); return; }
    const count = (s) => result.problems.filter(p => p.severity === s).length;
    const ne = count('error'), nw = count('warning'), ni = count('info');
    main.append(h('div', { class: 'verdict' }, ne || nw ? h('span', { class: ne ? 'bad' : 'warn' }, `${ne} error${ne === 1 ? '' : 's'}, ${nw} warning${nw === 1 ? '' : 's'}`) : h('span', { class: 'ok' }, '✓ Every login gets a valid context'),
      ni ? h('span', { class: 'muted' }, ` · ${ni} note${ni === 1 ? '' : 's'}`) : null,
      h('span', { class: 'muted' }, ` · ${result.policy && result.policy.label}`)));
    if (result.problems.length) main.append(card('problems', 'Problems', `${result.problems.length}`, result.problems.map(problemRow), true));
    main.append(card('logins', 'Logins and their ways in', `${result.mappings.length} seusers line${result.mappings.length === 1 ? '' : 's'}`, result.mappings.map(mappingCard), true));
    const sc = sessionsCard();
    if (sc) main.append(sc);
    const rc = runsCard();
    if (rc) main.append(rc);
    if ((result.notes || []).length) main.append(h('div', { class: 'notes' }, result.notes.map(n => h('div', { class: 'note muted' }, n))));
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
      render();
    } else if (m.cmd === 'sessionFix' || m.cmd === 'fixPlan' || m.cmd === 'applied') {
      const w = fixWait.get(m.key);
      if (!w) return;
      fixWait.delete(m.key);
      const f = fixes.get(w.id);
      if (!f) return;
      if (m.cmd === 'sessionFix') { f.state = 'done'; f.result = m.result; } else if (m.cmd === 'fixPlan') f.plans.set(w.k, { state: 'plan', plan: m.plan });
      else { const st = f.plans.get(w.k); if (st) st.state = 'applied'; }
      render();
    } else if (m.cmd === 'built') {
      if (m.ok && (!result || !result.policy || result.policy.build)) { fixes.clear(); load(); }
    } else if (m.cmd === 'error') {
      loading = false;
      result = { error: m.text, policies: (result && result.policies) || [] };
      render();
    }
  });
  render();
  load();
}());
