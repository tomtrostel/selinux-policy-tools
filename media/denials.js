// Denial assistant webview: a log box (pasted, opened or read from this host
// with ausearch), the policy to check against, and one card per group of
// denials with its verdict, the fixes and the evidence. Plain JS, no deps.
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

  const SINCE = [['recent', 'last 10 minutes'], ['this-hour', 'this hour'], ['boot', 'since boot'], ['today', 'today'], ['this-week', 'this week']];
  const BADGE = { label: 'label', boolean: 'boolean', allowed: 'allowed', generic: 'label', missing: 'rule', unknown: 'other policy', error: 'error' };

  const tip = (id, text) => $(id).setAttribute('title', text);
  tip('analyze', 'Read the denials in the box and check each group against the chosen policy');
  tip('host', 'Run ausearch in a terminal (sudo asks for your password there) and analyze what it finds');
  tip('openFile', 'Analyze a saved audit log (e.g. a copy of /var/log/audit/audit.log, or ausearch output from another machine)');
  tip('against', 'The policy that decides whether access is allowed or allowed under a boolean: normally the one running on the host that logged the denials');
  tip('since', 'How far back ausearch looks');
  tip('log', 'Paste audit records here: audit.log lines, ausearch output (raw or -i) or kernel/journal "avc: denied" lines');
  for (const [v, t] of SINCE) $('since').append(h('option', { value: v }, t));
  $('since').value = 'recent';

  let last = null;            // last analysis result
  const fixes = new Map();    // group key → { plan } | { applied: path } | { resolved } | { still: title } | { failed }
  const opened = new Map();   // group key → open (cards the user toggled)
  let verifying = false;      // an analysis against the build after a fix

  const saved = vscode.getState && vscode.getState();
  if (saved && saved.log) $('log').value = saved.log;

  function analyze(against) {
    const text = $('log').value;
    if (vscode.setState) vscode.setState({ log: text.length < 2e6 ? text : '' });
    if (!text.trim()) { $('status').textContent = 'Paste audit records, open a log file, or read them from this host.'; return; }
    $('status').textContent = 'Analyzing…';
    vscode.postMessage({ cmd: 'analyze', text, against: against || $('against').value || null });
  }
  $('analyze').addEventListener('click', () => analyze());
  $('host').addEventListener('click', () => vscode.postMessage({ cmd: 'ausearch', since: $('since').value }));
  $('openFile').addEventListener('click', () => vscode.postMessage({ cmd: 'openFile' }));
  $('against').addEventListener('change', () => { if ($('log').value.trim()) analyze(); });
  const rerender = () => { if (last) render(last); };

  const fmtTime = (ms) => { try { return new Date(ms).toLocaleString(); } catch { return String(ms); } };
  const ruleText = (r) => `${r.rt} ${r.s} ${r.t}:${r.c} { ${r.perms.join(' ')} };${r.cond ? `   [when ${r.cond.replace(/:true$/, '').replace(/^(.*):false$/, 'not ($1)')}]` : ''}`;
  const typeLink = (name, loc) => (loc ? h('button', { class: 'link', title: `Open the declaration of ${name}${loc.m ? ` (module ${loc.m})` : ''}`, onclick: () => vscode.postMessage({ cmd: 'open', loc }) }, name) : h('code', {}, name));

  const fixBtn = (g, what) => h('button', { title: 'Add this to the module of ' + g.source + ': shows exactly what will be inserted where, before anything changes',
    onclick: () => { fixes.set(g.key, { planning: true }); rerender(); vscode.postMessage({ cmd: 'fix', key: g.key, domain: g.source, ...what }); } }, 'Add to module…');

  /** What a planned / applied fix looks like in its card. */
  function fixBox(g) {
    const f = fixes.get(g.key);
    if (!f) return null;
    if (f.planning) return h('div', { class: 'fixbox muted' }, 'Working out where it goes…');
    if (f.resolved) return h('div', { class: 'fixbox ok' }, `✓ Resolved: your build now allows this (${f.resolved}). Install the module on the host to fix the denial there.`);
    if (f.still) return h('div', { class: 'fixbox warn' }, `Still not allowed by your build: ${f.still}.`);
    if (f.failed) return h('div', { class: 'fixbox warn' }, 'The build failed: see the Problems view, fix the error and save again.');
    if (f.applied) return h('div', { class: 'fixbox muted' }, `Added to ${f.applied}. Checking it against your build when the build finishes…`);
    const p = f.plan;
    if (p.unavailable || p.already) return h('div', { class: 'fixbox warn' }, p.unavailable || p.message, ' ', h('button', { onclick: () => { fixes.delete(g.key); rerender(); } }, 'OK'));
    return h('div', { class: 'fixbox' },
      h('div', {}, `${p.exists ? 'Adds to' : 'Creates'} `, h('code', {}, p.path), ` at line ${p.line + 1}${p.optional ? ' (in optional_policy: that module can be turned off)' : ''}:`),
      h('pre', { class: 'rules add' }, p.inserted.join('\n')),
      p.note ? h('div', { class: 'muted' }, p.note) : null,
      h('div', { class: 'cmd' },
        h('button', { class: 'primary', title: 'Write it (one undoable edit) and save: the module builds, and the denial is checked against the build', onclick: () => { vscode.postMessage({ cmd: 'applyFix', key: g.key, plan: p }); } }, 'Apply'),
        h('button', { title: 'Leave the module as it is', onclick: () => { fixes.delete(g.key); rerender(); } }, 'Cancel')));
  }

  const copyBtn = (text, what) => h('button', { title: `Copy ${what}`, onclick: () => vscode.postMessage({ cmd: 'copy', text }) }, 'Copy');

  /** The interfaces that grant a missing access, narrowest first (or the rule for the domain's own module). */
  function suggestions(g) {
    const s = g.suggest;
    if (!s) return null;
    if (s.own) {
      return [h('div', { class: 'sub', title: 'Both types belong to the same module, so a plain rule in that module is the normal way to allow it' }, `Fix: a rule in ${s.module ? `module ${s.module}` : 'the domain’s own module'}`),
        h('div', { class: 'cmd' }, h('code', {}, s.rule), copyBtn(s.rule, 'the rule'), fixBtn(g, { rule: s.rule }))];
    }
    const rows = (s.list || []).map((x, k) => {
      const call = `${x.name}(${g.source})`;
      const tags = [
        k === 0 && x.covers ? h('span', { class: 'tag best', title: 'Covers every denied permission with the fewest other rights' }, 'narrowest') : null,
        x.owner ? h('span', { class: 'tag', title: `Defined by the module that owns ${g.target}` }, 'owner') : null,
        x.broad ? h('span', { class: 'tag warn', title: 'Grants far more than the narrowest suggestion; use it only if the service needs all of it' }, 'broad') : null,
        x.off ? h('span', { class: 'tag warn', title: `Module ${x.module} is off in modules.conf: calling it needs optional_policy or turning the module on` }, 'module off') : null,
        !x.covers ? h('span', { class: 'tag warn', title: 'Grants only part of what was denied' }, `lacks ${x.missing.join(' ')}`) : null,
        x.cond ? h('span', { class: 'tag', title: 'Some of its rules are under a boolean (not counted here)' }, 'has boolean rules') : null,
      ];
      return h('div', { class: 'iface' },
        h('div', { class: 'cmd' },
          h('button', { class: 'link', title: `Open the definition of ${x.name}${x.module ? ` (module ${x.module})` : ''}`, onclick: () => vscode.postMessage({ cmd: 'open', loc: x.loc }) }, call),
          copyBtn(call, 'the call'), x.covers ? fixBtn(g, { call }) : null, tags),
        x.summary ? h('div', { class: 'muted' }, x.summary) : null,
        x.grants && x.grants.length ? h('div', { class: 'grants', title: 'What the interface grants besides the denied access (largest first); attributes count all their member types' },
          h('span', { class: 'muted' }, 'also grants: '), x.grants.join('; ')) : h('div', { class: 'grants muted' }, 'grants nothing else'),
        x.attrs && x.attrs.length ? h('div', { class: 'grants muted', title: 'Attributes the interface gives the domain; their rules count as granted too' }, `adds attributes: ${x.attrs.join(', ')}`) : null);
    });
    return [h('div', { class: 'sub', title: 'Interfaces that grant this access, worked out from what each one really expands to; the narrowest first' }, s.partial ? 'Interfaces that grant part of it' : 'Suggested interfaces'),
      rows.length ? rows : null, s.note ? h('div', { class: 'muted' }, s.note) : null];
  }

  function card(g, i) {
    const v = g.v;
    const head = h('summary', {},
      h('span', { class: `badge ${v.verdict}`, title: v.title }, BADGE[v.verdict] || v.verdict),
      h('span', { class: 'what' }, h('code', {}, g.source), ' → ', h('code', {}, g.target), ' ', h('span', { class: 'muted' }, `${g.tclass} { ${g.perms.join(' ')} }`)),
      h('span', { class: 'muted' }, `${g.count}×${g.comms && g.comms.length ? ` · ${g.comms.join(', ')}` : ''}`),
      h('span', { class: 'vtitle' }, v.title));
    const fixRows = (v.fixes || []).map(f => h('div', { class: 'fix' },
      h('div', {}, f.text),
      f.command ? h('div', { class: 'cmd' }, h('code', {}, f.command),
        h('button', { title: 'Copy the command', onclick: () => vscode.postMessage({ cmd: 'copy', text: f.command }) }, 'Copy'),
        h('button', { title: 'Put the command (with sudo) into a terminal on this host; press Enter there to run it', onclick: () => vscode.postMessage({ cmd: 'run', command: `sudo ${f.command}` }) }, 'Send to terminal')) : null));
    const body = h('div', { class: 'body' },
      fixBox(g),
      h('div', { class: 'detail' }, v.detail),
      fixRows.length ? h('div', { class: 'sub' }, 'Fix') : null, fixRows,
      v.rules && v.rules.length ? [h('div', { class: 'sub' }, 'Allowed by'), h('pre', { class: 'rules' }, v.rules.map(ruleText).join('\n'))] : null,
      suggestions(g),
      v.needed ? [h('div', { class: 'sub', title: 'What the denial asks for, written as one raw rule. Prefer an interface of the module that owns the target type' }, 'Access needed'), h('pre', { class: 'rules' }, v.needed)] : null,
      (v.notes || []).length ? h('ul', { class: 'notes' }, v.notes.map(n => h('li', {}, n))) : null,
      h('div', { class: 'sub' }, 'Evidence'),
      h('div', { class: 'facts' },
        h('div', {}, h('span', { class: 'lbl' }, 'Source'), typeLink(g.source, g.srcLoc), g.scontext ? h('span', { class: 'muted' }, ` ${g.scontext}`) : null),
        h('div', {}, h('span', { class: 'lbl' }, 'Target'), typeLink(g.target, g.tgtLoc), g.tcontext ? h('span', { class: 'muted' }, ` ${g.tcontext}`) : null),
        g.exes && g.exes.length ? h('div', {}, h('span', { class: 'lbl' }, 'Programs'), g.exes.join(', ')) : null,
        g.paths && g.paths.length ? h('div', {}, h('span', { class: 'lbl' }, 'Files'), h('span', {}, g.paths.slice(0, 8).join(', '), g.paths.length > 8 ? ` and ${g.paths.length - 8} more` : '')) : null,
        g.first ? h('div', {}, h('span', { class: 'lbl' }, 'When'), g.first === g.last ? fmtTime(g.first) : `${fmtTime(g.first)} – ${fmtTime(g.last)}`) : null));
    const open = opened.has(g.key) ? opened.get(g.key) : (i < 3 || fixes.has(g.key));
    const d = h('details', { class: `group ${v.verdict}`, open: open ? true : null, ontoggle: (e) => opened.set(g.key, !!e.target.open) }, head, body);
    return d;
  }

  function render(r) {
    last = r;
    if (verifying) {
      verifying = false;
      for (const [k, f] of fixes) {
        if (!f.applied) continue;
        const g = r.groups.find(x => x.key === k);
        if (g && g.v.verdict === 'allowed') fixes.set(k, { resolved: r.policy ? r.policy.label : 'the build' });
        else fixes.set(k, { still: g ? g.v.title.toLowerCase() : 'the denial is no longer in the log' });
      }
    }
    const list = $('list');
    list.replaceChildren();
    const n = r.groups.length;
    $('status').textContent = n ? `${r.count} denial${r.count === 1 ? '' : 's'} in ${n} group${n === 1 ? '' : 's'}${r.policy ? ` · checked against ${r.policy.label}` : ''}` : 'No denials found in the text.';
    $('status').setAttribute('title', r.policy ? `Rules from ${r.policy.label}; expected file labels from ${r.policy.fileContexts}` : '');
    if (r.notes && r.notes.length) list.append(h('ul', { class: 'notes top' }, r.notes.map(x => h('li', {}, x))));
    const order = ['label', 'boolean', 'generic', 'missing', 'allowed', 'unknown', 'error'];
    const counts = {};
    for (const g of r.groups) counts[g.v.verdict] = (counts[g.v.verdict] || 0) + 1;
    if (n > 1) list.append(h('div', { class: 'summary muted' }, order.filter(k => counts[k]).map(k => `${counts[k]} ${({ label: 'wrong label', boolean: 'boolean', generic: 'generic label', missing: 'missing rule', allowed: 'already allowed', unknown: 'not in this policy', error: 'error' })[k]}`).join(' · ')));
    r.groups.forEach((g, i) => list.append(card(g, i)));
  }

  function setPolicies(policies, selected) {
    const sel = $('against');
    const keep = selected || sel.value;
    sel.replaceChildren(...policies.map(p => h('option', { value: p.id }, p.label)));
    const pick = policies.find(p => p.id === keep) || policies.find(p => p.active) || policies.find(p => p.build) || policies[0];
    sel.value = pick ? pick.id : '';
    sel.disabled = !policies.length;
  }

  window.addEventListener('message', (e) => {
    const m = e.data;
    if (m.cmd === 'policies') setPolicies(m.policies);
    else if (m.cmd === 'result') { if (m.result.policies) setPolicies(m.result.policies, m.result.policy && m.result.policy.id); render(m.result); }
    else if (m.cmd === 'log') { $('log').value = m.text; analyze(); }
    else if (m.cmd === 'status') $('status').textContent = m.text;
    else if (m.cmd === 'fixPlan') { fixes.set(m.key, { plan: m.plan }); opened.set(m.key, true); rerender(); }
    else if (m.cmd === 'applied') { fixes.set(m.key, { applied: m.path }); rerender(); }
    else if (m.cmd === 'built') {
      const pending = [...fixes.values()].some(f => f.applied);
      if (!pending) return;
      if (!m.ok) { for (const [k, f] of fixes) if (f.applied) fixes.set(k, { failed: true }); rerender(); return; }
      verifying = true;
      $('status').textContent = 'Checking the fix against your build…';
      analyze('build');
    }
    else if (m.cmd === 'error') $('status').textContent = m.text;
  });
  vscode.postMessage({ cmd: 'ready' });
})();
