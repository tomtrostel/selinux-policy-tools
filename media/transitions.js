// Domain transition graph (webview). Plain JS + SVG, no dependencies.
// The extension answers {cmd:'expand'} with {cmd:'transitions'}; the layout is
// layered: the root in column 0, domains reached by expanding in later columns.
(function () {
  const vscode = acquireVsCodeApi();
  const $ = (id) => document.getElementById(id);
  const svg = $('graph');
  const NS = 'http://www.w3.org/2000/svg';
  const COLW = 300, ROWH = 26, NODEH = 20, PAD = 16;

  let root = null, dir = 'out', filter = '';
  let clickTimer = null;
  const kids = new Map();     // domain -> [{ other, tr }] once fetched
  const expanded = new Set();
  const loading = new Set();
  const locs = {};

  function setRoot(name, direction) {
    root = name; dir = direction || dir;
    kids.clear(); expanded.clear(); loading.clear();
    $('root').value = root;
    for (const r of document.querySelectorAll('input[name=dir]')) r.checked = r.value === dir;
    $('title').textContent = dir === 'out' ? `Transitions from ${root}` : `Who can enter ${root}`;
    vscode.postMessage({ cmd: 'rooted', root, dir });
    toggle(root);
  }

  function toggle(name) {
    if (expanded.has(name)) { expanded.delete(name); render(); return; }
    expanded.add(name);
    if (kids.has(name)) { render(); return; }
    loading.add(name);
    render();
    vscode.postMessage({ cmd: 'expand', name, dir });
  }

  window.addEventListener('message', (e) => {
    const m = e.data;
    if (m.cmd === 'init') {
      const dl = $('domains');
      dl.innerHTML = '';
      for (const d of m.domains || []) { const o = document.createElement('option'); o.value = d; dl.appendChild(o); }
      setRoot(m.root, m.dir);
    } else if (m.cmd === 'transitions' && m.dir === dir) {
      loading.delete(m.name);
      Object.assign(locs, m.locs || {});
      kids.set(m.name, (m.transitions || []).map(tr => ({ other: dir === 'out' ? tr.target : tr.source, tr })));
      render();
    } else if (m.cmd === 'error') {
      loading.delete(m.name);
      $('status').textContent = m.msg;
      render();
    }
  });

  // Visible graph: breadth-first from the root through expanded domains.
  function layout() {
    const depth = new Map([[root, 0]]);
    const order = [root];
    const edges = [];
    const queue = [root];
    while (queue.length) {
      const n = queue.shift();
      if (!expanded.has(n)) continue;
      for (const { other, tr } of kids.get(n) || []) {
        const shown = depth.has(other) || expanded.has(other) || !filter || other.toLowerCase().includes(filter);
        if (!shown) continue;
        edges.push({ from: n, to: other, tr });
        if (!depth.has(other)) { depth.set(other, depth.get(n) + 1); order.push(other); queue.push(other); }
      }
    }
    const cols = new Map();
    for (const n of order) { const d = depth.get(n); if (!cols.has(d)) cols.set(d, []); cols.get(d).push(n); }
    const pos = new Map();
    for (const [d, list] of cols) list.forEach((n, i) => pos.set(n, { x: PAD + d * COLW, y: PAD + i * ROWH, d }));
    return { pos, edges, cols };
  }

  function el(tag, attrs, parent) {
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
    if (parent) parent.appendChild(e);
    return e;
  }

  function edgeStyle(tr) {
    const auto = tr.auto && tr.auto.length, dyn = tr.dynamic && !(tr.entrypoints && tr.entrypoints.length);
    return { dash: dyn ? '2 3' : auto ? '' : '6 4', cls: tr.conditional && tr.conditional.length ? 'edge cond' : 'edge' };
  }

  function edgeTip(tr) {
    const lines = [`${tr.source} → ${tr.target}`];
    if (tr.entrypoints && tr.entrypoints.length) lines.push(`entrypoints: ${tr.entrypoints.join(', ')}`);
    if (tr.auto && tr.auto.length) lines.push(`automatic on executing: ${tr.auto.join(', ')} (type_transition)`);
    else if (tr.entrypoints && tr.entrypoints.length) lines.push(tr.setexec ? 'explicit: the source sets the context itself (setexec), e.g. runcon / sudo' : 'needs a type_transition or setexec to happen');
    if (tr.dynamic) lines.push('dynamic transition (dyntransition + setcurrent)');
    if (tr.conditional && tr.conditional.length) lines.push(`only when ${tr.conditional.join(', ')}`);
    return lines.join('\n');
  }

  function render() {
    if (!root) return;
    const { pos, edges, cols } = layout();
    svg.innerHTML = '';
    const defs = el('defs', {}, svg);
    const mk = el('marker', { id: 'arrow', viewBox: '0 0 10 10', refX: '10', refY: '5', markerWidth: '7', markerHeight: '7', orient: 'auto-start-reverse' }, defs);
    el('path', { d: 'M 0 0 L 10 5 L 0 10 z', class: 'arrowhead' }, mk);
    const maxRows = Math.max(...[...cols.values()].map(l => l.length));
    svg.setAttribute('width', PAD * 2 + cols.size * COLW);
    svg.setAttribute('height', PAD * 2 + maxRows * ROWH);
    const nodeW = 250;
    const gEdges = el('g', {}, svg), gNodes = el('g', {}, svg);
    for (const e of edges) {
      const a = pos.get(e.from), b = pos.get(e.to);
      const st = edgeStyle(e.tr);
      let d;
      if (b.d > a.d) {
        const x1 = a.x + nodeW, y1 = a.y + NODEH / 2, x2 = b.x, y2 = b.y + NODEH / 2, mx = (x1 + x2) / 2;
        d = `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
      } else {
        // back or sideways edge: loop above
        const x1 = a.x + nodeW / 2, y1 = a.y, x2 = b.x + nodeW / 2, y2 = b.y, top = Math.min(y1, y2) - 18;
        d = `M ${x1} ${y1} C ${x1} ${top}, ${x2} ${top}, ${x2} ${y2}`;
      }
      // "Who can enter X": arrows point from the source (child) to the target (parent).
      const p = el('path', { d, class: st.cls, 'stroke-dasharray': st.dash, [dir === 'out' ? 'marker-end' : 'marker-start']: 'url(#arrow)' }, gEdges);
      el('title', {}, p).textContent = edgeTip(e.tr);
    }
    for (const [n, q] of pos) {
      const g = el('g', { class: `node${n === root ? ' root' : ''}${expanded.has(n) ? ' open' : ''}`, transform: `translate(${q.x},${q.y})` }, gNodes);
      el('rect', { width: nodeW, height: NODEH, rx: 4 }, g);
      const k = kids.get(n);
      const suffix = loading.has(n) ? ' …' : k ? ` (${k.length})` : '';
      const t = el('text', { x: 8, y: 14 }, g);
      t.textContent = (n.length > 30 ? n.slice(0, 29) + '…' : n) + suffix;
      el('title', {}, g).textContent = `${n}${k ? `\n${k.length} ${dir === 'out' ? 'transitions out' : 'domains can enter it'}` : ''}\nclick: expand/collapse · double-click: open source · alt-click: make root`;
      g.addEventListener('click', (ev) => {
        if (ev.altKey) { setRoot(n, dir); return; }
        if (ev.ctrlKey || ev.metaKey) { open(n); return; }
        // A double-click also fires two clicks: wait briefly so it doesn't expand/collapse too.
        clearTimeout(clickTimer);
        clickTimer = setTimeout(() => toggle(n), 220);
      });
      g.addEventListener('dblclick', () => { clearTimeout(clickTimer); open(n); });
    }
    const shown = pos.size - 1;
    $('status').textContent = `${shown} domain${shown === 1 ? '' : 's'} shown${filter ? ` (filter: ${filter})` : ''}`;
  }

  function open(n) { vscode.postMessage({ cmd: 'open', name: n, loc: locs[n] || null }); }

  $('root').addEventListener('change', () => { if ($('root').value.trim()) setRoot($('root').value.trim(), dir); });
  for (const r of document.querySelectorAll('input[name=dir]')) r.addEventListener('change', () => setRoot(root, r.value));
  $('filter').addEventListener('input', () => { filter = $('filter').value.trim().toLowerCase(); render(); });
  vscode.postMessage({ cmd: 'ready' });
})();
