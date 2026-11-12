'use strict';
/*
 * Learn from a permissive run (pure): the AVC denials of a service running in
 * its new domain (permissive, so everything it does is logged) mapped onto
 * the service editor's model. Instead of audit2allow's raw rules the service
 * gets what the form offers: a higher access level on one of its own file
 * types, a capability, a self permission, a port to listen on or connect to,
 * an access group or an interface (the narrowest one, as the denial
 * assistant ranks them), or a new file type for files it uses under a
 * generic label. What doesn't fit is reported with the rule it would need.
 *
 * learn(model, groups, opts): groups from denials.groupDenials(); opts:
 *   domain, execType: the service's type names;
 *   fileTypeOf(row) → type; isGeneric(type); portStem(type) → stem of a
 *   corenetwork port type ('http' for http_port_t) or null;
 *   has(name); interfaces: Set of one-argument interfaces the form offers;
 *   accessByCall: Map interface → access group id; capNames: Set;
 *   suggestions: Map group key → { list: [{ name, covers }], partial } (the
 *   denial assistant's ranking, from the server).
 * → { model (a copy), report: [{ source, target, tclass, perms, count, action, text, ... }], stats }
 */

const LEVEL_RANK = { none: 0, read: 1, append: 1, manage: 2, custom: 3 };
const WRITE = new Set(['write', 'create', 'unlink', 'rename', 'rmdir', 'add_name', 'remove_name', 'setattr', 'link', 'reparent', 'relabelfrom', 'relabelto', 'swapon', 'quotaon', 'mounton']);
const APPEND_ONLY = new Set(['append', 'create', 'getattr', 'open', 'lock', 'ioctl', 'read', 'search', 'map']);
const FILE_CLASSES = new Set(['file', 'dir', 'lnk_file', 'sock_file', 'fifo_file', 'chr_file', 'blk_file']);
/** self permissions: [class, item id, test(perm)]: the form's item that grants a permission of the class. */
const SELF_RULES = [
  ['fifo_file', 'fifo', () => true],
  ['process', 'signal', (p) => /^sig/.test(p)],
  ['process', 'sched', (p) => /sched$/.test(p)],
  ['process', 'rlimit', (p) => p === 'setrlimit'],
  ['process', 'execmem', (p) => p === 'execmem'],
  ['unix_stream_socket', 'unixstream', () => true],
  ['unix_dgram_socket', 'unixdgram', () => true],
  ['shm', 'shm', () => true], ['sem', 'shm', () => true],
  ['netlink_route_socket', 'netlink', () => true],
];
const SOCKET_CLASSES = { tcp_socket: 'tcp', udp_socket: 'udp', sctp_socket: 'sctp' };
/** Directory labels a service's own files often sit under before they get a type (besides the generic ones). */
const LABEL_TYPES = new Set(['var_t', 'var_lib_t', 'var_log_t', 'var_run_t', 'var_spool_t', 'var_cache_t', 'tmp_t', 'var_tmp_t', 'etc_t', 'usr_t', 'default_t', 'var_lock_t']);

function levelFor(perms, kind) {
  const ps = new Set(perms);
  const levels = new Set(kind.access || ['manage', 'read', 'none']);
  let want = perms.some(p => WRITE.has(p)) ? 'manage' : perms.every(p => APPEND_ONLY.has(p)) && (ps.has('append') || ps.has('create')) ? 'append' : 'read';
  if (want === 'append' && !levels.has('append')) want = 'manage';
  if (want === 'read' && !levels.has('read')) want = 'manage';
  return want;
}

function learn(model, groups, opts) {
  const m = JSON.parse(JSON.stringify(model));
  m.files = m.files || []; m.caps = m.caps || []; m.self = m.self || []; m.extra = m.extra || []; m.access = m.access || [];
  m.net = m.net || { listen: [], connect: [] };
  const D = opts.domain;
  opts = { name: model.name, ...opts };
  const report = [];
  const stats = { mapped: 0, unmapped: 0, skipped: 0 };
  const add = (g, action, text, extra = {}) => {
    report.push({ source: g.source, target: g.target, tclass: g.tclass, perms: g.perms, count: g.count, action, text, ...extra });
    stats[action === 'unmapped' ? 'unmapped' : action === 'skipped' ? 'skipped' : 'mapped']++;
  };
  const rule = (g) => `allow ${g.source} ${g.source === g.target ? 'self' : g.target}:${g.tclass} { ${g.perms.join(' ')} };`;
  const kinds = (opts.fileKinds || []).filter(k => k.where);
  const rowType = new Map(m.files.map((row, i) => [opts.fileTypeOf(row), i]));

  // The service's own sockets are judged after the port entries they go with.
  const ownSocket = (g) => g.source === D && g.target === D && !!SOCKET_CLASSES[g.tclass];
  for (const g of [...groups.filter(g => !ownSocket(g)), ...groups.filter(ownSocket)]) {
    if (g.kind === 'error') { add(g, 'skipped', 'A SELinux error record, not an access denial; see the denial assistant.'); continue; }
    if (g.source !== D) { add(g, 'skipped', `${g.source} is not this service's domain${g.target === D ? ' (something else accessing the service)' : ''}.`); continue; }
    if (g.v && g.v.verdict === 'allowed') { add(g, 'skipped', 'Already allowed by the policy.'); continue; }
    if (g.tclass === 'process' && g.target !== D) {
      add(g, 'unmapped', `${D} starts or signals ${g.target}: a helper program (Helper programs section) or an interface of ${g.target}'s module.`, { rule: rule(g) });
      continue;
    }
    // Its own domain: capabilities and self permissions.
    if (g.target === D) {
      if (g.tclass === 'capability' || g.tclass === 'capability2') {
        const known = g.perms.filter(p => opts.capNames.has(p)), odd = g.perms.filter(p => !opts.capNames.has(p));
        for (const p of known) if (!m.caps.includes(p)) m.caps.push(p);
        if (known.length) add(g, 'cap', `Capabilit${known.length > 1 ? 'ies' : 'y'} ${known.join(', ')} ticked.`, { caps: known });
        if (odd.length) add({ ...g, perms: odd }, 'unmapped', `Capability ${odd.join(', ')} is not in the form; add the rule by hand.`, { rule: rule({ ...g, perms: odd }) });
        continue;
      }
      // Each permission to the form's item that grants it; what no item grants is left.
      const items = new Map();
      const left = [];
      for (const p of g.perms) {
        const sr = SELF_RULES.find(([cls, , test]) => cls === g.tclass && test(p));
        if (sr) { if (!items.has(sr[1])) items.set(sr[1], []); items.get(sr[1]).push(p); } else left.push(p);
      }
      for (const [id, ps] of items) {
        if (m.self.includes(id)) { add({ ...g, perms: ps }, 'covered', `Process and capabilities: "${id}" is already ticked (${g.tclass} ${ps.join(' ')}).`, { self: id }); continue; }
        m.self.push(id);
        add({ ...g, perms: ps }, 'self', `Process and capabilities: "${id}" ticked (${g.tclass} ${ps.join(' ')}).`, { self: id });
      }
      if (items.size && !left.length) continue;
      if (left.length && left.length < g.perms.length) { add({ ...g, perms: left }, 'unmapped', `${g.tclass} ${left.join(' ')} on itself: not in the form.`, { rule: rule({ ...g, perms: left }) }); continue; }
      if (SOCKET_CLASSES[g.tclass]) {
        const any = (m.net.listen || []).length + (m.net.connect || []).length;
        add(g, any ? 'covered' : 'unmapped', any ? `Its own ${g.tclass}: granted with the network entries.` : `Its own ${g.tclass}: add the port it listens on or connects to (Network section); the socket itself comes with it.`, any ? {} : { rule: rule(g) });
        continue;
      }
      add(g, 'unmapped', `${g.tclass} ${g.perms.join(' ')} on itself: not in the form.`, { rule: rule(g) });
      continue;
    }
    // One of its own file types: raise the access level.
    if (rowType.has(g.target)) {
      const i = rowType.get(g.target);
      const row = m.files[i];
      const kind = (opts.fileKinds || []).find(k => k.id === row.kind) || { access: ['manage', 'read', 'none'] };
      const want = levelFor(g.perms, kind);
      if (row.access === 'custom') { add(g, 'unmapped', `${g.target} is kept with custom rules; add ${g.perms.join(' ')} to them by hand.`, { rule: rule(g) }); continue; }
      if ((LEVEL_RANK[row.access] || 0) >= LEVEL_RANK[want]) { add(g, 'covered', `${g.target}: "${row.access}" already covers ${g.perms.join(' ')}.`); continue; }
      row.access = want;
      add(g, 'file', `${g.target} (${kind.label || row.kind}): access raised to "${want}" for ${g.perms.join(' ')}.`, { row: i, level: want });
      continue;
    }
    // Ports.
    const proto = SOCKET_CLASSES[g.tclass];
    if (proto && /_port_t$/.test(g.target) && g.perms.some(p => /^(name_bind|name_connect|send_msg|recv_msg)$/.test(p))) {
      const dir = g.perms.includes('name_bind') ? 'listen' : 'connect';
      if (g.target === 'unreserved_port_t' || g.target === 'ephemeral_port_t') {
        const n = dir === 'listen' ? `corenet_${proto}_bind_all_unreserved_ports` : proto === 'tcp' ? 'corenet_tcp_connect_all_unreserved_ports' : 'corenet_udp_sendrecv_all_unreserved_ports';
        if (opts.has(n)) { if (!m.extra.includes(n)) m.extra.push(n); add(g, 'extra', `Unreserved ports: ${n}() added (name the service's own port type instead to narrow it).`, { call: n }); } else add(g, 'unmapped', `${g.target}: no ${n} in this policy.`, { rule: rule(g) });
        continue;
      }
      const stem = opts.portStem(g.target);
      if (!stem) { add(g, 'unmapped', `${g.target} is not a port type this policy's corenetwork defines (${dir}).`, { rule: rule(g) }); continue; }
      const list = m.net[dir] = m.net[dir] || [];
      const p = proto === 'sctp' ? 'tcp' : proto;
      if (!list.some(x => x.proto === p && x.port === stem)) list.push({ proto: p, port: stem });
      add(g, 'net', `${dir === 'listen' ? 'Listens on' : 'Connects to'} ${p} ${stem} (${g.target}).`, { net: { dir, proto: p, port: stem } });
      continue;
    }
    if (/^(node|netif|packet)$/.test(g.tclass) || /^(node_t|netif_t)$|_node_t$|_netif_t$|_packet_t$/.test(g.target)) {
      add(g, 'covered', 'Network nodes, interfaces and packets: granted along with the port entries.');
      continue;
    }
    // The service's own files under a generic label (a path named after it): a file type of its own.
    const generic = opts.isGeneric(g.target) || LABEL_TYPES.has(g.target);
    if (FILE_CLASSES.has(g.tclass) && generic && (g.paths || []).length) {
      const hit = fileRowFor(g, kinds, m, opts);
      if (hit) { add(g, 'label', hit.text, { row: hit.row, path: hit.path }); continue; }
    }
    if (opts.isGeneric(g.target) && FILE_CLASSES.has(g.tclass)) {
      add(g, 'unmapped', `${g.target} is a generic label${(g.names || []).length ? ` (${g.names.slice(0, 3).join(', ')})` : ''}: give those files a type of their own (Files section) instead of allowing ${g.target} as a whole.`, { rule: rule(g) });
      continue;
    }
    // Anything else: the narrowest interface, as an access group when the form has one for it.
    const s = opts.suggestions && opts.suggestions.get(g.key);
    const top = s && (s.list || []).find(x => x.covers) || null;
    if (top) {
      const acc = opts.accessByCall.get(top.name);
      if (acc) {
        if (!m.access.includes(acc)) m.access.push(acc);
        add(g, 'access', `System access: "${opts.accessLabel(acc)}" ticked (${top.name}).`, { access: acc, call: top.name });
      } else if (m.extra.includes(top.name)) add(g, 'covered', `${top.name}() is already called.`);
      else if (opts.interfaces.has(top.name)) { m.extra.push(top.name); add(g, 'extra', `Interface ${top.name}() added.`, { call: top.name }); }
      else add(g, 'unmapped', `${top.name}() grants it but takes more than the domain; call it by hand.`, { rule: rule(g), call: top.name });
      continue;
    }
    if (s && s.partial && (s.list || []).length) add(g, 'unmapped', `No interface grants all of it; the closest is ${s.list[0].name}().`, { rule: rule(g), call: s.list[0].name });
    else add(g, 'unmapped', s && s.note ? s.note : 'No interface found for it.', { rule: rule(g) });
  }
  return { model: m, report, stats };
}

/** A new or widened file row for files of the service under a generic label (/var/lib/NAME/… → state). */
function fileRowFor(g, kinds, m, opts) {
  const paths = (g.paths || []).filter(p => p.startsWith('/'));
  // The kind whose directory holds the path (longest match), when the path is named after the service
  // (/var/lib/NAME/…, /var/log/NAME.log): other files there (/etc/hosts) are someone else's.
  const mine = (first) => !!opts.name && first.toLowerCase().includes(opts.name.toLowerCase());
  let best = null;
  for (const p of paths) {
    const k = kinds.filter(k => p.startsWith(k.where + '/') && mine(p.slice(k.where.length + 1).split('/')[0])).sort((a, b) => b.where.length - a.where.length)[0];
    if (k && (!best || k.where.length > best.k.where.length)) best = { k, p };
  }
  if (!best) return null;
  const { k, p } = best;
  const rest = p.slice(k.where.length + 1).split('/');
  const isDir = g.tclass === 'dir' || rest.length > 1;
  const path = rest.length > 1 || isDir ? `${k.where}/${rest[0]}/` : p;
  const want = levelFor(g.perms, k);
  // The row already holding the path, else the kind's row (one type per kind, unless named otherwise).
  let row = m.files.findIndex(r => r.kind === k.id && (r.paths || []).some(x => x === path || (path.endsWith('/') && x.startsWith(path))));
  if (row < 0) row = m.files.findIndex(r => r.kind === k.id && !r.type);
  if (row < 0) {
    m.files.push({ kind: k.id, paths: [path], access: want });
    return { row: m.files.length - 1, path, text: `${k.label}: new file type for ${path} (now ${g.target}), access "${want}".` };
  }
  const r = m.files[row];
  if (!r.paths.includes(path) && !r.paths.some(x => path.startsWith(x))) r.paths.push(path);
  if (r.access !== 'custom' && (LEVEL_RANK[r.access] || 0) < LEVEL_RANK[want]) r.access = want;
  return { row, path, text: `${k.label}: ${path} labeled with the service's ${k.id} type (was ${g.target}), access "${r.access}".` };
}

module.exports = { learn, levelFor, LEVEL_RANK };
