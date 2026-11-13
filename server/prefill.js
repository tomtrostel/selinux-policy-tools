'use strict';
/*
 * Prefill the service editor from a program on a host (this one or a target
 * reached over ssh): a first draft of the service model before any permissive
 * run, from what the host already knows about the program.
 *
 *   prefillScript(exec)   a `sh -s` script: the program's real path and
 *                         package, the package's files and config files, the
 *                         systemd units that start it (and their hardening
 *                         settings), socket units, its listening and
 *                         established sockets, D-Bus service files, cron and
 *                         xinetd entries, shared libraries, file capabilities.
 *   parsePrefill(out)     → facts (see below)
 *   draft(facts, model, opts) → { model, report, notes }: the model with the
 *                         facts mapped onto the form's settings, and a report
 *                         of what was filled in from where. Sets only; never
 *                         clears what the form already has.
 *
 * opts: { fileKinds (service.catalog().fileKinds), ports [{ name, nums: [{ proto,
 *   port }] }] (the policy's port types with their numbers), has(name) → the
 *   interface exists, capNames (Set), moduleExists(name), name (a module name
 *   already chosen, '' = none) }.
 */

const PATH_DIRS = ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin'];

/** Shell-quote one argument. */
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

/** The script. exec: an absolute path (validated by the caller). */
function prefillScript(exec) {
  const E = shq(exec);
  return `
sec() { printf '### %s\\n' "$1"; }
E=${E}
sec uid; id -u
sec exec
if [ -e "$E" ]; then R=$(realpath "$E" 2>/dev/null || printf '%s' "$E"); printf '%s\\t1\\n' "$R"; else R="$E"; printf '%s\\t0\\n' "$E"; fi
sec pkg
PKG=$(rpm -qf --qf '%{NAME}\\t%{SUMMARY}\\n' -- "$R" 2>/dev/null </dev/null | head -1)
case "$PKG" in *"not owned"*|error*|"") PKG= ;; esac
[ -n "$PKG" ] && printf '%s\\n' "$PKG"
P=$(printf '%s' "$PKG" | cut -f1)
sec files
if [ -n "$P" ]; then rpm -ql -- "$P" 2>/dev/null </dev/null | while IFS= read -r f; do
  if [ -L "$f" ]; then t=l; elif [ -d "$f" ]; then t=d; elif [ -e "$f" ]; then t=f; else t=-; fi; printf '%s\\t%s\\n' "$t" "$f"; done; fi
sec config
if [ -n "$P" ]; then rpm -qc -- "$P" 2>/dev/null </dev/null; fi
sec units
systemctl show --no-pager -p Id,Description,ExecStart,ExecStartPre,ExecStartPost,ExecReload,ExecStop,User,Group,Type,BusName,PIDFile,RuntimeDirectory,StateDirectory,LogsDirectory,CacheDirectory,ConfigurationDirectory,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,ReadOnlyPaths,FragmentPath,MainPID,ActiveState,PrivateTmp,NoNewPrivileges,TriggeredBy '*.service' 2>&1 </dev/null
sec sockets
systemctl show --no-pager -p Id,Listen,FragmentPath,Triggers '*.socket' 2>&1 </dev/null
sec ss; ss -ntuHap 2>&1 </dev/null
sec ps; ps -eo pid=,ppid=,user:32=,args= 2>&1 </dev/null
sec dbus
for f in /usr/share/dbus-1/system-services/*.service /etc/dbus-1/system-services/*.service; do [ -f "$f" ] || continue
  if grep -qF -- "$R" "$f" 2>/dev/null || { [ -n "$P" ] && rpm -qf -- "$f" 2>/dev/null </dev/null | grep -q "^$P-"; }; then printf '%s\\t%s\\n' "$f" "$(sed -n 's/^Name=//p' "$f" | head -1)"; fi; done
sec cron
for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do [ -f "$f" ] || continue
  if grep -qF -- "$R" "$f" 2>/dev/null || { [ -n "$P" ] && [ "$(rpm -qf --qf '%{NAME}' -- "$f" 2>/dev/null </dev/null)" = "$P" ] && [ "\${f#/etc/cron.}" != "$f" ]; }; then printf '%s\\n' "$f"; fi; done
sec xinetd
for f in /etc/xinetd.d/*; do [ -f "$f" ] && grep -qF -- "$R" "$f" 2>/dev/null && printf '%s\\n' "$f"; done
sec libs
[ -f "$R" ] && ldd "$R" 2>/dev/null </dev/null | sed -n 's/^[[:space:]]*\\([^ ]*\\) => .*/\\1/p; s/^[[:space:]]*\\(\\/[^ ]*\\) (.*/\\1/p'
sec filecaps
[ -f "$R" ] && getcap "$R" 2>/dev/null </dev/null
sec ports; semanage port -l -n 2>/dev/null </dev/null
sec stat
[ -e "$R" ] && stat -c '%U %a %C' "$R" 2>/dev/null
sec done
`;
}

/** `### key` sections → { key: text }. */
function splitSections(out) {
  const s = {};
  let cur = null;
  for (const line of String(out || '').split('\n')) {
    const m = /^### (\S+)$/.exec(line);
    if (m) { cur = m[1]; if (s[cur] == null) s[cur] = ''; continue; }
    if (cur != null) s[cur] += line + '\n';
  }
  return s;
}

/** systemctl show blocks (blank-line separated) → [{ ...kv }]. Repeated keys are joined with " ; ". */
function showBlocks(text) {
  const out = [];
  for (const block of String(text || '').split(/\n\s*\n/)) {
    const kv = {};
    for (const line of block.split('\n')) { const i = line.indexOf('='); if (i > 0) kv[line.slice(0, i)] = (kv[line.slice(0, i)] ? `${kv[line.slice(0, i)]} ; ` : '') + line.slice(i + 1); }
    if (kv.Id) out.push(kv);
  }
  return out;
}

/** `{ path=/usr/sbin/x ; argv[]=/usr/sbin/x -f ; ... }` → [{ path, argv }]. */
function execEntries(v) {
  const out = [];
  for (const m of String(v || '').matchAll(/\{\s*path=(\S+)\s*;\s*argv\[\]=([^;]*?)\s*;/g)) out.push({ path: m[1], argv: m[2].trim() });
  return out;
}

/** A capability set as systemd shows it: explicit list → names (cap_ prefix dropped); unlimited (a number, or ~everything) → null. */
function capSet(v) {
  const s = String(v || '').trim();
  if (!s || /^\d+$/.test(s) || /^~/.test(s)) return null;
  const caps = s.split(/\s+/).filter(Boolean).map(c => c.replace(/^cap_/, '').toLowerCase());
  return caps.length >= 30 ? null : caps;
}

/** `ss -ntuHap` → [{ proto, state, addr, port, peerAddr, peerPort, pids }]. */
function parseSockets(text) {
  const out = [];
  const addr = (a) => { const m = /^(.*):(\d+|\*)$/.exec(a || ''); return m ? { addr: m[1].replace(/^\[|\]$/g, ''), port: m[2] === '*' ? null : +m[2] } : null; };
  for (const line of String(text || '').split('\n')) {
    const f = line.trim().split(/\s+/);
    if (f.length < 6 || !/^(tcp|udp)$/.test(f[0])) continue;
    const local = addr(f[4]), peer = addr(f[5]);
    if (!local) continue;
    const pids = [...new Set([...line.matchAll(/pid=(\d+)/g)].map(x => +x[1]))];
    out.push({ proto: f[0], state: f[1], addr: local.addr, port: local.port, peerAddr: peer ? peer.addr : null, peerPort: peer ? peer.port : null, pids });
  }
  return out;
}

/** `semanage port -l -n` → [{ name, nums: [{ proto, port }] }] (port may be a range "8008-8010"); root only, else []. */
function parseSemanagePorts(text) {
  const by = new Map();
  for (const line of String(text || '').split('\n')) {
    const m = /^(\w+)_port_t\s+(tcp|udp|sctp|dccp)\s+(.+)$/.exec(line.trim());
    if (!m) continue;
    if (!by.has(m[1])) by.set(m[1], { name: m[1], nums: [] });
    for (const p of m[3].split(/\s*,\s*/)) if (/^\d+(-\d+)?$/.test(p)) by.get(m[1]).nums.push({ proto: m[2], port: p });
  }
  return [...by.values()];
}

/** prefillScript's output → facts. */
function parsePrefill(out) {
  const s = splitSections(out);
  const line1 = (k) => (s[k] || '').split('\n')[0] || '';
  const ex = line1('exec').split('\t');
  const pk = line1('pkg').split('\t');
  const files = [];
  for (const l of (s.files || '').split('\n')) { const m = /^([ldf-])\t(.+)$/.exec(l); if (m) files.push({ path: m[2], kind: m[1] }); }
  const config = new Set((s.config || '').split('\n').filter(l => l.startsWith('/')));
  const units = showBlocks(s.units).map(kv => ({
    id: kv.Id, description: kv.Description || '', fragment: kv.FragmentPath || null, active: kv.ActiveState || null, mainPid: +(kv.MainPID || 0) || 0,
    execStart: execEntries(kv.ExecStart), execPre: execEntries(kv.ExecStartPre), execPost: execEntries(kv.ExecStartPost), execReload: execEntries(kv.ExecReload), execStop: execEntries(kv.ExecStop),
    user: kv.User || '', group: kv.Group || '', type: kv.Type || '', busName: kv.BusName || '', pidFile: kv.PIDFile || '',
    runtimeDir: (kv.RuntimeDirectory || '').split(/\s+/).filter(Boolean), stateDir: (kv.StateDirectory || '').split(/\s+/).filter(Boolean), logsDir: (kv.LogsDirectory || '').split(/\s+/).filter(Boolean),
    cacheDir: (kv.CacheDirectory || '').split(/\s+/).filter(Boolean), confDir: (kv.ConfigurationDirectory || '').split(/\s+/).filter(Boolean),
    bounding: capSet(kv.CapabilityBoundingSet), ambient: capSet(kv.AmbientCapabilities) || [],
    rwPaths: (kv.ReadWritePaths || '').split(/\s+/).filter(Boolean), roPaths: (kv.ReadOnlyPaths || '').split(/\s+/).filter(Boolean),
    privateTmp: kv.PrivateTmp === 'yes', nnp: kv.NoNewPrivileges === 'yes', triggeredBy: (kv.TriggeredBy || '').split(/\s+/).filter(Boolean),
  }));
  const socketUnits = showBlocks(s.sockets).map(kv => ({
    id: kv.Id, fragment: kv.FragmentPath || null, triggers: (kv.Triggers || '').split(/\s+/).filter(Boolean),
    // Listen=/run/x.sock (Stream) ; Listen=[::]:80 (Stream) ; Listen=0.0.0.0:53 (Datagram)
    listen: [...String(kv.Listen || '').matchAll(/([^\s;]+)\s+\((Stream|Datagram|SequentialPacket|Netlink|FIFO|Special|MessageQueue|USBFunction)\)/g)].map(m => {
      const a = /^(.*):(\d+)$/.exec(m[1]);
      return { what: m[1], kind: m[2], port: a ? +a[2] : null, proto: a ? (m[2] === 'Datagram' ? 'udp' : 'tcp') : null };
    }),
  }));
  const processes = [];
  for (const l of (s.ps || '').split('\n')) { const m = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/.exec(l); if (m) processes.push({ pid: +m[1], ppid: +m[2], user: m[3], args: m[4] }); }
  const dbus = (s.dbus || '').split('\n').filter(l => l.startsWith('/')).map(l => { const [file, name] = l.split('\t'); return { file, name: name || '' }; });
  const st = line1('stat').split(' ');
  return {
    uid: parseInt(line1('uid'), 10),
    exec: ex[0] || null, exists: ex[1] === '1',
    pkg: pk[0] ? { name: pk[0], summary: pk[1] || '' } : null,
    files, config, units, socketUnits, sockets: parseSockets(s.ss), processes, dbus,
    cron: (s.cron || '').split('\n').filter(l => l.startsWith('/')),
    xinetd: (s.xinetd || '').split('\n').filter(l => l.startsWith('/')),
    libs: (s.libs || '').split('\n').map(l => l.trim()).filter(Boolean),
    fileCaps: [...(s.filecaps || '').matchAll(/\bcap_([a-z_]+)/g)].map(m => m[1]),
    ports: parseSemanagePorts(s.ports),
    owner: st[0] || null, mode: st[1] || null, label: st[2] || null,
    done: s.done != null,
  };
}

/* ---------- the draft ---------- */

const LEVEL_RANK = { none: 0, read: 1, append: 2, manage: 3, custom: 3 };
/** A unit's CapabilityBoundingSet is taken as the list of what the program needs only up to this many. */
const MAX_BOUNDING = 8;
const DEFAULT_ACCESS = { config: 'read', state: 'manage', log: 'append', runtime: 'manage', cache: 'manage', spool: 'manage', lock: 'manage', tmp: 'manage' };
/* Shared libraries that say what a program talks to: lib name prefix → access group id(s). */
const LIB_HINTS = [
  [/^libdbus-1\./, ['dbus']], [/^libpam\./, ['pam']], [/^libkrb5\./, ['kerberos']], [/^libgssapi_krb5\./, ['kerberos']],
  [/^libldap/, ['nsswitch']], [/^libsss_nss_idmap/, ['nsswitch']], [/^libssl\./, ['certs']], [/^libgnutls\./, ['certs']], [/^libnss3\./, ['certs']],
  [/^libcurl\./, ['dns', 'certs']], [/^libresolv\./, ['dns']], [/^libsystemd\./, ['syslog']],
];

const stem = (s) => String(s || '').toLowerCase().replace(/\.(service|socket|sh|py|pl|bin|conf|log|pid|sock|d)$/, '').replace(/[^a-z0-9]+/g, '_').replace(/^[^a-z]+/, '').replace(/_+$/, '');
/** Two names belong to the same program: equal, or one starts with the other (chrony/chronyd, httpd/http), 3+ characters. */
function sameProgram(a, b) {
  a = stem(a); b = stem(b);
  if (!a || !b || a.length < 3 || b.length < 3) return false;
  return a === b || a.startsWith(b) || b.startsWith(a);
}

/**
 * The facts mapped onto the model (a copy). Fills in what is empty or at the form's defaults and
 * adds to lists; never removes. Report rows: { field, text, from }.
 */
function draft(facts, model, opts = {}) {
  const m = JSON.parse(JSON.stringify(model));
  const report = [];
  const notes = [];
  const add = (field, text, from) => report.push({ field, text, from });
  const has = (n) => (opts.has ? opts.has(n) : true);
  const kinds = opts.fileKinds || [];
  const kind = (id) => kinds.find(k => k.id === id);
  if (!facts || !facts.exec) { notes.push('Nothing came back from the host.'); return { model: m, report, notes }; }
  if (!facts.exists) { notes.push(`${facts.exec} does not exist on the host.`); return { model: m, report, notes }; }
  const exec = facts.exec;

  // Units that run the program (ExecStart; a shell wrapper whose argv names it counts too).
  const runs = (e) => e.path === exec || (/\/(sh|bash|dash)$/.test(e.path) && e.argv.includes(exec));
  const units = facts.units.filter(u => u.execStart.some(runs));
  const unit = units[0] || null;
  const names = [...new Set([...units.map(u => stem(u.id)), facts.pkg ? stem(facts.pkg.name) : '', stem(exec.split('/').pop())].filter(Boolean))];

  // Name and summary.
  const chosen = (opts.name || m.name || '').trim();
  if (!chosen) {
    const taken = names.filter(n => opts.moduleExists && opts.moduleExists(n));
    const cand = names.find(n => !taken.includes(n));
    if (taken.length) notes.push(`A module named ${taken[0]} exists in this policy already: edit that one (Edit Service…) unless this is another program.`);
    if (cand) { m.name = cand; add('name', `Module name ${cand}`, unit && stem(unit.id) === cand ? `unit ${unit.id}` : facts.pkg && stem(facts.pkg.name) === cand ? `package ${facts.pkg.name}` : 'the program name'); }
  }
  const name = m.name || names[0] || '';
  if (!(m.summary || '').trim()) {
    const sum = unit && unit.description ? unit.description : facts.pkg ? facts.pkg.summary : '';
    if (sum) { m.summary = sum; add('summary', `Summary "${sum}"`, unit && unit.description ? `unit ${unit.id}` : `package ${facts.pkg.name}`); }
  }

  // Programs: the real path, plus other programs the units run that the same package owns.
  const pkgFiles = new Set(facts.files.map(f => f.path));
  const isDefaultExec = (m.exec || []).every(p => !p || /%/.test(p));
  if (isDefaultExec) m.exec = [];
  if (!m.exec.includes(exec)) { m.exec.push(exec); add('exec', `Program ${exec}`, facts.pkg ? `package ${facts.pkg.name}` : 'the host'); }
  for (const u of units) {
    for (const [what, list] of [['ExecStart', u.execStart], ['ExecStartPre', u.execPre], ['ExecStartPost', u.execPost], ['ExecReload', u.execReload], ['ExecStop', u.execStop]]) {
      for (const e of list) {
        if (e.path === exec || m.exec.includes(e.path)) continue;
        if (pkgFiles.has(e.path) && !/\/(sh|bash|dash)$/.test(e.path)) { m.exec.push(e.path); add('exec', `Program ${e.path} (also runs in the domain)`, `${u.id} ${what}`); }
        else if (what !== 'ExecStart') notes.push(`${u.id} ${what} runs ${e.path}: not part of the package, so it runs in systemd's domain, not the service's.`);
      }
    }
  }

  // Files: the package's files under the kinds' directories, named after the program; the unit's directories.
  const rowFor = (kid) => { let i = m.files.findIndex(r => r.kind === kid && !r.type); return i; };
  const putPath = (kid, p, from, access) => {
    const k = kind(kid);
    if (!k) return;
    let i = rowFor(kid);
    if (i < 0) { m.files.push({ kind: kid, paths: [], access: access || DEFAULT_ACCESS[kid] || (k.access || ['manage'])[0] }); i = m.files.length - 1; }
    const r = m.files[i];
    const dflt = (r.paths || []).every(x => /%/.test(x));
    if (dflt) r.paths = [];
    if (r.paths.includes(p) || r.paths.some(x => x.endsWith('/') && p.startsWith(x))) return;
    r.paths = r.paths.filter(x => !(p.endsWith('/') && x.startsWith(p)));
    r.paths.push(p);
    if (access && (LEVEL_RANK[r.access] || 0) < LEVEL_RANK[access] && r.access !== 'custom') r.access = access;
    add('files', `${k.label}: ${p}`, from);
  };
  const dirsOf = new Map(); // kind id → Set of top paths
  const under = (k, p) => k.where && p.startsWith(k.where + '/') ? p.slice(k.where.length + 1) : null;
  for (const f of facts.files) {
    if (f.kind === '-') continue;
    for (const k of kinds) {
      if (!k.where || k.where === 'tmpfs' || k.id === 'other') continue;
      const rest = under(k, f.path);
      if (!rest) continue;
      const first = rest.split('/')[0];
      if (!names.some(n => sameProgram(first, n))) continue;
      const top = `${k.where}/${first}`;
      const isDir = f.kind === 'd' || rest.includes('/');
      const p = isDir ? `${top}/` : f.path;
      if (!dirsOf.has(k.id)) dirsOf.set(k.id, new Map());
      dirsOf.get(k.id).set(p, isDir || dirsOf.get(k.id).get(p) || false);
    }
  }
  // Config files rpm marks as such, under /etc and named after the program (not /etc/logrotate.d/x, /etc/sysconfig/x: other programs read those).
  for (const [kid, paths] of dirsOf) {
    const from = facts.pkg ? `package ${facts.pkg.name}` : 'the host';
    for (const p of [...paths.keys()].sort()) {
      if (kid === 'config' && !p.endsWith('/') && !facts.config.has(p) && !/\.(conf|cfg|ini|keys|yaml|yml|json|toml)$/.test(p)) continue;
      putPath(kid, p, from);
    }
  }
  for (const u of units) {
    const from = `unit ${u.id}`;
    for (const d of u.runtimeDir) putPath('runtime', `/run/${d}/`, from);
    for (const d of u.stateDir) putPath('state', `/var/lib/${d}/`, from);
    for (const d of u.logsDir) putPath('log', `/var/log/${d}/`, from);
    for (const d of u.cacheDir) putPath('cache', `/var/cache/${d}/`, from);
    for (const d of u.confDir) putPath('config', `/etc/${d}/`, from);
    if (u.pidFile) { const dir = u.pidFile.replace(/\/[^/]+$/, ''); if (/^\/(run|var\/run)\//.test(dir)) putPath('runtime', `${dir.replace(/^\/var\/run/, '/run')}/`, `${from} PIDFile`); else notes.push(`${u.id} PIDFile=${u.pidFile} is outside /run: give it a file type by hand.`); }
    for (const p of u.rwPaths) {
      const k = kinds.find(k => k.where && k.where !== 'tmpfs' && k.id !== 'other' && (p === k.where || p.startsWith(k.where + '/')));
      if (k && p !== k.where) putPath(k.id, p.endsWith('/') ? p : `${p}/`, `${from} ReadWritePaths`, 'manage');
      else notes.push(`${u.id} ReadWritePaths=${p}: writable for the service; give it a file type if it is the service's own.`);
    }
    // The unit file itself, and the init script.
    if (u.fragment) {
      const i = m.files.findIndex(r => r.kind === 'unit');
      if (i >= 0 && (m.files[i].paths || []).every(x => /%/.test(x) || x === u.fragment)) { if (!m.files[i].paths.includes(u.fragment)) { m.files[i].paths = [u.fragment]; add('files', `systemd unit file ${u.fragment}`, from); } }
      else if (i >= 0 && !m.files[i].paths.includes(u.fragment)) { m.files[i].paths.push(u.fragment); add('files', `systemd unit file ${u.fragment}`, from); }
    }
  }
  for (const f of facts.files) if (/^\/etc\/rc\.d\/init\.d\//.test(f.path) && f.kind === 'f' && kind('initrc')) putPath('initrc', f.path, `package ${facts.pkg.name}`, 'none');
  for (const su of socketUnitsOf(facts, units)) if (su.fragment && kind('unit')) { const i = m.files.findIndex(r => r.kind === 'unit'); if (i >= 0 && !m.files[i].paths.includes(su.fragment)) { m.files[i].paths.push(su.fragment); add('files', `socket unit file ${su.fragment}`, `unit ${su.id}`); } }
  // Package directories the form has no kind for: said, not labeled.
  const other = new Set();
  for (const f of facts.files) {
    if (f.kind !== 'd') continue;
    const m2 = /^\/(usr\/share|usr\/lib(?:64)?|usr\/libexec|opt|srv|var\/www)\/([^/]+)$/.exec(f.path);
    if (m2 && names.some(n => sameProgram(m2[2], n))) other.add(f.path);
  }
  if (other.size) notes.push(`Left with their generic labels (read-only data and programs): ${[...other].sort().join(', ')}.`);

  // Network: the ports the running program listens on (its processes), socket units, and where it connects.
  const pids = new Set();
  for (const u of units) if (u.mainPid) pids.add(u.mainPid);
  for (const p of facts.processes) if (p.args === exec || p.args.startsWith(exec + ' ') || (unit && unit.mainPid && p.ppid === unit.mainPid)) pids.add(p.pid);
  // Port types with their numbers: the policy's (corenetwork), else what the host's semanage lists (standalone modules).
  const portTypes = (opts.ports && opts.ports.length ? opts.ports : facts.ports || []);
  const portTypeOf = (proto, port) => {
    for (const pt of portTypes) for (const n of pt.nums || []) {
      if (n.proto !== proto) continue;
      const r = /^(\d+)(?:-(\d+))?$/.exec(String(n.port));
      if (r && +r[1] <= port && port <= +(r[2] || r[1])) return pt.name;
    }
    return null;
  };
  const listenSeen = new Set(), connectSeen = new Set();
  const ownPort = (proto, port, from) => {
    // No port type for it: a port type of the service's own (standalone: declared in the module; tree: in corenetwork.te.in).
    const own = m.ports.find(p => !p.name || p.name === '%' || p.name === name);
    if (own) { if (!own.nums.some(n => n.proto === proto && String(n.port) === String(port))) own.nums.push({ proto, port: String(port), level: 's0' }); }
    else m.ports.push({ name: '', nums: [{ proto, port: String(port), level: 's0' }], _new: true });
    const pn = name || '%';
    if (!m.net.listen.some(x => x.proto === proto && x.port === pn)) m.net.listen.push({ proto, port: pn });
    add('net', `Listens on ${proto} ${port}: no port type has it, so a port type of its own (${pn}_port_t)`, from);
  };
  const listen = (proto, port, from) => {
    const key = `${proto}:${port}`;
    if (listenSeen.has(key)) return;
    listenSeen.add(key);
    const pt = portTypeOf(proto, port);
    if (pt) { if (!m.net.listen.some(x => x.proto === proto && x.port === pt)) m.net.listen.push({ proto, port: pt }); add('net', `Listens on ${proto} ${port} (${pt}_port_t)`, from); }
    else ownPort(proto, port, from);
    if (port < 1024 && !(unit && unit.user && unit.user !== 'root') && opts.capNames && opts.capNames.has('net_bind_service') && !m.caps.includes('net_bind_service')) { m.caps.push('net_bind_service'); add('caps', `Capability net_bind_service (port ${port} is below 1024)`, from); }
  };
  for (const s of facts.sockets) {
    if (!s.pids.some(p => pids.has(p))) continue;
    if (s.state === 'LISTEN' || (s.proto === 'udp' && s.state === 'UNCONN' && s.port)) listen(s.proto, s.port, `${s.proto} socket of pid ${s.pids[0]}`);
    else if (s.state === 'ESTAB' && s.peerPort) {
      const key = `${s.proto}:${s.peerPort}`;
      if (connectSeen.has(key) || s.peerPort >= 32768) continue;
      connectSeen.add(key);
      const pt = portTypeOf(s.proto, s.peerPort);
      if (pt) { if (!m.net.connect.some(x => x.proto === s.proto && x.port === pt)) m.net.connect.push({ proto: s.proto, port: pt }); add('net', `Connects to ${s.proto} ${s.peerPort} (${pt}_port_t)`, `connection of pid ${s.pids[0]}`); }
      else notes.push(`Connects to ${s.proto} port ${s.peerPort} (${s.peerAddr}): no port type has it; add one, or allow it by hand.`);
    }
  }
  for (const su of socketUnitsOf(facts, units)) for (const l of su.listen) if (l.port) listen(l.proto, l.port, `socket unit ${su.id}`);

  // Capabilities: file capabilities, what the unit grants or keeps.
  const capOk = (c) => opts.capNames ? opts.capNames.has(c) : true;
  for (const c of facts.fileCaps) if (capOk(c) && !m.caps.includes(c)) { m.caps.push(c); add('caps', `Capability ${c} (file capability of the program)`, 'getcap'); }
  for (const u of units) {
    for (const c of u.ambient) if (capOk(c) && !m.caps.includes(c)) { m.caps.push(c); add('caps', `Capability ${c}`, `${u.id} AmbientCapabilities`); }
    if (u.bounding && u.bounding.length <= MAX_BOUNDING) {
      // A unit that keeps only a few capabilities names what the program needs.
      const want = u.bounding.filter(capOk);
      for (const c of want) if (!m.caps.includes(c)) { m.caps.push(c); add('caps', `Capability ${c}`, `${u.id} CapabilityBoundingSet (the unit keeps only these)`); }
      const unknown = u.bounding.filter(c => !capOk(c));
      if (unknown.length) notes.push(`${u.id} keeps capabilities the form has no box for: ${unknown.join(', ')}; add them by hand if the program needs them.`);
    } else if (u.bounding) notes.push(`${u.id} keeps ${u.bounding.length} capabilities (${u.bounding.join(', ')}): too many to tick blindly; a permissive run shows which the program uses.`);
    if (u.user && u.user !== 'root') notes.push(`${u.id} runs as ${u.user}: systemd switches the user, so the domain needs no setuid/setgid for that.`);
    else if (!u.bounding && !u.ambient.length) notes.push(`${u.id} runs as root with every capability available: tick only the ones the program uses (a permissive run shows them).`);
    if (u.nnp && has('init_nnp_daemon_domain') && !m.access.includes('nnp')) { m.access.push('nnp'); add('access', 'Started with NoNewPrivileges (init_nnp_daemon_domain)', `${u.id} NoNewPrivileges=yes`); }
    if (u.privateTmp) notes.push(`${u.id} has PrivateTmp: /tmp is private to it (still tmp_t); add Temporary files if the program writes there.`);
  }

  // How it is started.
  const entries = m.entries || [];
  const hasEntry = (n) => entries.some(e => e.name === n);
  if (!units.length && facts.xinetd.length && has('inetd_tcp_service_domain')) {
    const i = entries.findIndex(e => /^init_/.test(e.name));
    if (i >= 0) entries.splice(i, 1);
    if (!hasEntry('inetd_tcp_service_domain')) entries.push({ name: 'inetd_tcp_service_domain', args: [] });
    add('starts', 'Started by inetd / xinetd', facts.xinetd.join(', '));
  }
  const busNames = [...new Set([...units.map(u => u.busName).filter(Boolean), ...facts.dbus.map(d => d.name).filter(Boolean)])];
  if ((busNames.length || facts.dbus.length) && has('dbus_system_domain')) {
    if (!hasEntry('dbus_system_domain')) { entries.push({ name: 'dbus_system_domain', args: [] }); add('starts', `Also: D-Bus activation${busNames.length ? ` (${busNames.join(', ')})` : ''}`, facts.dbus.length ? facts.dbus.map(d => d.file).join(', ') : `unit ${unit && unit.id}`); }
    if (has('dbus_system_bus_client') && !m.access.includes('dbus')) { m.access.push('dbus'); add('access', 'Uses the D-Bus system bus', busNames.length ? `bus name ${busNames[0]}` : 'D-Bus service file'); }
  } else if (busNames.length && !m.access.includes('dbus') && has('dbus_system_bus_client')) { m.access.push('dbus'); add('access', 'Uses the D-Bus system bus', `bus name ${busNames[0]}`); }
  if (facts.cron.length && has('cron_system_entry') && !hasEntry('cron_system_entry')) { entries.push({ name: 'cron_system_entry', args: [] }); add('starts', 'Also: run by cron', facts.cron.join(', ')); }
  m.entries = entries;
  if (!units.length && !facts.xinetd.length) notes.push(`No systemd unit runs ${exec} on the host${facts.processes.some(p => p.args === exec || p.args.startsWith(exec + ' ')) ? ' (it is running, started some other way)' : ''}: "Started by" is left as systemd.`);

  // Shared libraries: what the program talks to.
  const libHits = new Map();
  for (const l of facts.libs) { const b = l.split('/').pop(); for (const [re, ids] of LIB_HINTS) if (re.test(b)) for (const id of ids) if (!libHits.has(id)) libHits.set(id, b); }
  const ACCESS_IF = { dbus: 'dbus_system_bus_client', pam: 'auth_use_pam', kerberos: 'kerberos_use', nsswitch: 'auth_use_nsswitch', certs: 'miscfiles_read_generic_certs', dns: 'sysnet_dns_name_resolve', syslog: 'logging_send_syslog_msg' };
  for (const [id, lib] of libHits) {
    if (m.access.includes(id) || !has(ACCESS_IF[id])) continue;
    if (id === 'pam' && !(unit || facts.xinetd.length)) continue;
    m.access.push(id);
    add('access', `${({ dbus: 'Uses the D-Bus system bus', pam: 'Authenticates users with PAM', kerberos: 'Uses Kerberos', nsswitch: 'Looks up users, groups and host names', certs: 'Reads TLS certificates', dns: 'Resolves host names with DNS', syslog: 'Writes to the system log' })[id]}`, `library ${lib}`);
  }
  if (libHits.has('certs') && has('dev_read_urand') && !m.access.includes('urandom')) { m.access.push('urandom'); add('access', 'Reads /dev/urandom (TLS)', `library ${libHits.get('certs')}`); }

  if (!facts.done) notes.push('The look at the host did not run to its end; some facts may be missing.');
  if (facts.uid !== 0) notes.push('Not root on the host: ports are known only for processes of that user, and some files may be invisible.');
  return { model: m, report, notes };
}

/** Socket units that trigger one of the service's units. */
function socketUnitsOf(facts, units) {
  const ids = new Set(units.map(u => u.id));
  const trig = new Set(units.flatMap(u => u.triggeredBy));
  return facts.socketUnits.filter(su => trig.has(su.id) || su.triggers.some(t => ids.has(t)));
}

module.exports = { prefillScript, parsePrefill, parseSemanagePorts, draft, MAX_BOUNDING, splitSections, showBlocks, execEntries, capSet, parseSockets, sameProgram, stem, shq, PATH_DIRS, LIB_HINTS, DEFAULT_ACCESS };
