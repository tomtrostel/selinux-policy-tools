'use strict';
/*
 * Service editor: a system service's policy module described as a simple
 * model (a daemon domain started by init, the files it owns, the network
 * ports it uses, capabilities, common system access and other interfaces),
 * rendered as refpolicy .te/.if/.fc text, and read back from an existing
 * module.
 *
 * Editing an existing module is driven by what changed in the model, never
 * by regenerating the files: every setting is a "unit" producing statements;
 * only units the user added, removed or changed insert or delete lines, and
 * everything the model doesn't describe is left exactly as it is.
 *
 * Pure functions over texts plus a context `ctx`:
 *   has(name)        interface/macro exists in this tree
 *   optional(name)   calls to it belong in optional_policy (module may be off)
 *   moduleArgs       1 when policy_module() takes only the name (upstream), else 2
 */

const { parsePolicy } = require('./parser');

/* ---------- catalog ---------- */

// Files the service owns. decl: [helper, type suffix] alternatives (first that exists).
const FILE_KINDS = [
  { id: 'runtime', label: 'Runtime files', where: '/run', decl: [['files_runtime_file', '_runtime_t'], ['files_pid_file', '_var_run_t']],
    filetrans: ['files_runtime_filetrans', 'files_pid_filetrans'], ftClasses: '{ dir file sock_file }', extra: ['manage_sock_files_pattern'],
    path: '/run/%/', access: ['manage', 'read', 'none'], search: ['files_search_runtime', 'files_search_pids'] },
  { id: 'state', label: 'State data', where: '/var/lib', decl: [['files_type', '_var_lib_t']],
    filetrans: ['files_var_lib_filetrans'], ftClasses: 'dir', extra: ['manage_lnk_files_pattern'],
    path: '/var/lib/%/', access: ['manage', 'read', 'none'], search: ['files_search_var_lib'] },
  { id: 'log', label: 'Log files', where: '/var/log', decl: [['logging_log_file', '_log_t']],
    filetrans: ['logging_log_filetrans'], ftClasses: '{ dir file }',
    path: '/var/log/%/', access: ['append', 'manage', 'read', 'none'], search: ['logging_search_logs'] },
  { id: 'config', label: 'Configuration', where: '/etc', decl: [['files_config_file', '_conf_t']],
    path: '/etc/%/', access: ['read', 'manage', 'none'], search: ['files_search_etc'] },
  { id: 'cache', label: 'Cache', where: '/var/cache', decl: [['files_type', '_cache_t']],
    path: '/var/cache/%/', access: ['manage', 'read', 'none'], search: ['files_search_var'] },
  { id: 'spool', label: 'Spool', where: '/var/spool', decl: [['files_spool_file', '_spool_t'], ['files_type', '_spool_t']],
    filetrans: ['files_spool_filetrans'], ftClasses: 'dir',
    path: '/var/spool/%/', access: ['manage', 'read', 'none'], search: ['files_search_spool'] },
  { id: 'tmp', label: 'Temporary files', where: '/tmp', decl: [['files_tmp_file', '_tmp_t']],
    filetrans: ['files_tmp_filetrans'], ftClasses: '{ dir file }', access: ['manage', 'none'], search: ['files_search_tmp'] },
  { id: 'tmpfs', label: 'Shared memory', where: 'tmpfs', decl: [['files_tmpfs_file', '_tmpfs_t']],
    filetrans: ['fs_tmpfs_filetrans'], ftClasses: '{ dir file }', access: ['manage', 'none'] },
  { id: 'lock', label: 'Lock files', where: '/run/lock', decl: [['files_lock_file', '_lock_t']],
    filetrans: ['files_lock_filetrans'], ftClasses: 'file', access: ['manage', 'none'] },
  { id: 'other', label: 'Other files', where: '', decl: [['files_type', '_data_t']], path: '', access: ['read', 'manage', 'none'] },
  // Labels only: the domain gets no access.
  { id: 'unit', label: 'systemd unit file', where: '', decl: [['systemd_unit_file', '_unit_file_t'], ['init_unit_file', '_unit_t']],
    path: '/usr/lib/systemd/system/%.service', access: ['none'], file: true },
  { id: 'initrc', label: 'SysV init script', where: '', decl: [['init_script_file', '_initrc_exec_t']],
    path: '/etc/rc.d/init.d/%', access: ['none'], file: true },
];
const KIND = Object.fromEntries(FILE_KINDS.map(k => [k.id, k]));

const ACCESS_LABELS = { manage: 'create, change and delete', append: 'create and append (no rewriting)', read: 'read only', none: 'label only (no access)' };

// Common system access: [label, calls (each a list of alternative names), hint].
const ACCESS_GROUPS = [
  ['Logging', [
    ['syslog', 'Write to the system log (syslog, journal)', [['logging_send_syslog_msg']]],
    ['audit', 'Send audit messages', [['logging_send_audit_msgs']]],
  ]],
  ['Users and names', [
    ['nsswitch', 'Look up users, groups and host names (nsswitch: files, SSSD, LDAP, DNS)', [['auth_use_nsswitch']]],
    ['passwd', 'Read /etc/passwd and /etc/group only', [['auth_read_passwd']]],
    ['dns', 'Resolve host names with DNS', [['sysnet_dns_name_resolve']]],
    ['netconf', 'Read network configuration (/etc/hosts, resolv.conf)', [['sysnet_read_config']]],
    ['pam', 'Authenticate users with PAM', [['auth_use_pam']]],
    ['kerberos', 'Use Kerberos', [['kerberos_use']]],
  ]],
  ['System information', [
    ['sysstate', 'Read system state in /proc (meminfo, cpuinfo, mounts)', [['kernel_read_system_state']]],
    ['netstate', 'Read network state in /proc/net', [['kernel_read_network_state']]],
    ['sysctl', 'Read kernel settings (sysctl)', [['kernel_read_kernel_sysctls']]],
    ['netsysctl', 'Read network settings (net sysctl)', [['kernel_read_net_sysctls']]],
    ['sysfs', 'Read /sys', [['dev_read_sysfs']]],
    ['fsinfo', 'See file system usage (statfs, df)', [['fs_getattr_all_fs']]],
    ['utmp', 'Read who is logged in (utmp)', [['init_read_utmp']]],
  ]],
  ['Files and devices', [
    ['locale', 'Read locale and time zone data', [['miscfiles_read_localization']]],
    ['certs', 'Read TLS certificates', [['miscfiles_read_generic_certs']]],
    ['etcfiles', 'Read general files in /etc', [['files_read_etc_files']]],
    ['etcruntime', 'Read runtime files in /etc (mtab and similar)', [['files_read_etc_runtime_files']]],
    ['urandom', 'Read /dev/urandom', [['dev_read_urand']]],
    ['random', 'Read /dev/random', [['dev_read_rand']]],
    ['automount', 'Search automount points', [['fs_search_auto_mountpoints']]],
  ]],
  ['Programs', [
    ['bin', 'Run ordinary programs (/usr/bin), staying in this domain', [['corecmd_exec_bin']]],
    ['shell', 'Run shell scripts', [['corecmd_exec_shell']]],
    ['systemctl', 'Run systemctl', [['systemd_exec_systemctl']]],
    ['kmod', 'Ask the kernel to load modules', [['kernel_request_load_module']]],
  ]],
  ['Other services', [
    ['dbus', 'Use the D-Bus system bus', [['dbus_system_bus_client']]],
    ['mail', 'Send mail', [['mta_send_mail']]],
  ]],
  ['Started by systemd', [
    ['nnp', 'Allow starting with NoNewPrivileges (systemd hardening options)', [['init_nnp_daemon_domain']]],
    ['ttyfds', 'Use descriptors inherited from the session that started it', [['domain_use_interactive_fds']]],
    ['homequiet', 'Quietly refuse to search home directories (no audit noise)', [['userdom_dontaudit_search_user_home_dirs']]],
  ]],
];
const ACCESS = Object.fromEntries(ACCESS_GROUPS.flatMap(([, items]) => items.map(([id, label, calls]) => [id, { id, label, calls }])));

// Rules on the domain's own processes and sockets: class -> perms.
const SELF = [
  ['fifo', 'Use pipes between its own processes', { fifo_file: ['rw_fifo_file_perms'] }],
  ['signal', 'Send signals to its own processes', { process: ['signal_perms'] }],
  ['unixstream', 'Unix stream sockets (connect and listen)', { unix_stream_socket: ['create_stream_socket_perms'] }],
  ['unixdgram', 'Unix datagram sockets', { unix_dgram_socket: ['create_socket_perms'] }],
  ['sched', 'Change its own scheduling (priority, CPU affinity)', { process: ['getsched', 'setsched'] }],
  ['rlimit', 'Change its own resource limits', { process: ['setrlimit'] }],
  ['shm', 'Shared memory and semaphores (System V IPC)', { shm: ['create_shm_perms'], sem: ['create_sem_perms'] }],
  ['netlink', 'Read network interfaces and routes (netlink)', { netlink_route_socket: ['r_netlink_socket_perms'] }],
  ['execmem', 'Generate code at run time (JIT, execmem)', { process: ['execmem'] }, true],
];
const SELF_BY = Object.fromEntries(SELF.map(([id, label, perms, risky]) => [id, { id, label, perms, risky: !!risky }]));

// Linux capabilities: [name, class, description, risky].
const CAPS = [
  ['setuid', 'capability', 'Switch to another user (drop root)'],
  ['setgid', 'capability', 'Switch to another group'],
  ['chown', 'capability', 'Change file owners'],
  ['fowner', 'capability', 'Ignore file ownership checks (chmod others’ files)'],
  ['fsetid', 'capability', 'Keep setuid/setgid bits when changing files'],
  ['dac_read_search', 'capability', 'Read and search files regardless of permissions'],
  ['dac_override', 'capability', 'Write files regardless of permissions', true],
  ['kill', 'capability', 'Signal processes of other users'],
  ['net_bind_service', 'capability', 'Bind ports below 1024'],
  ['net_admin', 'capability', 'Configure network interfaces, routes, firewall', true],
  ['net_raw', 'capability', 'Use raw and packet sockets (ping, sniffing)', true],
  ['ipc_lock', 'capability', 'Lock memory (mlock)'],
  ['sys_nice', 'capability', 'Raise priorities, real-time scheduling'],
  ['sys_resource', 'capability', 'Exceed resource limits'],
  ['sys_time', 'capability', 'Set the system clock'],
  ['sys_chroot', 'capability', 'Use chroot'],
  ['sys_tty_config', 'capability', 'Configure terminals'],
  ['setpcap', 'capability', 'Change process capabilities'],
  ['audit_write', 'capability', 'Write audit records'],
  ['sys_ptrace', 'capability', 'Trace other processes', true],
  ['sys_rawio', 'capability', 'Raw I/O to devices and ports', true],
  ['sys_admin', 'capability', 'Broad system administration (mount, namespaces, …)', true],
  ['block_suspend', 'capability2', 'Prevent system suspend'],
  ['wake_alarm', 'capability2', 'Set wake-up alarms'],
];
const CAP_CLASS = Object.fromEntries(CAPS.map(c => [c[0], c[1]]));

// Interfaces the module offers to others (in its .if). %=module name.
const PROVIDES = [
  ['domtrans', '%_domtrans', 'Run the service’s program in its domain'],
  ['exec', '%_exec', 'Run the service’s program in the caller’s domain'],
  ['read_config', '%_read_config', 'Read its configuration', 'config'],
  ['read_log', '%_read_log', 'Read its logs', 'log'],
  ['read_lib_files', '%_read_lib_files', 'Read its state data', 'state'],
  ['manage_lib_files', '%_manage_lib_files', 'Manage its state data', 'state'],
  ['stream_connect', '%_stream_connect', 'Connect to its Unix socket', 'runtime'],
  ['admin', '%_admin', 'Administer the service (signal it, manage all its files)'],
];

/* ---------- small helpers ---------- */

const normArgs = (args) => args.map(a => {
  const t = a.replace(/\s+/g, ' ').trim();
  const m = /^\{(.*)\}$/.exec(t);
  return m ? `{ ${m[1].trim().split(/\s+/).sort().join(' ')} }` : t;
});
const callKey = (name, args) => `call:${name}(${normArgs(args).join(',')})`;
const callText = (name, args) => `${name}(${args.join(', ')})`;
const pick = (ctx, alts) => (alts || []).find(n => ctx.has(n)) || null;
const sub = (s, name) => (s || '').replace(/%/g, name);
const RX_SPECIAL = /[\\()[\]{}*+?|^$]/;

/** fc spec ⇄ the path shown in the editor: `/var/lib/foo/` = the directory and everything in it. */
function fcFromPath(p) {
  if (RX_SPECIAL.test(p)) return { spec: p };
  const esc = (s) => s.replace(/\./g, '\\.');
  if (p.endsWith('/') && p.length > 1) return { spec: `${esc(p.slice(0, -1))}(/.*)?` };
  return { spec: esc(p), file: true };
}
function pathFromFc(spec) {
  const simple = (s) => /^(?:[\w/@:-]|\\\.)+$/.test(s);
  const unesc = (s) => s.replace(/\\\./g, '.');
  const m = /^(.*)\(\/\.\*\)\?$/.exec(spec);
  if (m && simple(m[1])) return unesc(m[1]) + '/';
  if (simple(spec)) return unesc(spec);
  return spec;
}

/* ---------- units: what each setting generates ---------- */

/** The resolved names for a model: domain, exec type, file types. */
function names(model) {
  const n = model.name;
  return { D: model.domain || `${n}_t`, E: model.execType || `${n}_exec_t` };
}
function fileType(model, row, ctx) {
  if (row.type) return sub(row.type, model.name);
  const k = KIND[row.kind];
  const alt = k.decl.find(([h]) => ctx.has(h)) || k.decl[0];
  return `${model.name}${alt[1]}`;
}

// Statements inside tunable_policy(`b', ...) have keys of their own: the same call
// at the top level and under a boolean are different statements.
const scoped = (bool, key) => (bool ? `b:${bool}:${key}` : key);

/** The doc comment refpolicy puts above gen_tunable() (shown by semanage boolean -l). */
function tunableDoc(desc) {
  const words = (desc || '').replace(/\s+/g, ' ').trim().split(' ').filter(Boolean);
  const lines = [];
  let cur = '';
  for (const w of words) { if (cur && (cur + ' ' + w).length > 66) { lines.push(cur); cur = w; } else cur = cur ? `${cur} ${w}` : w; }
  if (cur) lines.push(cur);
  return ['## <desc>', '##\t<p>', ...(lines.length ? lines : ['(no description)']).map(l => `##\t${l}`), '##\t</p>', '## </desc>'];
}
function descFromDoc(lines) {
  return lines.map(l => l.replace(/^\s*#+\s?/, '')).join(' ').replace(/<\/?(desc|p)>/g, ' ').replace(/\s+/g, ' ').trim();
}

/**
 * Units of a model: key -> { sig, stmts }. A statement is
 * { key, kind: 'type'|'call'|'self'|'permissive'|'tunable', text, section: 'decl'|'local', opt, bool, group }.
 */
function unitsOf(model, ctx) {
  const units = new Map();
  const { D, E } = names(model);
  const add = (key, sig, stmts) => units.set(key, { sig: JSON.stringify(sig), stmts });
  const call = (name, args, section = 'local', group = null, bool = null) => ({ key: scoped(bool, callKey(name, args)), kind: 'call', name, args, text: callText(name, args), section, opt: section === 'local' && ctx.optional(name), group, bool });
  const type = (t) => ({ key: `type:${t}`, kind: 'type', text: `type ${t};`, section: 'decl' });

  add('domain', { D, E }, [type(D), type(E), call('init_daemon_domain', [D, E], 'decl')]);
  if (model.permissive) add('permissive', 1, [{ key: 'permissive', kind: 'permissive', text: `permissive ${D};`, section: 'decl' }]);

  for (const row of model.files || []) {
    const k = KIND[row.kind];
    if (!k) continue;
    const T = fileType(model, row, ctx);
    const decl = (k.decl.find(([h]) => ctx.has(h)) || k.decl[0])[0];
    const st = [type(T), call(decl, [T], 'decl')];
    const g = `file:${T}`;
    const pat = (p) => call(p, [D, T, T], 'local', g);
    const ft = pick(ctx, k.filetrans);
    const acc = row.access || k.access[0];
    if (acc === 'read') st.push(pat('list_dirs_pattern'), pat('read_files_pattern'), pat('read_lnk_files_pattern'));
    if (acc === 'append') st.push(pat('manage_dirs_pattern'), pat('append_files_pattern'), pat('create_files_pattern'), pat('setattr_files_pattern'));
    if (acc === 'manage') {
      st.push(pat('manage_dirs_pattern'), pat('manage_files_pattern'));
      for (const e of k.extra || []) st.push(pat(e));
    }
    if ((acc === 'manage' || acc === 'append') && ft) st.push(call(ft, [D, T, k.ftClasses], 'local', g));
    add(`file:${T}`, { kind: row.kind, access: acc }, st.map(s => (s.opt ? { ...s, opt: false } : s)));
  }

  grantUnits(model, '', null);
  // Booleans: the declaration (unless it is declared elsewhere, like use_nfs_home_dirs),
  // and what it grants inside tunable_policy.
  for (const b of model.booleans || []) {
    if (!b.name) continue;
    const name = sub(b.name, model.name);
    if (!b.external) {
      const def = b.default ? 'true' : 'false';
      add(`tunable:${name}`, { def, desc: (b.desc || '').replace(/\s+/g, ' ').trim() }, [{
        key: callKey('gen_tunable', [name, def]), kind: 'tunable', name, text: [...tunableDoc(b.desc), callText('gen_tunable', [name, def])].join('\n'), section: 'decl',
      }]);
    }
    grantUnits(b.grants || {}, `b:${name}:`, name);
  }
  return units;

  /** Units for what the domain is granted, at the top level (bool null) or under a boolean. */
  function grantUnits(g, prefix, bool) {
    const self = (cls, perm) => ({ key: scoped(bool, `self:${cls}:${perm}`), kind: 'self', cls, perm, section: 'local', bool });
    const dcall = (name, group) => call(name, [D], 'local', group, bool);
    for (const id of g.self || []) {
      const s = SELF_BY[id];
      if (!s) continue;
      add(`${prefix}self:${id}`, 1, Object.entries(s.perms).flatMap(([cls, ps]) => ps.map(p => self(cls, p))));
    }
    for (const c of g.caps || []) add(`${prefix}cap:${c}`, 1, [self(CAP_CLASS[c] || 'capability', c)]);

    // Network: generic node/interface rules are shared, so they stay while any port needs them.
    const net = g.net || {};
    for (const dir of ['listen', 'connect']) {
      for (const it of net[dir] || []) {
        const { proto, port } = it;
        if (!port) continue; // a row still being filled in
        const st = [];
        const opt = (n) => { if (ctx.has(n)) st.push(dcall(n, 'net')); };
        // Sockets and generic node/interface rules stay at the top level even for a port under a boolean.
        const shared = (n) => { if (ctx.has(n)) st.push(call(n, [D], 'local', 'net', null)); };
        st.push({ ...(proto === 'udp' ? self('udp_socket', 'create_socket_perms') : self('tcp_socket', 'create_stream_socket_perms')), bool: null, key: `self:${proto === 'udp' ? 'udp_socket:create_socket_perms' : 'tcp_socket:create_stream_socket_perms'}` });
        shared(`corenet_${proto}_sendrecv_generic_if`);
        shared(`corenet_${proto}_sendrecv_generic_node`);
        if (port === 'all') {
          opt(dir === 'listen' ? `corenet_${proto}_bind_all_ports` : proto === 'tcp' ? 'corenet_tcp_connect_all_ports' : 'corenet_udp_sendrecv_all_ports');
        } else if (dir === 'listen') {
          shared(`corenet_${proto}_bind_generic_node`);
          opt(`corenet_${proto}_bind_${port}_port`);
          opt(`corenet_sendrecv_${port}_server_packets`);
        } else {
          opt(proto === 'tcp' ? `corenet_tcp_connect_${port}_port` : `corenet_udp_sendrecv_${port}_port`);
          opt(`corenet_sendrecv_${port}_client_packets`);
        }
        add(`${prefix}net:${dir}:${proto}:${port}`, 1, st);
      }
    }

    for (const id of g.access || []) {
      const a = ACCESS[id];
      if (!a) continue;
      add(`${prefix}access:${id}`, 1, a.calls.map(alts => pick(ctx, alts)).filter(Boolean).map(n => dcall(n)));
    }
    for (const n of g.extra || []) add(`${prefix}extra:${n}`, 1, [dcall(n)]);
  }
}

/* ---------- reading an existing .te ---------- */

const BLOCK_CALLS = new Set(['optional_policy', 'tunable_policy', 'ifdef', 'ifndef', 'ifelse', 'gen_require', 'interface', 'template', 'define', 'require']);

/** tunable_policy(`b', `...') on one boolean, without an else branch: its body is editable. */
const plainTunable = (b) => b.name === 'tunable_policy' && b.args.length === 2 && /^\w+$/.test(b.args[0]);

/**
 * Statements of a .te, with where they are. Editable statements are at the
 * top level, directly inside one optional_policy block (opt), directly inside
 * a plain tunable_policy block (bool, tun), or in optional_policy >
 * tunable_policy (both). The rest are reported as kept-as-is.
 */
function scanTe(text) {
  const p = parsePolicy(text);
  const lines = text.split('\n');
  // Brace depth at the start of each line (if/else blocks, require blocks).
  const depth = [];
  let d = 0;
  for (const ln of lines) {
    depth.push(d);
    const code = ln.replace(/#.*$/, '');
    for (const ch of code) { if (ch === '{') d++; else if (ch === '}') d = Math.max(0, d - 1); }
  }
  const blocks = p.calls.filter(c => BLOCK_CALLS.has(c.name));
  const inside = (b, l) => l > b.l && l <= b.endL;
  const where = (l) => {
    const around = blocks.filter(b => inside(b, l)).sort((a, b) => a.l - b.l); // outermost first
    if (depth[l] > 0 && !around.length) return { top: false };
    if (!around.length) return { top: true };
    const [a, b] = around;
    if (around.length === 1 && a.name === 'optional_policy') return { top: false, opt: a };
    if (around.length === 1 && plainTunable(a)) return { top: false, bool: a.args[0], tun: a };
    if (around.length === 2 && a.name === 'optional_policy' && plainTunable(b)) return { top: false, opt: a, bool: b.args[0], tun: b };
    return { top: false };
  };
  const stmts = [];
  for (const c of p.calls) {
    if (BLOCK_CALLS.has(c.name) || c.inDef) continue;
    const w = where(c.l);
    stmts.push({ kind: 'call', name: c.name, args: c.args, key: scoped(w.bool, callKey(c.name, c.args)), l: c.l, endL: c.endL, ...w });
  }
  // Rules and declarations written in the policy language.
  lines.forEach((ln, l) => {
    const code = ln.replace(/#.*$/, '').trim();
    let m;
    if ((m = /^type\s+(\w+)\b[^;]*;/.exec(code))) stmts.push({ kind: 'type', name: m[1], key: `type:${m[1]}`, l, endL: l, ...where(l) });
    else if ((m = /^permissive\s+(\w+)\s*;/.exec(code))) stmts.push({ kind: 'permissive', name: m[1], key: `permissive:${m[1]}`, l, endL: l, ...where(l) });
    else if ((m = /^allow\s+(\w+)\s+([\w-]+)\s*:\s*(\w+)\s+(\{[^}]*\}|[\w-]+)\s*;$/.exec(code))) {
      const perms = m[4].replace(/[{}]/g, ' ').trim().split(/\s+/);
      stmts.push({ kind: 'allow', src: m[1], tgt: m[2], cls: m[3], perms, l, endL: l, ...where(l) });
    } else if (/^(allow|dontaudit|auditallow|type_transition|neverallow)\b/.test(code)) {
      let e = l;
      while (e < lines.length - 1 && !/;\s*(#.*)?$/.test(lines[e])) e++;
      stmts.push({ kind: 'rule', text: code, l, endL: e, ...where(l) });
    }
  });
  return { parse: p, lines, stmts, blocks };
}

/** Daemon domains of a module: init_daemon_domain(D, E) calls in its .te. */
function daemonDomains(teText) {
  return parsePolicy(teText).calls.filter(c => c.name === 'init_daemon_domain' && !c.inDef && c.args.length >= 2)
    .map(c => ({ domain: c.args[0], exec: c.args[1] }));
}

function parseFcLines(text) {
  const out = [];
  (text || '').split('\n').forEach((ln, l) => {
    const m = /^\s*(\S+)\s+(?:(-[-dlbcsp])\s+)?gen_context\(\s*\w+:\w+:(\w+)/.exec(ln);
    if (m && !ln.trim().startsWith('#')) out.push({ spec: m[1], ftype: m[2] || '', type: m[3], l });
  });
  return out;
}

/**
 * The model of an existing module, from its texts.
 * Returns { model, own, kept, domains, provided } where own maps unit keys to
 * the extra statements that belong to them (rules on a file type that the
 * model doesn't generate itself, so removing the file type removes them too).
 */
function recognize(texts, ctx, opts = {}) {
  const te = scanTe(texts.te || '');
  const domains = daemonDomains(texts.te || '');
  const mod = te.parse.module || opts.module;
  if (!domains.length) return { error: `${mod}.te has no init_daemon_domain() call, so it isn't a service module the editor understands.` };
  const dom = domains.find(x => x.domain === opts.domain) || domains.find(x => x.domain === `${mod}_t`) || domains[0];
  const D = dom.domain, E = dom.exec;
  const editable = te.stmts.filter(s => s.top || s.opt || s.bool);
  const claimed = new Set();
  const own = new Map();
  const ownAdd = (u, s) => { if (!own.has(u)) own.set(u, []); own.get(u).push(s); claimed.add(s); };
  const fc = parseFcLines(texts.fc);
  const pathsOf = (T) => fc.filter(e => e.type === T).map(e => pathFromFc(e.spec));
  const model = { name: mod, domain: D, execType: E, summary: '', exec: pathsOf(E), files: [], self: [], caps: [], net: { listen: [], connect: [] }, access: [], extra: [], permissive: false };
  const m = /^##\s*<summary>\s*([^<]*?)\s*(<\/summary>)?\s*$/m.exec(texts.if || '');
  if (m) model.summary = m[1];
  const claim = (pred) => { for (const s of editable) if (!claimed.has(s) && pred(s)) claimed.add(s); };
  claim(s => s.kind === 'type' && (s.name === D || s.name === E));
  claim(s => s.kind === 'call' && s.name === 'init_daemon_domain' && s.args[0] === D);

  // Owned file types: declared here, with a known declaration helper.
  const helperKinds = new Map(); // declaration helper -> [{ k, suffix }]
  for (const k of FILE_KINDS) {
    for (const [h, suffix] of k.decl) {
      if (!helperKinds.has(h)) helperKinds.set(h, []);
      helperKinds.get(h).push({ k, suffix });
    }
  }
  for (const t of editable.filter(s => s.kind === 'type' && s.top && s.name !== D && s.name !== E)) {
    const helper = editable.find(s => s.kind === 'call' && s.top && s.args.length === 1 && s.args[0] === t.name && helperKinds.has(s.name));
    if (!helper) continue;
    const cands = helperKinds.get(helper.name);
    const k = (cands.find(c => t.name.endsWith(c.suffix)) || cands.find(c => c.k.id === 'other') || cands[0]).k;
    const T = t.name, u = `file:${T}`;
    const pats = new Set(editable.filter(s => s.kind === 'call' && !s.bool && s.args[0] === D && s.args[1] === T && s.args[2] === T).map(s => s.name));
    let access = 'none';
    if (pats.has('manage_files_pattern')) access = 'manage';
    else if (pats.has('append_files_pattern')) access = 'append';
    else if (pats.has('read_files_pattern')) access = 'read';
    model.files.push({ kind: k.id, type: T, paths: pathsOf(T), access });
    ownAdd(u, t);
    // Declaration helpers on the type, rules from the domain to it.
    for (const s of editable) {
      if (claimed.has(s) || s.bool) continue; // rules under a boolean stay with the boolean
      if (s.kind === 'call' && s.top && s.args[0] === T) ownAdd(u, s);
      else if (s.kind === 'call' && s.args[0] === D && s.args.slice(1).includes(T) && /(_pattern|filetrans)$/.test(s.name)) ownAdd(u, s);
      else if (s.kind === 'allow' && s.src === D && s.tgt === T) ownAdd(u, s);
    }
  }

  if (editable.some(s => s.kind === 'permissive' && s.name === D)) { model.permissive = true; claim(s => s.kind === 'permissive' && s.name === D); }

  // Booleans declared here (gen_tunable with its doc comment above), then those only used here.
  model.booleans = [];
  const boolOf = new Map();
  for (const s of editable.filter(x => x.kind === 'call' && x.top && x.name === 'gen_tunable' && /^\w+$/.test(x.args[0] || ''))) {
    let a = s.l;
    // The ## doc lines, also across a lone "#" right below them (zebra.te), but not a section header.
    while (a > 0 && (/^\s*##/.test(te.lines[a - 1]) || (/^\s*#\s*$/.test(te.lines[a - 1]) && /^\s*##/.test(te.lines[a - 2] || '')))) a--;
    const b = { name: s.args[0], desc: descFromDoc(te.lines.slice(a, s.l)), default: s.args[1] === 'true', external: false, grants: emptyGrants() };
    model.booleans.push(b);
    boolOf.set(b.name, b);
    ownAdd(`tunable:${b.name}`, s);
    if (a < s.l) ownAdd(`tunable:${b.name}`, { kind: 'comment', l: a, endL: s.l - 1 });
  }
  for (const s of editable) {
    if (!s.bool || boolOf.has(s.bool) || !mentionsD(s)) continue;
    const b = { name: s.bool, desc: '', default: false, external: true, grants: emptyGrants() };
    model.booleans.push(b);
    boolOf.set(b.name, b);
  }

  // What the domain is granted, at the top level and under each boolean.
  grantsIn(model, null, '');
  for (const b of model.booleans) grantsIn(b.grants, b.name, `b:${b.name}:`);

  // Network statements the model generates are claimed through the units; the rest of the single-argument calls are "other interfaces".
  const gen = new Set();
  for (const u of unitsOf(model, ctx).values()) for (const s of u.stmts) gen.add(s.key);
  claim(s => gen.has(s.key) || (s.kind === 'type' && gen.has(`type:${s.name}`)));
  // Generic network rules are shared by all port items; without a port item that generates them they stay as they are.
  const generic = (n) => /^corenet_(tcp|udp)_(sendrecv_generic_(if|node)|bind_generic_node)$/.test(n);
  for (const s of editable) {
    if (claimed.has(s) || s.kind !== 'call' || s.args.length !== 1 || s.args[0] !== D || generic(s.name)) continue;
    const g = s.bool ? boolOf.get(s.bool).grants : model;
    if (!g.extra.includes(s.name)) g.extra.push(s.name);
    claimed.add(s);
  }

  // Everything else that mentions the domain stays as it is.
  const kept = [];
  // Rules on itself with permissions no setting stands for: shown, and never touched.
  const modelled = new Set();
  for (const u of unitsOf(model, ctx).values()) for (const s of u.stmts) if (s.kind === 'self') modelled.add(scoped(s.bool, `${s.cls}:${s.perm}`));
  for (const s of editable) {
    if (isSelf(s) && s.perms.some(p => !modelled.has(scoped(s.bool, `${s.cls}:${p}`)))) claimed.delete(s);
  }
  for (const s of te.stmts) if (!claimed.has(s) && mentionsD(s)) kept.push({ l: s.l, endL: s.endL, text: te.lines.slice(s.l, s.endL + 1).map(x => x.trim()).join(' ') });
  kept.sort((a, b) => a.l - b.l);
  const provided = (texts.if ? parsePolicy(texts.if).defs.map(d => d.name) : []);
  return { model, own, kept, domains, provided, scan: te };

  function emptyGrants() { return { self: [], caps: [], net: { listen: [], connect: [] }, access: [], extra: [] }; }
  function mentionsD(s) { return new RegExp(`\\b${D}\\b`).test(te.lines.slice(s.l, s.endL + 1).join('\n')); }
  function isSelf(s) { return s.kind === 'allow' && s.src === D && s.tgt === 'self' && (s.top || (s.bool && !s.opt)); }

  /** Self rules, port items, catalog items in one scope (top level: bool null). */
  function grantsIn(g, bool, prefix) {
    const inScope = (s) => (bool ? s.bool === bool : !s.bool);
    const selfPerms = new Map(); // cls -> Set
    for (const s of editable) {
      if (!isSelf(s) || !inScope(s)) continue;
      if (!selfPerms.has(s.cls)) selfPerms.set(s.cls, new Set());
      for (const p of s.perms) selfPerms.get(s.cls).add(p);
      claimed.add(s);
    }
    const hasSelf = (cls, p) => selfPerms.has(cls) && selfPerms.get(cls).has(p);
    for (const [id, , perms] of SELF) if (Object.entries(perms).every(([cls, ps]) => ps.every(p => hasSelf(cls, p)))) g.self.push(id);
    for (const [c, cls] of CAPS) if (hasSelf(cls, c)) g.caps.push(c);

    // Calls taking only the domain.
    const domCalls = editable.filter(s => inScope(s) && s.kind === 'call' && s.args.length === 1 && s.args[0] === D && !claimed.has(s));
    const present = new Set(domCalls.map(s => s.name));
    const take = (n) => { for (const s of domCalls) if (s.name === n) claimed.add(s); };
    for (const s of domCalls) {
      const r = /^corenet_(tcp|udp)_(bind|connect|sendrecv)_(\w+?)_port$/.exec(s.name);
      const all = /^corenet_(tcp|udp)_(bind|connect|sendrecv)_all_ports$/.exec(s.name);
      if (r && r[3] !== 'generic') {
        const [, proto, verb, port] = r;
        if (verb === 'sendrecv' && present.has(`corenet_udp_bind_${port}_port`)) continue;
        if (verb === 'sendrecv' && proto === 'tcp') continue;
        const dir = verb === 'bind' ? 'listen' : 'connect';
        if (!g.net[dir].some(x => x.proto === proto && x.port === port)) g.net[dir].push({ proto, port });
      } else if (all && (all[2] === 'connect' || all[2] === 'bind' || (all[1] === 'udp' && !present.has('corenet_udp_bind_all_ports')))) {
        // UDP has no connect: "connects to any UDP port" is sendrecv on all ports.
        const dir = all[2] === 'bind' ? 'listen' : 'connect';
        if (!g.net[dir].some(x => x.proto === all[1] && x.port === 'all')) g.net[dir].push({ proto: all[1], port: 'all' });
      }
    }
    // Port rules that belong to a port item without being generated for it (older style sendrecv
    // and packet rules) are removed with it.
    for (const dir of ['listen', 'connect']) {
      for (const { proto, port } of g.net[dir]) {
        if (port === 'all') continue;
        const related = [`corenet_${proto}_sendrecv_${port}_port`, `corenet_sendrecv_${port}_${dir === 'listen' ? 'server' : 'client'}_packets`];
        for (const s of domCalls) if (related.includes(s.name)) ownAdd(`${prefix}net:${dir}:${proto}:${port}`, s);
      }
    }
    for (const a of Object.values(ACCESS)) {
      const got = a.calls.map(alts => alts.find(n => present.has(n)));
      if (got.every(Boolean)) { g.access.push(a.id); got.forEach(take); }
    }
  }
}

/* ---------- rendering ---------- */

/** Order and group local statements the way refpolicy modules are laid out. */
function localBlocks(stmts) {
  const files = new Map(), net = [], other = [];
  for (const s of stmts) {
    if (s.group && s.group.startsWith('file:')) { if (!files.has(s.group)) files.set(s.group, []); files.get(s.group).push(s); }
    else if (s.group === 'net' || /^corenet_/.test(s.name)) net.push(s);
    else other.push(s);
  }
  const blocks = [...files.values()].map(b => b.map(s => s.text));
  if (net.length) {
    const rank = (n) => (/sendrecv_generic_(if|node)$/.test(n) ? 0 : /bind_generic_node$/.test(n) ? 1 : 2);
    blocks.push(net.sort((a, b) => rank(a.name) - rank(b.name) || a.name.localeCompare(b.name)).map(s => s.text));
  }
  other.sort((a, b) => a.name.localeCompare(b.name));
  let cur = null, prefix = null;
  for (const s of other) {
    const pfx = s.name.split('_')[0];
    if (pfx !== prefix) { blocks.push(cur = []); prefix = pfx; }
    cur.push(s.text);
  }
  return blocks;
}
const optBlock = (s) => `optional_policy(\`\n\t${s.text}\n')`;
const tunableBlock = (bool, body) => [`tunable_policy(\`${bool}',\``, ...body.map(t => `\t${t}`), "')"].join('\n');
// Calls into modules that may be off: optional_policy outside, tunable_policy inside (refpolicy's convention).
const optTunableBlock = (bool, body) => ['optional_policy(`', `\ttunable_policy(\`${bool}',\``, ...body.map(t => `\t\t${t}`), "\t')", "')"].join('\n');
function selfLine(D, cls, perms) {
  return `allow ${D} self:${cls} ${perms.length === 1 ? perms[0] : `{ ${perms.join(' ')} }`};`;
}
function selfLines(D, stmts) {
  const by = new Map();
  for (const s of stmts) { if (!by.has(s.cls)) by.set(s.cls, []); if (!by.get(s.cls).includes(s.perm)) by.get(s.cls).push(s.perm); }
  const order = ['capability', 'capability2', 'process'];
  const rank = (c) => (order.includes(c) ? order.indexOf(c) : 9);
  return [...by.entries()].sort((a, b) => rank(a[0]) - rank(b[0])).map(([cls, ps]) => selfLine(D, cls, ps));
}

const HEADER = (title) => `########################################\n#\n# ${title}\n#\n`;

/** A complete .te for a new module. */
function renderTe(model, ctx) {
  const units = unitsOf(model, ctx);
  const { D } = names(model);
  const all = [...units.values()].flatMap(u => u.stmts);
  const seen = new Set();
  const uniq = all.filter(s => (seen.has(s.key) ? false : seen.add(s.key)));
  const declBlocks = [], tunables = [];
  for (const [key, u] of units) {
    const ds = u.stmts.filter(s => s.section === 'decl');
    if (!ds.length) continue;
    if (key === 'permissive') continue;
    (ds[0].kind === 'tunable' ? tunables : declBlocks).push(ds.map(s => s.text).join('\n'));
  }
  declBlocks.unshift(...tunables);
  const local = uniq.filter(s => s.section === 'local' && !s.bool);
  const selfs = selfLines(D, local.filter(s => s.kind === 'self'));
  const calls = local.filter(s => s.kind === 'call');
  const underBool = uniq.filter(s => s.section === 'local' && s.bool);
  const parts = [];
  parts.push(ctx.moduleArgs === 1 ? `policy_module(${model.name})\n` : `policy_module(${model.name}, 1.0.0)\n`);
  parts.push(HEADER('Declarations'));
  parts.push(declBlocks.join('\n\n') + '\n');
  if (model.permissive) parts.push(`# Denials are logged but not enforced. Remove when the policy is complete.\npermissive ${D};\n`);
  parts.push(HEADER(`${model.name} local policy`));
  const body = [];
  if (selfs.length) body.push(selfs.join('\n'));
  for (const b of localBlocks(calls.filter(s => !s.opt))) body.push(b.join('\n'));
  for (const s of calls.filter(s => s.opt).sort((a, b) => a.name.localeCompare(b.name))) body.push(optBlock(s));
  for (const b of model.booleans || []) {
    const name = sub(b.name, model.name);
    const mine = underBool.filter(s => s.bool === name);
    const inner = [...selfLines(D, mine.filter(s => s.kind === 'self')), ...localBlocks(mine.filter(s => s.kind === 'call' && !s.opt)).flat()];
    if (inner.length) body.push(tunableBlock(name, inner));
    for (const s of mine.filter(s => s.kind === 'call' && s.opt).sort((x, y) => x.name.localeCompare(y.name))) body.push(optTunableBlock(name, [s.text]));
  }
  if (body.length) parts.push(body.join('\n\n') + '\n');
  return parts.join('\n');
}

function fcLine(spec, ftype, type) {
  return `${spec}\t${ftype ? ftype + '\t' : '\t'}gen_context(system_u:object_r:${type},s0)`;
}
function fcEntries(model, ctx) {
  const { E } = names(model);
  const out = [];
  for (const p of model.exec || []) if (p.trim()) out.push({ type: E, path: sub(p.trim(), model.name), exec: true });
  for (const row of model.files || []) for (const p of row.paths || []) if (p.trim()) out.push({ type: fileType(model, row, ctx), path: sub(p.trim(), model.name), file: KIND[row.kind] && KIND[row.kind].file });
  return out.map(e => {
    const f = fcFromPath(e.path);
    return { ...e, spec: f.spec, ftype: f.file || e.exec || e.file ? '--' : '' };
  });
}
function renderFc(model, ctx) {
  const es = fcEntries(model, ctx);
  const groups = [];
  let last = null;
  for (const e of es) { if (e.type !== last) { groups.push([]); last = e.type; } groups[groups.length - 1].push(fcLine(e.spec, e.ftype, e.type)); }
  return groups.map(g => g.join('\n')).join('\n\n') + (groups.length ? '\n' : '');
}

/* ---------- the .if ---------- */

const DOC_DOMAIN = '## <param name="domain">\n##\t<summary>\n##\tDomain allowed access.\n##\t</summary>\n## </param>';
const DOC_DOMAIN_TRANS = '## <param name="domain">\n##\t<summary>\n##\tDomain allowed to transition.\n##\t</summary>\n## </param>';
const DOC_ROLE = '## <param name="role">\n##\t<summary>\n##\tRole allowed access.\n##\t</summary>\n## </param>';

function ifaceText(id, model, ctx) {
  const n = model.name;
  const { D, E } = names(model);
  const row = (kind) => (model.files || []).find(r => r.kind === kind);
  const T = (kind) => (row(kind) ? fileType(model, row(kind), ctx) : null);
  const search = (kind) => pick(ctx, KIND[kind].search);
  const def = (name, summary, doc, types, body) => [
    '########################################',
    '## <summary>',
    `##\t${summary}`,
    '## </summary>',
    doc,
    '#',
    `interface(\`${name}',\``,
    '\tgen_require(`',
    `\t\ttype ${types.join(', ')};`,
    "\t')",
    '',
    ...body.map(l => (l ? `\t${l}` : '')),
    "')",
  ].join('\n');
  const reads = (t) => [`list_dirs_pattern($1, ${t}, ${t})`, `read_files_pattern($1, ${t}, ${t})`, `read_lnk_files_pattern($1, ${t}, ${t})`];
  const s = (kind) => (search(kind) ? [`${search(kind)}($1)`] : []);
  switch (id) {
    case 'domtrans': return def(`${n}_domtrans`, `Execute ${n} in the ${n} domain.`, DOC_DOMAIN_TRANS, [D, E], ['corecmd_search_bin($1)', `domtrans_pattern($1, ${E}, ${D})`]);
    case 'exec': return def(`${n}_exec`, `Execute ${n} in the caller domain.`, DOC_DOMAIN, [E], ['corecmd_search_bin($1)', `can_exec($1, ${E})`]);
    case 'read_config': return T('config') && def(`${n}_read_config`, `Read ${n} configuration.`, DOC_DOMAIN, [T('config')], [...s('config'), ...reads(T('config'))]);
    case 'read_log': return T('log') && def(`${n}_read_log`, `Read ${n} log files.`, DOC_DOMAIN, [T('log')], [...s('log'), ...reads(T('log'))]);
    case 'read_lib_files': return T('state') && def(`${n}_read_lib_files`, `Read ${n} state data.`, DOC_DOMAIN, [T('state')], [...s('state'), ...reads(T('state'))]);
    case 'manage_lib_files': return T('state') && def(`${n}_manage_lib_files`, `Create, read, write and delete ${n} state data.`, DOC_DOMAIN, [T('state')],
      [...s('state'), `manage_dirs_pattern($1, ${T('state')}, ${T('state')})`, `manage_files_pattern($1, ${T('state')}, ${T('state')})`, `manage_lnk_files_pattern($1, ${T('state')}, ${T('state')})`]);
    case 'stream_connect': return T('runtime') && def(`${n}_stream_connect`, `Connect to ${n} over a Unix stream socket.`, DOC_DOMAIN, [D, T('runtime')],
      [...s('runtime'), `stream_connect_pattern($1, ${T('runtime')}, ${T('runtime')}, ${D})`]);
    case 'admin': {
      const rows = (model.files || []).filter(r => r.kind !== 'unit' && r.kind !== 'initrc');
      const initrc = row('initrc') ? fileType(model, row('initrc'), ctx) : null;
      const body = [`allow $1 ${D}:process ${ctx.has('signal_perms') ? 'signal_perms' : '{ sigchld sigkill sigstop signull signal }'};`, `ps_process_pattern($1, ${D})`];
      if (initrc && ctx.has('init_labeled_script_domtrans')) body.push('', `init_labeled_script_domtrans($1, ${initrc})`, 'domain_system_change_exemption($1)', `role_transition $2 ${initrc} system_r;`, 'allow $2 system_r;');
      const admin = ctx.has('admin_pattern');
      for (const r of rows) {
        const t = fileType(model, r, ctx);
        body.push('');
        const sr = KIND[r.kind].search && search(r.kind);
        if (sr) body.push(`${sr}($1)`);
        body.push(...(admin ? [`admin_pattern($1, ${t})`] : [`manage_dirs_pattern($1, ${t}, ${t})`, `manage_files_pattern($1, ${t}, ${t})`]));
      }
      const doc = `## <summary>\n##\tAll of the rules required to\n##\tadminister an ${n} environment.\n## </summary>\n${DOC_DOMAIN}\n${DOC_ROLE}\n## <rolecap/>`;
      return [
        '########################################', doc, '#',
        `interface(\`${n}_admin',\``, '\tgen_require(`',
        `\t\ttype ${[D, ...rows.map(r => fileType(model, r, ctx)), ...(initrc ? [initrc] : [])].join(', ')};`, "\t')", '',
        ...body.map(l => (l ? `\t${l}` : '')), "')",
      ].join('\n');
    }
  }
  return null;
}
function renderIf(model, ctx) {
  const parts = [`## <summary>${model.summary || `Policy for ${model.name}`}</summary>`];
  for (const id of model.provides || []) { const t = ifaceText(id, model, ctx); if (t) parts.push(t); }
  return parts.join('\n\n') + '\n';
}

/* ---------- editing existing files ---------- */

/** Line edits applied bottom-up: delete line ranges, replace lines, insert after a line. */
function applyLineEdits(lines, edits) {
  const out = lines.slice();
  const del = new Set(), rep = new Map(), ins = new Map();
  for (const e of edits) {
    if (e.del) for (let l = e.del[0]; l <= e.del[1]; l++) del.add(l);
    if (e.rep) rep.set(e.rep[0], e.rep[1]);
    if (e.ins) { const k = e.ins[0]; if (!ins.has(k)) ins.set(k, []); ins.get(k).push(...e.ins[1]); }
  }
  if (!edits.length) return out;
  // Blank lines that would end up next to each other because of a deletion collapse into one.
  const res = [];
  let deleted = false;
  const push = (ln) => {
    if (deleted && ln.trim() === '' && res.length && res[res.length - 1].trim() === '') return;
    res.push(ln);
    if (ln.trim() !== '') deleted = false;
  };
  if (ins.has(-1)) ins.get(-1).forEach(push);
  for (let l = 0; l < out.length; l++) {
    if (del.has(l)) deleted = true;
    else push(rep.has(l) ? rep.get(l) : out[l]);
    if (ins.has(l)) ins.get(l).forEach(push);
  }
  return res;
}

/** New .te text for an edited model of an existing module. */
function editTe(text, rec, model, ctx) {
  const scan = rec.scan; // recognize() read this same text, so its statements are this text's
  const lines = scan.lines;
  const old = unitsOf(rec.model, ctx);
  const cur = unitsOf(model, ctx);
  const { D } = names(model);
  const genNew = new Set([...cur.values()].flatMap(u => u.stmts.map(s => s.key)));
  const editable = scan.stmts.filter(s => s.top || s.opt || s.bool);
  const presentKey = (s) => (s.kind === 'call' ? s.key : s.kind === 'type' ? `type:${s.name}` : s.kind === 'permissive' ? (s.name === D ? 'permissive' : null) : null);
  const byKey = new Map();
  for (const s of editable) { const k = presentKey(s); if (k) { if (!byKey.has(k)) byKey.set(k, []); byKey.get(k).push(s); } }
  // Self rules (top level, or directly under a boolean): perms per class with their lines.
  const selfStmts = editable.filter(s => s.kind === 'allow' && s.src === D && s.tgt === 'self' && (s.top || (s.bool && !s.opt)));
  const sameScope = (s, bool) => (s.bool || null) === (bool || null);
  const selfHas = (bool, cls, p) => selfStmts.some(s => sameScope(s, bool) && s.cls === cls && s.perms.includes(p));
  const isPresent = (st) => (st.kind === 'self' ? selfHas(st.bool, st.cls, st.perm) : byKey.has(st.key));

  // Units whose settings changed: delete what they had, insert what they need now.
  const delStmts = new Set(), delSelf = [], insStmts = [], insSelf = [];
  const queued = new Set();
  const edits = [];
  // A boolean whose default or description changed is rewritten in place (description and gen_tunable line).
  const inPlace = new Set();
  for (const [k, u] of cur) {
    const o = old.get(k);
    if (!k.startsWith('tunable:') || !o || o.sig === u.sig) continue;
    const own = rec.own.get(k) || [];
    const callSt = own.find(s => s.kind === 'call');
    if (!callSt) continue;
    for (const s of own) delStmts.add(s);
    edits.push({ ins: [callSt.endL, u.stmts[0].text.split('\n')] });
    inPlace.add(k);
  }
  for (const [k, u] of old) {
    const n = cur.get(k);
    if (inPlace.has(k) || (n && n.sig === u.sig)) continue;
    for (const st of u.stmts) {
      if (genNew.has(st.key)) continue;
      if (st.kind === 'self') { if (selfHas(st.bool, st.cls, st.perm)) delSelf.push(st); continue; }
      for (const s of byKey.get(st.key) || []) delStmts.add(s);
    }
    for (const o of rec.own.get(k) || []) {
      const pk = presentKey(o);
      if (pk && genNew.has(pk)) continue;
      delStmts.add(o);
    }
  }
  for (const [k, u] of cur) {
    const o = old.get(k);
    if (inPlace.has(k) || (o && o.sig === u.sig)) continue;
    for (const st of u.stmts) {
      if (queued.has(st.key)) continue;
      const have = st.kind === 'self' ? [] : byKey.get(st.key) || [];
      if (have.length && have.every(s => delStmts.has(s))) { for (const s of have) delStmts.delete(s); continue; } // still needed
      if (isPresent(st)) continue;
      queued.add(st.key);
      (st.kind === 'self' ? insSelf : insStmts).push(st);
    }
  }

  // Deleting statements; an optional_policy or tunable_policy block left empty goes too (inner blocks first).
  const delLines = new Set();
  for (const s of delStmts) for (let l = s.l; l <= s.endL; l++) delLines.add(l);
  // Self rules: drop perms from their lines, add new perms to the class's first line in the same scope.
  const newPerms = new Map(); // scope \0 cls -> perms
  for (const st of insSelf) { const k = `${st.bool || ''}\0${st.cls}`; if (!newPerms.has(k)) newPerms.set(k, []); newPerms.get(k).push(st.perm); }
  const perms = new Map(); // line -> perms
  for (const s of selfStmts) perms.set(s.l, s.perms.slice());
  for (const st of delSelf) for (const s of selfStmts) if (sameScope(s, st.bool) && s.cls === st.cls) perms.set(s.l, perms.get(s.l).filter(p => p !== st.perm));
  const newClassLines = new Map(); // scope -> lines
  for (const [k, ps] of newPerms) {
    const [bool, cls] = k.split('\0');
    const first = selfStmts.find(s => sameScope(s, bool) && s.cls === cls && perms.get(s.l).length && !delLines.has(s.l));
    if (first) perms.set(first.l, [...perms.get(first.l), ...ps]);
    else { if (!newClassLines.has(bool)) newClassLines.set(bool, []); newClassLines.get(bool).push(...selfLines(D, ps.map(perm => ({ cls, perm })))); }
  }
  for (const s of selfStmts) {
    if (delLines.has(s.l)) continue;
    const ps = perms.get(s.l);
    if (ps.join(' ') === s.perms.join(' ')) continue;
    if (!ps.length) { delLines.add(s.l); continue; }
    const indent = /^\s*/.exec(lines[s.l])[0];
    const comment = /\s*#.*$/.exec(lines[s.l]);
    edits.push({ rep: [s.l, indent + selfLine(D, s.cls, ps) + (comment ? comment[0] : '')] });
  }
  const containers = scan.blocks.filter(b => b.name === 'optional_policy' || b.name === 'tunable_policy').sort((a, b) => (a.endL - a.l) - (b.endL - b.l));
  for (const b of containers) {
    if (!/`\s*(#.*)?$/.test(lines[b.l]) || !/^\s*'\s*\)\s*(#.*)?$/.test(lines[b.endL])) continue;
    let touched = false, empty = true;
    for (let l = b.l + 1; l < b.endL; l++) {
      if (delLines.has(l)) touched = true;
      else if (lines[l].trim()) { empty = false; break; }
    }
    if (touched && empty) for (let l = b.l; l <= b.endL; l++) delLines.add(l);
  }

  for (const l of delLines) edits.push({ del: [l, l] });

  // Where new statements go.
  const top = editable.filter(s => s.top && !delLines.has(s.l));
  const declHelpers = new Set(FILE_KINDS.flatMap(k => k.decl.map(([h]) => h)).concat(['init_daemon_domain', 'domain_type', 'init_domain', 'gen_tunable', 'gen_bool', 'attribute_role', 'roleattribute']));
  const firstLocal = top.find(s => (s.kind === 'allow' || s.kind === 'rule') || (s.kind === 'call' && !declHelpers.has(s.name) && !/^policy_module$/.test(s.name)));
  const localHeader = (() => {
    const lim = firstLocal ? firstLocal.l : lines.length;
    for (let l = lim - 1; l >= 0; l--) if (/^#\s*\S.*polic(y|ies)\s*$/i.test(lines[l]) && /^#{10,}/.test(lines[l - 2] || '')) return l - 2;
    return null;
  })();
  const declEnd = Math.max(-1, ...top.filter(s => (s.kind === 'type' || (s.kind === 'call' && declHelpers.has(s.name))) && (localHeader == null || s.l < localHeader) && (!firstLocal || s.l < firstLocal.l)).map(s => s.endL));
  const policyModule = top.find(s => s.kind === 'call' && s.name === 'policy_module');
  const declAfter = declEnd >= 0 ? declEnd : policyModule ? policyModule.endL : -1;
  const domTop = top.filter(s => (s.kind === 'call' && s.args[0] === D && s.name !== 'init_daemon_domain') || (s.kind === 'allow' && s.src === D));
  const lastSelf = selfStmts.filter(s => s.top && !delLines.has(s.l)).map(s => s.l);
  const localAfter = domTop.length ? Math.max(...domTop.map(s => s.endL)) : (lastSelf.length ? Math.max(...lastSelf) : lines.length - 1);
  const optBlocksOfD = scan.blocks.filter(b => b.name === 'optional_policy' && editable.some(s => s.opt === b && !s.bool && s.kind === 'call' && s.args[0] === D) && !delLines.has(b.l));
  const optAfter = optBlocksOfD.length ? Math.max(localAfter, ...optBlocksOfD.map(b => b.endL)) : localAfter;
  const selfAfter = lastSelf.length ? Math.max(...lastSelf) : (localHeader != null ? localHeader + 4 : localAfter);
  // Boolean blocks go after the domain's last rule or block.
  const outerEnd = (s) => (s.opt ? s.opt.endL : s.tun ? s.tun.endL : s.endL);
  const domAll = editable.filter(s => (s.kind === 'call' && s.args[0] === D && s.name !== 'init_daemon_domain') || (s.kind === 'allow' && s.src === D));
  const boolAfter = Math.max(optAfter, ...domAll.map(outerEnd));

  // Declarations: booleans with the other gen_tunable lines (or above the domain's type), the rest after the last declaration.
  const declIns = [], tunIns = [];
  for (const [k, u] of cur) {
    const o = old.get(k);
    if (o && o.sig === u.sig) continue;
    const ds = u.stmts.filter(s => s.section === 'decl' && insStmts.includes(s));
    if (!ds.length) continue;
    if (ds[0].kind === 'tunable') tunIns.push(...ds.map(s => s.text.split('\n')));
    else declIns.push(['', ...ds.map(s => s.text)]);
  }
  if (tunIns.length) {
    const tuns = top.filter(s => s.kind === 'call' && s.name === 'gen_tunable');
    const typeD = top.find(s => s.kind === 'type' && s.name === D);
    if (tuns.length) edits.push({ ins: [Math.max(...tuns.map(s => s.endL)), tunIns.flatMap(t => ['', ...t])] });
    else if (typeD) {
      let at = typeD.l;
      while (at > 0 && /^\s*##/.test(lines[at - 1])) at--;
      edits.push({ ins: [at - 1, tunIns.flatMap(t => [...t, ''])] });
    } else edits.push({ ins: [declAfter, tunIns.flatMap(t => ['', ...t])] });
  }
  if (declIns.length) edits.push({ ins: [declAfter, declIns.flat()] });
  const topNew = newClassLines.get('') || [];
  if (topNew.length) edits.push({ ins: [selfAfter, lastSelf.length ? topNew : ['', ...topNew]] });
  const localNew = insStmts.filter(s => s.section === 'local' && !s.opt && !s.bool);
  if (localNew.length) edits.push({ ins: [localAfter, localBlocks(localNew).flatMap(b => ['', ...b])] });
  const optNew = insStmts.filter(s => s.section === 'local' && s.opt && !s.bool).sort((a, b) => a.name.localeCompare(b.name));
  if (optNew.length) edits.push({ ins: [optAfter, optNew.flatMap(s => ['', ...optBlock(s).split('\n')])] });

  // Under booleans: into the boolean's existing tunable_policy block, else a new one.
  const bools = new Set([...insStmts.filter(s => s.bool).map(s => s.bool), ...[...newClassLines.keys()].filter(Boolean)]);
  const indentOf = (l) => /^\s*/.exec(lines[l])[0];
  const closes = (b) => /^\s*'\s*\)\s*(#.*)?$/.test(lines[b.endL]) && !delLines.has(b.l);
  const outside = (b) => !scan.blocks.some(o => o !== b && o.l < b.l && o.endL >= b.endL);
  const optAround = (b) => scan.blocks.filter(o => o !== b && o.l < b.l && o.endL >= b.endL);
  const boolEdits = [];
  for (const bool of [...bools].sort()) {
    const content = [...(newClassLines.get(bool) || []), ...localBlocks(insStmts.filter(s => s.bool === bool && !s.opt)).flat()];
    if (content.length) {
      const blk = scan.blocks.find(b => plainTunable(b) && b.args[0] === bool && outside(b) && closes(b));
      if (blk) edits.push({ ins: [blk.endL - 1, content.map(t => indentOf(blk.l) + '\t' + t)] });
      else boolEdits.push('', `tunable_policy(\`${bool}',\``, ...content.map(t => '\t' + t), "')");
    }
    for (const s of insStmts.filter(x => x.bool === bool && x.opt).sort((a, b) => a.name.localeCompare(b.name))) {
      const blk = scan.blocks.find(b => plainTunable(b) && b.args[0] === bool && closes(b) && optAround(b).length === 1 && optAround(b)[0].name === 'optional_policy');
      if (blk) edits.push({ ins: [blk.endL - 1, [indentOf(blk.l) + '\t' + s.text]] });
      else boolEdits.push('', ...optTunableBlock(bool, [s.text]).split('\n'));
    }
  }
  if (boolEdits.length) edits.push({ ins: [boolAfter, boolEdits] });

  return applyLineEdits(lines, edits).join('\n');
}

/** New .fc text: only the file types whose paths changed get lines removed or added. */
function editFc(text, rec, model, ctx) {
  const lines = (text || '').split('\n');
  const entries = parseFcLines(text);
  const want = fcEntries(model, ctx);
  const oldTypes = new Map(); // type -> paths in the recognized model
  oldTypes.set(rec.model.execType, (rec.model.exec || []).join('\n'));
  for (const r of rec.model.files) oldTypes.set(r.type, (r.paths || []).join('\n'));
  const newTypes = new Map();
  const { E } = names(model);
  newTypes.set(E, (model.exec || []).map(p => sub(p.trim(), model.name)).filter(Boolean).join('\n'));
  for (const r of model.files || []) newTypes.set(fileType(model, r, ctx), (r.paths || []).map(p => sub(p.trim(), model.name)).filter(Boolean).join('\n'));
  const edits = [];
  const changed = new Set();
  for (const [t, p] of oldTypes) if (newTypes.get(t) !== p) changed.add(t);
  for (const [t, p] of newTypes) if (oldTypes.get(t) !== p) changed.add(t);
  for (const t of changed) {
    const specs = new Set(want.filter(w => w.type === t).map(w => w.spec));
    const have = entries.filter(e => e.type === t);
    for (const e of have) if (!specs.has(e.spec)) edits.push({ del: [e.l, e.l] });
    const missing = want.filter(w => w.type === t && !have.some(e => e.spec === w.spec));
    if (!missing.length) continue;
    const kept = have.filter(e => specs.has(e.spec));
    const after = kept.length ? Math.max(...kept.map(e => e.l)) : (lines.length && lines[lines.length - 1] === '' ? lines.length - 2 : lines.length - 1);
    edits.push({ ins: [after, [...(kept.length ? [] : [''])].concat(missing.map(w => fcLine(w.spec, w.ftype, w.type)))] });
  }
  const out = applyLineEdits(lines, edits);
  while (edits.length && out.length > 1 && out[0].trim() === '') out.shift();
  return out.join('\n');
}

function editIf(text, rec, model, ctx) {
  const have = new Set(rec.provided);
  const add = (model.provides || []).map(id => [id, sub(PROVIDES.find(p => p[0] === id)[1], model.name)]).filter(([, n]) => !have.has(n));
  if (!add.length) return text;
  const blocks = add.map(([id]) => ifaceText(id, model, ctx)).filter(Boolean);
  return text.replace(/\s*$/, '\n') + '\n' + blocks.join('\n\n') + '\n';
}

/* ---------- checks and plan ---------- */

/**
 * Problems that would make the generated module wrong (strings; [] when
 * fine). Messages starting with "Note:" are advice and don't block applying.
 */
function validate(model, ctx, opts = {}) {
  const out = [];
  if (!/^[a-z][a-z0-9_]*$/.test(model.name || '')) out.push('The name must start with a letter and use only lowercase letters, digits and _.');
  if (opts.isNew && ctx.moduleExists && ctx.moduleExists(model.name)) out.push(`A module named ${model.name} already exists.`);
  const types = new Set();
  for (const r of model.files || []) {
    const t = fileType(model, r, ctx);
    if (!/^\w+_t$/.test(t)) out.push(`File type name "${t}" should end in _t.`);
    if (types.has(t)) out.push(`File type ${t} is listed twice.`);
    types.add(t);
    if (opts.isNew && ctx.typeExists && ctx.typeExists(t)) out.push(`Type ${t} is already declared elsewhere.`);
  }
  for (const p of (model.exec || []).concat(...(model.files || []).map(r => r.paths || []))) if (p.trim() && !p.trim().startsWith('/')) out.push(`Path "${p}" must be absolute.`);
  if (!(model.exec || []).some(p => p.trim())) out.push('Note: no program path, so nothing gets the program label and the service won’t start in its domain.');
  if (model.permissive) out.push('Note: permissive: denials are logged, not enforced. Turn it off when the policy is complete.');
  const grants = (g, where) => {
    for (const dir of ['listen', 'connect']) for (const it of (g.net || {})[dir] || []) {
      if (it.port && it.port !== 'all' && !ctx.has(dir === 'listen' ? `corenet_${it.proto}_bind_${it.port}_port` : it.proto === 'tcp' ? `corenet_tcp_connect_${it.port}_port` : `corenet_udp_sendrecv_${it.port}_port`)) out.push(`No ${it.proto} port type ${it.port}_port_t in this policy (${dir}${where}).`);
    }
    for (const n of g.extra || []) if (!ctx.has(n)) out.push(`Interface ${n} doesn't exist in this policy${where}.`);
  };
  grants(model, '');
  const bools = new Set();
  for (const b of model.booleans || []) {
    const n = sub(b.name || '', model.name);
    if (!/^[a-z][a-z0-9_]*$/.test(n)) { out.push(`Boolean name "${n}" must start with a letter and use only lowercase letters, digits and _.`); continue; }
    if (bools.has(n)) out.push(`Boolean ${n} is listed twice.`);
    bools.add(n);
    if (b.external && ctx.boolExists && !ctx.boolExists(n)) out.push(`There is no boolean ${n} in this policy.`);
    if (!b.external && (opts.isNew || b._new) && ctx.boolExists && ctx.boolExists(n)) out.push(`A boolean named ${n} already exists: add it as an existing boolean, or choose another name.`);
    const g = b.grants || {};
    if (![...(g.self || []), ...(g.caps || []), ...(g.access || []), ...(g.extra || []), ...((g.net || {}).listen || []).filter(x => x.port), ...((g.net || {}).connect || []).filter(x => x.port)].length) out.push(`Note: boolean ${n} doesn't allow anything yet.`);
    grants(g, ` under ${n}`);
    // Only what is being added now: an existing module isn't blamed for what it already has.
    const base = opts.baseline && (opts.baseline.booleans || []).find(x => x.name === n);
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    const added = (kind, v) => !base || !(kind === 'listen' || kind === 'connect' ? (base.grants.net || {})[kind] || [] : base.grants[kind] || []).some(x => same(x, v));
    const always = (kind, v) => (kind === 'listen' || kind === 'connect' ? (model.net || {})[kind] || [] : model[kind] || []).some(x => same(x, v));
    const label = { access: (id) => (ACCESS[id] ? `"${ACCESS[id].label}"` : id), extra: (x) => x, caps: (x) => `capability ${x}`, self: (id) => (SELF_BY[id] ? `"${SELF_BY[id].label}"` : id),
      listen: (x) => `listening on ${x.proto} ${x.port}`, connect: (x) => `connecting to ${x.proto} ${x.port}` };
    for (const kind of ['access', 'extra', 'caps', 'self', 'listen', 'connect']) {
      for (const v of (kind === 'listen' || kind === 'connect' ? (g.net || {})[kind] || [] : g[kind] || [])) {
        if (!added(kind, v)) continue;
        // Granting it both always and under the boolean: harmless for allow rules, but type rules
        // (a domain transition, e.g. mta_send_mail) would be duplicates the build refuses.
        if (always(kind, v)) out.push(`${label[kind](v)} under ${n} is already always allowed; remove it from one of the two places.`);
        // checkmodule allows only allow/dontaudit/type rules inside a conditional.
        const calls = kind === 'access' ? (ACCESS[v] ? ACCESS[v].calls.map(a => pick(ctx, a)).filter(Boolean) : []) : kind === 'extra' ? [v] : [];
        const bad = calls.find(c => ctx.condSafe && !ctx.condSafe(c));
        if (bad) out.push(`${label[kind](v)} can't be granted under ${n}: ${bad}() declares attributes or contains blocks that conditional policy doesn't allow. Grant it always, or leave it out.`);
      }
    }
  }
  return out;
}

/** The new texts for a model: { te, if, fc } (null = unchanged / not needed). */
function plan(model, ctx, existing) {
  if (!existing) return { te: renderTe(model, ctx), if: renderIf(model, ctx), fc: renderFc(model, ctx) };
  // Work on LF text; files with CRLF line endings get them back.
  const crlf = {}, lf = {};
  for (const k of ['te', 'if', 'fc']) { const t = existing[k] || ''; crlf[k] = t.includes('\r\n'); lf[k] = t.replace(/\r\n/g, '\n'); }
  const rec = recognize(lf, ctx, { domain: model.domain });
  if (rec.error) return { error: rec.error };
  const out = { te: editTe(lf.te, rec, model, ctx), if: editIf(lf.if, rec, model, ctx), fc: editFc(lf.fc, rec, model, ctx) };
  for (const k of ['te', 'if', 'fc']) out[k] = out[k] === lf[k] ? existing[k] || '' : crlf[k] ? out[k].replace(/\n/g, '\r\n') : out[k];
  return out;
}

/** Line diff for previews: [[' '|'+'|'-', text], ...]. */
function lineDiff(a, b) {
  const x = a.split('\n'), y = b.split('\n');
  let s = 0;
  while (s < x.length && s < y.length && x[s] === y[s]) s++;
  let ex = x.length, ey = y.length;
  while (ex > s && ey > s && x[ex - 1] === y[ey - 1]) { ex--; ey--; }
  const xm = x.slice(s, ex), ym = y.slice(s, ey);
  const n = xm.length, m = ym.length;
  const out = x.slice(0, s).map(t => [' ', t]);
  if (n * m > 4e6) { out.push(...xm.map(t => ['-', t]), ...ym.map(t => ['+', t])); }
  else {
    const L = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = xm[i] === ym[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
    let i = 0, j = 0;
    while (i < n && j < m) {
      if (xm[i] === ym[j]) { out.push([' ', xm[i]]); i++; j++; }
      else if (L[i + 1][j] >= L[i][j + 1]) out.push(['-', xm[i++]]);
      else out.push(['+', ym[j++]]);
    }
    while (i < n) out.push(['-', xm[i++]]);
    while (j < m) out.push(['+', ym[j++]]);
  }
  out.push(...x.slice(ex).map(t => [' ', t]));
  return out;
}

/** Default model for a new service. */
function newModel() {
  return {
    name: '', summary: '', exec: ['/usr/bin/%'],
    files: [{ kind: 'unit', paths: ['/usr/lib/systemd/system/%.service'], access: 'none' }, { kind: 'runtime', paths: ['/run/%/'], access: 'manage' }],
    self: ['fifo'], caps: [], net: { listen: [], connect: [] }, access: ['syslog', 'locale'], extra: [], permissive: false,
    booleans: [], provides: ['domtrans', 'admin'],
  };
}

/** The catalog as the editor UI needs it, limited to what exists in this tree. */
function catalog(ctx) {
  const avail = (alts) => alts.some(a => a.some(n => ctx.has(n)));
  return {
    fileKinds: FILE_KINDS.filter(k => k.decl.some(([h]) => ctx.has(h))).map(k => ({
      id: k.id, label: k.label, where: k.where, path: k.path || '', access: k.access, file: !!k.file,
      suffix: (k.decl.find(([h]) => ctx.has(h)) || k.decl[0])[1],
    })),
    accessLabels: ACCESS_LABELS,
    access: ACCESS_GROUPS.map(([g, items]) => ({ group: g, items: items.filter(([, , calls]) => avail(calls)).map(([id, label, calls]) => {
      const names = calls.map(a => pick(ctx, a)).filter(Boolean);
      return { id, label, calls: names, optional: calls.some(a => ctx.optional(pick(ctx, a) || a[0])), cond: names.every(n => !ctx.condSafe || ctx.condSafe(n)) };
    }) })).filter(g => g.items.length),
    self: SELF.map(([id, label, perms, risky]) => ({ id, label, risky: !!risky, rule: Object.entries(perms).map(([c, ps]) => `${c} ${ps.join(' ')}`).join('; ') })),
    caps: CAPS.map(([name, cls, label, risky]) => ({ name, cls, label, risky: !!risky })),
    provides: PROVIDES.map(([id, name, label, needs]) => ({ id, name, label, needs: needs || null })),
  };
}

module.exports = {
  FILE_KINDS, ACCESS_GROUPS, SELF, CAPS, PROVIDES,
  unitsOf, recognize, daemonDomains, plan, validate, renderTe, renderIf, renderFc, lineDiff, newModel, catalog,
  fcFromPath, pathFromFc, scanTe, fileType,
};
