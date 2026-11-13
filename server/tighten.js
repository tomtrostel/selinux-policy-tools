'use strict';
/*
 * The tighten report for a service module: what the module grants, broadest
 * and riskiest first, each with what would narrow it and the form change that
 * does it. From the service model (what the form shows) plus what each extra
 * interface expands to (server: the probe expansion + attribute sizes) and the
 * module's kept lines.
 *
 *   report(model, opts) → { rows, summary: { high, medium, low }, notes }
 *     opts: { domain, catalog (service.catalog(ctx)), grants: Map name →
 *       { cost, types, writes, rules: [text], broadest } (optional), kept:
 *       [{ text, l }] (lines the form keeps as written) }
 *   row: { kind: permissive | cap | self | file | access | extra | boolean | kept,
 *       id, severity: high | medium | low, title, text, fix: { op, ...args,
 *       label } | null, line? }
 */
const { permWeight } = require('./denials');

/* Interfaces that grant across whole classes of types: what they are for, and what usually suffices. */
const BROAD = [
  [/^files_(read|manage|rw|list|getattr|relabel|dontaudit_\w+)_all_(files|dirs|symlinks|sockets|pipes|chr_files|blk_files|non_security_files)|^files_(read|manage|rw)_non_(security|auth)_files|^files_(manage|rw|read)_all_/, 'every file on the system (every file type)', 'the service\'s own file types, plus a read interface for the one or two other types it reads'],
  [/_all_(files|dirs|file_type|non_security_files)$/, 'every file of that kind, whatever its type', 'the interface for the specific type the program touches'],
  [/^domain_(manage|rw|read|getattr|signal|kill|ptrace|dyntrans|setpriority|dontaudit_\w+)_all_domains|_all_domains$/, 'every process on the system', 'the interface for the one domain it needs (NAME_read_state, NAME_signal, …)'],
  [/^unconfined_|^unconfined_domain|^init_unconfined/, 'the unconfined set: nothing the policy stops', 'a confined domain with the rights it needs'],
  [/^corenet_\w+_all_(ports|reserved_ports|unreserved_ports|nodes|if)$|^corenet_(tcp|udp|sctp)_(bind|connect|sendrecv)_all_/, 'every port (or node, interface)', 'the port type of the service (Network section), or its own port type'],
  [/^dev_(rw|manage|read|write|relabel)_all_|^dev_rw_generic_chr_files|^dev_manage_all_dev_nodes/, 'every device', 'the interface for the device it uses (dev_read_urand, dev_rw_sysfs, …)'],
  [/^kernel_(rw|manage)_all_sysctls|^kernel_rw_kernel_sysctl|^kernel_load_module|^kernel_rw_all_sysctls/, 'kernel settings as a whole', 'the specific sysctl group (kernel_read_net_sysctls, …) or a read interface'],
  [/^storage_(raw_)?(read|write|rw)_(fixed|removable)_disk|^storage_manage_fixed_disk/, 'raw disks', 'a file type on the data the program needs'],
  [/^auth_(read|rw|manage|relabel)_shadow$|^auth_tunable_read_shadow/, 'the password hashes', 'auth_use_pam / auth_domtrans_chk_passwd (PAM checks the password on its behalf)'],
  [/^userdom_(manage|rw|read|write|relabel)_(all_)?(user|home|tmp)/, 'users\' files', 'a type of the service\'s own under the users\' directories, or read-only access'],
  [/^fs_(manage|rw|relabel|mount|unmount|remount)_all_|^fs_mount_all_fs|^fs_unmount_all_fs|^fs_getattr_all_fs$/, 'every file system', 'the file system it uses (fs_rw_tmpfs_files, fs_getattr_xattr_fs, …)'],
  [/^selinux_(load_policy|set_enforce_mode|setenforce|set_all_booleans|set_generic_booleans|compute_access_vector|unconfined)/, 'the SELinux policy itself', 'nothing: a service should not change the policy'],
  [/^seutil_(domtrans_setfiles|run_setfiles|run_semanage|domtrans_semanage|manage_bin_policy|manage_config)/, 'relabeling or policy management tools', 'nothing, or restorecon through a helper domain'],
  [/^init_(all_labeled_tty|rw_all_|manage_all_|domtrans_script|run_daemon)|^init_(exec|spec_domtrans)_script/, 'init scripts or systemd as a whole', 'systemd_exec_systemctl, or the specific init interface'],
  [/^term_use_all_(ttys|ptys|terms)|^term_use_generic_ptys/, 'every terminal', 'the login program interfaces, or none (a service needs no terminal)'],
  [/^mount_domtrans|^mount_run|^mount_exec/, 'mounting', 'fs_mount_* for the one file system, or a helper domain'],
  [/^su_|^sudo_|^newrole_/, 'switching users or roles', 'nothing: a daemon should not run su/sudo'],
  [/^(libs|miscfiles)_(manage|rw|relabel)_/, 'shared libraries or system data', 'read-only access (libs_use_ld_so, miscfiles_read_localization)'],
];

/* Capabilities and self permissions the catalog marks risky, with the severity and why. */
const CAP_RISK = {
  sys_admin: ['high', 'nearly root: mount, namespaces, device configuration and much else. Most daemons need a narrower capability or none.'],
  dac_override: ['high', 'ignores every file permission for writing. Usually a sign that the service runs as root and writes files owned by another user; running it as its own user is the fix.'],
  sys_ptrace: ['high', 'traces and reads the memory of other processes (also /proc/PID/mem). Monitoring tools need it; others do not.'],
  sys_rawio: ['high', 'raw I/O to devices and ports.'],
  net_admin: ['medium', 'configures interfaces, routes and the firewall. Needed by network managers and VPNs, not by a plain server.'],
  net_raw: ['medium', 'raw and packet sockets: ping and sniffing.'],
  dac_read_search: ['medium', 'reads and searches every file regardless of permissions.'],
  setpcap: ['medium', 'changes its own capabilities (drops or regains them).'],
  sys_module: ['high', 'loads kernel modules.'],
  sys_boot: ['high', 'reboots the machine.'],
  mknod: ['medium', 'creates device nodes.'],
  mac_admin: ['high', 'sets labels the policy does not know (MAC administration).'],
  mac_override: ['high', 'overrides the mandatory access control.'],
  audit_control: ['high', 'controls the audit system.'],
  sys_chroot: ['low', 'chroot: fine for a daemon that locks itself into a directory.'],
  setuid: ['low', 'switches user: fine when the daemon drops root at start; a leftover when systemd runs it as its user already.'],
  setgid: ['low', 'switches group: as setuid.'],
};
const SELF_RISK = { execmem: ['medium', 'generates code at run time (JIT): a bug can become code execution. Needed by JIT runtimes, not by C daemons.'] };
/* Access groups that widen the service a lot. */
const ACCESS_RISK = {
  bin: ['medium', 'runs every program in /usr/bin and /usr/sbin, in its own domain: a shell escape, or a program the attacker drops into PATH, runs with the service\'s rights. If it runs one or two helpers, give them a helper domain (Helper programs) or label them.'],
  shell: ['medium', 'runs shell scripts in its own domain: anything a script does, the service may do.'],
  kmod: ['high', 'asks the kernel to load modules.'],
  systemctl: ['medium', 'runs systemctl: starts and stops any service.'],
  sessions: ['high', 'starts user sessions in their own domains: a login program\'s right.'],
  loginpgm: ['high', 'a login program\'s rights (PAM, switching identities).'],
  etcfiles: ['low', 'reads every ordinary file in /etc (etc_t). Fine for most services; a config file of its own would be narrower.'],
};

const SEV = { high: 3, medium: 2, low: 1 };
const plural = (n, w) => `${n} ${n === 1 ? w : `${w}s`}`;

function report(model, opts = {}) {
  const rows = [];
  const notes = [];
  const cat = opts.catalog || {};
  const D = opts.domain || `${model.name || 'NAME'}_t`;
  const add = (r) => rows.push({ line: null, fix: null, ...r });
  // 1. Permissive left on.
  if (model.permissive) add({ kind: 'permissive', id: 'permissive', severity: 'high', title: 'Permissive while testing is still on', text: `${D} is declared permissive: nothing is ever stopped, every denial only logged. Turn it off before shipping; the checklist's enforce-and-verify proves it works enforced.`, fix: { op: 'permissive', label: 'Turn permissive off' } });
  // 2. Capabilities.
  const capInfo = new Map((cat.caps || []).map(c => [c.id || c[0], c]));
  for (const c of model.caps || []) {
    const risk = CAP_RISK[c];
    if (!risk) continue;
    const info = capInfo.get(c) || {};
    add({ kind: 'cap', id: c, severity: risk[0], title: `Capability ${c}`, text: `${info.label || info[2] || c}: ${risk[1]}`, fix: { op: 'cap', cap: c, label: `Untick ${c}` } });
  }
  for (const s of model.self || []) {
    const risk = SELF_RISK[s];
    if (risk) add({ kind: 'self', id: s, severity: risk[0], title: `Self permission ${s}`, text: risk[1], fix: { op: 'self', self: s, label: `Untick ${s}` } });
  }
  // 3. Access groups.
  for (const a of model.access || []) {
    const risk = ACCESS_RISK[a];
    if (risk) add({ kind: 'access', id: a, severity: risk[0], title: `System access: ${labelOfAccess(cat, a)}`, text: risk[1], fix: { op: 'access', access: a, label: 'Untick it' } });
  }
  // 4. File rows: manage where read or append would do.
  (model.files || []).forEach((row, i) => {
    if (row.access === 'manage' && row.kind === 'log') add({ kind: 'file', id: `file:${i}`, severity: 'medium', title: `Log files: full management of ${row.type || `${model.name}_log_t`}`, text: `The service may rewrite and delete its logs${row.paths && row.paths.length ? ` (${row.paths.join(', ')})` : ''}; "create and append" lets it write them without being able to erase its tracks. Log rotation is logrotate's job, in its own domain.`, fix: { op: 'fileAccess', row: i, access: 'append', label: 'Set to create and append' } });
    if (row.access === 'manage' && row.kind === 'config') add({ kind: 'file', id: `file:${i}`, severity: 'medium', title: `Configuration: the service rewrites ${row.type || `${model.name}_conf_t`}`, text: `A daemon rarely needs to change its own configuration${row.paths && row.paths.length ? ` (${row.paths.join(', ')})` : ''}; with "read only" a compromised service cannot reconfigure itself. Keep manage only when it really writes there (a permissive run shows it).`, fix: { op: 'fileAccess', row: i, access: 'read', label: 'Set to read only' } });
    if (row.access === 'manage' && row.kind === 'unit') add({ kind: 'file', id: `file:${i}`, severity: 'high', title: 'The service may change its own unit file', text: 'A unit file is label-only in every daemon module: a service that can rewrite how systemd starts it can escalate.', fix: { op: 'fileAccess', row: i, access: 'none', label: 'Label only' } });
  });
  // 5. Extra interfaces: the broad ones by name, and by what they expand to.
  const grants = opts.grants || new Map();
  for (const n of model.extra || []) {
    const b = BROAD.find(([re]) => re.test(n));
    const g = grants.get(n);
    if (b) add({ kind: 'extra', id: n, severity: /^unconfined|selinux_|su_|sudo_|newrole_|auth_(read|rw|manage|relabel)_shadow|_all_domains|^files_\w+_all_|storage_|kernel_load_module|mac_/.test(n) ? 'high' : 'medium', title: `${n}(): ${b[1]}`, text: `Grants ${b[1]}${g && g.types ? ` (${plural(g.types, 'type')}${g.writes ? ', with writes' : ''})` : ''}. Narrower: ${b[2]}.${g && g.broadest ? ` Broadest rule: ${g.broadest}` : ''}`, fix: { op: 'extra', name: n, label: 'Remove the call' } });
    else if (g && g.cost >= 800) add({ kind: 'extra', id: n, severity: g.cost >= 5000 ? 'high' : 'medium', title: `${n}(): ${plural(g.types, 'type')} reached${g.writes ? ', with writes' : ''}`, text: `What it expands to covers ${plural(g.types, 'type')}${g.writes ? ' and lets the service write or execute some of them' : ''}.${g.broadest ? ` Broadest rule: ${g.broadest}` : ''} If the program touches one type among them, call that type's interface instead.`, fix: { op: 'extra', name: n, label: 'Remove the call' } });
  }
  // 6. Booleans on by default that grant a lot.
  for (const b of model.booleans || []) {
    if (b.external || b.default !== true) continue;
    const g = b.grants || {};
    const n = (g.caps || []).length + (g.extra || []).length + (g.access || []).length + ((g.net || {}).listen || []).length + ((g.net || {}).connect || []).length + (g.files || []).length;
    if (n) add({ kind: 'boolean', id: b.name, severity: 'low', title: `Boolean ${b.name} is on by default`, text: `It grants ${plural(n, 'setting')} unless an administrator turns it off: a boolean that is on by default is no boundary. Default off when the grant is for a less common setup.`, fix: { op: 'boolDefault', name: b.name, label: 'Default off' } });
  }
  // 7. Kept lines: dontaudit, and rules on broad targets.
  const kept = opts.kept || [];
  const dontaudit = kept.filter(k => /^\s*dontaudit\b/.test(k.text));
  if (dontaudit.length) add({ kind: 'kept', id: 'dontaudit', severity: 'low', title: `${plural(dontaudit.length, 'dontaudit rule')} hide refusals`, text: `Fine for known noise, but a hidden refusal of something the program needs is a silent failure (no AVC, nothing to learn from). Check each one still matches a harmless probe: ${dontaudit.slice(0, 3).map(k => k.text.trim().replace(/\s+/g, ' ').slice(0, 90)).join(' · ')}${dontaudit.length > 3 ? ' · …' : ''}`, line: dontaudit[0].l });
  for (const k of kept) {
    const m = /^\s*allow\s+(\S+)\s+(\S+)\s*:\s*(\S+|\{[^}]*\})\s+(\S+|\{[^}]*\})\s*;/.exec(k.text);
    if (!m) continue;
    const [, src, tgt, cls, perms] = m;
    if (src !== D && src !== '$1') continue;
    const broadTgt = /^(file_type|domain|non_security_file_type|non_auth_file_type|exec_type|device_node|port_type|node_type|netif_type|init_script_file_type|security_file_type|mountpoint)$/.test(tgt);
    const ps = perms.replace(/[{}]/g, '').trim().split(/\s+/);
    const w = Math.max(...ps.map(permWeight));
    if (broadTgt || perms === '*' || ps.includes('*')) add({ kind: 'kept', id: `line:${k.l}`, severity: w >= 3 || tgt === 'domain' ? 'high' : 'medium', title: `A rule on ${tgt} (every ${tgt === 'domain' ? 'process' : 'type with that attribute'})`, text: `${k.text.trim().replace(/\s+/g, ' ')} — ${w >= 3 ? 'writes or executes' : 'reads'} across the whole attribute. Name the type the program needs instead.`, line: k.l });
    else if (ps.includes('entrypoint') && tgt !== `${model.name}_exec_t`) add({ kind: 'kept', id: `line:${k.l}`, severity: 'medium', title: `Another entrypoint into ${D}`, text: `${k.text.trim().replace(/\s+/g, ' ')} — a second program type may enter the domain; make sure it is meant.`, line: k.l });
  }
  const KIND_ORDER = { permissive: 0, cap: 1, self: 2, access: 3, file: 4, extra: 5, kept: 6, boolean: 7 };
  rows.sort((a, b) => (SEV[b.severity] - SEV[a.severity]) || (KIND_ORDER[a.kind] - KIND_ORDER[b.kind]) || a.title.localeCompare(b.title));
  const summary = { high: rows.filter(r => r.severity === 'high').length, medium: rows.filter(r => r.severity === 'medium').length, low: rows.filter(r => r.severity === 'low').length };
  if (!rows.length) notes.push('Nothing broad or risky in what the form shows: the module grants its own files, named interfaces and a plain set of capabilities.');
  if (!opts.grants) notes.push('Build the tree (or the module) to see what each extra interface expands to; only the broad ones by name are listed.');
  return { rows, summary, notes };
}

function labelOfAccess(cat, id) {
  for (const grp of cat.access || []) for (const it of grp.items || []) if (it.id === id) return it.label;
  return id;
}

/**
 * The cost of an interface from its expansion: rules with the domain (or an attribute it gained) as source,
 * each worth size(target) × the heaviest permission weight; types = distinct target types reached (attributes
 * expanded by size); writes = any write/exec permission; broadest = the rule reaching most.
 * rules: [{ src: [names], tgt: [names], cls: [names], perms: [names], text }], attrs: added to the domain,
 * sizeOf(name) → number of types (1 for a type).
 */
function costOf(rules, attrs, domain, sizeOf) {
  const srcs = new Set([domain, ...(attrs || [])]);
  let cost = 0, types = 0, writes = false, broadest = null, best = -1;
  for (const r of rules) {
    if (!r.src.some(s => srcs.has(s) || s === 'self')) continue;
    const size = r.tgt.reduce((n, t) => n + (t === 'self' ? 1 : (sizeOf(t) || 1)), 0);
    const w = Math.max(1, ...r.perms.map(permWeight));
    if (w > 1) writes = true;
    cost += size * w;
    types = Math.max(types, size);
    if (size * w > best) { best = size * w; broadest = r.text; }
  }
  return { cost, types, writes, broadest };
}

module.exports = { report, costOf, BROAD, CAP_RISK, SELF_RISK, ACCESS_RISK, SEV };
