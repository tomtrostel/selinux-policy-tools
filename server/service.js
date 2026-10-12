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

const ACCESS_LABELS = { manage: 'create, change and delete', append: 'create and append (no rewriting)', read: 'read only', none: 'label only (no access)', custom: 'custom (kept as written)' };

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
  ['Logins', [
    ['loginpgm', 'Log users in: PAM, and switching to the user’s identity and role (a login program)', [['auth_login_pgm_domain']]],
    ['sessions', 'Start users’ sessions in their own domains, and signal them', [['userdom_spec_domtrans_all_users'], ['userdom_signal_all_users']]],
    ['loginrecords', 'Record logins (utmp, wtmp)', [['auth_rw_login_records']]],
    ['lastlog', 'Update lastlog', [['auth_rw_lastlog']]],
    ['faillog', 'Record failed logins (faillog)', [['auth_rw_faillog']]],
    ['usercontexts', 'Work out the SELinux context of a user’s session', [['seutil_read_default_contexts'], ['selinux_compute_user_contexts']]],
    ['ttys', 'Use the console and virtual terminals', [['term_use_unallocated_ttys'], ['term_setattr_unallocated_ttys']]],
    ['ptys', 'Use users’ pseudo-terminals', [['term_use_all_ptys'], ['term_setattr_all_ptys']]],
  ]],
  ['Started by systemd', [
    ['nnp', 'Allow starting with NoNewPrivileges (systemd hardening options)', [['init_nnp_daemon_domain']]],
    ['ttyfds', 'Use descriptors inherited from the session that started it', [['domain_use_interactive_fds']]],
    ['homequiet', 'Quietly refuse to search home directories (no audit noise)', [['userdom_dontaudit_search_user_home_dirs']]],
  ]],
];
/**
 * Calls that make a domain one init/systemd starts: (domain, program type[, MLS range]).
 * New services use init_daemon_domain; existing modules keep whichever they have.
 */
const INIT_CALLS = ['init_daemon_domain', 'init_ranged_daemon_domain', 'init_system_domain', 'init_ranged_system_domain', 'init_domain', 'init_ranged_domain'];
/*
 * Other ways a system service is started, each (domain, program type): D-Bus activation, a mail server,
 * inetd/xinetd (or ucspi-tcp), cron. Their modules may be off, so they usually sit in optional_policy.
 * MAIN: one of them starts the service ("Started by"); ALSO: a further way, next to the main one.
 */
const START_CALLS = ['dbus_system_domain', 'mta_mailserver', 'mta_sendmail_mailserver', 'inetd_service_domain', 'inetd_tcp_service_domain', 'inetd_udp_service_domain', 'inetd_core_service_domain', 'ucspitcp_service_domain', 'cron_system_entry'];
const ENTRY_CALLS = [...INIT_CALLS, ...START_CALLS];
const ENTRY = new Set(ENTRY_CALLS);
// Entry calls with the program type built in: only the domain is passed.
const ENTRY_EXEC = { mta_sendmail_mailserver: 'sendmail_exec_t' };
const ENTRY_RE = new RegExp(`\\b(${ENTRY_CALLS.join('|')})\\s*\\(`);
const STARTS = {
  main: [
    ['init_daemon_domain', 'systemd (or an init script)', 'systemd starts it from its unit file (or init from a SysV script), and it runs in its domain. The usual choice.'],
    ['mta_mailserver', 'systemd, as a mail server', 'systemd starts it as the system’s mail server (MTA): like systemd, plus it becomes a mailserver_domain, which mail clients and delivery agents are allowed to talk to.'],
    ['inetd_service_domain', 'inetd / xinetd (TCP and UDP)', 'inetd or xinetd listens on its port and starts the program for each connection; the program gets the connection as its standard input and output.'],
    ['inetd_tcp_service_domain', 'inetd / xinetd (TCP)', 'inetd or xinetd starts the program for each TCP connection and hands it the socket.'],
    ['inetd_udp_service_domain', 'inetd / xinetd (UDP)', 'inetd or xinetd starts the program when a UDP datagram arrives on its port.'],
  ],
  also: [
    ['dbus_system_domain', 'D-Bus activation', 'The D-Bus system bus may start it on demand when a client calls its bus name (a D-Bus service file with SystemdService= or Exec=). Also makes it a system bus service.'],
    ['cron_system_entry', 'Run by cron', 'System cron jobs (/etc/cron.d, /etc/cron.daily, …) may run the program, and it runs in its domain instead of the cron job’s.'],
  ],
};
const ALSO = new Set(STARTS.also.map(s => s[0]));

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

// Hover help for the form, by catalog section and id. {T} = the type a file kind adds.
const HELP = {
  file: {
    runtime: 'Files the service creates in /run while it runs: its PID file and Unix sockets. Adds the type {T}, labels the path, and gives what the service creates directly in /run that type automatically.',
    state: 'Data the service keeps between restarts in /var/lib (databases, keys, anything it must not lose). Adds the type {T}, labels the directory, and gives what it creates directly in /var/lib that type.',
    log: 'The service’s own log files in /var/log (for syslog or the journal, tick “Write to the system log” instead). Adds the type {T}. “Create and append” lets it add to its logs but not rewrite or delete them.',
    config: 'Configuration files in /etc that only this service (and administrators) should read, instead of the generic etc_t everyone can read. Adds the type {T}; usually read only.',
    cache: 'Data in /var/cache the service can rebuild if it is deleted. Adds the type {T} and labels the directory.',
    spool: 'Queued work in /var/spool (mail, jobs, …). Adds the type {T}, labels the directory, and gives what it creates directly in /var/spool that type.',
    tmp: 'Temporary files the service creates in /tmp or /var/tmp. Adds the type {T}; what it creates there gets that type automatically, so other services can’t read it. Needs no path.',
    tmpfs: 'Shared memory (files in /dev/shm, memfd). Adds the type {T}; what the service creates on tmpfs gets that type automatically. Needs no path.',
    lock: 'Lock files in /run/lock. Adds the type {T}; locks it creates there get that type automatically. Needs no path.',
    other: 'Files anywhere else, e.g. /srv/% or /opt/%/data. Adds a type ({T} unless you name it) for the paths you list, with the access you choose.',
    unit: 'Labels the service’s systemd unit file with {T}, so policy can say who may start, stop or change this service. The service itself gets no access to it.',
    initrc: 'Labels a SysV init script (/etc/rc.d/init.d) with {T}, for systems that start the service with service/init scripts. The service itself gets no access to it.',
  },
  level: {
    manage: 'Create, write, rename and delete files and directories of this type.',
    append: 'Create files and add to them, but not overwrite, truncate or delete them, so a compromised service can’t erase its own logs.',
    read: 'Read files and list directories; no changes.',
    none: 'Only label the files; the service gets no access (for files that other programs use).',
    custom: 'The module gives the service access with rules that match none of the levels here (e.g. mmap_manage_files_pattern, plain allow rules, a type transition of its own); they are kept exactly as written and listed below. Choosing a level replaces them with that level’s standard rules.',
  },
  access: {
    syslog: 'Log through syslog() or the systemd journal (/dev/log). Almost every daemon needs this.',
    audit: 'Write records to the kernel audit log, for security-relevant events (as login programs do).',
    nsswitch: 'Look up users, groups and host names the way glibc does: /etc/passwd and /etc/hosts, plus SSSD, LDAP, NIS or DNS as nsswitch.conf says. Choose this when the service resolves user or host names.',
    passwd: 'Read /etc/passwd and /etc/group only, for a service that just maps user IDs to names. Narrower than the nsswitch option.',
    dns: 'Send DNS queries and read the resolver configuration. Needed to reach other servers by name.',
    netconf: 'Read /etc/hosts, /etc/resolv.conf and similar network configuration, without sending DNS queries.',
    pam: 'Check passwords and open sessions through PAM, as login-like services do. Grants what PAM modules typically need (password checker, faillock, …).',
    kerberos: 'Use Kerberos: read krb5.conf and talk to the KDC. Reading a keytab needs more (e.g. kerberos_read_keytab under Other interfaces).',
    sysstate: 'Read general system information in /proc: memory, CPUs, mounts, uptime, load.',
    netstate: 'Read /proc/net: open sockets, interface statistics, routes.',
    sysctl: 'Read kernel settings under /proc/sys/kernel (hostname, limits, …).',
    netsysctl: 'Read network settings under /proc/sys/net.',
    sysfs: 'Read device and kernel information in /sys.',
    fsinfo: 'See the size and free space of any file system (statfs, as df does).',
    utmp: 'Read /run/utmp to see who is logged in.',
    locale: 'Read locale definitions and time zone data (/usr/share/zoneinfo, /etc/localtime). Most programs that format dates need this.',
    certs: 'Read the system’s TLS certificates and CA bundles (/etc/pki, /etc/ssl), e.g. to check servers it connects to over TLS.',
    etcfiles: 'Read the ordinary files in /etc (etc_t) that belong to no particular service.',
    etcruntime: 'Read files in /etc that are rewritten at run time (etc_runtime_t, e.g. mtab).',
    urandom: 'Read /dev/urandom. Older crypto libraries need it; getrandom() needs nothing.',
    random: 'Read /dev/random.',
    automount: 'Search automounted directories (autofs mount points such as /net), for paths that may lie under them.',
    bin: 'Run ordinary programs from /usr/bin and /usr/sbin. They run in this service’s domain with its rights, not in a domain of their own.',
    shell: 'Run /bin/sh and shell scripts, in this service’s domain.',
    systemctl: 'Run the systemctl program. Actually starting or stopping units also needs rules for talking to systemd.',
    kmod: 'Ask the kernel to load a kernel module on demand (e.g. for a protocol). The kernel loads it, not the service.',
    dbus: 'Connect to the D-Bus system bus to send and receive messages. Which services it may talk to is decided separately (D-Bus policy and rules for each peer).',
    mail: 'Run sendmail to send mail (e.g. alerts). The mail program runs in its own domain.',
    loginpgm: 'Makes it a login program, like sshd, login or a display manager: PAM, reading shadow through the password checker, and setting the SELinux user, role and level of the sessions it starts. Grants a lot; only for programs that really log users in.',
    sessions: 'Start a logged-in user’s shell or session in that user’s own domain (user_t, staff_t, unconfined_t, …) instead of its own, and signal those sessions (e.g. to end them at logout).',
    loginrecords: 'Add and remove entries in /run/utmp and /var/log/wtmp, as login programs do for who and last.',
    lastlog: 'Update /var/log/lastlog with each user’s last login.',
    faillog: 'Record failed login attempts (faillog, faillock).',
    usercontexts: 'Read the default_contexts configuration and ask the kernel which contexts a user may have, to start the session in the right SELinux context.',
    ttys: 'Read and write the console and virtual terminals (/dev/console, /dev/tty1…) and set their owner and mode, as getty and login do.',
    ptys: 'Read and write any user’s pseudo-terminal (/dev/pts/*) and set its owner and mode. For a pty type of its own for the sessions it creates, tick “Pseudo-terminals for logins”.',
    nnp: 'Lets systemd start it in its domain when the unit sets NoNewPrivileges=yes or options that imply it (e.g. SystemCallFilter=); without this the start is refused.',
    ttyfds: 'Use descriptors inherited from whoever started it, e.g. the terminal when an administrator runs it by hand.',
    homequiet: 'Grants nothing: refusals to look into users’ home directories are just not logged, so harmless probing doesn’t fill the audit log.',
  },
  self: {
    fifo: 'Pipes between the service’s own processes (parent and workers, or a pipe to a child program it runs).',
    signal: 'Its processes may signal each other, e.g. a master process telling workers to reload or stop.',
    unixstream: 'Unix stream sockets of its own: socketpair() between its processes, listening on its own socket. Connecting to another service’s socket needs that service’s interface.',
    unixdgram: 'Unix datagram sockets of its own (socketpair, its own datagram sockets).',
    sched: 'Change its own priority, scheduling policy or CPU affinity.',
    rlimit: 'Change its own resource limits (open files, core size, …).',
    shm: 'System V shared memory and semaphores between its own processes.',
    netlink: 'Read network interfaces, addresses and routes through netlink (what getifaddrs() and “ip addr” use).',
    execmem: 'Make memory writable and executable at once (JIT compilers, some interpreters). Weakens protection against injected code; grant it only when denials show it’s needed.',
  },
  cap: {
    setuid: 'Change its user ID, usually to drop root after starting.',
    setgid: 'Change its group IDs, usually to drop root after starting.',
    chown: 'Change the owner or group of files, e.g. hand its directories to the service user.',
    fowner: 'Skip “you must own the file” checks: chmod, utime or ACLs on files it doesn’t own.',
    fsetid: 'Keep setuid/setgid bits when it changes files, and set the setgid bit for groups it isn’t in.',
    dac_read_search: 'Read any file and search any directory whatever its Unix permissions (SELinux rules still apply). Often needed when root reads files owned by other users.',
    dac_override: 'Read, write and run any file whatever its Unix permissions (SELinux rules still apply). Root daemons often trip over this because of file modes; fixing the files’ owner is usually better.',
    kill: 'Send signals to processes of other users (SELinux still decides which domains).',
    net_bind_service: 'Bind TCP/UDP ports below 1024 (80, 443, …). Which ports is still set in Network.',
    net_admin: 'Configure network interfaces, routes and firewall rules, and use admin-only socket options. Grants a lot.',
    net_raw: 'Raw and packet sockets: send any packet, see others’ traffic (ping, DHCP clients). Grants a lot.',
    ipc_lock: 'Lock memory so it isn’t swapped out (mlock), e.g. to keep keys out of swap.',
    sys_nice: 'Raise its priority, use real-time scheduling, change other processes’ priority.',
    sys_resource: 'Go beyond resource limits (open files, reserved disk space, …).',
    sys_time: 'Set the system clock (time services).',
    sys_chroot: 'Call chroot() to shut itself into a directory.',
    sys_tty_config: 'Configure terminals (vhangup, keyboard settings).',
    setpcap: 'Change capabilities: drop them from the bounding set, keep them across a user change.',
    audit_write: 'Write records to the kernel audit log.',
    sys_ptrace: 'Trace and inspect other processes (ptrace). Grants a lot.',
    sys_rawio: 'Raw access to I/O ports and device memory. Grants a lot.',
    sys_admin: 'A catch-all for many admin operations (mount, namespaces, quotas, sethostname, …). Close to full root; avoid it.',
    block_suspend: 'Keep the system from suspending.',
    wake_alarm: 'Set timers that wake the system from suspend.',
  },
  provides: {
    domtrans: 'Lets other domains run the program so it starts in this service’s domain (e.g. a tool that starts the service).',
    exec: 'Lets other domains run the program without a transition: it then runs with the caller’s rights.',
    read_config: 'Lets other domains (admin tools, …) read its configuration files.',
    read_log: 'Lets other domains (log readers, …) read its log files.',
    read_lib_files: 'Lets other domains read its state data in /var/lib.',
    manage_lib_files: 'Lets other domains create, change and delete its state data.',
    stream_connect: 'Lets other domains connect to its Unix socket in /run, i.e. be its clients.',
    admin: 'For administrator roles: signal the service and see its processes, manage all its files, and run its init script.',
  },
};

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
/*
 * Helper domains (model.helpers: [{ name, domain, execType, exec, signal, decl, files: [{ type, access }],
 * self, caps, net, access, extra }]): programs the service runs in a domain of their own, entered
 * through domtrans_pattern from the service's domain, each with its own rights.
 */
const helperBase = (model, h) => sub((h.name || '').trim() || '%_helper', model.name);
function helperNames(model, h) {
  const b = helperBase(model, h);
  return { H: h.domain || `${b}_t`, HE: h.execType || `${b}_exec_t` };
}
const HELPER_DECLS = ['domain_type', 'domain_entry_file', 'application_domain'];
function fileType(model, row, ctx) {
  if (row.type) return sub(row.type, model.name);
  const k = KIND[row.kind];
  const alt = k.decl.find(([h]) => ctx.has(h)) || k.decl[0];
  return `${model.name}${alt[1]}`;
}

/*
 * Port types of the service (model.ports: [{ name, nums: [{ proto, port, level }] }], name '' = the
 * module name). In a tree they are network_port() lines in corenetwork.te.in, which generates the
 * corenet_* interfaces for them; a standalone module declares the type itself (corenet_port) and,
 * since a loadable module can't hold portcon statements, gets its numbers from semanage.
 */
const portName = (model, p) => sub((p.name || '').trim() || '%', model.name);
const portNums = (p) => (p.nums || []).filter(x => String(x.port || '').trim()).map(x => ({ proto: x.proto || 'tcp', port: String(x.port).trim(), level: x.level || 's0' }));
const SEMANAGE_RE = /^\s*#\s*semanage port -a -t (\w+) -p (tcp|udp|sctp|dccp) (\d+(?:-\d+)?)\s*$/;
const PORT_HDR_RE = /^\s*#\s*Port numbers\b/;
function portDeclText(P, nums) {
  const head = nums.length ? ['# Port numbers: a module can\'t set them, so after installing run', ...nums.map(x => `#\tsemanage port -a -t ${P} -p ${x.proto} ${x.port}`)] : [];
  return [...head, `type ${P};`, `corenet_port(${P})`].join('\n');
}
/** In a tree, the corenet_* interfaces of new port types exist once corenetwork is rebuilt: ctx.has says so. */
function portCtx(model, ctx) {
  if (!ctx.corenet || ctx.withPorts || !(model.ports || []).length) return ctx;
  const mine = new Set(model.ports.map(p => portName(model, p)).filter(n => /^\w+$/.test(n)));
  const re = /^(corenet_\w+?_)(\w+)(_port|_client_packets|_server_packets)$/;
  const has = (n) => {
    if (ctx.has(n)) return true;
    const m = re.exec(n);
    if (!m) return false;
    for (const x of mine) {
      if (!n.endsWith(`_${x}${m[3]}`)) continue;
      const head = n.slice(0, n.length - x.length - m[3].length);
      if (!ctx.portRef || ctx.has(head + ctx.portRef + m[3])) return true;
    }
    return false;
  };
  return { ...ctx, has, withPorts: true };
}
/** The pattern calls of an access level on a file type (pat(name) makes the call). */
function levelStmts(acc, pat, k) {
  if (acc === 'read') return [pat('list_dirs_pattern'), pat('read_files_pattern'), pat('read_lnk_files_pattern')];
  if (acc === 'append') return [pat('manage_dirs_pattern'), pat('append_files_pattern'), pat('create_files_pattern'), pat('setattr_files_pattern')];
  if (acc === 'manage') return [pat('manage_dirs_pattern'), pat('manage_files_pattern'), ...(k.extra || []).map(pat)];
  return [];
}
// Levels by how much they allow, to tell when a boolean adds nothing (append and read differ, but neither covers the other).
const LEVEL_RANK = { none: 0, read: 1, append: 1, manage: 2 };

const allowKey = (src, tgt, cls, perms) => `allow:${src}:${tgt}:${cls}:${perms.slice().sort().join(' ')}`;

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
  ctx = portCtx(model, ctx);
  const units = new Map();
  const { D, E } = names(model);
  const add = (key, sig, stmts) => units.set(key, { sig: JSON.stringify(sig), stmts });
  const call = (name, args, section = 'local', group = null, bool = null) => ({ key: scoped(bool, callKey(name, args)), kind: 'call', name, args, text: callText(name, args), section, opt: section === 'local' && ctx.optional(name), group, bool });
  const callOf = call;
  const type = (t) => ({ key: `type:${t}`, kind: 'type', text: `type ${t};`, section: 'decl' });

  const by = model.declaredBy || null;
  // Started by the template that declares it (by.starts), or by its own start calls (init_daemon_domain by default).
  const entries = model.entries && model.entries.length ? model.entries : by && by.starts ? [] : [{ name: 'init_daemon_domain', args: [] }];
  // Further ways to start it (D-Bus activation, cron) go in optional_policy when their module may be off;
  // the main one stays at the top level, since without it the type isn't a domain at all.
  const entryStmt = (e) => {
    const args = ENTRY_EXEC[e.name] ? [D] : [D, E, ...(e.args || [])];
    return ALSO.has(e.name) && ctx.optional(e.name) ? call(e.name, args, 'local', 'start') : call(e.name, args, 'decl');
  };
  const elsewhere = !!model.execElsewhere || (by && by.execToo);
  add('domain', { D, E, entries, by, elsewhere: !!model.execElsewhere }, [by ? call(by.name, by.args, 'decl') : type(D), ...(elsewhere ? [] : [type(E)]), ...entries.map(entryStmt)]);
  if (model.loginPty) {
    const P = `${D.replace(/_t$/, '')}_devpts_t`;
    add('loginpty', 1, [type(P), call('term_login_pty', [P], 'decl'),
      { key: allowKey(D, P, 'chr_file', ['rw_chr_file_perms', 'setattr_chr_file_perms', 'relabelfrom']), kind: 'allow', name: 'allow', text: `allow ${D} ${P}:chr_file { rw_chr_file_perms setattr_chr_file_perms relabelfrom };`, section: 'local', group: 'loginpty' },
      call('term_create_pty', [D, P], 'local', 'loginpty')].map(x => (x.opt ? { ...x, opt: false } : x)));
  }
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
    st.push(...levelStmts(acc, pat, k));
    if ((acc === 'manage' || acc === 'append') && ft) st.push(call(ft, [D, T, k.ftClasses], 'local', g));
    add(`file:${T}`, { kind: row.kind, access: acc }, st.map(s => (s.opt ? { ...s, opt: false } : s)));
  }
  const rowByType = new Map((model.files || []).filter(r => KIND[r.kind]).map(r => [fileType(model, r, ctx), r]));

  // Port types declared in the module (standalone; in a tree they live in corenetwork.te.in).
  const ownPorts = new Set();
  if (!ctx.corenet) {
    for (const p of model.ports || []) {
      const P = `${portName(model, p)}_port_t`;
      if (!/^\w+_port_t$/.test(P)) continue;
      ownPorts.add(portName(model, p));
      add(`port:${P}`, portNums(p), [{ key: `type:${P}`, kind: 'type', name: P, text: portDeclText(P, portNums(p)), section: 'decl' }]);
    }
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
    // More access to the service's own files while the boolean is on (e.g. read always, manage when on).
    for (const f of (b.grants || {}).files || []) {
      const r = rowByType.get(f.type);
      if (!r || !['read', 'append', 'manage'].includes(f.access)) continue;
      const k = KIND[r.kind], T = f.type, g = `file:${T}`;
      const pat = (p) => ({ ...call(p, [D, T, T], 'local', g, name), opt: false });
      const st = levelStmts(f.access, pat, k);
      // The type transition only when the always-on level has none (a duplicate type rule fails the
      // build) and its interface may sit in a conditional.
      const ft = pick(ctx, k.filetrans);
      const always = r.access || k.access[0];
      const withFt = !!ft && (f.access === 'manage' || f.access === 'append') && (always === 'none' || always === 'read') && (!ctx.condSafe || ctx.condSafe(ft));
      if (withFt) st.push({ ...call(ft, [D, T, k.ftClasses], 'local', g, name), opt: false });
      add(`b:${name}:file:${T}`, { access: f.access, ft: withFt }, st);
    }
  }

  // Helper domains: declared here, entered from the service's domain, with rights of their own.
  const fileKinds = new Map([...rowByType].map(([T, r]) => [T, KIND[r.kind]]));
  for (const h of model.helpers || []) {
    const { H, HE } = helperNames(model, h);
    if (!/^\w+_t$/.test(H) || !/^\w+_t$/.test(HE) || H === D) continue;
    const decl = h.decl === 'application_domain' ? [call('application_domain', [H, HE], 'decl')] : [call('domain_type', [H], 'decl'), call('domain_entry_file', [H, HE], 'decl')];
    add(`helper:${H}`, { H, HE, decl: h.decl || 'domain_type' }, [type(H), type(HE), ...decl,
      { key: `role:system_r:${H}`, kind: 'role', text: `role system_r types ${H};`, section: 'decl' },
      { ...call('domtrans_pattern', [D, HE, H]), opt: false, dom: D }]);
    if (h.signal) add(`h:${H}:signal`, 1, [{ key: allowKey(D, H, 'process', ['signal']), kind: 'allow', name: 'allow', text: `allow ${D} ${H}:process signal;`, section: 'local', dom: D }]);
    for (const f of h.files || []) {
      const k = fileKinds.get(f.type);
      if (!k || !f.access || f.access === 'none') continue;
      const T = f.type, g = `file:${T}`;
      const pat = (p) => ({ ...call(p, [H, T, T], 'local', g), opt: false, dom: H, key: callKey(p, [H, T, T]) });
      const st = levelStmts(f.access, pat, k);
      const ft = pick(ctx, k.filetrans);
      if ((f.access === 'manage' || f.access === 'append') && ft) st.push({ ...call(ft, [H, T, k.ftClasses], 'local', g), opt: false, dom: H });
      add(`h:${H}:file:${T}`, f.access, st);
    }
    grantUnits(h, `h:${H}:`, null, H);
  }
  return units;

  /** Units for what a domain (the service's, or a helper's: S) is granted, at the top level (bool null) or under a boolean. */
  function grantUnits(g, prefix, bool, S = D) {
    const selfKey = (cls, perm, b) => (S === D ? scoped(b, `self:${cls}:${perm}`) : `h:${S}:self:${cls}:${perm}`);
    const self = (cls, perm) => ({ key: selfKey(cls, perm, bool), kind: 'self', cls, perm, section: 'local', bool, dom: S });
    const call = (name, args, section, group, b) => ({ ...callOf(name, args, section, group, b), dom: S });
    const dcall = (name, group) => call(name, [S], 'local', group, bool);
    const allow = (tgt, cls, perms) => ({ key: scoped(bool, allowKey(S, tgt, cls, perms)), kind: 'allow', name: 'allow', text: `allow ${S} ${tgt}:${cls} ${perms.length === 1 ? perms[0] : `{ ${perms.join(' ')} }`};`, section: 'local', group: 'net', bool, dom: S });
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
        const shared = (n) => { if (ctx.has(n)) st.push(call(n, [S], 'local', 'net', null)); };
        const sock = proto === 'udp' ? ['udp_socket', 'create_socket_perms'] : ['tcp_socket', 'create_stream_socket_perms'];
        st.push({ ...self(...sock), bool: null, key: selfKey(...sock, null) });
        shared(`corenet_${proto}_sendrecv_generic_if`);
        shared(`corenet_${proto}_sendrecv_generic_node`);
        if (ownPorts.has(port)) {
          // A port type of the module's own: plain rules, there are no corenet interfaces for it.
          if (dir === 'listen') shared(`corenet_${proto}_bind_generic_node`);
          const cls = `${proto}_socket`;
          st.push(allow(`${port}_port_t`, cls, dir === 'listen' ? ['name_bind'] : proto === 'tcp' ? ['name_connect'] : ['recv_msg', 'send_msg']));
        } else if (port === 'all') {
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
    else if ((m = /^role\s+(\w+)\s+types\s+(\w+)\s*;/.exec(code))) stmts.push({ kind: 'role', role: m[1], name: m[2], key: `role:${m[1]}:${m[2]}`, l, endL: l, ...where(l) });
    else if ((m = /^allow\s+(\w+)\s+([\w-]+)\s*:\s*(\w+)\s+(\{[^}]*\}|[\w-]+)\s*;$/.exec(code))) {
      const perms = m[4].replace(/[{}]/g, ' ').trim().split(/\s+/);
      const w = where(l);
      stmts.push({ kind: 'allow', src: m[1], tgt: m[2], cls: m[3], perms, key: scoped(w.bool, allowKey(m[1], m[2], m[3], perms)), l, endL: l, ...w });
    } else if (/^(allow|dontaudit|auditallow|type_transition|neverallow)\b/.test(code)) {
      let e = l;
      while (e < lines.length - 1 && !/;\s*(#.*)?$/.test(lines[e])) e++;
      stmts.push({ kind: 'rule', text: code, l, endL: e, ...where(l) });
    }
  });
  return { parse: p, lines, stmts, blocks };
}

/**
 * Start calls inside templates: makeStartsVia(getDef)(name) → [{ d, e, via }] with $N standing for the
 * template's arguments (rpc_domain_template: { d: '$1_t', e: '$1_exec_t', via: 'init_daemon_domain' }),
 * through nested templates. getDef(name) → a definition with bodyCalls [{ name, args, cond }].
 * Only start calls outside optional/ifdef blocks of the body count (cond).
 */
function makeStartsVia(getDef) {
  const memo = new Map();
  const subst = (s, args) => s.replace(/\$(\d+)/g, (m, n) => (args[n - 1] !== undefined ? args[n - 1] : m));
  const walk = (name, depth) => {
    if (memo.has(name)) return memo.get(name);
    memo.set(name, []);
    const d = getDef(name);
    const out = [];
    if (d && depth < 5) {
      for (const bc of d.bodyCalls || []) {
        if (bc.cond) continue;
        if (ENTRY.has(bc.name)) {
          const e = ENTRY_EXEC[bc.name] || bc.args[1];
          if (bc.args[0] && e) out.push({ d: bc.args[0].trim(), e: e.trim(), via: bc.name });
        } else if (/\$\d/.test((bc.args || []).join(' '))) {
          for (const x of walk(bc.name, depth + 1)) out.push({ d: subst(x.d, bc.args.map(a => a.trim())), e: subst(x.e, bc.args.map(a => a.trim())), via: x.via });
        }
      }
    }
    memo.set(name, out);
    return out;
  };
  return (name) => walk(name, 0);
}

/**
 * Services of a module's .te: (domain, program type) of its start calls (init_*domain, D-Bus activation,
 * inetd, cron, mail server). init_daemon_domain's program type wins, then other init_* calls'.
 * With ctx.startsVia, also domains a template call at the top level declares and starts
 * (rpc_domain_template(nfsd) → nfsd_t), marked with { template: { name, args } }.
 */
function daemonDomains(teText, ctx) {
  const out = [];
  const rank = (n) => (n === 'init_daemon_domain' ? 0 : INIT_CALLS.includes(n) ? 1 : 2);
  const calls = parsePolicy(teText).calls;
  for (const c of calls) {
    if (!ENTRY.has(c.name) || c.inDef || c.args.length < (ENTRY_EXEC[c.name] ? 1 : 2) || !/^\w+$/.test(c.args[0])) continue;
    const exec = ENTRY_EXEC[c.name] || c.args[1];
    const have = out.find(x => x.domain === c.args[0]);
    if (!have) out.push({ domain: c.args[0], exec, via: c.name });
    else if (rank(c.name) < rank(have.via)) Object.assign(have, { exec, via: c.name });
  }
  if (ctx && ctx.startsVia) {
    const sub = (s, args) => s.replace(/\$(\d+)/g, (m, n) => (args[n - 1] !== undefined ? args[n - 1] : m));
    for (const c of calls) {
      if (c.inDef || ENTRY.has(c.name) || BLOCK_CALLS.has(c.name) || !c.args.length || !c.args.every(a => /^\w+$/.test(a))) continue;
      for (const x of ctx.startsVia(c.name)) {
        const domain = sub(x.d, c.args), exec = sub(x.e, c.args);
        if (!/^\w+_t$/.test(domain) || !/^\w+_t$/.test(exec)) continue;
        const template = { name: c.name, args: c.args };
        const have = out.find(o => o.domain === domain);
        // Also started by a call of its own (e.g. cron_system_entry next to the template): the template still declares it.
        if (have) { if (have.exec === exec && !have.template) Object.assign(have, rank(x.via) <= rank(have.via) ? { via: x.via, template } : { template }); continue; }
        out.push({ domain, exec, via: x.via, template });
      }
    }
  }
  return out;
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
  const domains = daemonDomains(texts.te || '', ctx);
  const mod = te.parse.module || opts.module;
  if (!domains.length) return { error: `${mod}.te has no init_daemon_domain() (or another call that starts a service: init_system_domain(), dbus_system_domain(), inetd_service_domain(), cron_system_entry(), …), so it isn't a service module the editor understands.` };
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
  // How it is started (init_daemon_domain, init_system_domain, a ranged variant, D-Bus activation, inetd, cron, …),
  // at the top level or in optional_policy, kept as written.
  model.entries = [];
  for (const st of editable) {
    if (st.kind !== 'call' || st.bool || !ENTRY.has(st.name) || st.args[0] !== D || claimed.has(st)) continue;
    if (ENTRY_EXEC[st.name] ? st.args.length !== 1 || ENTRY_EXEC[st.name] !== E : st.args[1] !== E) continue;
    claimed.add(st);
    model.entries.push({ name: st.name, args: ENTRY_EXEC[st.name] ? [] : st.args.slice(2) });
  }
  // A program type the module doesn't declare (mta_sendmail_mailserver: sendmail_exec_t of the mta module).
  if (!editable.some(st => st.kind === 'type' && st.name === E) && model.entries.some(e => ENTRY_EXEC[e.name] === E)) model.execElsewhere = true;
  claim(s => s.kind === 'call' && s.name === 'init_daemon_domain' && s.args[0] === D);
  // A domain a template declares and starts (rpc_domain_template(nfsd): nfsd_t, nfsd_exec_t, init_daemon_domain).
  if (dom.template) {
    const t = editable.find(st => st.kind === 'call' && !st.bool && !claimed.has(st) && st.name === dom.template.name && st.args.length === dom.template.args.length && st.args.every((a, i) => a === dom.template.args[i]));
    if (t) {
      claimed.add(t);
      model.declaredBy = { name: t.name, args: t.args, execToo: !editable.some(st => st.kind === 'type' && st.name === E), starts: dom.via };
    }
  }
  // A domain declared by a template (e.g. ssh_server_template(sshd) declares sshd_t).
  if (!model.declaredBy && !editable.some(st => st.kind === 'type' && st.name === D) && ctx.declares) {
    const t = editable.find(st => st.kind === 'call' && st.top && !claimed.has(st) && st.args.length >= 1 && `${st.args[0]}_t` === D && (ctx.declares(st.name) || []).includes('$1_t'));
    if (t) {
      claimed.add(t);
      const pats = ctx.declares(t.name);
      model.declaredBy = { name: t.name, args: t.args, execToo: !editable.some(st => st.kind === 'type' && st.name === E) && `${t.args[0]}_exec_t` === E && pats.includes('$1_exec_t') };
    }
  }
  // A pty type of its own for the sessions it starts (term_login_pty).
  for (const st of editable.filter(x => x.kind === 'type' && x.top && !claimed.has(x))) {
    const decl = editable.find(x => x.kind === 'call' && x.top && x.name === 'term_login_pty' && x.args[0] === st.name);
    if (!decl || st.name !== `${D.replace(/_t$/, '')}_devpts_t`) continue;
    model.loginPty = true;
    claimed.add(st); claimed.add(decl);
    for (const x of editable) {
      if (claimed.has(x) || x.bool) continue;
      if ((x.kind === 'call' && x.name === 'term_create_pty' && x.args[0] === D && x.args[1] === st.name) || (x.kind === 'allow' && x.src === D && x.tgt === st.name && x.cls === 'chr_file')) ownAdd('loginpty', x);
    }
  }
  claim(s => s.kind === 'role' && s.name === D);

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
    const row = { kind: k.id, type: T, paths: pathsOf(T), access };
    model.files.push(row);
    ownAdd(u, t);
    // Declaration helpers on the type, rules from the domain to it.
    for (const s of editable) {
      if (claimed.has(s) || s.bool) continue; // rules under a boolean stay with the boolean
      if (s.kind === 'call' && s.top && s.args[0] === T) ownAdd(u, s);
      else if (s.kind === 'call' && s.args[0] === D && s.args.slice(1).includes(T) && /(_pattern|filetrans)$/.test(s.name)) ownAdd(u, s);
      else if (s.kind === 'allow' && s.src === D && s.tgt === T) ownAdd(u, s);
    }
    // No level matched, but the domain does get access (mmap_manage_files_pattern, allow rules, …):
    // "custom", with those rules kept as written (and shown), not "label only".
    if (access === 'none') {
      const rules = (own.get(u) || []).filter(x => (x.kind === 'call' && x.args[0] === D) || ((x.kind === 'allow' || x.kind === 'rule') && (x.src === D || new RegExp(`^\\w+\\s+${D}\\b`).test(x.text || ''))));
      if (rules.length) {
        row.access = 'custom';
        rules.sort((a, b) => a.l - b.l);
        row.rules = rules.map(x => te.lines.slice(x.l, x.endL + 1).map(ln => ln.trim()).join(' '));
        row.ruleLines = rules.map(x => x.l); // 0-based lines in the .te, to open them
      }
    }
  }

  // Port types: in a tree the server passes the ones in corenetwork.te.in named after the module;
  // a standalone module declares its own (type + corenet_port, numbers in the semanage comment above).
  model.ports = (opts.ports || []).map(p => ({ name: p.name, nums: portNums(p) }));
  if (!ctx.corenet) {
    for (const t of editable.filter(s => s.kind === 'type' && s.top && /^\w+_port_t$/.test(s.name))) {
      const decl = editable.find(s => s.kind === 'call' && s.top && s.name === 'corenet_port' && s.args[0] === t.name);
      if (!decl) continue;
      const P = t.name, u = `port:${P}`, nums = [];
      let a = t.l;
      while (a > 0 && (SEMANAGE_RE.test(te.lines[a - 1]) || PORT_HDR_RE.test(te.lines[a - 1]))) {
        a--;
        const m = SEMANAGE_RE.exec(te.lines[a]);
        if (m && m[1] === P) nums.unshift({ proto: m[2], port: m[3], level: 's0' });
      }
      model.ports.push({ name: P.slice(0, -7), nums });
      ownAdd(u, t);
      if (a < t.l) ownAdd(u, { kind: 'comment', l: a, endL: t.l - 1 });
      for (const s of editable) if (!claimed.has(s) && s.kind === 'call' && s.top && s.args.length === 1 && s.args[0] === P) ownAdd(u, s);
    }
  }
  const ownPortTypes = new Set(ctx.corenet ? [] : model.ports.map(p => `${p.name}_port_t`));

  // Helper domains: declared here (domain_type + domain_entry_file, or application_domain) and
  // entered from the service's domain (domtrans_pattern at the top level). Other daemons aren't helpers.
  model.helpers = [];
  const daemons = new Set(domains.map(x => x.domain));
  const topCall = (name, args) => editable.find(s => s.kind === 'call' && s.top && s.name === name && s.args.length === args.length && args.every((a, i) => s.args[i] === a));
  for (const t of editable.filter(s => s.kind === 'type' && s.top && !claimed.has(s) && !daemons.has(s.name))) {
    const H = t.name;
    const dtp = editable.find(s => s.kind === 'call' && s.top && s.name === 'domtrans_pattern' && s.args.length === 3 && s.args[0] === D && s.args[2] === H);
    if (!dtp) continue;
    const HE = dtp.args[1];
    const app = topCall('application_domain', [H, HE]);
    const dt = topCall('domain_type', [H]), de = topCall('domain_entry_file', [H, HE]);
    const typeE = editable.find(s => s.kind === 'type' && s.top && s.name === HE);
    if (!typeE || !(app || (dt && de))) continue;
    const u = `helper:${H}`;
    const h = { name: H.replace(/_t$/, ''), domain: H, execType: HE, exec: pathsOf(HE), decl: app && !(dt && de) ? 'application_domain' : 'domain_type', signal: false, files: [], ...emptyGrants() };
    if (h.domain === `${h.name}_t`) delete h.domain;
    if (h.execType === `${h.name}_exec_t`) delete h.execType;
    model.helpers.push(h);
    for (const st of [t, typeE, dtp, ...(h.decl === 'application_domain' ? [app] : [dt, de])]) ownAdd(u, st);
    for (const st of editable) {
      if (claimed.has(st)) continue;
      if (st.kind === 'role' && st.top && st.name === H) ownAdd(u, st);
      else if (st.kind === 'call' && st.top && st.args.length === 1 && st.args[0] === HE) ownAdd(u, st);
    }
    const sig = editable.find(st => st.kind === 'allow' && st.top && st.src === D && st.tgt === H && st.cls === 'process' && st.perms.join(' ') === 'signal');
    if (sig) { h.signal = true; ownAdd(`h:${H}:signal`, sig); }
  }
  const helperOf = new Map(model.helpers.map(h => [h.domain || `${h.name}_t`, h]));
  // Their access to the service's file types (patterns on T, at the top level or in optional_policy).
  for (const [H, h] of helperOf) {
    for (const r of model.files) {
      const T = r.type;
      const mine = editable.filter(st => !st.bool && !claimed.has(st) && ((st.kind === 'call' && st.args[0] === H && st.args.slice(1).includes(T) && /(_pattern|filetrans)$/.test(st.name)) || (st.kind === 'allow' && st.src === H && st.tgt === T)));
      if (!mine.length) continue;
      const pats = new Set(mine.filter(st => st.kind === 'call' && st.args[1] === T && st.args[2] === T).map(st => st.name));
      const access = pats.has('manage_files_pattern') ? 'manage' : pats.has('append_files_pattern') ? 'append' : pats.has('read_files_pattern') ? 'read' : null;
      if (!access) continue;
      h.files.push({ type: T, access });
      for (const st of mine) ownAdd(`h:${H}:file:${T}`, st);
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
  for (const [H, h] of helperOf) grantsIn(h, null, `h:${H}:`, H);

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
  for (const s of editable) {
    const h = s.kind === 'call' && s.args.length === 1 && !s.bool && helperOf.get(s.args[0]);
    if (!h || claimed.has(s) || generic(s.name) || HELPER_DECLS.includes(s.name)) continue;
    if (!h.extra.includes(s.name)) h.extra.push(s.name);
    claimed.add(s);
  }

  // Everything else that mentions the domain stays as it is.
  const kept = [];
  // Rules on itself with permissions no setting stands for: shown, and never touched.
  const modelled = new Set();
  for (const u of unitsOf(model, ctx).values()) for (const s of u.stmts) if (s.kind === 'self') modelled.add(s.key);
  const selfKeyOf = (s, p) => (s.src === D ? scoped(s.bool, `self:${s.cls}:${p}`) : `h:${s.src}:self:${s.cls}:${p}`);
  for (const s of editable) {
    if ((isSelf(s) || [...helperOf.keys()].some(H => isSelf(s, H))) && s.perms.some(p => !modelled.has(selfKeyOf(s, p)))) claimed.delete(s);
  }
  for (const s of te.stmts) if (!claimed.has(s) && mentionsD(s)) kept.push({ l: s.l, endL: s.endL, text: te.lines.slice(s.l, s.endL + 1).map(x => x.trim()).join(' ') });
  kept.sort((a, b) => a.l - b.l);
  const provided = (texts.if ? parsePolicy(texts.if).defs.map(d => d.name) : []);
  return { model, own, kept, domains, provided, scan: te };

  function emptyGrants() { return { self: [], caps: [], net: { listen: [], connect: [] }, access: [], extra: [], files: [] }; }
  function mentionsD(s) {
    const text = te.lines.slice(s.l, s.endL + 1).join('\n');
    return [D, ...(model.helpers || []).map(h => h.domain || `${h.name}_t`)].some(x => new RegExp(`\\b${x}\\b`).test(text));
  }
  // Self rules of the service's domain (top level or directly under a boolean), or of a helper (S; top level only).
  function isSelf(s, S = D) { return s.kind === 'allow' && s.src === S && s.tgt === 'self' && (s.top || (S === D && s.bool && !s.opt)); }

  /** Self rules, port items, catalog items of domain S in one scope (top level: bool null). */
  function grantsIn(g, bool, prefix, S = D) {
    const inScope = (s) => (bool ? s.bool === bool : !s.bool);
    const selfPerms = new Map(); // cls -> Set
    for (const s of editable) {
      if (!isSelf(s, S) || !inScope(s)) continue;
      if (!selfPerms.has(s.cls)) selfPerms.set(s.cls, new Set());
      for (const p of s.perms) selfPerms.get(s.cls).add(p);
      claimed.add(s);
    }
    const hasSelf = (cls, p) => selfPerms.has(cls) && selfPerms.get(cls).has(p);
    // Under a boolean: access to the service's own file types at one of the levels (rules matching
    // none stay kept). Its other rules on the type in the same block go with it.
    if (bool && S === D) {
      for (const r of model.files) {
        const T = r.type;
        const mine = editable.filter(s => inScope(s) && !claimed.has(s) && ((s.kind === 'call' && s.args[0] === D && s.args.slice(1).includes(T) && /(_pattern|filetrans)$/.test(s.name)) || (s.kind === 'allow' && s.src === D && s.tgt === T)));
        const pats = new Set(mine.filter(s => s.kind === 'call' && s.args[1] === T && s.args[2] === T).map(s => s.name));
        const access = pats.has('manage_files_pattern') ? 'manage' : pats.has('append_files_pattern') ? 'append' : pats.has('read_files_pattern') ? 'read' : null;
        if (!access) continue;
        g.files.push({ type: T, access });
        for (const s of mine) ownAdd(`${prefix}file:${T}`, s);
      }
    }
    for (const [id, , perms] of SELF) if (Object.entries(perms).every(([cls, ps]) => ps.every(p => hasSelf(cls, p)))) g.self.push(id);
    for (const [c, cls] of CAPS) if (hasSelf(cls, c)) g.caps.push(c);

    // Calls taking only the domain.
    const domCalls = editable.filter(s => inScope(s) && s.kind === 'call' && s.args.length === 1 && s.args[0] === S && !claimed.has(s));
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
    // Upstream refpolicy generates no corenet_udp_sendrecv_X_port: there a UDP client of port X is just
    // the generic rules plus the client packets of X (when nothing else of X claims those).
    for (const s of domCalls) {
      const m = /^corenet_sendrecv_(\w+)_client_packets$/.exec(s.name);
      if (!m || m[1] === 'all' || ctx.has(`corenet_udp_sendrecv_${m[1]}_port`) || !ctx.has(`corenet_udp_bind_${m[1]}_port`)) continue;
      if (g.net.connect.some(x => x.port === m[1])) continue;
      g.net.connect.push({ proto: 'udp', port: m[1] });
    }
    // Rules on the module's own port types (standalone).
    for (const s of editable) {
      if (!inScope(s) || s.kind !== 'allow' || s.src !== S || !ownPortTypes.has(s.tgt) || claimed.has(s)) continue;
      const proto = { tcp_socket: 'tcp', udp_socket: 'udp' }[s.cls];
      const ps = s.perms.slice().sort().join(' ');
      const dir = ps === 'name_bind' ? 'listen' : (proto === 'tcp' && ps === 'name_connect') || (proto === 'udp' && ps === 'recv_msg send_msg') ? 'connect' : null;
      const port = s.tgt.slice(0, -7);
      if (proto && dir && !g.net[dir].some(x => x.proto === proto && x.port === port)) g.net[dir].push({ proto, port });
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
  const ofD = (s) => (s.dom || D) === D;
  const local = uniq.filter(s => s.section === 'local' && !s.bool && ofD(s));
  const selfs = selfLines(D, local.filter(s => s.kind === 'self'));
  const calls = local.filter(s => s.kind === 'call' || s.kind === 'allow');
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
    const inner = [...selfLines(D, mine.filter(s => s.kind === 'self')), ...localBlocks(mine.filter(s => (s.kind === 'call' || s.kind === 'allow') && !s.opt)).flat()];
    if (inner.length) body.push(tunableBlock(name, inner));
    for (const s of mine.filter(s => s.kind === 'call' && s.opt).sort((x, y) => x.name.localeCompare(y.name))) body.push(optTunableBlock(name, [s.text]));
  }
  if (body.length) parts.push(body.join('\n\n') + '\n');
  // Each helper domain in a section of its own.
  for (const h of model.helpers || []) {
    const { H } = helperNames(model, h);
    const mine = uniq.filter(s => s.section === 'local' && s.dom === H);
    const hb = [];
    const hs = selfLines(H, mine.filter(s => s.kind === 'self'));
    if (hs.length) hb.push(hs.join('\n'));
    const hc = mine.filter(s => s.kind === 'call' || s.kind === 'allow');
    for (const b of localBlocks(hc.filter(s => !s.opt))) hb.push(b.join('\n'));
    for (const s of hc.filter(s => s.opt).sort((a, b) => a.name.localeCompare(b.name))) hb.push(optBlock(s));
    parts.push(HEADER(`${H} local policy`));
    if (hb.length) parts.push(hb.join('\n\n') + '\n');
  }
  return parts.join('\n');
}

function fcLine(spec, ftype, type) {
  return `${spec}\t${ftype ? ftype + '\t' : '\t'}gen_context(system_u:object_r:${type},s0)`;
}
function fcEntries(model, ctx) {
  const { E } = names(model);
  const out = [];
  for (const p of model.exec || []) if (p.trim()) out.push({ type: E, path: sub(p.trim(), model.name), exec: true });
  for (const h of model.helpers || []) for (const p of h.exec || []) if (p.trim()) out.push({ type: helperNames(model, h).HE, path: sub(p.trim(), model.name), exec: true });
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
  const presentKey = (s) => (s.kind === 'call' || s.kind === 'allow' || s.kind === 'role' ? s.key : s.kind === 'type' ? `type:${s.name}` : s.kind === 'permissive' ? (s.name === D ? 'permissive' : null) : null);
  const byKey = new Map();
  for (const s of editable) { const k = presentKey(s); if (k) { if (!byKey.has(k)) byKey.set(k, []); byKey.get(k).push(s); } }
  // Self rules (top level, or directly under a boolean): perms per class with their lines.
  // Scopes of self rules: '' (top level), a boolean's name, or '@H' for a helper domain H (top level only).
  const helperDoms = new Set([rec.model, model].flatMap(m => (m.helpers || []).map(h => helperNames(m, h).H)));
  const selfStmts = editable.filter(s => s.kind === 'allow' && s.tgt === 'self' && ((s.src === D && (s.top || (s.bool && !s.opt))) || (helperDoms.has(s.src) && s.src !== D && s.top)));
  const scopeOf = (s) => (s.src === D ? s.bool || '' : `@${s.src}`);
  const stScope = (st) => (st.dom && st.dom !== D ? `@${st.dom}` : st.bool || '');
  const subjOf = (scope) => (scope.startsWith('@') ? scope.slice(1) : D);
  const sameScope = (s, scope) => scopeOf(s) === (scope || '');
  const selfHas = (scope, cls, p) => selfStmts.some(s => sameScope(s, scope) && s.cls === cls && s.perms.includes(p));
  const isPresent = (st) => (st.kind === 'self' ? selfHas(stScope(st), st.cls, st.perm) : byKey.has(st.key));

  // Units whose settings changed: delete what they had, insert what they need now.
  const delStmts = new Set(), delSelf = [], insStmts = [], insSelf = [];
  const queued = new Set();
  const edits = [];
  // A boolean whose default or description changed is rewritten in place (description and gen_tunable
  // line), and so is a port type of the module's own whose numbers changed.
  const inPlace = new Set();
  for (const [k, u] of cur) {
    const o = old.get(k);
    if (!(k.startsWith('tunable:') || k.startsWith('port:')) || !o || o.sig === u.sig) continue;
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
      if (st.kind === 'self') { if (selfHas(stScope(st), st.cls, st.perm)) delSelf.push(st); continue; }
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
  for (const st of insSelf) { const k = `${stScope(st)}\0${st.cls}`; if (!newPerms.has(k)) newPerms.set(k, []); newPerms.get(k).push(st.perm); }
  const perms = new Map(); // line -> perms
  for (const s of selfStmts) perms.set(s.l, s.perms.slice());
  for (const st of delSelf) for (const s of selfStmts) if (sameScope(s, stScope(st)) && s.cls === st.cls) perms.set(s.l, perms.get(s.l).filter(p => p !== st.perm));
  const newClassLines = new Map(); // scope -> lines
  for (const [k, ps] of newPerms) {
    const [bool, cls] = k.split('\0');
    const first = selfStmts.find(s => sameScope(s, bool) && s.cls === cls && perms.get(s.l).length && !delLines.has(s.l));
    if (first) perms.set(first.l, [...perms.get(first.l), ...ps]);
    else { if (!newClassLines.has(bool)) newClassLines.set(bool, []); newClassLines.get(bool).push(...selfLines(subjOf(bool), ps.map(perm => ({ cls, perm })))); }
  }
  for (const s of selfStmts) {
    if (delLines.has(s.l)) continue;
    const ps = perms.get(s.l);
    if (ps.join(' ') === s.perms.join(' ')) continue;
    if (!ps.length) { delLines.add(s.l); continue; }
    const indent = /^\s*/.exec(lines[s.l])[0];
    const comment = /\s*#.*$/.exec(lines[s.l]);
    edits.push({ rep: [s.l, indent + selfLine(s.src, s.cls, ps) + (comment ? comment[0] : '')] });
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
  // A removed helper's "# H local policy" header goes when nothing but blank lines is left under it.
  const gone = (rec.model.helpers || []).map(h => helperNames(rec.model, h).H).filter(H => !(model.helpers || []).some(h => helperNames(model, h).H === H));
  for (const H of gone) {
    const at = lines.findIndex((ln, l) => new RegExp(`^#\\s*${H} local policy\\s*$`).test(ln) && /^#{10,}/.test(lines[l - 2] || '') && /^#\s*$/.test(lines[l + 1] || ''));
    if (at < 0) continue;
    let end = at + 2;
    while (end < lines.length && !(/^#{10,}/.test(lines[end]) && /^#\s*$/.test(lines[end + 1] || ''))) end++;
    let empty = true;
    for (let l = at + 2; l < end; l++) if (!delLines.has(l) && lines[l].trim()) { empty = false; break; }
    if (empty) for (let l = at - 2; l < end; l++) delLines.add(l);
  }

  for (const l of delLines) edits.push({ del: [l, l] });

  // Where new statements go.
  const top = editable.filter(s => s.top && !delLines.has(s.l));
  const declHelpers = new Set(FILE_KINDS.flatMap(k => k.decl.map(([h]) => h)).concat([...ENTRY_CALLS, 'domain_type', 'gen_tunable', 'gen_bool', 'attribute_role', 'roleattribute', 'corenet_port', ...HELPER_DECLS]));
  if (rec.model.declaredBy) declHelpers.add(rec.model.declaredBy.name); // the template that declares the domain
  const firstLocal = top.find(s => (s.kind === 'allow' || s.kind === 'rule') || (s.kind === 'call' && !declHelpers.has(s.name) && !/^policy_module$/.test(s.name)));
  const localHeader = (() => {
    const lim = firstLocal ? firstLocal.l : lines.length;
    for (let l = lim - 1; l >= 0; l--) if (/^#\s*\S.*polic(y|ies)\s*$/i.test(lines[l]) && /^#{10,}/.test(lines[l - 2] || '')) return l - 2;
    return null;
  })();
  // The declarations end at the first "... local policy" header (they may hold other calls, e.g.
  // application_executable_file); without one, after the last declaration before the first rule.
  const firstHeader = lines.findIndex((ln, l) => /^#\s*(\S.*\s)?local polic(y|ies)\s*$/i.test(ln) && /^#{10,}/.test(lines[l - 2] || ''));
  const beforeHeader = firstHeader > 1 ? top.filter(s => s.endL < firstHeader - 2 && s.kind !== 'rule' && !(s.kind === 'call' && s.name === 'policy_module')) : [];
  const declEnd = beforeHeader.length ? Math.max(...beforeHeader.map(s => s.endL))
    : Math.max(-1, ...top.filter(s => (s.kind === 'type' || s.kind === 'role' || (s.kind === 'call' && declHelpers.has(s.name))) && (localHeader == null || s.l < localHeader) && (!firstLocal || s.l < firstLocal.l)).map(s => s.endL));
  const policyModule = top.find(s => s.kind === 'call' && s.name === 'policy_module');
  const declAfter = declEnd >= 0 ? declEnd : policyModule ? policyModule.endL : -1;
  const domTop = top.filter(s => (s.kind === 'call' && s.args[0] === D && !ENTRY.has(s.name)) || (s.kind === 'allow' && s.src === D));
  const lastSelf = selfStmts.filter(s => s.top && !delLines.has(s.l)).map(s => s.l);
  const localAfter = domTop.length ? Math.max(...domTop.map(s => s.endL)) : (lastSelf.length ? Math.max(...lastSelf) : lines.length - 1);
  const optBlocksOfD = scan.blocks.filter(b => b.name === 'optional_policy' && editable.some(s => s.opt === b && !s.bool && s.kind === 'call' && s.args[0] === D) && !delLines.has(b.l));
  const optAfter = optBlocksOfD.length ? Math.max(localAfter, ...optBlocksOfD.map(b => b.endL)) : localAfter;
  const selfAfter = lastSelf.length ? Math.max(...lastSelf) : (localHeader != null ? localHeader + 4 : localAfter);
  // Boolean blocks go after the domain's last rule or block.
  const outerEnd = (s) => (s.opt ? s.opt.endL : s.tun ? s.tun.endL : s.endL);
  const domAll = editable.filter(s => (s.kind === 'call' && s.args[0] === D && !ENTRY.has(s.name)) || (s.kind === 'allow' && s.src === D));
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
  const ofD = (st) => (st.dom || D) === D;
  const localNew = insStmts.filter(s => s.section === 'local' && !s.opt && !s.bool && ofD(s));
  if (localNew.length) edits.push({ ins: [localAfter, localBlocks(localNew).flatMap(b => ['', ...b])] });
  const optNew = insStmts.filter(s => s.section === 'local' && s.opt && !s.bool && ofD(s)).sort((a, b) => a.name.localeCompare(b.name));
  if (optNew.length) edits.push({ ins: [optAfter, optNew.flatMap(s => ['', ...optBlock(s).split('\n')])] });

  // Under booleans: into the boolean's existing tunable_policy block, else a new one.
  const bools = new Set([...insStmts.filter(s => s.bool).map(s => s.bool), ...[...newClassLines.keys()].filter(k => k && !k.startsWith('@'))]);
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

  // Helper domains: after the helper's last rule, or a section of its own at the end.
  const lastLine = lines.length && lines[lines.length - 1] === '' ? lines.length - 2 : lines.length - 1;
  for (const h of model.helpers || []) {
    const { H } = helperNames(model, h);
    const selfNew = newClassLines.get(`@${H}`) || [];
    const mine = insStmts.filter(st => st.section === 'local' && st.dom === H);
    const plain = mine.filter(st => !st.opt), opts = mine.filter(st => st.opt).sort((a, b) => a.name.localeCompare(b.name));
    if (!selfNew.length && !mine.length) continue;
    const rules = top.filter(st => (st.kind === 'call' && st.args[0] === H && !declHelpers.has(st.name)) || (st.kind === 'allow' && st.src === H));
    const optBlocks = scan.blocks.filter(b => b.name === 'optional_policy' && !delLines.has(b.l) && editable.some(st => st.opt === b && !st.bool && st.kind === 'call' && st.args[0] === H));
    if (!rules.length && !optBlocks.length) {
      const body = [selfNew, ...localBlocks(plain), ...opts.map(st => optBlock(st).split('\n'))].filter(b => b.length);
      edits.push({ ins: [lastLine, ['', ...HEADER(`${H} local policy`).split('\n'), ...body.flatMap((b, i) => (i ? ['', ...b] : b))]] });
      continue;
    }
    const hSelf = selfStmts.filter(st => st.src === H && !delLines.has(st.l)).map(st => st.l);
    const after = rules.length ? Math.max(...rules.map(st => st.endL)) : Math.max(...optBlocks.map(b => b.endL));
    if (selfNew.length) edits.push({ ins: [hSelf.length ? Math.max(...hSelf) : after, hSelf.length ? selfNew : ['', ...selfNew]] });
    if (plain.length) edits.push({ ins: [after, localBlocks(plain).flatMap(b => ['', ...b])] });
    if (opts.length) edits.push({ ins: [Math.max(after, ...optBlocks.map(b => b.endL)), opts.flatMap(st => ['', ...optBlock(st).split('\n')])] });
  }

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
  for (const h of rec.model.helpers || []) oldTypes.set(helperNames(rec.model, h).HE, (h.exec || []).join('\n'));
  const newTypes = new Map();
  const { E } = names(model);
  newTypes.set(E, (model.exec || []).map(p => sub(p.trim(), model.name)).filter(Boolean).join('\n'));
  for (const r of model.files || []) newTypes.set(fileType(model, r, ctx), (r.paths || []).map(p => sub(p.trim(), model.name)).filter(Boolean).join('\n'));
  for (const h of model.helpers || []) newTypes.set(helperNames(model, h).HE, (h.exec || []).map(p => sub(p.trim(), model.name)).filter(Boolean).join('\n'));
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

/** corenetwork.te.in with the model's port types: changed ones rewritten, new ones added in alphabetical place. */
function portLine(name, nums) {
  return `network_port(${name}${nums.map(x => `, ${x.proto},${x.port},${x.level || 's0'}`).join('')})`;
}
function editCorenet(text, before, model) {
  const lines = text.split('\n');
  const edits = [];
  const was = new Map((before || []).map(p => [p.name, p]));
  const sig = (nums) => JSON.stringify(nums.map(x => [x.proto, x.port, x.level || 's0']));
  const portAt = (l) => /^network_port\(\s*(\w+)\s*[,)]/.exec(lines[l]);
  const inserts = [];
  for (const p of model.ports || []) {
    const n = portName(model, p);
    if (!/^\w+$/.test(n)) continue;
    const nums = portNums(p);
    const b = was.get(n);
    if (!b) { inserts.push([n, portLine(n, nums)]); continue; }
    if (sig(portNums(b)) === sig(nums)) continue;
    const l = lines.findIndex((_, i) => { const m = portAt(i); return m && m[1] === n; });
    if (l < 0) continue;
    const comment = /\s*#.*$/.exec(lines[l]);
    edits.push({ rep: [l, portLine(n, nums) + (comment ? comment[0] : '')] });
  }
  const all = lines.map((_, i) => [i, portAt(i)]).filter(x => x[1]);
  for (const [n, line] of inserts.sort((a, b) => a[0].localeCompare(b[0]))) {
    const prev = all.filter(([, m]) => m[1] < n);
    const at = prev.length ? prev[prev.length - 1][0] : all.length ? all[0][0] - 1 : lines.length - 1;
    edits.push({ ins: [at, [line]] });
  }
  return applyLineEdits(lines, edits).join('\n');
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
  // The login pty type must not be a file type of the module already (e.g. ipsec_mgmt_devpts_t).
  if (model.loginPty) {
    const P = `${names(model).D.replace(/_t$/, '')}_devpts_t`;
    if ((model.files || []).some(r => fileType(model, r, ctx) === P)) out.push(`${P} is already one of this module's file types, so “Pseudo-terminals for logins” can't declare it again; untick it, or remove that file type first.`);
  }
  for (const p of (model.exec || []).concat(...(model.files || []).map(r => r.paths || []), ...(model.helpers || []).map(h => h.exec || []))) if (p.trim() && !/^(\/|HOME_DIR(\/|$)|HOME_ROOT(\/|$))/.test(p.trim())) out.push(`Path "${p}" must be absolute (or start with HOME_DIR/ or HOME_ROOT/, the home directory placeholders of .fc files).`);
  // One path, one label: setfiles refuses a file_contexts with two specifications for the same path.
  const specType = new Map();
  for (const e of fcEntries(model, ctx)) {
    const t = specType.get(e.spec);
    if (t && t !== e.type) out.push(`${e.path} is labeled both ${t} and ${e.type}; a path can have only one type, so remove it from one of them.`);
    else specType.set(e.spec, e.type);
  }
  // How it is started: one main way at most, and only calls this policy has.
  const entries = model.entries || [];
  if (opts.isNew && !entries.length) out.push('Nothing starts the service: choose how it is started (Started by).');
  for (const e of entries) if (ctx.has && !ctx.has(e.name)) out.push(`${e.name} doesn't exist in this policy, so it can't start the service.`);
  const picked = [...new Set(entries.filter(e => STARTS.main.some(s => s[0] === e.name)).map(e => e.name))];
  const sameAsBefore = opts.baseline && JSON.stringify((opts.baseline.entries || []).map(e => e.name).sort()) === JSON.stringify(entries.map(e => e.name).sort());
  if (picked.length > 1 && !sameAsBefore) out.push(`It is started by ${picked.join(' and ')}; choose one of them under Started by.`);
  // The main way is outside optional_policy: its module must be on, or linking fails.
  for (const e of entries) {
    const off = !ALSO.has(e.name) && ctx.off && ctx.off(e.name);
    if (off && !sameAsBefore) out.push(`${e.name} belongs to the ${off} module, which is off in this policy (modules.conf), so the build would fail to link. Turn ${off} on, or choose another way under Started by.`);
  }
  if (!(model.exec || []).some(p => p.trim())) out.push('Note: no program path, so nothing gets the program label and the service won’t start in its domain.');
  if (model.permissive) out.push('Note: permissive: denials are logged, not enforced. Turn it off when the policy is complete.');
  ctx = portCtx(model, ctx);
  // Port types of the service.
  const ownPorts = new Set();
  const usedPorts = new Set([model, ...(model.booleans || []).map(b => b.grants || {})].flatMap(g => ['listen', 'connect'].flatMap(d => ((g.net || {})[d] || []).map(x => x.port))));
  const numSeen = new Set();
  let overlaps = 0;
  for (const p of model.ports || []) {
    const n = portName(model, p), P = `${n}_port_t`;
    if (!/^[a-z][a-z0-9_]*$/.test(n)) { out.push(`Port type name "${n}" must start with a letter and use only lowercase letters, digits and _.`); continue; }
    if (ownPorts.has(n)) out.push(`Port type ${P} is listed twice.`);
    ownPorts.add(n);
    if ((opts.isNew || p._new) && ctx.typeExists && ctx.typeExists(P)) out.push(`Type ${P} already exists: pick it under Listens on or Connects to, or choose another name.`);
    const nums = portNums(p);
    // (an existing one may have none on purpose, e.g. CLIP's milter_port_t)
    if (!nums.length && ctx.corenet && (opts.isNew || p._new)) out.push(`Port type ${P} has no port numbers yet.`);
    for (const x of nums) {
      const m = /^(\d+)(?:-(\d+))?$/.exec(x.port);
      if (!m) { out.push(`"${x.port}" (${P}) isn't a port number or a range like 8000-8010.`); continue; }
      const lo = +m[1], hi = m[2] ? +m[2] : lo;
      if (lo < 1 || hi > 65535 || lo > hi) { out.push(`${x.proto} ${x.port} (${P}) is outside 1-65535 or backwards.`); continue; }
      const k = `${x.proto} ${lo}-${hi}`;
      if (numSeen.has(k)) out.push(`${x.proto} ${x.port} is listed twice.`);
      numSeen.add(k);
      for (const q of ctx.portNums || []) {
        if (q.name === n || q.proto !== x.proto || lo > q.hi || q.lo > hi) continue;
        if (q.lo === lo && q.hi === hi) out.push(`${x.proto} ${x.port} already belongs to ${q.name}_port_t; a port number can have only one port type. Use ${q.name} under Listens on or Connects to instead.`);
        else if (overlaps++ < 3) out.push(`Note: ${x.proto} ${x.port} (${P}) overlaps ${q.name}_port_t (${q.lo === q.hi ? q.lo : `${q.lo}-${q.hi}`}); the narrower entry wins for the ports in both.`);
      }
    }
    if (!ctx.corenet && nums.length) out.push(`Note: a loadable module can't set port numbers; after installing it run ${nums.map(x => `semanage port -a -t ${P} -p ${x.proto} ${x.port}`).join('; ')}.`);
    if (!usedPorts.has(n)) out.push(`Note: port type ${P} isn't used yet; pick ${n} under Listens on or Connects to.`);
  }
  const grants = (g, where) => {
    for (const dir of ['listen', 'connect']) for (const it of (g.net || {})[dir] || []) {
      if (!ctx.corenet && ownPorts.has(it.port)) continue;
      if (it.port && it.port !== 'all' && !ctx.has(`corenet_${dir === 'listen' ? it.proto : 'tcp'}_bind_${it.port}_port`)) out.push(`No ${it.proto} port type ${it.port}_port_t in this policy (${dir}${where}).`);
    }
    for (const n of g.extra || []) if (!ctx.has(n)) out.push(`Interface ${n} doesn't exist in this policy${where}.`);
  };
  grants(model, '');
  // Helper domains.
  const helperSeen = new Set();
  for (const h of model.helpers || []) {
    const b = helperBase(model, h);
    if (!/^[a-z][a-z0-9_]*$/.test(b)) { out.push(`Helper name "${b}" must start with a letter and use only lowercase letters, digits and _.`); continue; }
    const { H, HE } = helperNames(model, h);
    if (H === names(model).D || types.has(H) || types.has(HE)) out.push(`Helper ${H} has the name of another type of this service; choose another name.`);
    if (helperSeen.has(H)) out.push(`Helper ${H} is listed twice.`);
    helperSeen.add(H);
    if ((opts.isNew || h._new) && ctx.typeExists) for (const t of [H, HE]) if (ctx.typeExists(t)) out.push(`Type ${t} is already declared elsewhere; choose another helper name.`);
    if (!(h.exec || []).some(p => p.trim())) out.push(`Note: helper ${H} has no program path, so nothing gets ${HE} and the service can't start it in its domain.`);
    for (const fa of h.files || []) if (fa.access && fa.access !== 'none' && !types.has(fa.type)) out.push(`Helper ${H}: ${fa.type} isn't one of this service's file types any more; remove that access.`);
    grants(h, ` for helper ${H}`);
  }
  const bools = new Set();
  for (const b of model.booleans || []) {
    const n = sub(b.name || '', model.name);
    if (!/^[a-z][a-z0-9_]*$/.test(n)) { out.push(`Boolean name "${n}" must start with a letter and use only lowercase letters, digits and _.`); continue; }
    if (bools.has(n)) out.push(`Boolean ${n} is listed twice.`);
    bools.add(n);
    if (b.external && ctx.boolExists && !ctx.boolExists(n)) out.push(`There is no boolean ${n} in this policy.`);
    if (!b.external && (opts.isNew || b._new) && ctx.boolExists && ctx.boolExists(n)) out.push(`A boolean named ${n} already exists: add it as an existing boolean, or choose another name.`);
    const g = b.grants || {};
    const boolFiles = (g.files || []).filter(f => f.access && f.access !== 'none');
    if (![...(g.self || []), ...(g.caps || []), ...(g.access || []), ...(g.extra || []), ...boolFiles, ...((g.net || {}).listen || []).filter(x => x.port), ...((g.net || {}).connect || []).filter(x => x.port)].length) out.push(`Note: boolean ${n} doesn't allow anything yet.`);
    grants(g, ` under ${n}`);
    for (const f of boolFiles) {
      const r = (model.files || []).find(x => fileType(model, x, ctx) === f.type);
      if (!r) { out.push(`Boolean ${n}: ${f.type} isn't one of this service's file types any more; remove that access.`); continue; }
      const always = r.access || (KIND[r.kind] ? KIND[r.kind].access[0] : 'none');
      if (always !== 'custom' && (always === f.access || LEVEL_RANK[f.access] < LEVEL_RANK[always])) out.push(`Note: under ${n}, ${f.type} gets "${ACCESS_LABELS[f.access]}", but the service always has "${ACCESS_LABELS[always]}" on it, so the boolean adds nothing there.`);
    }
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

/**
 * The new texts for a model: { te, if, fc, net }. corenet = { text, ports } (corenetwork.te.in and
 * the port types in it that belong to the module) in a tree; net is then its new text, else null.
 */
function plan(model, ctx, existing, corenet = null) {
  let net = null;
  if (corenet && ctx.corenet) {
    const lf = corenet.text.replace(/\r\n/g, '\n');
    const t = editCorenet(lf, corenet.ports, model);
    net = t === lf ? corenet.text : corenet.text.includes('\r\n') ? t.replace(/\n/g, '\r\n') : t;
  }
  if (!existing) return { te: renderTe(model, ctx), if: renderIf(model, ctx), fc: renderFc(model, ctx), net };
  // Work on LF text; files with CRLF line endings get them back.
  const crlf = {}, lf = {};
  for (const k of ['te', 'if', 'fc']) { const t = existing[k] || ''; crlf[k] = t.includes('\r\n'); lf[k] = t.replace(/\r\n/g, '\n'); }
  const rec = recognize(lf, ctx, { domain: model.domain, ports: corenet ? corenet.ports : [] });
  if (rec.error) return { error: rec.error };
  const out = { te: editTe(lf.te, rec, model, ctx), if: editIf(lf.if, rec, model, ctx), fc: editFc(lf.fc, rec, model, ctx), net };
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
    name: '', summary: '', exec: ['/usr/bin/%'], entries: [{ name: 'init_daemon_domain', args: [] }],
    files: [{ kind: 'unit', paths: ['/usr/lib/systemd/system/%.service'], access: 'none' }, { kind: 'runtime', paths: ['/run/%/'], access: 'manage' }],
    self: ['fifo'], caps: [], net: { listen: [], connect: [] }, access: ['syslog', 'locale'], extra: [], permissive: false,
    booleans: [], ports: [], helpers: [], provides: ['domtrans', 'admin'],
  };
}

/** The catalog as the editor UI needs it, limited to what exists in this tree. */
function catalog(ctx) {
  const avail = (alts) => alts.some(a => a.some(n => ctx.has(n)));
  return {
    fileKinds: FILE_KINDS.filter(k => k.decl.some(([h]) => ctx.has(h))).map(k => {
      const suffix = (k.decl.find(([h]) => ctx.has(h)) || k.decl[0])[1];
      return { id: k.id, label: k.label, where: k.where, path: k.path || '', access: k.access, file: !!k.file, suffix, help: HELP.file[k.id].replace(/\{T\}/g, `%${suffix}`) };
    }),
    accessLabels: ACCESS_LABELS,
    accessHelp: HELP.level,
    access: ACCESS_GROUPS.map(([g, items]) => ({ group: g, items: items.filter(([, , calls]) => avail(calls)).map(([id, label, calls]) => {
      const names = calls.map(a => pick(ctx, a)).filter(Boolean);
      return { id, label, calls: names, help: HELP.access[id], optional: calls.some(a => ctx.optional(pick(ctx, a) || a[0])), cond: names.every(n => !ctx.condSafe || ctx.condSafe(n)) };
    }) })).filter(g => g.items.length),
    self: SELF.map(([id, label, perms, risky]) => ({ id, label, help: HELP.self[id], risky: !!risky, rule: Object.entries(perms).map(([c, ps]) => `${c} ${ps.join(' ')}`).join('; ') })),
    caps: CAPS.map(([name, cls, label, risky]) => ({ name, cls, label, help: HELP.cap[name], risky: !!risky })),
    provides: PROVIDES.map(([id, name, label, needs]) => ({ id, name, label, help: HELP.provides[id], needs: needs || null })),
    // How the service is started: the main ways and further ones (only those this tree has).
    // off: the module that provides it is off in this tree (modules.conf), named.
    starts: { main: STARTS.main.filter(([n]) => ctx.has(n)).map(([name, label, help]) => ({ name, label, help, off: (ctx.off && ctx.off(name)) || null })),
      also: STARTS.also.filter(([n]) => ctx.has(n)).map(([name, label, help]) => ({ name, label, help, optional: !!ctx.optional(name), off: (ctx.off && ctx.off(name)) || null })) },
    // A pty type of its own for the sessions a login service starts (shown with the Logins options).
    loginPty: ctx.has('term_login_pty') && ctx.has('term_create_pty') ? { label: 'Pseudo-terminals for logins (a pty type of its own)',
      help: 'Gives the sessions it starts pseudo-terminals of a type of its own (DOMAIN_devpts_t, declared with term_login_pty), which it may create, use and hand to the user, as sshd does. The user’s session then gets the terminal relabeled to its own pty type.' } : null,
  };
}

module.exports = {
  FILE_KINDS, ACCESS_GROUPS, SELF, CAPS, PROVIDES, HELP,
  unitsOf, recognize, daemonDomains, plan, validate, renderTe, renderIf, renderFc, lineDiff, newModel, catalog,
  fcFromPath, pathFromFc, scanTe, fileType, editCorenet, helperNames, ENTRY_RE, ENTRY_CALLS, STARTS, makeStartsVia,
};
