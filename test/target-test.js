// Target hosts (server/target.js): the host spec, ssh arguments, the askpass
// helper, the facts script's output parsed, the mirror command. Any OS, in npm test.
const T = require('../server/target');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + (typeof extra === 'string' ? extra : JSON.stringify(extra, null, 1)).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

// 1. Specs and ids.
check(JSON.stringify(T.parseSpec('192.0.2.10')) === JSON.stringify({ user: 'root', host: '192.0.2.10', port: 22 }), 'parseSpec: a bare host is root, port 22');
check(JSON.stringify(T.parseSpec(' admin@box.example.org:2222 ')) === JSON.stringify({ user: 'admin', host: 'box.example.org', port: 2222 }), 'parseSpec: user@host:port');
check(T.parseSpec('[fe80::1]').host === 'fe80::1' && T.parseSpec('root@[fe80::1]:22').port === 22, 'parseSpec: a bracketed IPv6 address');
check(T.parseSpec('a b') === null && T.parseSpec('') === null && T.parseSpec('host:') === null && T.parseSpec('--opt@host') === null, 'parseSpec: refuses what is not a host');
check(T.targetId({ user: 'root', host: 'h', port: 22 }) === 'root@h' && T.targetId({ user: 'u', host: 'h', port: 2200 }) === 'u@h:2200' && T.targetId({ user: null, host: 'h', port: 22 }) === 'h', 'targetId');
check(T.parseSpec('box', { user: null }).user === null && T.parseSpec('u@box', { user: null }).user === 'u' && T.sshDest({ user: null, host: 'box' }) === 'box' && T.sshArgs({ user: null, host: 'box', port: 22 }, { control: '/x' }).pop() === 'box', 'parseSpec with no default user (key logins): ssh picks the user');
check(T.shq("it's") === `'it'\\''s'` && T.shq('/a b') === `'/a b'`, 'shq quotes for sh');

// 2. ssh arguments.
const t = { user: 'root', host: 'h', port: 2200 };
const master = T.sshArgs(t, { control: '/x/cm', master: true });
check(master.includes('ControlMaster=yes') && master.includes('ControlPersist=600') && master.includes('NumberOfPasswordPrompts=1') && !master.includes('BatchMode=yes') && master.includes('StrictHostKeyChecking=accept-new') && master.slice(-3).join(' ') === '-p 2200 root@h',
  'sshArgs master: opens the control connection, one password prompt allowed, accept-new host keys, port, user@host last', master);
const run = T.sshArgs(t, { control: '/x/cm' });
check(run.includes('ControlMaster=no') && run.includes('BatchMode=yes') && !run.includes('ControlPersist=600') && run[1] === 'ControlPath=/x/cm', 'sshArgs command: rides the control socket, never prompts', run);
check(T.sshArgs(t, { control: '/x/cm', master: true, keyOnly: true }).includes('BatchMode=yes') && !T.sshArgs({ user: 'u', host: 'h', port: 22 }, { control: '/x' }).includes('-p'), 'sshArgs: key-only masters never prompt; port 22 not passed');
check(T.sshArgs(t, { control: '/x/cm', knownHosts: '/k' }).includes('UserKnownHostsFile=/k'), 'sshArgs: own known_hosts file when given');
check(/^#!\/bin\/sh\n/.test(T.ASKPASS_SCRIPT) && /\*assword\*\) cat "\$SELINUX_TARGET_PW_FILE"/.test(T.ASKPASS_SCRIPT) && /\*\) echo no/.test(T.ASKPASS_SCRIPT), 'askpass helper: prints the password file only for a password prompt, "no" to anything else');

// 3. The facts script's output.
const OUT = `### hostname
box
### uid
0
### now
1762950000
### os-release
NAME="Rocky Linux"
VERSION="9.8 (Blue Onyx)"
ID="rocky"
VERSION_ID="9.8"
PRETTY_NAME="Rocky Linux 9.8 (Blue Onyx)"
### config
# This file controls the state of SELinux on the system.
SELINUX=enforcing
SELINUXTYPE=targeted
### getenforce
Permissive
### policy-rpm
selinux-policy-38.1.75-2.el9_8.noarch
### policy-files
-rw-r--r--. 1 root root 3663793 Nov  5 06:21 /etc/selinux/targeted/policy/policy.33
-rw-r--r--. 1 root root 3600000 Oct  1 06:21 /etc/selinux/targeted/policy/policy.32
-rw-r--r--. 1 root root 2600000 Nov  5 06:21 /etc/selinux/clip/policy/policy.33
### modules
100 abrt             pp
100 accountsd        pp
400 mylocal          cil
200 container        pp disabled
### permissive
httpd_t
chronyd_t
### booleans
abrt_anon_write --> off
ssh_sysadm_login --> on
### ssh-version
OpenSSH_9.9p1, OpenSSL 3.5.8 25 Aug 2026
### done
`;
const f = T.parseFacts(OUT);
check(f.hostname === 'box' && f.root && f.uid === 0 && f.at === 1762950000 && f.complete, 'parseFacts: hostname, root, clock, complete', f);
check(f.os.id === 'rocky' && f.os.version === '9.8' && f.os.pretty === 'Rocky Linux 9.8 (Blue Onyx)', 'parseFacts: os-release', f.os);
check(f.mode === 'Permissive' && f.config.mode === 'enforcing' && f.config.type === 'targeted', 'parseFacts: getenforce vs /etc/selinux/config', [f.mode, f.config]);
check(f.policyRpm === 'selinux-policy-38.1.75-2.el9_8.noarch', 'parseFacts: the policy package');
check(f.policies.length === 2 && f.policy.name === 'targeted' && f.policy.version === 33 && f.policy.file === '/etc/selinux/targeted/policy/policy.33' && f.policy.size === 3663793 && f.policies.find(p => p.name === 'clip').version === 33,
  'parseFacts: the newest policy file per store; the configured store first', f.policies);
check(f.modules.length === 4 && f.modules[2].priority === 400 && f.modules[2].lang === 'cil' && f.modules[3].disabled && !f.modules[0].disabled, 'parseFacts: semodule --list-modules=full', f.modules);
check(JSON.stringify(f.permissive) === '["httpd_t","chronyd_t"]' && f.booleans.abrt_anon_write === false && f.booleans.ssh_sysadm_login === true, 'parseFacts: permissive domains and booleans');
check(f.sshVersion.startsWith('OpenSSH_9.9') && !f.notes.length, 'parseFacts: no notes when everything was read', f.notes);

// Not root: the commands that need it print errors under <key>.err.
const USER = OUT.replace('### uid\n0', '### uid\n1000').replace(/### modules\n[\s\S]*?### permissive\n[\s\S]*?### booleans/, '### modules\n### modules.err\nlibsemanage.semanage_create_store: Could not read from module store, active modules subdirectory at /var/lib/selinux/targeted/active/modules. (Permission denied).\n### permissive\n### permissive.err\nValueError: SELinux policy is not managed or store cannot be accessed.\n### booleans');
const u = T.parseFacts(USER);
check(!u.root && u.modules === null && u.permissive === null && u.booleans && u.notes.length === 2 && u.notes.every(n => /not root on the target/.test(n)) && /module list/.test(u.notes[0]) && /Permissive domains/.test(u.notes[1]),
  'parseFacts: not root → module list and permissive domains unavailable, said so', u.notes);
const cut = T.parseFacts(OUT.split('### modules')[0]);
check(!cut.complete && cut.notes.some(n => /did not run to its end/.test(n)) && cut.policy && cut.modules.length === 0, 'parseFacts: a cut-off output is noted', cut.notes);
const none = T.parseFacts('### hostname\nx\n### uid\n0\n### policy-files\n### getenforce\n### getenforce.err\nsh: getenforce: command not found\n### done\n');
check(none.policy === null && none.mode === null && none.notes.some(n => /No policy file/.test(n)) && none.notes.some(n => /SELinux mode: sh: getenforce: command not found/.test(n)), 'parseFacts: no SELinux on the target', none.notes);
check(T.parseFacts(OUT.replace('### getenforce\nPermissive', '### getenforce\nDisabled')).notes.some(n => /disabled on the target/.test(n)), 'parseFacts: disabled is noted');

// 4. Descriptions and the mirror.
check(T.describe({ user: 'root', host: 'box', port: 22 }, f) === 'root@box (targeted, permissive)' && T.describe({ user: 'u', host: 'box', port: 22 }, u) === 'u@box (targeted, permissive, not root)' && T.describe({ user: 'root', host: 'box', port: 22 }, null) === 'root@box', 'describe');
const mp = T.mirrorPaths('targeted', '/etc/selinux/targeted/policy/policy.33');
check(JSON.stringify(mp) === JSON.stringify(['config', 'targeted/seusers', 'targeted/contexts', 'targeted/setrans.conf', 'targeted/policy/policy.33']), 'mirrorPaths: config, seusers, the contexts tree, setrans.conf, the policy file', mp);
const mc = T.mirrorCommand('targeted', '/etc/selinux/targeted/policy/policy.33');
check(/^cd \/etc\/selinux && tar czf - --ignore-failed-read 'config' 'targeted\/seusers' .* 'targeted\/policy\/policy\.33' 2>\/dev\/null$/.test(mc), 'mirrorCommand: one tar stream from /etc/selinux, unreadable files skipped', mc);
check(/^### %s/.test('### %s') && /sec hostname/.test(T.FACTS_SCRIPT) && /semodule --list-modules=full/.test(T.FACTS_SCRIPT) && /getsebool -a/.test(T.FACTS_SCRIPT) && /sec done\s*$/.test(T.FACTS_SCRIPT) && !/\bsudo\b/.test(T.FACTS_SCRIPT),
  'FACTS_SCRIPT: gathers everything in one run, ends with done, never sudo');
check(Object.keys(T.splitSections('### a\n1\n2\n### b\n### a\n3\n')).join() === 'a,b' && T.splitSections('### a\n1\n2\n### b\n').a === '1\n2' && T.splitSections('### a\n1\n### b\n').b === '', 'splitSections');

// 5. Denials read on the target.
const ds = T.denialsScript('this-hour');
check(/ausearch -m avc,user_avc,selinux_err -ts this-hour --raw/.test(ds) && /journalctl -q --since '-1h'/.test(ds) && /pam_selinux\|ssh_selinux/.test(ds) && /sec mode; getenforce/.test(ds) && /sec done/.test(ds), 'denialsScript: ausearch raw since the words given, the journal for the login programs, the mode', ds);
check(/-ts recent --raw/.test(T.denialsScript('x; rm -rf /')) && /-ts recent --raw/.test(T.denialsScript(null)) && /journalctl -q -b /.test(T.denialsScript('boot')) && /\ntrue\n/.test(T.denialsScript('yesterday-ish')), 'denialsScript: odd words fall back to recent; boot uses -b; no journal for unknown words');
const REC = 'type=AVC msg=audit(1700000000.001:1): avc:  denied  { read } for  pid=1 comm="x" scontext=system_u:system_r:a_t:s0 tcontext=system_u:object_r:b_t:s0 tclass=file permissive=1';
let d = T.parseDenialsOutput(`### mode\nPermissive\n### audit\n${REC}\ntype=SYSCALL msg=audit(1700000000.001:1): arch=c000003e syscall=2\n----\n${REC.replace(':1)', ':2)')}\n### journal\nNov 12 10:00:00 box sshd[1]: pam_selinux(sshd:session): Unable to get valid context for u\n### done\n`);
check(!d.error && d.mode === 'Permissive' && d.count === 2 && d.text.split('\n').length === 5 && /pam_selinux/.test(d.text), 'parseDenialsOutput: records and journal lines joined, AVC count, mode', d);
d = T.parseDenialsOutput('### mode\nEnforcing\n### audit\n### journal\n### done\n');
check(!d.error && d.text === '' && d.count === 0 && d.mode === 'Enforcing', 'parseDenialsOutput: nothing logged', d);
d = T.parseDenialsOutput('### mode\nEnforcing\n### audit\n### audit.err\nError opening /var/log/audit/audit.log (Permission denied)\n### journal\n### done\n');
check(d.error === 'The audit log needs root on the target.', 'parseDenialsOutput: not root', d);
d = T.parseDenialsOutput('### mode\nEnforcing\n### audit\n### audit.err\nsh: line 3: ausearch: command not found\n### journal\n### done\n');
check(/not installed/.test(d.error), 'parseDenialsOutput: no ausearch', d);
check(/did not finish/.test(T.parseDenialsOutput('### mode\nEnforcing\n### audit\n').error), 'parseDenialsOutput: cut off');

// 6. The target's programs: the facts script and the path resolver.
check(/sec ps; ps -eo pid=,ppid=,user:32=,label=,comm=,args=/.test(T.HOST_FACTS_SCRIPT) && /systemctl show --no-pager -p Id,ExecStart,MainPID,ActiveState,SubState,FragmentPath,User,NoNewPrivileges '\*\.service'/.test(T.HOST_FACTS_SCRIPT) && /ss -lntuHp/.test(T.HOST_FACTS_SCRIPT) && /sec uid; id -u/.test(T.HOST_FACTS_SCRIPT) && /sec done\s*$/.test(T.HOST_FACTS_SCRIPT), 'HOST_FACTS_SCRIPT: ps, systemctl show, ss as What Runs Unconfined runs them, uid, done');
const ps = T.pathsScript(['/usr/sbin/sshd', 'bootctl', '/opt/x y/agent', '/usr/sbin/sshd', "it's", 'bad\nline', 'EOF_PATHS']);
check(/<<'EOF_PATHS'\n\/usr\/sbin\/sshd\nbootctl\n\/opt\/x y\/agent\nit's\nEOF_PATHS\n/.test(ps) && !/bad/.test(ps) && (ps.match(/EOF_PATHS/g) || []).length === 2 && /for d in \/usr\/local\/sbin \/usr\/local\/bin \/usr\/sbin \/usr\/bin \/sbin \/bin/.test(ps) && /rpm -qf --qf/.test(ps) && /realpath/.test(ps) && /printf '### done/.test(ps),
  'pathsScript: the candidates in a quoted heredoc (deduplicated; newlines and the terminator refused), systemd\'s PATH for bare names, realpath and the package', ps);
const pm = T.parsePaths('/usr/sbin/sshd\t/usr/sbin/sshd\t1\topenssh-server\nbootctl\t/usr/bin/bootctl\t1\tsystemd-udev\n/opt/x y/agent\t\t0\t\n/bin/sh\t/usr/bin/bash\t1\tbash\n### done\n');
check(pm.done && pm.size === 4 && pm.get('/usr/sbin/sshd').pkg === 'openssh-server' && pm.get('bootctl').real === '/usr/bin/bootctl' && pm.get('/opt/x y/agent').exists === false && pm.get('/opt/x y/agent').real === null && pm.get('/bin/sh').real === '/usr/bin/bash', 'parsePaths: real path, existence, package per candidate', [...pm]);
check(!T.parsePaths('/a\t/a\t1\t\n').done && T.parsePaths('/a\t/a\t1\t\n').get('/a').pkg === null, 'parsePaths: cut off → not done; no package → null');

console.log(failures ? `\n${failures} target checks FAILED` : '\nall target checks passed');
process.exit(failures ? 1 : 0);
