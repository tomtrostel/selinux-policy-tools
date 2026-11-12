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
check(!d.error && d.text === '' && d.count === 0 && d.mode === 'Enforcing' && d.note === null, 'parseDenialsOutput: nothing logged', d);
d = T.parseDenialsOutput('### mode\nEnforcing\n### auditd\nactive\nAudit daemon is suspending logging due to low disk space.\n### audit\n### journal\n### done\n');
check(!d.error && d.auditd.active && d.auditd.suspended && /suspended logging \(low disk space\)/.test(d.note) && /service auditd restart/.test(d.note), 'parseDenialsOutput: auditd suspended logging on low disk space (ricardo, 2026-10-29) → said so', d);
d = T.parseDenialsOutput('### mode\nEnforcing\n### auditd\ninactive\n\n### audit\n### journal\n### done\n');
check(/auditd is not running/.test(d.note) && !d.auditd.active, 'parseDenialsOutput: auditd not running → said so', d);
d = T.parseDenialsOutput('### mode\nEnforcing\n### auditd\nactive\nStarted Security Auditing Service.\n### audit\n### journal\n### done\n');
check(d.note === null && d.auditd.active && !d.auditd.suspended, 'parseDenialsOutput: a restarted auditd is fine', d);
check(/sec auditd\nsystemctl is-active auditd/.test(T.denialsScript('recent')) && /journalctl -u auditd -n 8 -o cat/.test(T.denialsScript('recent')), 'denialsScript: asks about auditd');
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

// 7. Pushing a build: the policy version, the store checksums,
const hdr = Buffer.alloc(32); hdr.writeUInt32LE(0xf97cff8c, 0); hdr.writeUInt32LE(8, 4); hdr.write('SE Linux', 8, 'latin1'); hdr.writeUInt32LE(33, 16);
check(T.policyVersionOf(hdr) === 33 && T.policyVersionOf(Buffer.from('not a policy file at all, really')) === null && T.policyVersionOf(hdr.slice(0, 10)) === null, 'policyVersionOf: the header of a kernel policy file');
// the directories to relabel, where context files go, the scripts and their output.
const cs = T.storeChecksumScript('targeted');
check(/\/var\/lib\/selinux\/'targeted'\/active\/modules\/\*\/\*/.test(cs) && /bzcat "\$d\/hll"/.test(cs) && /md5sum/.test(cs) && /lang_ext/.test(cs) && /\*\[!0-9\]\*\) continue/.test(cs) && /### done/.test(cs), 'storeChecksumScript: every module of the store, the hll decompressed, non-numeric priority dirs skipped', cs);
const st = T.parseStoreChecksums('100\tbase\tpp\taaaa\n100\tzebra\tpp\tbbbb\n400\tzebra\tcil\tcccc\n200\tcontainer\tpp\tdddd\nodd line\n### done\n');
check(st.done && st.modules.size === 3 && st.modules.get('zebra').priority === 400 && st.modules.get('zebra').md5 === 'cccc' && st.modules.get('zebra').all.length === 2 && st.modules.get('base').lang === 'pp' && !T.parseStoreChecksums('100\tbase\tpp\taaaa\n').done, 'parseStoreChecksums: the highest priority wins, every copy kept, done', [...st.modules]);
const dirs = T.fixedPrefixDirs(['/usr/sbin/zebra', '/var/run/zebra(/.*)?', '/var/run/zebra/x\\.pid', '/etc/quagga(/.*)?', '/etc/quagga/zebra\\.conf', '/usr/lib(64)?/libz\\.so', 'HOME_DIR/\\.ssh(/.*)?', '/.*', '/']);
check(JSON.stringify(dirs) === JSON.stringify(['/etc/quagga', '/usr/sbin/zebra', '/var/run/zebra']), 'fixedPrefixDirs: a whole path or directory spec as is, a regex inside a name → its directory (never a top-level one), no root, no subdirectories of another, sorted', dirs);
check(T.fixedPrefixDirs(Array.from({ length: 50 }, (_, i) => `/d${i}/x`)).length === 30, 'fixedPrefixDirs: capped');
check(T.installedPathOf('default_contexts', 'clip') === '/etc/selinux/clip/contexts/default_contexts' && T.installedPathOf('staff_u_default_contexts', 'clip') === '/etc/selinux/clip/contexts/users/staff_u' && T.installedPathOf('media', 'clip') === '/etc/selinux/clip/contexts/files/media' && T.installedPathOf('setrans.conf', 'clip') === '/etc/selinux/clip/setrans.conf' && T.installedPathOf('seusers', 'clip') === null && T.installedPathOf('../x', 'clip') === null,
  'installedPathOf: contexts files, users\' files, media, setrans.conf; seusers goes with base.pp; odd names refused');
const push = T.pushScript({ name: 'targeted', dir: '/root/selinux-policy-tools/push-1', backupDir: '/root/selinux-policy-tools/push-1/backup', modules: [{ name: 'zebra', priority: 100, had: true }, { name: 'mynew', priority: 100, had: false }, { name: 'local', priority: 400, had: true }],
  contexts: [{ file: 'default_contexts', to: '/etc/selinux/targeted/contexts/default_contexts', had: true }, { file: 'brk_u_default_contexts', to: '/etc/selinux/targeted/contexts/users/brk_u', had: false }], booleans: [{ name: 'allow_ptrace', value: true }], restoreDirs: ['/usr/sbin', '/var/run/zebra'], setPermissive: true });
check(/step start\ndate \+%s\ngetenforce/.test(push) && /step permissive\nsetenforce 0/.test(push) && /semodule -s 'targeted' -X 100 -E 'zebra'/.test(push) && /semodule -s 'targeted' -X 400 -E 'local'/.test(push) && !/-E 'mynew'/.test(push) && /cp -p '\/etc\/selinux\/targeted\/contexts\/default_contexts' '\/root\/selinux-policy-tools\/push-1\/backup\/contexts\/default_contexts'/.test(push) && !/cp -p '\/etc\/selinux\/targeted\/contexts\/users\/brk_u' '\/root/.test(push),
  'pushScript: the clock and mode first, setenforce 0 when asked, a backup of every replaced module and context file (not of new ones)', push);
check(/semodule -s 'targeted' -X 100 -i '\/root\/selinux-policy-tools\/push-1\/zebra\.pp' '\/root\/selinux-policy-tools\/push-1\/mynew\.pp'/.test(push) && /semodule -s 'targeted' -X 400 -i '\/root\/selinux-policy-tools\/push-1\/local\.pp'/.test(push) && push.indexOf('-X 100 -i') < push.indexOf('-X 400 -i'),
  'pushScript: semodule -i per priority, lowest first');
check(/mkdir -p \$\(dirname '\/etc\/selinux\/targeted\/contexts\/users\/brk_u'\) && cp -p '\/root\/selinux-policy-tools\/push-1\/contexts\/brk_u_default_contexts' '\/etc\/selinux\/targeted\/contexts\/users\/brk_u'/.test(push) && /setsebool -P 'allow_ptrace=1'/.test(push) && /restorecon -R '\/usr\/sbin' '\/var\/run\/zebra'/.test(push) && /--list-modules=full 2>\/dev\/null \| grep -E '\^\[0-9\]\+ \(zebra\|mynew\|local\) '/.test(push) && /step done\nrc \$\(\(1 - ok\)\)/.test(push),
  'pushScript: context files copied, booleans set, the directories relabeled, the modules verified, done with the overall result', push);
check(/if \[ \$ok = 1 \]; then/.test(push) && (push.match(/else rc skipped; fi/g) || []).length === 4, 'pushScript: later steps are skipped once a step failed');
const push2 = T.pushScript({ name: 'targeted', dir: '/d', backupDir: '/d/b', modules: [{ name: 'a', priority: 100, had: false }], contexts: [], booleans: [], restoreDirs: [], setPermissive: false });
check(!/setenforce/.test(push2) && /step booleans\nif \[ \$ok = 1 \]; then\n  rc 0/.test(push2) && /step restorecon\nif \[ \$ok = 1 \]; then\n  rc 0/.test(push2), 'pushScript: nothing optional when there is nothing to do');
const rb = T.rollbackScript({ name: 'targeted', backupDir: '/d/b', modules: [{ name: 'zebra', priority: 100, had: true }, { name: 'mynew', priority: 100, had: false }], contexts: [{ file: 'default_contexts', to: '/etc/selinux/targeted/contexts/default_contexts', had: true }, { file: 'x', to: '/etc/selinux/targeted/contexts/users/brk_u', had: false }], booleans: [{ name: 'allow_ptrace', value: true, was: false }], restoreDirs: ['/usr/sbin'] });
check(/semodule -s 'targeted' -X 100 -i '\/d\/b\/zebra\.pp'/.test(rb) && /semodule -s 'targeted' -X 100 -r 'mynew'/.test(rb) && /cp -p '\/d\/b\/contexts\/default_contexts' '\/etc\/selinux\/targeted\/contexts\/default_contexts'/.test(rb) && /rm -f '\/etc\/selinux\/targeted\/contexts\/users\/brk_u'/.test(rb) && /setsebool -P 'allow_ptrace=0'/.test(rb) && /restorecon -R '\/usr\/sbin'/.test(rb),
  'rollbackScript: replaced modules reinstalled from the backup, new ones removed, context files restored or removed, booleans back', rb);
const steps = T.parseSteps('### step start\n1700000000\nEnforcing\n### rc 0\n### step backup\nsome output\n### rc 0\n### step install\nlibsemanage: boom\n### rc 1\n### step contexts\n### rc skipped\n### step done\n### rc 1\n');
check(!steps.ok && steps.done && steps.at === 1700000000 && steps.mode === 'Enforcing' && steps.failed.join() === 'install' && steps.steps.find(s => s.id === 'install').out === 'libsemanage: boom' && steps.steps.find(s => s.id === 'contexts').rc === 'skipped' && steps.steps.find(s => s.id === 'backup').out === 'some output',
  'parseSteps: steps with their output and exit codes, the failed one named, skipped ones not failures', steps);
check(T.parseSteps('### step start\n1700000000\nPermissive\n### rc 0\n### step done\n### rc 0\n').ok && !T.parseSteps('### step start\n1\n### rc 0\n### step install\n').done, 'parseSteps: ok when done with 0; not done when cut off');
check(/systemctl restart 'sshd.service' 'chronyd.service'/.test(T.restartScript(['sshd.service', 'chronyd.service'])) && /systemctl is-active "\$u"/.test(T.restartScript(['a'])) && /semanage permissive -a 'zebra_t'/.test(T.permissiveScript('zebra_t', true)) && /semanage permissive -d 'zebra_t'/.test(T.permissiveScript('zebra_t', false)) && /semanage permissive -l -n/.test(T.permissiveScript('x', true)), 'restartScript / permissiveScript');
check(T.windowFor(60) === 'recent' && T.windowFor(600) === 'this-hour' && T.windowFor(4000) === 'today' && T.windowFor(90000) === 'this-week' && T.windowFor(10 * 86400) === 'this-month' && T.windowFor(40 * 86400) === 'this-year', 'windowFor: the ausearch window covering an age');
const since = T.recordsSince(`${REC.replace('1700000000.001', '1699999999.500')}\n${REC}\n----\nNov 12 sshd[1]: pam_selinux: Unable to get valid context\n`, 1700000000);
check(since.trim().split('\n').length === 3 && !/1699999999/.test(since) && /1700000000\.001/.test(since) && /----/.test(since) && /pam_selinux/.test(since), 'recordsSince: older audit events dropped, unstamped lines kept', since);
check(/journalctl -q --since '@1700000000'/.test(T.denialsScript('today', 1700000000.7)) && /-ts today --raw/.test(T.denialsScript('today', 1700000000)), 'denialsScript with an epoch: the journal from it, ausearch over the window word');

console.log(failures ? `\n${failures} target checks FAILED` : '\nall target checks passed');
process.exit(failures ? 1 : 0);
