# Security properties, checked after every build

Write your policy's security requirements down once, in `selinux.checks` at
the tree root, and version it with the policy. Every build re-checks them
against the compiled policy. **SELinux: Open Property Checks** creates
the file with examples.

```
# only auditd may write the audit log
only auditd_t may write auditd_log_t
# users must not touch password hashes
never user_t, staff_t may write shadow_t
# no way from user_t to sysadm_t, direct or through other domains
never user_t reaches sysadm_t
# password hashes must not flow to anything user_t can read
never shadow_t flows to user_t except passwd_t chkpwd_t
# the lockdown must not break logging
require syslogd_t may { append create } var_log_t:file
# roles and users
only sysadm_r may run sysadm_t
never staff_u may use sysadm_r
# logins (seusers and the contexts files)
never unconfined_u may log in
never login __default__ reaches sysadm_t
never login * may read shadow_t:file
# levels (MLS / MCS)
never container_t may ignore levels
require container_t isolated by levels
```

* `only` / `never` / `require` … `may` *permissions* *types*: who may access what.
* `reaches`: no domain transition path; `except through <domains>` allows
  the paths through those (e.g. a wrapper that is the only way in, as
  **SELinux: New Wrapped Programs…** writes them).
* `flows to`: no information flow through any chain of domains and files.
  `except` names the types trusted to pass the data on.
* Permission groups: `read`, `write`, `execute`, `any`, or `{ exact perms }`;
  names can be types, aliases or attributes (`*` = every domain).
* Logins: `only|never <users> may log in` checks which SELinux users seusers
  hands out; `never login <logins> …` follows a Linux login (`alice`,
  `%group`, `__default__`, `*` = all) to its user, where its ways in land
  and what its sessions can reach (`reaches`) or do (`may`), as **Logins and
  Users** shows it.
* Levels: `only|never <domains> may ignore levels [on <classes>]` checks
  which domains pass the MLS/MCS constraints whatever the levels;
  `require <domains> isolated by levels` checks that what two processes of a
  domain can share is level-checked, as **Levels and Categories** shows it.

Each line shows **✓ holds** or **✗** with the reason. A failure appears in
the Problems panel, with links to the source statements that grant each
violating rule, or to the steps of the path. The status bar counts failures.

This works for standalone modules too: the module is linked with the
installed policy, so "can my module read `shadow_t`?" has a real answer.
