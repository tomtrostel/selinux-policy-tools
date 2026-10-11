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
```

* `only` / `never` / `require` … `may` *permissions* *types*: who may access what.
* `reaches`: no domain transition path.
* `flows to`: no information flow through any chain of domains and files.
  `except` names the types trusted to pass the data on.
* Permission groups: `read`, `write`, `execute`, `any`, or `{ exact perms }`;
  names can be types, aliases or attributes (`*` = every domain).

Each line shows **✓ holds** or **✗** with the reason. A failure appears in
the Problems panel, with links to the source statements that grant each
violating rule, or to the steps of the path. The status bar counts failures.

This works for standalone modules too: the module is linked with the
installed policy, so "can my module read `shadow_t`?" has a real answer.
