# Contexts that won't load

A policy can compile and still fail on the host: the login programs, semodule,
restorecon and other programs read contexts from the policy's configuration
files, and each fails in its own way when the policy rejects one. Two checks
find these before a host does. Both run after every tree build, put their
problems on the lines that cause them, and have a panel that also checks
any installed policy.

**SELinux: Check Login Contexts…** works out the context each `seusers`
line gets for each way in (ssh, console, graphical, cron, systemd user
sessions), as libselinux does when a session starts:

* a login mapped to a user the policy lacks, a range it rejects, entries
  with a role the user can't have, a login program that may not switch to
  the user's domain: "Unable to get valid context for *user*";
* RHEL 8 and RHEL 9 pick differently (RHEL 9 takes the first valid entry
  without checking that the program may switch to it), so a configuration
  can work on one and fail on the other. The report says which.
* a login that gets a context and then bounces: the user's domain can't
  be entered through the shell or can't load its libraries, the kernel
  closes the terminal it inherits (no `fd use` on sshd, no access to the
  pty), or NoNewPrivileges / a nosuid mount refuses the change
  ("security_bounded_transition"). **How to fix** lists the interfaces of
  your policy that grant exactly what is missing, narrowest first, and
  writes the one you pick into the domain's module.
* what a restricted user then runs: wrappers and the programs they start,
  a command sshd forces, the startup scripts' programs. A `*_domtrans`
  call without the role for the new domain makes the exec fail with no
  AVC; a wrapper without the login program's descriptors runs without the
  terminal.

Each problem says what a host would log for it: an AVC, nothing (a
`dontaudit` rule hides it), `SELINUX_ERR`, or only "Unable to get valid
context" in sshd's log. After each build, problems the build added are marked
new, with the files you changed and the line that causes them.

**SELinux: Check Context Files…** covers every other place a context is
named:

* `file_contexts`: an invalid context or two lines for one path make
  `make validate` and semodule refuse the policy; the problem is on the
  module's `.fc` line;
* this host's `file_contexts.local`: one stale line makes every `semodule`
  and `semanage` change fail;
* home directories: the lines genhomedircon would silently leave out for a
  user (its prefix, role and level);
* types restorecon can't put on files (not file types);
* `default_type`, `x_contexts`, `dbus_contexts`, `openssh_contexts`,
  `lxc_contexts` and the rest, each with what its program does with a bad
  entry. Files read by programs your policy doesn't have are only noted.

Editing `seusers` or a contexts file updates the diagnostics without a
rebuild.
